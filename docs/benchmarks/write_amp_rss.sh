#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The #645 write-amplification + RSS-per-message HEAD-TO-HEAD (V2-M12): IronBus
# disk-durable defaults vs nats-server JetStream file storage, matched workloads.
#
# What it measures, per side and per payload size (256 B and 4 KiB by default):
#
#   WRITE AMPLIFICATION - two numbers, deliberately different in meaning:
#     * write_bytes amp = delta(/proc/<broker pid>/io write_bytes) / logical payload bytes.
#       write_bytes counts what the broker process caused the storage layer to write during
#       the produce phase, so it captures rewrite/index/compaction churn that never stays
#       on disk.
#     * du amp = delta(du -sB1 <store dir>) / logical payload bytes. du captures what is
#       RETAINED on disk after the produce phase settles (including preallocation slack).
#   RSS-PER-MESSAGE - broker VmRSS + VmHWM (/proc/<broker pid>/status) at idle, after
#     COUNT stored, and (256 B leg) after BIG_TOTAL stored; the steady-RSS delta per stored
#     message between the two stored points is the headline number.
#
# Matched workload, both sides: same message count, same payload bytes, pipelined durable
# publish (IronBus `bench --stream --pubwindow 1024` vs `nats bench js pub async --batch 500`),
# file-backed storage, fresh store per leg. The IronBus payload shape is `random`
# (incompressible) so the default lz4 compression cannot flatter the IronBus numbers; a
# `realistic` (compressible) context leg is recorded separately. The NATS server runs
# JetStream `sync_interval: always` - the closest match to IronBus's fsync-backed group
# commit, and REQUIRED for a fair write_bytes reading (without it, JetStream's writeback is
# attributed to kernel flusher threads, not the broker process); a default-sync-interval
# context leg is recorded separately so that choice is auditable. The remaining guarantee
# asymmetry (the JetStream publish ack is still NOT fsync-coupled; the IronBus ack is) is
# recorded in the results doc, not scored.
#
# Every measurement line is prefixed `OBSERV:` so a transcript can be grepped straight into
# the results table (docs/benchmarks/write-amp-rss.md). This script asserts nothing.
#
# Usage (Linux only - /proc semantics; no root needed; downloads the pinned nats-server +
# natscli for this arch; IRONBUS_BIN must point at a release `ironbus`):
#   IRONBUS_BIN=target/release/ironbus bash docs/benchmarks/write_amp_rss.sh [--side ib|nats|all]
# Environment overrides: NATS_SERVER_VERSION, NATSCLI_VERSION, WORK (scratch dir; keep it on
# a real local filesystem, NOT a bind mount, or write_bytes/du lose meaning), COUNT (200000),
# BIG_TOTAL (1000000; 0 skips the big leg), PAYLOADS ("256 4096").

set -u

IRONBUS_BIN=${IRONBUS_BIN:-ironbus}
NATS_SERVER_VERSION=${NATS_SERVER_VERSION:-2.14.3}
NATSCLI_VERSION=${NATSCLI_VERSION:-0.4.0}
WORK=${WORK:-$(mktemp -d /tmp/write-amp-rss.XXXXXX)}
COUNT=${COUNT:-200000}
BIG_TOTAL=${BIG_TOTAL:-1000000}
PAYLOADS=${PAYLOADS:-"256 4096"}
IB_ADDR=127.0.0.1:7777
NATS_URL=nats://127.0.0.1:4222
SIDE=all
# natscli's context machinery errors out when the shared config home is unusable; the
# harness never wants a saved context anyway (same private home as the #644 harness).
export XDG_CONFIG_HOME="$WORK/xdg"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --side) SIDE=$2; shift ;;
    *) echo "unknown argument $1 (only --side ib|nats|all)"; exit 2 ;;
  esac
  shift
done

case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64) ARCH=amd64 ;;
  *) echo "unsupported arch $(uname -m)"; exit 1 ;;
esac

mkdir -p "$WORK"
cd "$WORK" || exit 1

NATS="$WORK/nats -s $NATS_URL"
if [ "$SIDE" != "ib" ]; then
  echo "== downloading nats-server v${NATS_SERVER_VERSION} + natscli v${NATSCLI_VERSION} (linux-${ARCH})"
  curl -fsSL -o ns.tar.gz "https://github.com/nats-io/nats-server/releases/download/v${NATS_SERVER_VERSION}/nats-server-v${NATS_SERVER_VERSION}-linux-${ARCH}.tar.gz"
  tar xzf ns.tar.gz
  cp "nats-server-v${NATS_SERVER_VERSION}-linux-${ARCH}/nats-server" .
  curl -fsSL -o natscli.zip "https://github.com/nats-io/natscli/releases/download/v${NATSCLI_VERSION}/nats-${NATSCLI_VERSION}-linux-${ARCH}.zip"
  if command -v unzip >/dev/null 2>&1; then
    unzip -oq natscli.zip
  else
    python3 -m zipfile -e natscli.zip .
  fi
  cp "nats-${NATSCLI_VERSION}-linux-${ARCH}/nats" .
  chmod +x nats
  ./nats-server --version
  ./nats --version
fi
if [ "$SIDE" != "nats" ]; then
  "$IRONBUS_BIN" --version
fi

# ---- probes (all raw values in bytes; RSS lines also echo the raw kB source) -------------

# $1 pid -> "wchar write_bytes cancelled_write_bytes"
proc_io() {
  awk '/^wchar:/{w=$2} /^write_bytes:/{wb=$2} /^cancelled_write_bytes:/{c=$2} END{print w, wb, c}' "/proc/$1/io"
}
# $1 pid -> "VmRSS_bytes VmHWM_bytes"
proc_rss() {
  awk '/^VmRSS:/{r=$2} /^VmHWM:/{h=$2} END{print r*1024, h*1024}' "/proc/$1/status"
}
# $1 dir -> retained bytes
dus() { du -sB1 "$1" 2>/dev/null | cut -f1; }

# Capture one probe point: "VmRSS VmHWM wchar write_bytes cancelled_write_bytes du" (bytes).
capture() { # $1 pid, $2 store dir
  echo "$(proc_rss "$1") $(proc_io "$1") $(dus "$2")"
}

# OBSERV: print a captured probe point. $1 label, $2 the capture() string.
snapshot() {
  local label=$1 cap=$2
  echo "OBSERV: [$label] rss_bytes=$(field "$cap" 1) hwm_bytes=$(field "$cap" 2) wchar=$(field "$cap" 3) write_bytes=$(field "$cap" 4) cancelled_write_bytes=$(field "$cap" 5) du_bytes=$(field "$cap" 6)"
}

# Compute + print the derived deltas between two snapshot lines already emitted.
# $1 tag, $2..$4 before: rss wb du, $5..$7 after: rss wb du, $8 msgs, $9 payload_bytes
derive() {
  awk -v tag="$1" -v r0="$2" -v w0="$3" -v d0="$4" -v r1="$5" -v w1="$6" -v d1="$7" \
      -v n="$8" -v p="$9" 'BEGIN {
    # %.0f, not %d: mawk clamps %d at 2^31-1 and these deltas pass 2 GiB.
    logical = n * p
    printf "OBSERV: [%s] logical_bytes=%.0f write_bytes_delta=%.0f du_delta=%.0f rss_delta=%.0f\n", tag, logical, w1-w0, d1-d0, r1-r0
    printf "OBSERV: [%s] write_amp_write_bytes=%.3f write_amp_du=%.3f rss_bytes_per_msg=%.2f\n", tag, (w1-w0)/logical, (d1-d0)/logical, (r1-r0)/n
  }'
}

field() { echo "$1" | cut -d' ' -f"$2"; }

# ---- IronBus side ------------------------------------------------------------------------

SRV_PID=""
start_ironbus() { # $1 data dir
  "$IRONBUS_BIN" serve --data-dir "$1" > "$1.log" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/7777") 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "OBSERV: ironbus serve failed to become ready; log tail:"; tail -5 "$1.log"
  return 1
}

stop_broker() {
  kill -TERM "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
  SRV_PID=""
}

ib_publish() { # $1 count, $2 payload bytes, $3 shape
  "$IRONBUS_BIN" bench --addr "$IB_ADDR" --i-understand-this-is-live --mode publish \
    --stream --pubwindow 1024 --count "$1" --payload-bytes "$2" --payload-shape "$3" --json \
    > "$WORK/ib-pub.json" 2> "$WORK/ib-pub.err" || { echo "OBSERV: ironbus publish FAILED:"; tail -3 "$WORK/ib-pub.err"; return 1; }
  echo "OBSERV: producer: $(grep -oE '"(produced|elapsed_secs|msgs_per_sec)":[0-9.]+' "$WORK/ib-pub.json" | tr '\n' ' ')"
}

# One IronBus leg. $1 payload bytes, $2 shape, $3 leg tag, $4 big total (0 = skip).
leg_ironbus() {
  local size=$1 shape=$2 tag=$3 big=$4 data idle after big_after
  data=$WORK/ib-$tag
  echo
  echo "================ IronBus leg [$tag]: ${COUNT} x ${size} B, shape=$shape, disk-durable defaults ================"
  start_ironbus "$data" || return 1
  sleep 2
  idle=$(capture "$SRV_PID" "$data")
  snapshot "$tag idle" "$idle"
  ib_publish "$COUNT" "$size" "$shape" || { stop_broker; return 1; }
  sleep 3
  after=$(capture "$SRV_PID" "$data")
  snapshot "$tag after-${COUNT}" "$after"
  derive "$tag produce-${COUNT}" \
    "$(field "$idle" 1)" "$(field "$idle" 4)" "$(field "$idle" 6)" \
    "$(field "$after" 1)" "$(field "$after" 4)" "$(field "$after" 6)" "$COUNT" "$size"
  if [ "$big" -gt "$COUNT" ]; then
    ib_publish $((big - COUNT)) "$size" "$shape" || { stop_broker; return 1; }
    sleep 3
    big_after=$(capture "$SRV_PID" "$data")
    snapshot "$tag after-${big}" "$big_after"
    derive "$tag grow-${COUNT}-to-${big}" \
      "$(field "$after" 1)" "$(field "$after" 4)" "$(field "$after" 6)" \
      "$(field "$big_after" 1)" "$(field "$big_after" 4)" "$(field "$big_after" 6)" $((big - COUNT)) "$size"
    derive "$tag produce-${big}-cumulative" \
      "$(field "$idle" 1)" "$(field "$idle" 4)" "$(field "$idle" 6)" \
      "$(field "$big_after" 1)" "$(field "$big_after" 4)" "$(field "$big_after" 6)" "$big" "$size"
  fi
  stop_broker
  echo "OBSERV: [$tag] du_bytes_after_clean_shutdown=$(dus "$data")"
  rm -rf "$data" "$data.log"
}

# ---- NATS side ---------------------------------------------------------------------------

start_nats() { # $1 store dir, $2 sync mode (always | default)
  local sync_line=""
  [ "$2" = "always" ] && sync_line="sync_interval: always"
  cat > "$1.conf" <<EOF
port: 4222
jetstream {
  store_dir: "$1"
  $sync_line
}
EOF
  ./nats-server -c "$1.conf" > "$1.log" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 1 100); do
    $NATS rtt >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  echo "OBSERV: nats-server failed to become ready; log tail:"; tail -5 "$1.log"
  return 1
}

nats_stream_state() {
  $NATS stream info benchstream --json 2>/dev/null | grep -oE '"(messages|bytes)": *[0-9]+' | tr '\n' ' '
}

# One NATS leg. $1 payload bytes, $2 leg tag, $3 big total (0 = skip), $4 sync mode.
leg_nats() {
  local size=$1 tag=$2 big=$3 sync=$4 store idle after big_after
  store=$WORK/nats-$tag
  mkdir -p "$store"
  echo
  echo "================ NATS leg [$tag]: ${COUNT} x ${size} B, JetStream file storage, sync=$sync ================"
  start_nats "$store" "$sync" || return 1
  sleep 2
  idle=$(capture "$SRV_PID" "$store")
  snapshot "$tag idle" "$idle"
  $NATS bench js pub async wamp --create --storage file --purge \
    --msgs "$COUNT" --size "${size}B" --batch 500 > "$WORK/nats-pub.out" 2>&1 \
    || { echo "OBSERV: nats publish FAILED:"; tail -3 "$WORK/nats-pub.out"; stop_broker; return 1; }
  echo "OBSERV: producer: $(grep -E 'Pub stats|msgs/sec' "$WORK/nats-pub.out" | tail -1 | sed 's/^ *//')"
  sleep 3
  after=$(capture "$SRV_PID" "$store")
  snapshot "$tag after-${COUNT}" "$after"
  echo "OBSERV: [$tag] stream state after ${COUNT}: $(nats_stream_state)"
  derive "$tag produce-${COUNT}" \
    "$(field "$idle" 1)" "$(field "$idle" 4)" "$(field "$idle" 6)" \
    "$(field "$after" 1)" "$(field "$after" 4)" "$(field "$after" 6)" "$COUNT" "$size"
  if [ "$big" -gt "$COUNT" ]; then
    $NATS bench js pub async wamp \
      --msgs $((big - COUNT)) --size "${size}B" --batch 500 > "$WORK/nats-pub2.out" 2>&1 \
      || { echo "OBSERV: nats grow publish FAILED:"; tail -3 "$WORK/nats-pub2.out"; stop_broker; return 1; }
    sleep 3
    big_after=$(capture "$SRV_PID" "$store")
    snapshot "$tag after-${big}" "$big_after"
    echo "OBSERV: [$tag] stream state after ${big}: $(nats_stream_state)"
    derive "$tag grow-${COUNT}-to-${big}" \
      "$(field "$after" 1)" "$(field "$after" 4)" "$(field "$after" 6)" \
      "$(field "$big_after" 1)" "$(field "$big_after" 4)" "$(field "$big_after" 6)" $((big - COUNT)) "$size"
    derive "$tag produce-${big}-cumulative" \
      "$(field "$idle" 1)" "$(field "$idle" 4)" "$(field "$idle" 6)" \
      "$(field "$big_after" 1)" "$(field "$big_after" 4)" "$(field "$big_after" 6)" "$big" "$size"
  fi
  stop_broker
  echo "OBSERV: [$tag] du_bytes_after_clean_shutdown=$(dus "$store")"
  rm -rf "$store" "$store.log" "$store.conf"
}

# ---- run ---------------------------------------------------------------------------------

# Two context legs ride along with the 256 B size (both deliberately UNPAIRED):
#   * ib-256-realistic - the same workload with the default-shipped compressible
#     (`realistic`) payload shape, showing what the default lz4 compression does to IronBus
#     write amplification on structured-telemetry-like payloads. NATS does not compress by
#     default, so this leg has no matched other side.
#   * nats-256-defaultsync - the same workload against NATS's SHIPPED default sync interval
#     (2 min, no fsync per write), so the `sync_interval: always` choice on the matched leg
#     is auditable rather than taken on faith. On this leg the broker's write_bytes
#     UNDERCOUNTS real disk traffic (writeback is attributed to kernel flusher threads) and
#     the durability is strictly weaker than the IronBus side; it is context, not a pair.
for size in $PAYLOADS; do
  big=0
  [ "$size" = "256" ] && big=$BIG_TOTAL
  if [ "$SIDE" != "nats" ]; then
    leg_ironbus "$size" random "ib-${size}" "$big"
    [ "$size" = "256" ] && leg_ironbus 256 realistic "ib-256-realistic" 0
  fi
  if [ "$SIDE" != "ib" ]; then
    leg_nats "$size" "nats-${size}" "$big" always
    [ "$size" = "256" ] && leg_nats 256 "nats-256-defaultsync" 0 default
  fi
done

echo
echo "== done; transcripts in $WORK (grep OBSERV: for the results table inputs)"
