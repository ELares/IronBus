#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The NATS side of the #644 corruption-recovery HEAD-TO-HEAD (V2-M12).
#
# Reproduces the four corruption classes of the head-to-head against a single-node
# nats-server with JetStream file storage and `sync_interval: always`, and RECORDS the
# observed behavior (it asserts nothing — the point is measurement):
#
#   S1  single-bit flip in a stored .blk        (nats-server issue #7549)
#   S2  a >= 32 MB record under a 64 MB limit   (nats-server issue #6797)
#   S3  a torn tail (partial trailing write)    (the power-cut class)
#   S4  a stale index: index.db references a missing msg block (nats-server issue #5412;
#       the cluster-wide snapshot-corruption escalation is #7556, cluster-only, not
#       reproducible single-node)
#
# The IronBus side of the same four classes is the repeatable
# `crates/ironbus-cli/tests/corruption_recovery.rs` integration test; the measured results
# of BOTH sides live in `docs/benchmarks/corruption-recovery.md`.
#
# Usage (no root needed; downloads the pinned nats-server + natscli for this arch):
#   bash docs/benchmarks/corruption_recovery_nats.sh
# Environment overrides: NATS_SERVER_VERSION, NATSCLI_VERSION, WORK (scratch dir).
#
# Every observation line is prefixed `OBSERV:` so a transcript can be grepped into the
# results table.

set -u

NATS_SERVER_VERSION=${NATS_SERVER_VERSION:-2.14.3}
NATSCLI_VERSION=${NATSCLI_VERSION:-0.4.0}
WORK=${WORK:-$(mktemp -d /tmp/corruption-recovery-nats.XXXXXX)}
URL=nats://127.0.0.1:4222
NATS="$WORK/nats -s $URL"
# A private config home: natscli's context machinery errors out ("context not found") when the
# shared config home is unusable; the harness never wants a saved context anyway.
export XDG_CONFIG_HOME="$WORK/xdg"

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

# Starts nats-server over $1 (store dir), logging to $1.log. max_payload is $2 (bytes).
start_server() {
  local store=$1 max_payload=$2
  cat > "$store.conf" <<EOF
port: 4222
max_payload: $max_payload
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

stop_server() {
  kill -TERM "$SRV_PID" 2>/dev/null
  wait "$SRV_PID" 2>/dev/null
}

# Counts how many of the stream's messages are actually readable via a fresh pull consumer,
# and prints the distinct payload markers seen. $1 stream, $2 expected count, $3 marker regex.
readback() {
  local stream=$1 expected=$2 marker=$3
  local cons="RB$RANDOM"
  $NATS consumer add "$stream" "$cons" --pull --deliver=all --ack=explicit --defaults >/dev/null 2>&1
  $NATS consumer next "$stream" "$cons" --count="$expected" --timeout=5s > "$WORK/rb.out" 2>&1
  grep -oE "$marker" "$WORK/rb.out" | sort -u > "$WORK/rb.seen"
  echo "$(wc -l < "$WORK/rb.seen" | tr -d ' ')"
}

flip_bit() { # $1 file, $2 ascii pattern: flip lowest bit of the pattern's first byte
  local f=$1 pat=$2
  local off b
  off=$(grep -abo "$pat" "$f" | head -1 | cut -d: -f1)
  if [ -z "$off" ]; then echo "OBSERV: pattern $pat NOT FOUND in $f"; return 1; fi
  b=$(dd if="$f" bs=1 skip="$off" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  printf "\\$(printf '%03o' $((b ^ 1)))" | dd of="$f" bs=1 seek="$off" conv=notrunc 2>/dev/null
  echo "OBSERV: flipped one bit at byte $off of $(basename "$f") (in payload \"$pat\")"
}

filestore_warnings() { # $1 log file
  grep -E "\[(WRN|ERR)\]" "$1" | grep -viE "insecure|deprecat" | sed 's/^/OBSERV:   server log: /' | tail -6
}

echo
echo "================ S1: single-bit flip in a stored .blk (#7549) ================"
S1=$WORK/store-s1
start_server "$S1" 1048576
$NATS stream add S1 --subjects=s1 --storage=file --replicas=1 --defaults >/dev/null
$NATS pub s1 "rec-{{Count}}-payload-padding-to-make-records-realistic" --count=300 >/dev/null 2>&1
echo "OBSERV: pre-corruption: messages=$($NATS stream info S1 --json | grep -o '"messages": *[0-9]*' | head -1)"
stop_server
BLK=$(find "$S1" -name '*.blk' | sort | head -1)
echo "OBSERV: store layout: $(find "$S1" -name '*.blk' -o -name 'index.db' | sed "s|$S1/||" | tr '\n' ' ')"
flip_bit "$BLK" "rec-150-payload"
start_server "$S1" 1048576
echo "OBSERV: post-corruption: messages=$($NATS stream info S1 --json | grep -o '"messages": *[0-9]*' | head -1)"
SEEN=$(readback S1 300 'rec-[0-9]+-payload')
FRAMES=$(grep -c "str seq:" "$WORK/rb.out")
echo "OBSERV: readback: $FRAMES messages delivered; $SEEN of 300 carry an INTACT payload"
grep -q "str seq: 150 " "$WORK/rb.out" \
  && echo "OBSERV: a frame for stream seq 150 WAS delivered" \
  || echo "OBSERV: no frame for stream seq 150 was delivered (skipped without an error to the consumer)"
awk -F- '{print $2}' "$WORK/rb.seen" | sort -n > "$WORK/rb.nums"
LOST=$(comm -23 <(seq 1 300) "$WORK/rb.nums" | tr '\n' ',' | cut -c1-120)
echo "OBSERV: acknowledged messages missing an intact readback (by number): ${LOST:-none}"
# The load-bearing distinction: was the flipped message DROPPED, or DELIVERED CORRUPTED?
# The flip turns the leading 'r' of "rec-150-payload..." into 's', so a delivered corrupt
# payload reads "sec-150-payload...".
CORRUPT_SERVED=$(grep -oE 'sec-150-payload[a-z-]*' "$WORK/rb.out" | head -1)
if [ -n "$CORRUPT_SERVED" ]; then
  echo "OBSERV: the flipped message WAS DELIVERED, CORRUPTED, AS TRUTH: \"$CORRUPT_SERVED\" (no error, no warning)"
else
  echo "OBSERV: the flipped message was silently dropped (not delivered at all)"
fi
filestore_warnings "$S1.log"
stop_server

echo
echo "================ S2: >= 32 MB record under a 64 MB max_payload (#6797) ================"
S2=$WORK/store-s2
start_server "$S2" 67108864
$NATS stream add BIG --subjects=big --storage=file --replicas=1 --max-msg-size=-1 --defaults >/dev/null
head -c 33554432 /dev/urandom | base64 -w0 | head -c 33554432 > "$WORK/payload32.bin"
echo "OBSERV: publishing one $(stat -c %s "$WORK/payload32.bin")-byte message (32 MiB) with max_payload=64MB"
# A JetStream (acknowledged) publish, the shape of the #6797 report.
if $NATS pub big --jetstream --force-stdin < "$WORK/payload32.bin" > "$WORK/s2-pub.out" 2>&1; then
  echo "OBSERV: JetStream publish result: $(grep -viE '^\s*$' "$WORK/s2-pub.out" | tail -1)"
else
  echo "OBSERV: JetStream publish FAILED: $(grep -viE '^\s*$' "$WORK/s2-pub.out" | tail -1)"
fi
# The core (fire-and-forget) publish captured by the stream, for the silent-drop variant.
$NATS pub big --force-stdin < "$WORK/payload32.bin" > "$WORK/s2-pub-core.out" 2>&1 \
  && echo "OBSERV: core (unacked) publish of the same 32 MiB: client reports success" \
  || echo "OBSERV: core (unacked) publish FAILED: $(tail -1 "$WORK/s2-pub-core.out")"
sleep 1
echo "OBSERV: stream state: messages=$($NATS stream info BIG --json | grep -o '"messages": *[0-9]*' | head -1)"
$NATS consumer add BIG CB --pull --deliver=all --ack=explicit --defaults >/dev/null 2>&1
$NATS consumer next BIG CB --count=1 --timeout=10s > "$WORK/s2-read.out" 2>&1
RC=$?
BYTES=$(wc -c < "$WORK/s2-read.out" | tr -d ' ')
echo "OBSERV: consume attempt: exit=$RC, output bytes=$BYTES, tail: $(tail -c 200 "$WORK/s2-read.out" | tr '\n' ' ')"
echo "OBSERV: after a restart (lookup path exercised cold):"
stop_server
start_server "$S2" 67108864
$NATS consumer next BIG CB --count=1 --timeout=10s > "$WORK/s2-read2.out" 2>&1
RC=$?
BYTES=$(wc -c < "$WORK/s2-read2.out" | tr -d ' ')
echo "OBSERV: consume after restart: exit=$RC, output bytes=$BYTES, tail: $(tail -c 200 "$WORK/s2-read2.out" | tr '\n' ' ')"
filestore_warnings "$S2.log"
stop_server

echo
echo "================ S3: torn tail — partial trailing write ================"
S3=$WORK/store-s3
start_server "$S3" 1048576
$NATS stream add S3 --subjects=s3 --storage=file --replicas=1 --defaults >/dev/null
$NATS pub s3 "torn-{{Count}}-payload-padding-for-realistic-record-size" --count=100 >/dev/null 2>&1
echo "OBSERV: pre-corruption: messages=$($NATS stream info S3 --json | grep -o '"messages": *[0-9]*' | head -1)"
stop_server
BLK=$(find "$S3" -name '*.blk' | sort | tail -1)
SZ=$(stat -c %s "$BLK")
truncate -s -7 "$BLK"
echo "OBSERV: truncated $(basename "$BLK") by 7 bytes ($SZ -> $(stat -c %s "$BLK")) — a torn trailing record"
start_server "$S3" 1048576
echo "OBSERV: post-corruption: messages=$($NATS stream info S3 --json | grep -o '"messages": *[0-9]*' | head -1)"
SEEN=$(readback S3 100 'torn-[0-9]+')
echo "OBSERV: readback: $SEEN of 100 acknowledged messages readable"
filestore_warnings "$S3.log"
stop_server

echo
echo "================ S4: stale index — index.db references a missing block (#5412) ================"
S4=$WORK/store-s4
start_server "$S4" 1048576
$NATS stream add S4 --subjects=s4 --storage=file --replicas=1 --defaults >/dev/null
$NATS consumer add S4 C4 --pull --deliver=all --ack=explicit --defaults >/dev/null
$NATS pub s4 "stale-{{Count}}-payload-padding-for-realistic-record-size" --count=50 >/dev/null 2>&1
$NATS consumer next S4 C4 --count=20 --timeout=5s >/dev/null 2>&1
echo "OBSERV: pre-corruption: messages=$($NATS stream info S4 --json | grep -o '"messages": *[0-9]*' | head -1), consumer acked 20"
stop_server
echo "OBSERV: store layout: $(find "$S4" -path '*S4*' \( -name '*.blk' -o -name 'index.db' \) | sed "s|$S4/||" | tr '\n' ' ')"
find "$S4" -path '*S4*' -name '*.blk' -delete
echo "OBSERV: deleted the stream's msg block(s); index.db retained (the #5412 shape: the index references a block that no longer exists)"
start_server "$S4" 1048576
echo "OBSERV: post-corruption stream state: $($NATS stream info S4 --json | grep -oE '"(messages|first_seq|last_seq)": *[0-9]*' | tr '\n' ' ')"
echo "OBSERV: consumer state: $($NATS consumer info S4 C4 --json | grep -oE '"(stream_seq|consumer_seq|num_pending)": *[0-9]*' | tr '\n' ' ')"
$NATS pub s4 "post-restart-{{Count}}" --count=5 >/dev/null 2>&1
$NATS consumer next S4 C4 --count=40 --timeout=5s > "$WORK/s4-read.out" 2>&1
SEEN_OLD=$(grep -cE 'stale-[0-9]+' "$WORK/s4-read.out")
SEEN_NEW=$(grep -cE 'post-restart-' "$WORK/s4-read.out")
echo "OBSERV: consumer readback after restart: $SEEN_OLD of the 30 unacked pre-corruption messages, $SEEN_NEW of 5 post-restart messages; tail: $(tail -c 150 "$WORK/s4-read.out" | tr '\n' ' ')"
filestore_warnings "$S4.log"
stop_server

echo
echo "== done; transcripts in $WORK (grep OBSERV: for the results table inputs)"
