#!/bin/bash
# c1diag.sh — ATTRIBUTION diagnostic for the C1 consume regression (#1191 stage 2).
#
# The 2026-07 refresh smoke found IronBus C1/128B (Tier-S durable consume) at ~1.3M msg/s
# vs the study's pre-sendfile 5.66M on the same matched-VM substrate. Prime suspect: the
# #1174 zero-copy sendfile(2) splice delivery path (AUTO-ON on Linux+plaintext+disk),
# which on guest loopback turns each delivered batch into a write(header)+sendfile(body)
# syscall pair where the old copy path accumulated into one write.
#
# The bench-spawned isolated broker HARDCODES the sendfile toggle ON (ServeConfig::
# bench_default(); bench_run.rs never consults the kill-switch), so the OFF arm cannot
# run through the matrix path. This script instead runs C1 through `bench --addr` LIVE
# mode against a REAL `ironbus serve` broker started with and without the operator
# kill-switch `--no-zero-copy-sendfile`, everything else matched to the bench broker
# (checkpoint-interval=1, shipped defaults, fresh ext4 data dir per run, guest loopback).
#
# Rows land in results/results.jsonl with mode=diag-live-on / diag-live-off (NEVER
# "timed", so medians2.py and the matrix can never mix them in) and a config_summary
# that names the arm; the OFF arm carries the "+nosplice" suffix.
#
# Mechanism evidence: one extra UNRECORDED run per arm at 128B under
# `strace -c -f -p <serve pid>` — the write/sendfile syscall counts pin the mechanism,
# not just the delta. strace slows the broker, so straced runs are never recorded.
set -u
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPTS_DIR/lib2.sh"

RESULTS="$XB2_RESULTS/results.jsonl"
SERVE_DIR="$XB2_TMP/c1diag"
SERVE_PID=""

VMNOTE="; MATCHED-VM: broker AND client inside the same lima vz VM (Ubuntu kernel 7.0, ext4 on virtio vda1, guest loopback); fsync = guest fdatasync through virtio — matched across brokers, not a host-power-loss claim"

serve_start() { # ARM: on | off
  local arm="$1" flags=""
  [ "$arm" = "off" ] && flags="--no-zero-copy-sendfile"
  assert_serial_clear
  rm -rf "$SERVE_DIR"; mkdir -p "$SERVE_DIR"
  # checkpoint-interval=1 matches the bench-spawned broker (durable cursor write per
  # ack); every other knob is the shipped default, exactly like bench_default().
  "$IRONBUS_BIN" serve --data-dir "$SERVE_DIR/data" --checkpoint-interval 1 $flags \
    > "$SERVE_DIR/serve.log" 2>&1 &
  SERVE_PID=$!
  wait_port_open 7777 20 || xb_die "c1diag: serve ($arm) did not open 7777"
}

serve_stop() {
  if [ -n "$SERVE_PID" ]; then
    kill -INT "$SERVE_PID" 2>/dev/null
    wait "$SERVE_PID" 2>/dev/null
    SERVE_PID=""
  fi
  wait_port_free 7777 15 || xb_die "c1diag: 7777 still busy after serve stop"
}
trap serve_stop EXIT

bench_live() { # SIZE COUNT RAW
  local size="$1" count="$2" raw="$3"
  (cd "$IRONBUS_RELEASE_DIR" && "$IRONBUS_BIN" bench \
      --mode subscribe --consume-tier streaming \
      --count "$count" --payload-bytes "$size" --payload-shape realistic \
      --addr 127.0.0.1:7777 --i-understand-this-is-live --json) \
      > "$raw" 2>"$raw.err"
}

record() { # ARM SIZE COUNT RUNIDX RAW
  local arm="$1"
  XD_ARM="$arm" XD_SIZE="$2" XD_COUNT="$3" XD_RUNIDX="$4" XD_RAW="$5" \
  XD_RESULTS="$RESULTS" XD_VMNOTE="$VMNOTE" python3 <<'PYEOF'
import json, os, sys
raw = os.environ["XD_RAW"]
d = json.loads(open(raw, errors="replace").read())
r = d["results"]
msgs = r["msgs_per_sec"]
if msgs is None or msgs != msgs or msgs <= 0:
    sys.stderr.write("c1diag PARSE FAILURE: no sane msgs_per_sec from %s\n" % raw)
    sys.exit(3)
size = int(os.environ["XD_SIZE"])
arm = os.environ["XD_ARM"]
base = ("ironbus DIAGNOSTIC attribution run (NOT a matrix row): real `serve` broker on "
        "guest loopback, checkpoint-interval=1 (matching the bench-spawned broker), "
        "shipped defaults otherwise; Tier-S streaming consume via bench --addr live mode, "
        "self-prefilled, drain-only timing")
if arm == "on":
    cfg = base + "; zero-copy sendfile(2) AUTO-ON (the shipped #1174 default)" + os.environ["XD_VMNOTE"]
else:
    cfg = base + "; zero-copy sendfile(2) FORCED OFF via `serve --no-zero-copy-sendfile` (userspace copy path)+nosplice" + os.environ["XD_VMNOTE"]
rec = {
    "row": "C1", "size": size, "broker": "ironbus", "tier_label": "durable-consume",
    "mode": "diag-live-%s" % arm, "run_idx": int(os.environ["XD_RUNIDX"]),
    "count": int(os.environ["XD_COUNT"]),
    "msgs_per_sec": round(msgs, 3), "mb_per_sec": round(msgs * size / 1e6, 4),
    "p50_us": r.get("latency_p50_us"), "p99_us": r.get("latency_p99_us"),
    "p999_us": r.get("latency_p999_us"),
    "raw_log": raw, "config_summary": cfg, "ts": int(os.environ["XD_TS"]),
}
with open(os.environ["XD_RESULTS"], "a") as f:
    f.write(json.dumps(rec) + "\n")
print("MSGS_PER_SEC=%d" % int(msgs))
PYEOF
}

clamp() { # RATE SIZE -> frozen count (row2.sh C1 clamp: rate*20s, [50k, 5M], 3GiB byte cap)
  local rate="$1" size="$2" c
  c=$((rate * 20))
  [ "$c" -lt 50000 ] && c=50000
  [ "$c" -gt 5000000 ] && c=5000000
  local maxmsgs=$(( 3221225472 / size ))
  [ "$c" -gt "$maxmsgs" ] && c=$maxmsgs
  echo "$c"
}

for SIZE in 128 1024; do
  for ARM in on off; do
    xb_log "=== c1diag C1/$SIZE arm=$ARM ==="

    # pilot -> freeze (fresh broker, mirroring the isolated per-invocation lifecycle)
    serve_start "$ARM"
    TS=$(date +%s); export XD_TS="$TS"
    PRAW="$XB2_LOGS/c1diag_${SIZE}_${ARM}_pilot_${TS}.log"
    bench_live "$SIZE" 50000 "$PRAW" || xb_die "c1diag pilot failed ($SIZE/$ARM, see $PRAW.err)"
    serve_stop
    RATE=$(python3 -c "import json;print(int(json.load(open('$PRAW'))['results']['msgs_per_sec']))")
    [ -n "$RATE" ] && [ "$RATE" -gt 0 ] || xb_die "c1diag pilot produced no rate ($SIZE/$ARM)"
    COUNT="$(clamp "$RATE" "$SIZE")"
    xb_log "c1diag C1/$SIZE/$ARM pilot rate=$RATE msg/s -> frozen count=$COUNT"

    # 3 timed runs, each on a fresh broker + fresh data dir (the isolated protocol)
    i=1
    while [ "$i" -le 3 ]; do
      serve_start "$ARM"
      TS=$(date +%s); export XD_TS="$TS"
      RAW="$XB2_LOGS/c1diag_${SIZE}_${ARM}_timed${i}_${TS}.log"
      bench_live "$SIZE" "$COUNT" "$RAW" || xb_die "c1diag timed $i failed ($SIZE/$ARM, see $RAW.err)"
      serve_stop
      OUT="$(record "$ARM" "$SIZE" "$COUNT" "$i" "$RAW")" || xb_die "c1diag record failed"
      xb_log "c1diag C1/$SIZE/$ARM timed $i: $OUT"
      sleep 15
      i=$((i+1))
    done

    # strace mechanism evidence @128B only: one UNRECORDED run per arm at a FIXED
    # count (identical both arms, so per-batch syscall ratios are comparable).
    # strace slows the broker; this run is never recorded.
    if [ "$SIZE" = "128" ]; then
      serve_start "$ARM"
      SRAW="$XB2_LOGS/c1diag_128_${ARM}_strace_$(date +%s)"
      strace -c -f -p "$SERVE_PID" -o "$SRAW.strace" 2>/dev/null &
      TPID=$!
      sleep 0.5
      bench_live 128 1000000 "$SRAW.bench" \
        || xb_log "c1diag strace-run bench failed ($ARM) — counts may be partial"
      sleep 0.5
      kill -INT "$TPID" 2>/dev/null
      wait "$TPID" 2>/dev/null
      serve_stop
      xb_log "c1diag strace ($ARM) -> $SRAW.strace"
    fi
    sleep 5
  done
done

xb_log "c1diag complete"
