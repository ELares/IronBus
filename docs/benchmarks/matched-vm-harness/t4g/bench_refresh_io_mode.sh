#!/bin/bash
# bench_refresh.sh — medians-of-3 t4g matrix, IronBus (--io-mode auto, which auto-detects
# EBS as network-durable and engages the safe O_DIRECT metadata-free barrier) vs Redpanda
# v26.1.12 (production mode, write_caching=false = genuine fsync-before-ack). Real EBS gp3
# fdatasync. Run in-guest on a t4g.large (2 vCPU) via `bash bench_refresh.sh`.
#
# AUTHORITATIVE rows (published in REDPANDA_MATCHED_2026_07.md §7 "io-mode update"):
#   P1 (both sizes), P2 single-conn (both sizes), L1 durable-ack latency (both sizes).
#   These are single-process, fair-config comparisons that are sound on a 2-vCPU box.
#
# NOT authoritative on a 2-vCPU box (kept here for the methodology, but do NOT publish):
#   * "P2 multi x8" for Redpanda runs 8 parallel kafka-producer-perf JVMs; 8 JVMs starving
#     2 vCPUs measures JVM contention, not Redpanda's throughput. §7's careful 1/4/8-client
#     concurrency sweep (Redpanda peaks at 1 client, IronBus scales) is the fair treatment.
#   * "C1 consume" via kafka-consumer-perf-test under-measures Redpanda ~3x vs §7's method;
#     C1 stays methodology-sensitive — see §7 / the matched-VM study, not this row.
set -u
IB="$HOME/ironbus-bin"
export TMPDIR="$HOME/benchtmp"; mkdir -p "$TMPDIR"
KP="$HOME/xb/kafka/kafka_2.13-4.3.1/bin/kafka-producer-perf-test.sh"
KC="$HOME/xb/kafka/kafka_2.13-4.3.1/bin/kafka-consumer-perf-test.sh"
BOOT=127.0.0.1:9092
median3() { printf '%s\n%s\n%s\n' "$1" "$2" "$3" | sort -n | sed -n 2p; }

ib_msgs() { # ARGS -> median msgs/sec (3 runs)
  local v1 v2 v3
  for r in 1 2 3; do
    local out; out=$( (cd "$(dirname "$IB")" && "$IB" bench --io-mode auto --storage disk --payload-shape realistic "$@" --json 2>/dev/null) \
      | python3 -c "import json,sys;print(int(json.load(sys.stdin)['results']['msgs_per_sec']))" 2>/dev/null )
    eval "v$r=${out:-0}"
  done
  median3 "$v1" "$v2" "$v3"
}
ib_lat() { # ARGS -> "p50 p99" median us (3 runs)
  local a1 a2 a3 b1 b2 b3
  for r in 1 2 3; do
    read -r a b < <( (cd "$(dirname "$IB")" && "$IB" bench --io-mode auto --storage disk --payload-shape realistic "$@" --json 2>/dev/null) \
      | python3 -c "import json,sys;r=json.load(sys.stdin)['results'];print(int(r.get('ack_p50_us') or 0), int(r.get('ack_p99_us') or 0))" 2>/dev/null )
    eval "a$r=${a:-0}; b$r=${b:-0}"
  done
  echo "$(median3 "$a1" "$a2" "$a3") $(median3 "$b1" "$b2" "$b3")"
}

rp_up() { sudo rpk redpanda mode production >/dev/null 2>&1; sudo systemctl restart redpanda >/dev/null 2>&1
  for i in $(seq 1 60); do rpk cluster info -X brokers=$BOOT >/dev/null 2>&1 && break; sleep 2; done
  sudo rpk cluster config set write_caching_default false >/dev/null 2>&1; }
rp_down() { sudo systemctl stop redpanda >/dev/null 2>&1; }
rp_topic() { rpk topic delete "$1" >/dev/null 2>&1; sleep 1; rpk topic create "$1" -p "${2:-1}" -r 1 -c write.caching=false >/dev/null 2>&1; }
rp_rate() { # topic count size extraprops... -> median records/sec (3 runs)
  local t=$1 n=$2 sz=$3; shift 3; local v1 v2 v3
  for r in 1 2 3; do
    rpk topic delete "$t" >/dev/null 2>&1; sleep 1; rpk topic create "$t" -p 1 -r 1 -c write.caching=false >/dev/null 2>&1
    local o; o=$("$KP" --topic "$t" --num-records "$n" --record-size "$sz" --throughput -1 --producer-props bootstrap.servers=$BOOT "$@" 2>&1 | grep 'records sent' | tail -1 | grep -oE '[0-9.]+ records/sec' | head -1 | grep -oE '^[0-9]+')
    eval "v$r=${o:-0}"
  done
  median3 "$v1" "$v2" "$v3"
}

echo "############ IRONBUS (--io-mode auto) — medians of 3 ############"
for sz in 128 1024; do
  echo "P1/${sz}  sync-per-msg : $(ib_msgs --mode publish --pubwindow 1 --count 3000 --payload-bytes $sz) msg/s"
  echo "L1/${sz}  durable-ack  : $(ib_lat  --mode publish --pubwindow 1 --count 20000 --payload-bytes $sz) us (p50 p99)"
  echo "P2/${sz}  single w4096 : $(ib_msgs --mode publish --stream --pubwindow 4096 --producers 1 --count 500000 --payload-bytes $sz) msg/s"
  echo "P2/${sz}  multi   x8   : $(ib_msgs --mode publish --stream --pubwindow 4096 --producers 8 --count 1200000 --payload-bytes $sz) msg/s"
  echo "C1/${sz}  consume(matched): $(ib_msgs --mode subscribe --consume-tier streaming --fetch-batch 2048 --no-fsync --count 3000000 --payload-bytes $sz) msg/s"
done

echo "############ REDPANDA v26.1.12 (production, write_caching=false) — medians of 3 ############"
rp_up
for sz in 128 1024; do
  echo "P1/${sz}  sync-per-msg : $(rp_rate p1 3000 $sz acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none) rec/s"
  echo "P2/${sz}  single       : $(rp_rate p2 500000 $sz acks=all batch.size=65536 linger.ms=5 max.in.flight.requests.per.connection=5 compression.type=none) rec/s"
done
echo "--- L1 un-queued latency (rate 200, acks=all, no client-queue inflation) ---"
for sz in 128 1024; do
  rpk topic delete l1 >/dev/null 2>&1; sleep 1; rpk topic create l1 -p 1 -r 1 -c write.caching=false >/dev/null 2>&1
  echo "L1/${sz} : $("$KP" --topic l1 --num-records 4000 --record-size $sz --throughput 200 --producer-props bootstrap.servers=$BOOT acks=all batch.size=1 linger.ms=0 max.in.flight.requests.per.connection=1 compression.type=none 2>&1 | grep 'records sent' | tail -1 | grep -oE '[0-9]+ ms 50th|[0-9]+ ms 99th' | tr '\n' ' ')"
done
echo "--- P2 multi (8 parallel producers to 8 partitions, sum) ---"
for sz in 128 1024; do
  rpk topic delete p2m >/dev/null 2>&1; sleep 1; rpk topic create p2m -p 8 -r 1 -c write.caching=false >/dev/null 2>&1
  rm -f /tmp/p2m.txt
  for k in 1 2 3 4 5 6 7 8; do "$KP" --topic p2m --num-records 150000 --record-size $sz --throughput -1 --producer-props bootstrap.servers=$BOOT acks=all batch.size=65536 linger.ms=5 max.in.flight.requests.per.connection=5 compression.type=none 2>&1 | grep 'records sent' | grep -oE '[0-9.]+ records/sec' | head -1 | grep -oE '^[0-9]+' >> /tmp/p2m.txt & done
  wait
  echo "P2/${sz} multi x8 sum : $(paste -sd+ /tmp/p2m.txt | bc) rec/s"
done
echo "--- C1 consume ---"
for sz in 128 1024; do
  rpk topic delete c1 >/dev/null 2>&1; sleep 1; rpk topic create c1 -p 1 -r 1 >/dev/null 2>&1
  "$KP" --topic c1 --num-records 3000000 --record-size $sz --throughput -1 --producer-props bootstrap.servers=$BOOT acks=1 batch.size=65536 linger.ms=5 compression.type=none >/dev/null 2>&1
  echo "C1/${sz} : $("$KC" --topic c1 --messages 3000000 --bootstrap-server $BOOT --group c1g --timeout 60000 2>/dev/null | tail -1 | awk -F, '{print "MB.sec="$4" nMsg.sec="$6}')"
done
rp_down
echo "BENCH_REFRESH DONE"
