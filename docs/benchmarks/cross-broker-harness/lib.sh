#!/bin/bash
# xbench lib.sh — per-broker lifecycle helpers for the cross-broker benchmark harness.
# bash 3.2 compatible (macOS default). Absolute paths only; no reliance on cwd.
# Brokers: ironbus | nats | kafka | redpanda
#
# Contract per broker B:
#   fresh_datadir_B          — wipe + recreate the broker's data store
#   start_B TIER             — start the broker with the tier's pinned durability config
#   wait_ready_B             — block until the broker accepts client traffic (or die)
#   stop_B                   — stop the broker and verify its port is free
#
# ironbus NOTE: the ironbus bench tools SPAWN THEIR OWN broker (isolated, fresh temp
# data dir, auto-reaped). start/stop/wait are therefore NO-OPS for ironbus cells; the
# driver owns the broker lifecycle. fresh_datadir_ironbus only clears the shared
# scratch dir for hygiene.

set -u

# --- roots (parameterized: point these at YOUR machine) ---------------------
# XBENCH_SCRATCH is the one required root: the work area holding the broker
# installs (under $XBENCH_SCRATCH/brokers/...), the IronBus checkout, and the
# xbench logs/results tree. Every individual location below can also be
# overridden separately via its own environment variable.
SCRATCH="${XBENCH_SCRATCH:?set XBENCH_SCRATCH to the benchmark work root (see the harness README)}"
XB="${XBENCH_DIR:-$SCRATCH/xbench}"
XB_LOGS="$XB/logs"
XB_RESULTS="$XB/results"

# --- broker locations -------------------------------------------------------
IRONBUS_RELEASE_DIR="${IRONBUS_RELEASE_DIR:-$SCRATCH/IronBus/target/release}"
IRONBUS_BIN="${IRONBUS_BIN:-$IRONBUS_RELEASE_DIR/ironbus}"
IRONBUS_BENCH_BIN="${IRONBUS_BENCH_BIN:-$IRONBUS_RELEASE_DIR/ironbus-bench}"
IRONBUS_DATA="${IRONBUS_DATA:-$SCRATCH/brokers/ironbus/data}"

NATS_DIR="${NATS_DIR:-$SCRATCH/brokers/nats}"
NATS_SERVER="${NATS_SERVER:-$NATS_DIR/nats-server}"
NATS_CLI="${NATS_CLI:-$NATS_DIR/nats}"
NATS_DATA="$NATS_DIR/data"
NATS_URL="nats://127.0.0.1:4222"
NATS_SYNC_CONF="$NATS_DIR/nats-sync-always.conf"
NATS_PIDFILE="$NATS_DIR/nats-server.pid"
NATS_LOG="$NATS_DIR/nats-server.log"

KAFKA_DIR="${KAFKA_DIR:-$SCRATCH/brokers/kafka}"
KAFKA_HOME="${KAFKA_HOME:-$KAFKA_DIR/kafka_2.13-4.3.1}"
KAFKA_DATA="$KAFKA_DIR/data"
KAFKA_BASE_PROPS="$KAFKA_DIR/server-single.properties"
KAFKA_CLUSTER_UUID="${KAFKA_CLUSTER_UUID:-z1yAGhrIR1qaCptIWzFlPg}"
KAFKA_BOOTSTRAP="127.0.0.1:9092"
export JAVA_HOME="${JAVA_HOME:-$SCRATCH/brokers/jdk/jdk-21.0.11+10/Contents/Home}"

LIMA_BIN_DIR="${LIMA_BIN_DIR:-$SCRATCH/brokers/lima/bin}"
export LIMA_HOME="${LIMA_HOME:-$SCRATCH/brokers/lima-home}"
RPK="${RPK:-$SCRATCH/brokers/redpanda/rpk}"
RP_VM="${RP_VM:-redpanda}"
RP_BOOTSTRAP="127.0.0.1:9092"

# --- generic helpers --------------------------------------------------------
xb_log() { echo "[xbench $(date '+%H:%M:%S')] $*" >&2; }
xb_die() { xb_log "FATAL: $*"; exit 1; }

# wait_port_free PORT TIMEOUT_SECS
wait_port_free() {
  local port="$1" timeout="${2:-30}" i=0
  while [ "$i" -lt "$timeout" ]; do
    if ! /usr/sbin/lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i+1))
  done
  /usr/sbin/lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2
  return 1
}

# wait_port_open PORT TIMEOUT_SECS
wait_port_open() {
  local port="$1" timeout="${2:-30}" i=0
  while [ "$i" -lt "$timeout" ]; do
    if /usr/sbin/lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i+1))
  done
  return 1
}

# assert_no_other_broker PORT_EXPECTED... — sanity: serial-only discipline
assert_serial_clear() {
  # nothing should be listening on any broker port before we start one
  local p
  for p in 7777 4222 9092; do
    if /usr/sbin/lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
      xb_die "port $p is busy before broker start — serial discipline violated"
    fi
  done
}

# =============================================================================
# IRONBUS — bench tools spawn their own broker; lifecycle is a no-op.
# =============================================================================
fresh_datadir_ironbus() {
  rm -rf "$IRONBUS_DATA"
  mkdir -p "$IRONBUS_DATA"
}
start_ironbus() { # TIER (unused — driver owns the broker and its durability flags)
  xb_log "ironbus: no-op start (bench driver spawns its own isolated broker; tier=$1)"
}
wait_ready_ironbus() { :; }
stop_ironbus() {
  # No-op by contract, but defensively verify nothing was left behind by a
  # crashed driver: the spawned broker binds 7777 by default.
  if /usr/sbin/lsof -nP -iTCP:7777 -sTCP:LISTEN >/dev/null 2>&1; then
    xb_log "ironbus: stray broker on 7777 — reaping"
    local pid
    pid=$(/usr/sbin/lsof -nP -iTCP:7777 -sTCP:LISTEN -t | head -1)
    [ -n "$pid" ] && kill -INT "$pid" 2>/dev/null
    wait_port_free 7777 15 || xb_die "port 7777 still busy after ironbus reap"
  fi
}

# =============================================================================
# NATS — tiers: sync (jetstream sync_interval=always, fsync per message)
#               default (sync_interval default ~2m, page-cache)
# =============================================================================
fresh_datadir_nats() {
  rm -rf "$NATS_DATA"
  mkdir -p "$NATS_DATA"
}
start_nats() { # TIER: sync | default
  local tier="$1"
  assert_serial_clear
  rm -f "$NATS_PIDFILE"
  : > "$NATS_LOG"
  case "$tier" in
    sync)
      nohup "$NATS_SERVER" -c "$NATS_SYNC_CONF" -l "$NATS_LOG" -P "$NATS_PIDFILE" >/dev/null 2>&1 &
      ;;
    default)
      nohup "$NATS_SERVER" -js -sd "$NATS_DATA" -p 4222 -l "$NATS_LOG" -P "$NATS_PIDFILE" >/dev/null 2>&1 &
      ;;
    *) xb_die "start_nats: unknown tier '$tier' (want sync|default)" ;;
  esac
  # tier-config validation: record which config path is live
  if [ "$tier" = "sync" ]; then
    xb_log "nats: started with config $NATS_SYNC_CONF (sync_interval: always)"
    grep -q 'sync_interval: always' "$NATS_SYNC_CONF" || xb_die "nats sync config missing sync_interval always"
  else
    xb_log "nats: started with CLI defaults (-js, sync_interval default ~2m)"
  fi
}
wait_ready_nats() {
  wait_port_open 4222 20 || xb_die "nats-server did not open 4222"
  local i=0
  while [ "$i" -lt 20 ]; do
    if "$NATS_CLI" -s "$NATS_URL" server check jetstream >/dev/null 2>&1 || \
       "$NATS_CLI" -s "$NATS_URL" rtt >/dev/null 2>&1; then return 0; fi
    sleep 1; i=$((i+1))
  done
  xb_die "nats-server on 4222 but not answering clients"
}
stop_nats() {
  if [ -f "$NATS_PIDFILE" ]; then
    kill "$(cat "$NATS_PIDFILE")" 2>/dev/null || true
  fi
  if ! wait_port_free 4222 15; then
    local pid
    pid=$(/usr/sbin/lsof -nP -iTCP:4222 -sTCP:LISTEN -t | head -1)
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
    wait_port_free 4222 10 || xb_die "port 4222 still busy after nats stop"
  fi
  xb_log "nats: stopped, 4222 free"
}

# =============================================================================
# KAFKA — KRaft single node. Tiers via server.properties variants:
#   fsync   : log.flush.interval.messages=1     (fsync every record)
#   group   : log.flush.interval.messages=1000  (group-commit-ish coalesced fsync)
#   default : flush interval unset               (page-cache, OS flush)
# fresh run = WIPE data dir + re-format KRaft storage.
# =============================================================================
kafka_props_for_tier() { # TIER -> echoes properties file path (generates variants)
  local tier="$1" out
  case "$tier" in
    fsync)
      out="$KAFKA_DIR/server-fsync.properties"
      { cat "$KAFKA_BASE_PROPS"; echo "log.flush.interval.messages=1"; } > "$out"
      ;;
    group)
      out="$KAFKA_DIR/server-group.properties"
      { cat "$KAFKA_BASE_PROPS"; echo "log.flush.interval.messages=1000"; } > "$out"
      ;;
    default)
      out="$KAFKA_BASE_PROPS"
      ;;
    *) xb_die "kafka_props_for_tier: unknown tier '$tier' (want fsync|group|default)" ;;
  esac
  echo "$out"
}
fresh_datadir_kafka() {
  rm -rf "$KAFKA_DATA"
  mkdir -p "$KAFKA_DATA/kraft-logs"
}
start_kafka() { # TIER: fsync | group | default
  local tier="$1" props
  assert_serial_clear
  props=$(kafka_props_for_tier "$tier") || exit 1
  # re-format if the data dir is fresh (no meta.properties)
  if [ ! -f "$KAFKA_DATA/kraft-logs/meta.properties" ]; then
    "$KAFKA_HOME/bin/kafka-storage.sh" format -t "$KAFKA_CLUSTER_UUID" -c "$props" \
      > "$XB_LOGS/kafka-format-last.log" 2>&1 || xb_die "kafka-storage format failed (see $XB_LOGS/kafka-format-last.log)"
  fi
  : > "$KAFKA_DIR/broker.log"
  nohup "$KAFKA_HOME/bin/kafka-server-start.sh" "$props" > "$KAFKA_DIR/broker.log" 2>&1 &
  # tier-config validation: assert the live properties file carries the knob
  case "$tier" in
    fsync)   grep -q '^log.flush.interval.messages=1$'    "$props" || xb_die "kafka fsync tier props wrong" ;;
    group)   grep -q '^log.flush.interval.messages=1000$' "$props" || xb_die "kafka group tier props wrong" ;;
    default) ! grep -q '^log.flush.interval.messages='    "$props" || xb_die "kafka default tier props carries a flush override" ;;
  esac
  xb_log "kafka: starting with $props (tier=$tier)"
}
wait_ready_kafka() {
  local i=0
  while [ "$i" -lt 45 ]; do
    if grep -q 'Kafka Server started' "$KAFKA_DIR/broker.log" 2>/dev/null; then
      wait_port_open 9092 15 || xb_die "kafka started per log but 9092 closed"
      return 0
    fi
    sleep 1; i=$((i+1))
  done
  tail -20 "$KAFKA_DIR/broker.log" >&2
  xb_die "kafka did not report 'Kafka Server started' in 45s"
}
stop_kafka() {
  "$KAFKA_HOME/bin/kafka-server-stop.sh" >/dev/null 2>&1 || true
  if ! wait_port_free 9092 40; then
    xb_log "kafka: graceful stop timed out, killing"
    pkill -9 -f 'kafka\.Kafka .*server-.*\.properties' 2>/dev/null || true
    wait_port_free 9092 15 || xb_die "port 9092 still busy after kafka stop"
  fi
  xb_log "kafka: stopped, 9092 free"
}

# =============================================================================
# REDPANDA — lima VM (vz). Tiers (BOTH knobs set per tier, production mode):
#   durable : developer_mode=false + write_caching_default=false (fsync before ack)
#   relaxed : developer_mode=false + write_caching_default=true  (page-cache ack)
# Provisioned dev-mode had developer_mode=true (rpk adds --unsafe-bypass-fsync=true);
# both benchmark tiers MUST run developer_mode=false.
# Data dir lives in the VM at /var/lib/redpanda/data.
# NOTE: wiping the data dir resets cluster config, so start_redpanda re-applies
# write_caching_default AFTER the wipe+boot, then validates both knobs.
# =============================================================================
_limactl() { PATH="$LIMA_BIN_DIR:$PATH" LIMA_HOME="$LIMA_HOME" "$LIMA_BIN_DIR/limactl" "$@"; }
_rp_shell() { _limactl shell --workdir /tmp "$RP_VM" -- "$@"; }

rp_vm_up() {
  if _limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^$RP_VM Running"; then
    return 0
  fi
  xb_log "redpanda: starting lima VM (~1 min)"
  _limactl start "$RP_VM" >/dev/null 2>&1 || xb_die "limactl start $RP_VM failed"
}
fresh_datadir_redpanda() {
  rp_vm_up
  _rp_shell sudo systemctl stop redpanda >/dev/null 2>&1 || true
  # lima's dynamic port-forward drops the host 9092 listener asynchronously after
  # the guest service stops — wait for it so the serial-discipline check can't race
  wait_port_free 9092 30 || xb_die "host 9092 forward did not drop after redpanda stop"
  _rp_shell sudo bash -c 'rm -rf /var/lib/redpanda/data/* /var/lib/redpanda/data/.??* 2>/dev/null; true' \
    || xb_die "redpanda data wipe failed"
  xb_log "redpanda: /var/lib/redpanda/data wiped"
}
start_redpanda() { # TIER: durable | relaxed
  local tier="$1" wc
  case "$tier" in
    durable) wc=false ;;
    relaxed) wc=true ;;
    *) xb_die "start_redpanda: unknown tier '$tier' (want durable|relaxed)" ;;
  esac
  assert_serial_clear
  rp_vm_up
  # knob 1: developer_mode=false in /etc/redpanda/redpanda.yaml (drops --unsafe-bypass-fsync).
  # Also: production mode enforces >=1GiB per core, and the 8-vCPU/8GiB VM fails that
  # at auto sizing — pin --smp=6 --memory=6G. And seed the yaml-level
  # write_caching_default per tier (a wiped data dir re-bootstraps cluster config
  # from this seed; we ALSO set it via rpk cluster config after boot and verify).
  _rp_shell sudo env XB_WC="$wc" python3 -c "
import re, os
p = '/etc/redpanda/redpanda.yaml'
s = open(p).read()
s = re.sub(r'developer_mode:\s*\S+', 'developer_mode: false', s)
s = re.sub(r'write_caching_default:\s*\S+', 'write_caching_default: \"%s\"' % os.environ['XB_WC'], s)
if '--smp=' not in s:
    s = s.replace('- --reactor-backend=io_uring',
                  '- --smp=6\n        - --memory=6G\n        - --reactor-backend=io_uring')
open(p, 'w').write(s)
" || xb_die "failed to set developer_mode/write_caching_default/smp in redpanda.yaml"
  _rp_shell sudo systemctl restart redpanda || xb_die "systemctl restart redpanda failed"
  wait_ready_redpanda
  # knob 2: write_caching_default per tier (must be set AFTER boot; wipe resets it)
  _rp_shell sudo rpk cluster config set write_caching_default "$wc" >/dev/null \
    || xb_die "rpk cluster config set write_caching_default $wc failed"
  # cluster config change may need a moment; validate BOTH knobs
  local got dm bypass
  got=$(_rp_shell sudo rpk cluster config get write_caching_default 2>/dev/null | tr -d '[:space:]"'"'")
  [ "$got" = "$wc" ] || xb_die "redpanda tier validation: write_caching_default='$got' wanted '$wc'"
  dm=$(_rp_shell grep -c 'developer_mode: false' /etc/redpanda/redpanda.yaml 2>/dev/null | tr -d '[:space:]')
  [ "$dm" -ge 1 ] || xb_die "redpanda tier validation: developer_mode not false in redpanda.yaml"
  bypass=$(_rp_shell bash -c "tr '\\0' ' ' < /proc/\$(pgrep -x redpanda | head -1)/cmdline" 2>/dev/null | grep -c 'unsafe-bypass-fsync=true' || true)
  [ "${bypass:-0}" -eq 0 ] || xb_die "redpanda tier validation: broker still running with --unsafe-bypass-fsync=true"
  xb_log "redpanda: tier=$tier validated (developer_mode=false, write_caching_default=$wc, no fsync bypass)"
}
wait_ready_redpanda() {
  local i=0
  while [ "$i" -lt 90 ]; do
    if "$RPK" cluster info -X brokers="$RP_BOOTSTRAP" >/dev/null 2>&1; then return 0; fi
    sleep 2; i=$((i+1))
  done
  xb_die "redpanda kafka api not reachable at $RP_BOOTSTRAP"
}
stop_redpanda() {
  if _limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^$RP_VM Running"; then
    _rp_shell sudo systemctl stop redpanda >/dev/null 2>&1 || true
    _limactl stop "$RP_VM" >/dev/null 2>&1 || _limactl stop -f "$RP_VM" >/dev/null 2>&1 || true
  fi
  wait_port_free 9092 30 || xb_die "port 9092 still busy after redpanda VM stop"
  _limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | grep -q "^$RP_VM Stopped" \
    || xb_die "lima VM $RP_VM not in Stopped state"
  xb_log "redpanda: VM stopped, 9092 free"
}

# natscore (EXTRA L2 datapoint) shares the nats server lifecycle entirely.
fresh_datadir_natscore() { fresh_datadir_nats "$@"; }
start_natscore()         { start_nats "$@"; }
stop_natscore()          { stop_nats "$@"; }
wait_ready_natscore()    { wait_ready_nats "$@"; }
