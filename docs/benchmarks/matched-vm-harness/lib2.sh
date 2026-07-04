#!/bin/bash
# xbench2 lib2.sh — MATCHED-VM cross-broker harness (IronBus vs Redpanda), guest-resident.
# Both brokers AND both load clients run INSIDE the same lima vz VM (Ubuntu, ext4 on
# virtio vda1, guest loopback) — the VM confound of the 2026-07 host study cancels out.
#
# Fairness pins:
#   * ironbus bench data dirs -> TMPDIR on ext4 (guest /tmp is tmpfs = RAM; that would
#     silently turn IronBus "disk" rows into RAM rows). Redpanda writes /var/lib/redpanda
#     on the SAME vda1 ext4.
#   * redpanda: production mode (developer_mode=false, no --unsafe-bypass-fsync),
#     --smp=6 --memory=6G (its own >=1GiB/core production floor on a 8vCPU/8GiB VM),
#     io_uring reactor backend, write_caching per tier. Validated at every start.
#   * ironbus: unpinned (single engine thread + session tasks never exceed the box).
#   * each system's stack (broker + its standard client) gets the whole 8-vCPU box.
#   * serial discipline: one broker at a time; ports 7777/9092 asserted free.

set -u

XB2="$HOME/xb2"
XB2_LOGS="$XB2/logs"
XB2_RESULTS="$XB2/results"
XB2_TMP="$XB2/tmp"            # ext4-backed TMPDIR for ironbus's spawned brokers

IRONBUS_RELEASE_DIR="$HOME/IronBus/target/release"
IRONBUS_BIN="$IRONBUS_RELEASE_DIR/ironbus"

KAFKA_HOME="$HOME/xb/kafka/kafka_2.13-4.3.1"
RP_BOOTSTRAP="127.0.0.1:9092"

mkdir -p "$XB2_LOGS" "$XB2_RESULTS" "$XB2_TMP"

xb_log() { echo "[xb2 $(date '+%H:%M:%S')] $*" >&2; }
xb_die() { xb_log "FATAL: $*"; exit 1; }

port_busy() { ss -ltnH "sport = :$1" 2>/dev/null | grep -q .; }

wait_port_free() { # PORT TIMEOUT
  local port="$1" timeout="${2:-30}" i=0
  while [ "$i" -lt "$timeout" ]; do
    port_busy "$port" || return 0
    sleep 1; i=$((i+1))
  done
  ss -ltnH "sport = :$port" >&2
  return 1
}

wait_port_open() { # PORT TIMEOUT
  local port="$1" timeout="${2:-30}" i=0
  while [ "$i" -lt "$timeout" ]; do
    port_busy "$port" && return 0
    sleep 1; i=$((i+1))
  done
  return 1
}

assert_serial_clear() {
  local p
  for p in 7777 9092; do
    if port_busy "$p"; then
      xb_die "port $p busy before broker start — serial discipline violated"
    fi
  done
}

# ============================ IRONBUS =======================================
# bench spawns its own isolated broker (fresh temp data dir under TMPDIR, reaped
# on exit). Lifecycle is a no-op apart from stray-broker defense.
fresh_datadir_ironbus() { rm -rf "$XB2_TMP"; mkdir -p "$XB2_TMP"; }
start_ironbus() { xb_log "ironbus: no-op start (bench spawns its own broker; tier=$1)"; }
wait_ready_ironbus() { :; }
stop_ironbus() {
  if port_busy 7777; then
    xb_log "ironbus: stray broker on 7777 — reaping"
    local pid
    pid=$(ss -ltnpH "sport = :7777" 2>/dev/null | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)
    [ -n "$pid" ] && kill -INT "$pid" 2>/dev/null
    wait_port_free 7777 15 || xb_die "port 7777 still busy after ironbus reap"
  fi
}

# ============================ REDPANDA ======================================
# Direct (in-guest) lifecycle. Tiers: durable (write_caching=false, fsync before
# ack) | relaxed (write_caching=true, acked before fsync — NOT power-loss-safe).
fresh_datadir_redpanda() {
  sudo systemctl stop redpanda >/dev/null 2>&1 || true
  wait_port_free 9092 30 || xb_die "9092 did not free after redpanda stop"
  sudo bash -c 'rm -rf /var/lib/redpanda/data/* /var/lib/redpanda/data/.??* 2>/dev/null; true' \
    || xb_die "redpanda data wipe failed"
  xb_log "redpanda: /var/lib/redpanda/data wiped"
}
start_redpanda() { # TIER: durable | relaxed
  local tier="$1" wc
  case "$tier" in
    durable) wc=false ;;
    relaxed) wc=true ;;
    *) xb_die "start_redpanda: unknown tier '$tier'" ;;
  esac
  assert_serial_clear
  # seed yaml-level knobs (a wiped data dir re-bootstraps cluster config from this
  # seed); production pinning (--smp=6 --memory=6G, developer_mode=false) persists
  # from provisioning — validated below either way.
  sudo env XB_WC="$wc" python3 -c "
import re, os
p = '/etc/redpanda/redpanda.yaml'
s = open(p).read()
s = re.sub(r'developer_mode:\s*\S+', 'developer_mode: false', s)
s = re.sub(r'write_caching_default:\s*\S+', 'write_caching_default: \"%s\"' % os.environ['XB_WC'], s)
open(p, 'w').write(s)
" || xb_die "failed to seed redpanda.yaml tier knobs"
  sudo systemctl restart redpanda || xb_die "systemctl restart redpanda failed"
  wait_ready_redpanda
  sudo rpk cluster config set write_caching_default "$wc" >/dev/null \
    || xb_die "rpk set write_caching_default $wc failed"
  local got dm bypass smp
  got=$(sudo rpk cluster config get write_caching_default 2>/dev/null | tr -d '[:space:]"'"'")
  [ "$got" = "$wc" ] || xb_die "redpanda tier validation: write_caching_default='$got' wanted '$wc'"
  dm=$(grep -c 'developer_mode: false' /etc/redpanda/redpanda.yaml || true)
  [ "$dm" -ge 1 ] || xb_die "redpanda tier validation: developer_mode not false"
  smp=$(grep -c -- '--smp=6' /etc/redpanda/redpanda.yaml || true)
  [ "$smp" -ge 1 ] || xb_die "redpanda tier validation: --smp=6 pin missing"
  bypass=$(tr '\0' ' ' < "/proc/$(pgrep -x redpanda | head -1)/cmdline" 2>/dev/null | grep -c 'unsafe-bypass-fsync=true' || true)
  [ "${bypass:-0}" -eq 0 ] || xb_die "redpanda tier validation: --unsafe-bypass-fsync=true present"
  xb_log "redpanda: tier=$tier validated (production mode, write_caching_default=$wc, smp=6, no fsync bypass)"
}
wait_ready_redpanda() {
  local i=0
  while [ "$i" -lt 90 ]; do
    if rpk cluster info -X brokers="$RP_BOOTSTRAP" >/dev/null 2>&1; then return 0; fi
    sleep 2; i=$((i+1))
  done
  xb_die "redpanda kafka api not reachable at $RP_BOOTSTRAP"
}
stop_redpanda() {
  sudo systemctl stop redpanda >/dev/null 2>&1 || true
  wait_port_free 9092 30 || xb_die "9092 still busy after redpanda stop"
  xb_log "redpanda: stopped, 9092 free"
}
