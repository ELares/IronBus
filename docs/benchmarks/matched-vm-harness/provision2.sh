#!/bin/bash
# provision2.sh — provision the matched-VM harness substrate (#1191, epic #1196).
#
# Creates the DEDICATED lima `vz` guest the harness runs in (Ubuntu, 8 vCPU / 8 GiB,
# single ext4 on virtio vda1 — the documented substrate of REDPANDA_MATCHED_2026_07.md
# §1) and provisions everything the guest-resident harness (lib2.sh/cell2.sh/…) assumes:
#
#   * in-guest release build of `ironbus` from a PINNED engine commit (recorded in
#     the guest at $HOME/IronBus/.engine-sha and echoed at the end),
#   * Redpanda v26.1.12 PRODUCTION mode via systemd (developer_mode=false — developer
#     mode bypasses fsync and is auto-disqualifying per the study), pinned + apt-held,
#     with the documented start flags (--smp=6 --memory=6G, io_uring reactor backend)
#     and `rpk redpanda tune all` best-effort (charitable-config; some tuners are
#     N/A inside a VM and that is non-fatal),
#   * the Kafka perf client tools (kafka_2.13-4.3.1 + a headless JRE) at $HOME/xb/kafka,
#   * the $HOME/xb2 work dirs lib2.sh expects.
#
# Idempotent: re-runs skip the VM/create, the deps, the build (unless the pinned SHA
# changed or XB2_FORCE_BUILD=1), the Redpanda install, and the Kafka download.
#
# Usage:   ./provision2.sh            # provision + verify
#          ./provision2.sh verify     # verification only (brokers start + tier validation)
# Env:     XB2_VM         guest name              (default: xb2)
#          IRONBUS_SHA    engine commit to build  (default: origin/main of this repo)
#          XB2_FORCE_BUILD=1  rebuild even if the recorded SHA matches
#
# All guest paths are $HOME-relative; nothing host-specific is recorded in the guest
# or in this file. The Redpanda version pin is OWNER-GATED: if v26.1.12 disappears
# from the apt repo this script fails loudly rather than silently bumping.

set -euo pipefail

VM="${XB2_VM:-xb2}"
RP_VERSION="26.1.12"
KAFKA_VER="4.3.1"
KAFKA_SCALA="2.13"
KAFKA_DIR="kafka_${KAFKA_SCALA}-${KAFKA_VER}"
TEMPLATE="template://ubuntu"   # latest Ubuntu (26.04 at refresh time; kernel 7.x — see §1)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

log() { echo "[provision2 $(date '+%H:%M:%S')] $*" >&2; }
die() { log "FATAL: $*"; exit 1; }

command -v limactl >/dev/null 2>&1 \
  || die "limactl not on PATH — the harness substrate is a lima vz guest (README/§1)"
git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1 \
  || die "cannot resolve the IronBus repo above this script"

# limactl shell inherits the (possibly read-only, host-mapped) cwd — always start in $HOME.
guest() { limactl shell "$VM" -- bash -lc "cd \"\$HOME\" && { $*; }"; }

# ---------------------------------------------------------------- VM lifecycle
vm_up() {
  local state
  state="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null | awk -v vm="$VM" '$1==vm{print $2}')"
  case "$state" in
    Running) log "VM $VM already running" ;;
    "")
      log "creating VM $VM (vz, 8 vCPU, 8 GiB, $TEMPLATE)"
      limactl create --name "$VM" --vm-type vz --cpus 8 --memory 8 --disk 100 \
        --containerd none --tty=false "$TEMPLATE"
      limactl start "$VM" --tty=false ;;
    *)
      log "starting existing VM $VM (state=$state)"
      limactl start "$VM" --tty=false ;;
  esac
  guest 'true' || die "guest shell not reachable"
}

# ------------------------------------------------------------------ guest deps
guest_deps() {
  log "guest deps: apt packages + rustup (idempotent)"
  guest 'sudo DEBIAN_FRONTEND=noninteractive apt-get update -q'
  guest 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
           build-essential pkg-config cmake curl ca-certificates default-jre-headless' \
    || guest 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
           build-essential pkg-config cmake curl ca-certificates openjdk-21-jre-headless'
  guest 'command -v cargo >/dev/null 2>&1 || test -x "$HOME/.cargo/bin/cargo" || \
           curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | \
           sh -s -- -y --profile minimal --default-toolchain stable'
}

# -------------------------------------------------- ironbus source + release build
engine_sha() {
  if [ -n "${IRONBUS_SHA:-}" ]; then
    git -C "$REPO_ROOT" rev-parse "$IRONBUS_SHA"
  else
    git -C "$REPO_ROOT" rev-parse origin/main 2>/dev/null \
      || git -C "$REPO_ROOT" rev-parse HEAD
  fi
}

sync_and_build() {
  local sha have
  sha="$(engine_sha)"
  have="$(guest 'cat "$HOME/IronBus/.engine-sha" 2>/dev/null || true')"
  if [ "$have" = "$sha" ] && [ "${XB2_FORCE_BUILD:-0}" != "1" ] \
     && guest 'test -x "$HOME/IronBus/target/release/ironbus"'; then
    log "ironbus already built at pinned SHA $sha — skipping (XB2_FORCE_BUILD=1 to force)"
    return
  fi
  log "syncing ironbus source at pinned SHA $sha into the guest"
  git -C "$REPO_ROOT" archive --format=tar "$sha" | limactl shell "$VM" -- bash -c '
    set -e
    rm -rf "$HOME/IronBus.stage"; mkdir -p "$HOME/IronBus.stage"
    tar -xf - -C "$HOME/IronBus.stage"
    [ -d "$HOME/IronBus/target" ] && mv "$HOME/IronBus/target" "$HOME/IronBus.stage/target"
    rm -rf "$HOME/IronBus"; mv "$HOME/IronBus.stage" "$HOME/IronBus"
  ' || die "source sync failed"
  guest "echo $sha > \"\$HOME/IronBus/.engine-sha\""
  log "building ironbus release in-guest (aarch64-unknown-linux-gnu, --locked)"
  guest '. "$HOME/.cargo/env"; cd "$HOME/IronBus" && cargo build --release --locked -p ironbus-cli' \
    || die "in-guest release build failed"
  guest 'test -x "$HOME/IronBus/target/release/ironbus"' || die "ironbus binary missing after build"
  log "ironbus built at $sha"
}

# ------------------------------------------------------------------- redpanda
redpanda_install() {
  if guest "command -v rpk >/dev/null 2>&1 && rpk version 2>/dev/null | grep -q '$RP_VERSION'"; then
    log "redpanda $RP_VERSION already installed"
  else
    log "installing redpanda $RP_VERSION (pinned; apt-held)"
    guest 'curl -1sLf https://dl.redpanda.com/nzc4ZYQK3WRGd9sy/redpanda/cfg/setup/bash.deb.sh | sudo bash' \
      || die "redpanda apt repo setup failed"
    local pkg
    pkg="$(guest "apt-cache madison redpanda | awk '/$RP_VERSION/{print \$3; exit}'")"
    [ -n "$pkg" ] || die "redpanda $RP_VERSION not found in the apt repo — the version pin is owner-gated (epic #1196); do NOT silently bump"
    guest "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades \
             redpanda=$pkg redpanda-rpk=$pkg redpanda-tuner=$pkg" \
      || die "redpanda install failed"
    guest 'sudo apt-mark hold redpanda redpanda-rpk redpanda-tuner'
  fi

  log "redpanda production-mode config (developer_mode=false, --smp=6 --memory=6G, io_uring backend)"
  guest 'sudo systemctl stop redpanda >/dev/null 2>&1 || true'
  guest 'sudo rpk redpanda mode production' || die "rpk mode production failed"
  guest "sudo rpk redpanda config set rpk.additional_start_flags \"['--smp=6','--memory=6G','--reactor-backend=io_uring']\"" \
    || die "setting additional_start_flags failed"
  # seed the yaml-level write_caching key lib2.sh re-seeds per tier (a wiped data dir
  # re-bootstraps cluster config from this seed); durable (false) is the default tier.
  guest 'sudo rpk redpanda config set redpanda.write_caching_default false' || true
  guest 'grep -q "write_caching_default" /etc/redpanda/redpanda.yaml || \
           sudo python3 -c "
import re
p = \"/etc/redpanda/redpanda.yaml\"
s = open(p).read()
s = re.sub(r\"^redpanda:\", \"redpanda:\n    write_caching_default: \\\"false\\\"\", s, count=1, flags=re.M)
open(p, \"w\").write(s)"'
  # rpk v26 normalizes developer_mode=false to KEY-ABSENT and EVERY `rpk redpanda config
  # set` rewrite re-strips it, so this seed must run AFTER all rpk config writes above.
  # lib2.sh's per-start validation greps for the literal `developer_mode: false` line;
  # redpanda accepts the explicit false, and lib2.sh itself only edits the yaml via
  # python + the cluster API, so the seeded line survives harness runs.
  guest 'grep -q "developer_mode:" /etc/redpanda/redpanda.yaml || sudo python3 -c "
import re
p = \"/etc/redpanda/redpanda.yaml\"
s = open(p).read()
s = re.sub(r\"^redpanda:\", \"redpanda:\n    developer_mode: false\", s, count=1, flags=re.M)
open(p, \"w\").write(s)"' || die "seeding developer_mode: false failed"
  guest 'grep -q "developer_mode: false" /etc/redpanda/redpanda.yaml' \
    || die "developer_mode is not false after mode production — auto-disqualifying"
  guest 'grep -q -- "--smp=6" /etc/redpanda/redpanda.yaml' || die "--smp=6 pin missing from redpanda.yaml"
  # charitable-config: apply the tuners; several are N/A inside a VM — non-fatal.
  guest 'sudo rpk redpanda tune all || true'
}

# --------------------------------------------------------------- kafka clients
kafka_install() {
  if guest "test -x \"\$HOME/xb/kafka/$KAFKA_DIR/bin/kafka-producer-perf-test.sh\""; then
    log "kafka perf tools already installed"
    return
  fi
  log "installing kafka perf tools ($KAFKA_DIR)"
  guest "mkdir -p \"\$HOME/xb/kafka\" && cd \"\$HOME/xb/kafka\" && \
         { curl -fsSLO https://downloads.apache.org/kafka/$KAFKA_VER/$KAFKA_DIR.tgz || \
           curl -fsSLO https://archive.apache.org/dist/kafka/$KAFKA_VER/$KAFKA_DIR.tgz; } && \
         tar xzf $KAFKA_DIR.tgz && rm -f $KAFKA_DIR.tgz" \
    || die "kafka tools download/extract failed"
}

# -------------------------------------------------------------------- verify
verify() {
  log "verify: guest environment"
  guest 'mkdir -p "$HOME/xb2/logs" "$HOME/xb2/results" "$HOME/xb2/tmp"'
  guest '{ echo "engine_sha=$(cat "$HOME/IronBus/.engine-sha" 2>/dev/null)";
           echo "kernel=$(uname -r)  arch=$(uname -m)  vcpus=$(nproc)";
           free -h | sed -n 2p; df -h / | sed -n 2p;
           rpk version 2>/dev/null | head -2; } | tee "$HOME/xb2/provision.log"'

  log "verify: ironbus broker (tiny in-guest bench, TMPDIR pinned to ext4)"
  guest 'cd "$HOME/IronBus/target/release" && TMPDIR="$HOME/xb2/tmp" ./ironbus bench \
           --count 1000 --payload-bytes 128 --payload-shape realistic \
           --mode publish --pubwindow 1 --storage disk --json >/dev/null' \
    || die "ironbus bench smoke failed"
  log "verify: ironbus OK"

  log "verify: redpanda production mode + both tier validations (lib2.sh)"
  guest 'cd "$HOME/IronBus/docs/benchmarks/matched-vm-harness" && . ./lib2.sh &&
         fresh_datadir_redpanda && start_redpanda durable &&
         tr "\0" " " < "/proc/$(pgrep -x redpanda | head -1)/cmdline" | grep -q "reactor-backend=io_uring" &&
         xb_log "redpanda: io_uring reactor backend confirmed on cmdline" &&
         ! tr "\0" " " < "/proc/$(pgrep -x redpanda | head -1)/cmdline" | grep -q -- "--overprovisioned" &&
         xb_log "redpanda: no developer-mode --overprovisioned flag on cmdline" &&
         stop_redpanda &&
         fresh_datadir_redpanda && start_redpanda relaxed && stop_redpanda' \
    || die "redpanda tier validation failed"
  log "verify: redpanda OK (production mode, both tiers validated)"
}

# ---------------------------------------------------------------------- main
if [ "${1:-}" = "verify" ]; then
  vm_up; verify; log "verification complete"; exit 0
fi

vm_up
guest_deps
sync_and_build
redpanda_install
kafka_install
verify
log "provisioning complete — engine SHA $(engine_sha); run cells via cell2.sh/row2.sh in-guest"
