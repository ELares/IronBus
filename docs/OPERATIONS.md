# Rolling upgrade and rollback (the healthz-gated runbook)

How to take a running IronBus broker from one binary version to the next without a
silent outage, and how to back it out, with `/healthz` as the gate that decides when
each step is safe to proceed (#501, parent #17).

This is the OPERATOR runbook. It is grounded in the broker that exists today: the
atomic `ironbus upgrade` / `ironbus rollback` swap (#104), the loopback health surface
([MONITORING.md](MONITORING.md)), and the fail-closed on-disk `FORMAT_VERSION` gate
([COMPATIBILITY.md](COMPATIBILITY.md)). It cites only flags, endpoints, and paths that
the binary actually has. The packaging/systemd side of the same flow (the
fall-back-after-N unit, the `.deb`, the container) lives in
[DISTRIBUTION.md](DISTRIBUTION.md); this doc is the procedure an operator follows.

## The gate: what `/healthz` (and `/readyz`) actually mean

The health surface is four loopback HTTP endpoints, served only when `serve` is given
`--health-addr` (off by default). The surface is unauthenticated, so `serve` refuses a
non-loopback `--health-addr` without `--health-allow-public` (see
[THREAT_MODEL.md](THREAT_MODEL.md)). The two endpoints this runbook gates on:

- **`GET /healthz` -- liveness.** It answers `200 ok` while the broker's accept loop is
  making progress, and `503` (`no event-loop progress`) only after the loop has gone a
  whole `--health-liveness-window-ms` with NO tick. The loop ticks every iteration,
  including the idle would-block poll, so a slow-but-progressing broker stays `200` and
  only a genuinely STUCK (or crashed) loop trips. A window of `0` disables the watchdog
  (always `200` while up). `/healthz` reads the monotonic clock directly, not through the
  writer, so a frozen writer does NOT make it `503`.
- **`GET /readyz` -- readiness.** It answers `200 ready` only when the durable-log writer
  is live and accepting writes, and `503` when the writer is frozen (`writer frozen`,
  e.g. a fatal fsync or a failed segment roll) or during a shutdown drain
  (`shutting down`).

The distinction is the whole point of a gated rollout: **wait on `/healthz` to know the
new process came up and its accept loop is running; check `/readyz` to know it can take
writes before you send it traffic.** A fresh broker that is up but whose writer has not
yet opened the active segment is `/healthz` `200` and `/readyz` `503`; do not advance
until BOTH are green.

`GET /metrics` (Prometheus text) and the opt-in `GET /admin` (`serve --enable-admin`,
read-only JSON) round out the surface and are the during-upgrade observability source;
see [MONITORING.md](MONITORING.md) and [METRICS.md](METRICS.md).

### A reusable healthz-wait gate

Every step below waits for the same condition: the new process answers `/healthz` `200`
AND `/readyz` `200`. The wait is a plain `curl` poll against the loopback health port (no
extra tooling), so the runbook is copy-pasteable:

```sh
# wait_ready <health-addr> <timeout-seconds>
# Blocks until the broker at <health-addr> is BOTH live (/healthz 200) and ready
# (/readyz 200), or exits non-zero on timeout. Pure curl; nothing IronBus-specific.
wait_ready() {
  addr="$1"; deadline=$(( $(date +%s) + ${2:-60} ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS -o /dev/null "http://$addr/healthz" \
       && curl -fsS -o /dev/null "http://$addr/readyz"; then
      return 0
    fi
    sleep 1
  done
  echo "wait_ready: $addr not ready within ${2:-60}s" >&2
  return 1
}
```

`curl -f` makes a `503` a non-zero exit, so the loop only returns once both endpoints
are `200`. This is the gate referenced as "WAIT for `/healthz` ready" throughout the
steps below.

## Before you start: the store-format check (read this first)

IronBus is a single durable log with an open WAL, so an upgrade is a lifecycle operation,
not just a file copy. The on-disk record header, segment header, and segment footer each
carry a single `FORMAT_VERSION` byte (`= 1` today). A v1 reader reads only v1 and
**refuses any other version loudly** rather than guessing a layout it does not know (see
[COMPATIBILITY.md](COMPATIBILITY.md) and
[DISTRIBUTION.md](DISTRIBUTION.md#on-disk-format-compatibility-and-the-migrate-gate)).

This is the critical pre-flight: **a rolling upgrade is safe only WITHIN a major store
format version.** Confirm the new binary reads this data dir's format before you touch the
live binary:

```sh
ironbus migrate --data-dir /var/lib/ironbus
```

- Same format (the data dir's stamped version equals the new build's): `migrate` reports
  "no migration needed" and the data dir opens with no migration. Proceed with the rolling
  upgrade below.
- **Different format: STOP.** `migrate` refuses the data dir with a usage error unless you
  pass `--allow <to-version>`, and even with `--allow` this v1 build has **no in-place
  migrator** -- it reports the honest state rather than reinterpreting bytes under a layout
  it does not know. A cross-version upgrade therefore needs a real migration path
  (read-old-write-new or an in-place upcast), which **does not exist yet and is tracked by
  [#500](https://github.com/ELares/IronBus/issues/500)**. Do not attempt a rolling upgrade
  across an incompatible store version: the new binary would fail closed on the old data,
  which (correctly) refuses to start rather than corrupt the log. Wait for #500.

The rest of this runbook assumes the same-major-version case `migrate` just confirmed.

## Rolling upgrade (single node, in place)

The `ironbus upgrade` swap is atomic and retains the prior binary as `<dest>.prev` for a
one-command rollback (#104). The download-and-verify of the new bytes stays in the
fail-closed installer (`scripts/install.sh`); `upgrade` only ever swaps over already-verified
bytes, so the fail-closed posture is never weakened. The per-node steps:

1. **Pre-flight the store format** (above): `ironbus migrate --data-dir <dir>` must report
   no migration needed. If it does not, STOP (see #500).

2. **Stage and verify the new binary**, then atomically swap it in. `upgrade` writes the
   new bytes to a sibling temp on the SAME filesystem, fsyncs, stages a copy of the current
   binary, does the single atomic `rename(2)`, and only then commits the prior bytes onto
   `<dest>.prev`:
   ```sh
   ironbus upgrade --new-binary /tmp/ironbus.new --dest /usr/bin/ironbus
   ```
   A power cut mid-swap leaves EITHER the old binary or the fully-written new one, never a
   half-written one. A same-version re-run is a no-op that does not clobber `<dest>.prev`.

3. **Drain and stop the old process.** Stop the running broker via your supervisor
   (systemd: `systemctl stop ironbus`). A clean stop drains in-flight work; under the
   default `sync` durability level, every acked message is already durable, so a stop loses
   nothing by contract (see [DURABILITY.md](DURABILITY.md)).

4. **Start the new process** on the same data dir and the same health port:
   ```sh
   ironbus serve --data-dir /var/lib/ironbus --addr 127.0.0.1:7777 \
     --health-addr 127.0.0.1:9090
   ```
   (systemd: `systemctl start ironbus`.) On startup the new binary runs recovery over the
   existing log (longest-valid-prefix; see [RECOVERY.md](RECOVERY.md)) and opens the active
   segment.

5. **WAIT for the health gate before proceeding.** Do not route traffic, and on a fleet do
   not move to the next node, until the new process is BOTH live and ready:
   ```sh
   wait_ready 127.0.0.1:9090 60
   ```
   `/healthz` `200` confirms the accept loop is running; `/readyz` `200` confirms the writer
   opened the active segment and can take writes. If `wait_ready` times out (the new process
   did not come up, or `/readyz` stays `503`), treat it as a failed start and roll back
   (below) rather than leaving the node down.

6. **Confirm and clear the start counter.** Once the broker is confirmed healthy, clear the
   consecutive-failed-start counter so a later transient restart does not accumulate toward
   the automatic fall-back:
   ```sh
   ironbus record-start --dest /usr/bin/ironbus --ok
   ```
   (The packaged systemd unit drives `record-start --failed` / `--ok` / `--check` at the
   three lifecycle points automatically; see
   [DISTRIBUTION.md](DISTRIBUTION.md#fall-back-after-n-wiring-the-systemd-unit). Run it by
   hand only when you are not using the unit.)

### Fleet ordering

Apply the per-node sequence **one node at a time**, gated on step 5: a node is "done" only
once its `/healthz` and `/readyz` are both `200`. Do not start the swap on node N+1 until
node N has passed the gate. This keeps capacity available throughout and means a bad build
trips the gate on the first node, before it has touched the rest of the fleet. (IronBus v1
is a single-node durable broker; "fleet" here means many independent edge nodes upgraded in
sequence, not a replicated cluster.)

## Rollback

If the new binary fails the health gate, or misbehaves after it is live, roll back to the
retained previous bytes. `ironbus rollback` restores `<dest>.prev` over the live binary
with the same atomic, fsynced swap, and is careful never to destroy the good `.prev` or
promote bytes recorded as known-bad (#104, #348):

1. **Stop the misbehaving process** (systemd: `systemctl stop ironbus`).

2. **Restore the previous binary:**
   ```sh
   ironbus rollback --dest /usr/bin/ironbus
   ```
   This is the one-command path back to the last known-good bytes. If there is no
   `<dest>.prev` (nothing was ever upgraded over this destination), `rollback` reports that
   and changes nothing.

3. **Start the restored process and WAIT for the gate**, exactly as in the upgrade:
   ```sh
   ironbus serve --data-dir /var/lib/ironbus --addr 127.0.0.1:7777 \
     --health-addr 127.0.0.1:9090
   wait_ready 127.0.0.1:9090 60
   ```
   The old binary reads the v1 on-disk format it always did — **with one documented
   exception: COMPACTION**. A compacted segment is stamped `version = 2`
   (`FORMAT_VERSION_COMPACTED`), which a strictly-older binary REFUSES fail-closed at
   recovery — so a rollback across a data dir that compaction has touched since the upgrade
   will refuse to start rather than come up (correct for durability, but it means the
   rollback is NOT unconditional). There is no v2-segment preflight tool yet — that gap is
   exactly #1071. Until it lands: compaction is OPT-IN (`--compact`, off by default), so if
   this broker has ever run with `--compact` on this data dir, do NOT roll the binary back
   in place — restore from the pre-upgrade backup instead. A dir that has never been
   compacted is byte-for-byte v1, and recovery and readiness come up exactly as before.
   Then clear the counter:
   ```sh
   ironbus record-start --dest /usr/bin/ironbus --ok
   ```

### Automatic fall-back

You do not have to be watching for the rollback to happen. A node records consecutive
failed starts in a counter file next to the binary; after `DEFAULT_MAX_FAILED_STARTS` (3)
failed starts the packaged systemd unit consults `record-start --check` and restores
`ironbus.prev` over the binary via the same atomic swap, recovering an unreachable node to
the last known-good bytes without an operator. The three-attempt threshold tolerates a
transient first-boot hiccup before deciding the new binary is genuinely broken. The unit
wiring is documented in
[DISTRIBUTION.md](DISTRIBUTION.md#fall-back-after-n-wiring-the-systemd-unit); the
upgrade-after-rollback path is hardened against re-promoting the known-bad bytes (#348).

## Store-format upgrades are out of scope for THIS procedure

To be explicit, because it is the one way this runbook can bite: the procedure above is for
upgrades **within** a store format version. The fail-closed `FORMAT_VERSION` gate means an
upgrade to a build that writes a NEW on-disk format cannot be done as a rolling binary swap
on the old data dir -- the new binary will refuse the old format, and the old binary will
refuse the new format, so neither a forward swap nor a rollback bridges the gap silently.
That is by design (a refuse-and-report beats a silent misread), and it is why a real
migration path is a prerequisite, not an afterthought, for any cross-format rollout. That
migration story (`migrate` today only version-REJECTS; it has no read-old-write-new or
in-place upcast) is tracked by [#500](https://github.com/ELares/IronBus/issues/500) and
must land before a fleet crosses a format version.

## See also

- [DISTRIBUTION.md](DISTRIBUTION.md) -- the fail-closed installer, the `.deb` / container,
  the systemd fall-back-after-N unit, and the `migrate` gate this runbook leans on.
- [MONITORING.md](MONITORING.md) -- the full `/healthz`, `/readyz`, `/metrics`, `/admin`
  surface and the dashboard/alerts to watch during an upgrade.
- [COMPATIBILITY.md](COMPATIBILITY.md) -- the on-disk and wire compatibility rules, and the
  v1-reader-refuses-an-unknown-version mechanism the store-format check relies on.
- [RECOVERY.md](RECOVERY.md) and [DURABILITY.md](DURABILITY.md) -- what the new process does
  to the log at startup, and why a clean stop loses nothing under the default level.
- [ACCEPTANCE.md](ACCEPTANCE.md) -- the golden-path release gate, whose final step is an
  in-place upgrade over the real installer.
