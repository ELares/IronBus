# Edge tuning: the hardware constraint to knob mapping

This document maps each edge hardware constraint to the specific shipped `serve`
knob(s) that honor it, with a recommended edge value and the reasoning. It is the
operator-facing companion to the flag-and-default reference in
[CLI.md](CLI.md), the WAL and overflow mechanics in [WAL.md](WAL.md), the
target table in [SLO.md](SLO.md), and the resource-exhaustion mitigations in
[THREAT_MODEL.md](THREAT_MODEL.md). It does not introduce or duplicate any flag;
every flag below is defined canonically in CLI.md and verified against the
`main.rs` and `engine.rs` constants.

## Honesty up front: `--profile edge-tiny` now sets these for you

Named-profile selection is SHIPPED (#87): `serve --profile edge-tiny` stamps the
small-RAM, flash-gentle preset in one move (the 8 MiB `EDGE_SEGMENT_BYTES`
segment size, tight per-connection credits, few connections and groups,
`drop-new`, and the 64 MiB `ram_ceiling_bytes` refuse-to-boot ceiling), then any
explicit key still overrides an individual knob (precedence profile < env <
flag; the exact preset values are in [CONFIG.md](CONFIG.md) section 6). With no
profile the default stays `balanced` (exactly the compiled-in `DEFAULT_*` set,
64 MiB segments), so a zero-config broker is unchanged.

The TOML config FILE (`serve --config <path>`) is also SHIPPED (#382), on the
precedence `flag > env > FILE > default`; the env-var layer (`IRONBUS_<FLAG>`)
sits between flags and the file as before. The validate-whole-then-swap re-read
RELOAD engine ships too, running as a startup self-check AND on a runtime trigger:
SIGHUP re-reads `--config` at runtime and applies the live-reloadable subset (the
retention bounds + the disk-full policy) to the running broker (#380). The other
residual on that surface is the MUTATING wire `CONFIG SET`/`SAVE` admin verbs,
which wait on the #106 connection-scoped auth (#380). The refuse-to-boot RAM guard (#115) is wired
too: with `--ram-ceiling-bytes` set (which `edge-tiny` does, to 64 MiB), a
broker whose configured caps provably exceed the ceiling refuses to start (the
worst-case formula is in [RAM_BUDGET.md](RAM_BUDGET.md)).

So everything below is BOTH the rationale for what `--profile edge-tiny` sets
for you AND the per-knob reference for an operator who tunes an individual
value past the preset on the `serve` command line (or via the matching
`IRONBUS_*` env var or a `--config` file key); an explicit key always wins
over the profile.

## The constraint table

Every recommended value below is a real, currently-accepted flag value. Defaults
and ranges are cited from [CLI.md](CLI.md), which in turn cites the `main.rs` /
`engine.rs` constants. "Edge value" is a recommendation for a constrained device,
not a hard requirement.

| Hardware constraint | Knob(s) | Default | Recommended edge value | Why |
|---|---|---|---|---|
| **Limited RAM** (e.g. the 64 MiB ceiling, #115) | `--max-segment-bytes` | `67108864` (64 MiB); min `4096` | `8388608` (8 MiB) | The active segment is buffered/served from memory; an 8 MiB roll size (the `EDGE_SEGMENT_BYTES` value, which `--profile edge-tiny` sets for you) keeps the working set small and bounds the largest single in-memory region. |
| | `--consumer-credit` | `64`; min `1` | `64` (default, or lower) | Caps the per-CONNECTION un-acked message count. The default is already small and memory-justified; keep it or lower it on a very tight box. |
| | `--consumer-credit-bytes` | `8388608` (8 MiB); `0` = unlimited | `8388608` (8 MiB) | The per-CONNECTION un-acked BYTE budget. This is the firm RAM-side bound: a large-payload consumer cannot blow the ceiling despite a small message count, since a fetch stops once in-flight bytes reach the budget (hard floor of one message so it never wedges). Do NOT set `0` on the edge. |
| | `--max-in-flight` | `1024`; min `1` | a few hundred or fewer | The per-GROUP max-ack-pending window. Lower it so the in-flight set across a group cannot pin many records' worth of lease state in memory at once. |
| | `--max-groups` | `1024`; `0` = unlimited | `1024` (default) or lower | Caps live work-groups so a client cannot exhaust memory by naming endless groups (#240; see THREAT_MODEL.md "unbounded group names"). Keep the non-zero default; never `0` on the edge. |
| | `--max-total-bytes` | `0` = unlimited | a disk-sized cap, e.g. `268435456` (256 MiB) | A hard durable-log byte cap. It bounds disk, not RSS directly, but a bounded log keeps the in-memory derived offset index (rebuilt from the log on startup) small, so it composes with the RAM bound. |
| **Flash wear / slow storage** | `--storage memory` (#443) | `disk` | `memory` ONLY when reboot loss is acceptable | Removes flash writes and fsync latency entirely by holding the log in RAM: no files, no fsync, and NO restart durability (a stop or crash loses every acked message). Gated behind `--ephemeral-loss-ack` and a non-zero `--max-total-bytes`. See "When memory mode is the right call" below, including the tmpfs alternative. |
| | `--checkpoint-interval` | `1024` (messages) | `1024` (default) or higher | The cursor is checkpointed after it advances this many offsets, so the checkpoint write rate stays far below one write per ack (edge flash endurance). A larger value writes the checkpoint less often (at the cost of redelivering more after an abrupt crash); do NOT lower it toward 1 on flash. |
| | `--max-total-bytes` | `0` = unlimited | a disk-sized cap (as above) | Bounds total durable bytes so the log does not grow until the device fills; the drop-new shed backstop. |
| | `--max-retained-bytes` / `--max-age-ms` / `--max-messages` | `0` = off (each) | enable at least one, sized to the device | Retention reaps whole old, fully-consumed sealed segments (consumer-safe, never below the slowest consumer, never the active segment). Bounding the on-disk footprint bounds the rewrite/erase volume the flash sees over time (write amplification, #19). |
| | `--disk-full-policy` | `drop-new` | `drop-new` (default) | When `--max-total-bytes` is hit, drop-new sheds the over-cap produce and preserves older accepted data, avoiding the extra force-reap writes (and the consumer truncation) that `drop-oldest` incurs. |
| **Limited CPU** | (single-writer, always on) | n/a | n/a | Produces serialize through one writer and one `fdatasync` at a time; there is no thread-count knob to tune. Keep `--max-connections` (default `256`) modest so accept/decode work stays bounded. |
| | `--compression` | `lz4` (the #139 default; zstd opt-in behind a feature) | `lz4` (default) or `none` | Per the #139 decision, lz4_flex (cheap, pure Rust) is the default codec and zstd is opt-in only behind a feature, never on the default path. The write path is WIRED (#387 runtime, #430 wiring): a compressible payload of 64 bytes or more is stored compressed behind the `COMPRESSED` record flag (smaller or incompressible payloads store raw by design), the materialized-config `compression=` echo matches the bytes on disk, the offline reader prints the real stored codec, and the client decompresses transparently on deliver. `none` stores every record raw, byte-for-byte the historical layout. |
| **Intermittent power** | `--durability-level` | `sync` | `sync` (default) | Every acknowledged durable write is `fdatasync`'d before the ack under the DEFAULT `sync` level, so a power loss never loses an acknowledged write. The relaxed levels (`interval` / `async` / `none`, #341 / #379) are strictly OPT-IN: `async` / `none` refuse to boot without the explicit `--async-loss-ack` acknowledgement, and any relaxed level logs a loud I2-waived startup WARN, so you cannot accidentally weaken durability from the command line. Keep `sync` on a device that can brown out. |
| | `--disk-full-policy` | `drop-new` | `drop-new` (default) | On a device that may brown out mid-write, drop-new avoids the extra reaping writes of `drop-oldest`; the older accepted (and already-`fdatasync`'d) data is preserved. |
| | graceful shutdown (always on, #195) | n/a | n/a | SIGINT / SIGTERM stops accepting, flushes every work-group's committed cursor, and exits 0, so a clean shutdown does not redelivery-replay acked work. Un-acked in-flight messages still correctly redeliver (at-least-once). SIGHUP does not stop; it re-reads `--config` to reload the live subset (#380). |
| | `--checkpoint-interval` | `1024` | `1024` (default) | After an abrupt (non-graceful) power cut, at most this many messages redeliver. It bounds the post-crash replay; recovery itself always restores the longest valid prefix and bounds + reports any corruption-skip loss (see below). |

### How the RAM knobs compose to keep RSS under the ceiling

The four RAM-side knobs bound different buffers, and they compose:

- `--max-segment-bytes 8388608` bounds the active-segment working set (the
  largest single in-memory region) to 8 MiB.
- `--consumer-credit-bytes 8388608` bounds the un-acked PAYLOAD bytes held PER
  CONNECTION to 8 MiB, with a hard floor of one message so it never wedges. This
  is the per-consumer RAM ceiling.
- `--consumer-credit 64` bounds the un-acked MESSAGE count per connection; the
  effective per-fetch credit is `min(message credit, byte budget, group
  window)`, so whichever binds first stops the fetch.
- `--max-in-flight` bounds the per-GROUP lease state.
- `--max-groups 1024` bounds how many groups (each with its own cursor + lease
  state) can exist, so total consumer-state memory is `O(max_groups *
  per-group)` rather than unbounded (#240; THREAT_MODEL.md).

The product of the per-connection byte budget and the connection cap, plus the
active-segment buffer and the bounded per-group state, is what an operator sizes
under the device's RAM ceiling. The auto-itemized per-buffer budget with a
refuse-to-boot guard is now SHIPPED (#115): set `--ram-ceiling-bytes` (or
`--profile edge-tiny`, which sets the 64 MiB ceiling) and a broker whose
worst-case bounded-buffer footprint provably exceeds the ceiling refuses to
start (the formula is in [RAM_BUDGET.md](RAM_BUDGET.md)). With no ceiling set,
the operator does this sizing by hand.

### Write amplification and flash endurance (#19)

Write amplification (on-disk data-dir bytes written per byte of user payload) is
the flash-wear realism metric in #19 and a row in the SLO table (target TBD,
not yet ratified). The knobs that hold it down on the edge:

- The group-commit `fdatasync` batches the appends that arrived during the
  previous sync into one sync, so the per-ack sync cost amortizes rather than
  one `fdatasync` per message.
- `--checkpoint-interval` (default `1024`) keeps the cursor-checkpoint write
  rate far below one write per ack; the checkpoint and the durable counters
  snapshot ride the same cadence (not fsynced per increment).
- Retention (`--max-retained-bytes` / `--max-age-ms` / `--max-messages`) and the
  `--max-total-bytes` cap bound how much data is on disk over time, which bounds
  the erase/rewrite volume the flash controller does.
- Segments are append-only and never recycled in v1 (ADR 0002), so there is no
  in-place rewrite of an existing segment; a reaped segment is unlinked whole.

### Recovery bounds under power loss

These are not knobs, but they bound the blast radius an operator is sizing
around. Startup always recovers the longest valid prefix; a torn tail is
truncated, and a corrupt record or segment is skipped, never fatal. Corruption
loss is bounded (at most one segment or 64 MiB per event, at most 1 percent of
durable bytes per recovery) and reported as a number; exceeding either cap
freezes the log read-only and alerts. See README and
[INVARIANTS.md](INVARIANTS.md).

## When memory mode is the right call (#443, #444)

`serve --storage memory` is the deliberate answer for a flash-wear-bound deployment that can
tolerate reboot loss: the broker holds the whole log in RAM, so flash sees zero writes and the
produce path pays no durability barrier at all.

The measured baseline (the deployed edge hive, 2026-06-10, 256 B messages; the #443 numbers):

- SD card (the durable default): 9.0 ms per fsync, about 50 msg/s sustained, and roughly
  70 KB of PHYSICAL flash writes per 256 B message once segment append, cursor checkpoint,
  and filesystem journal amplification stack up. On a wear-rated SD part, that write
  amplification, not CPU, is the budget that runs out first.
- RAM-backed (tmpfs mount): 0.5 ms per publish, about 92 msg/s, with the ceiling moving to
  CPU. Memory mode runs the same engine over RAM, so it sits in the same performance regime
  while writing nothing to any filesystem.

Take memory mode when ALL of these hold: the data is reconstructible from a live source (or
the loss window is genuinely acceptable), consumers tolerate replay-from-live after a restart
(a revived memory broker is EMPTY: offset 0, no records), and introspection can be live-only
(`/healthz`, `/readyz`, `/metrics`, `/admin`, `top --addr`; there is no data dir for the
offline verbs, ever). Size `--max-total-bytes` deliberately: in RAM it is the OOM guard, and
stored records are resident memory ON TOP of the bounded buffers `--ram-ceiling-bytes` meters.

### The honest tmpfs baseline

Running the ordinary DISK backend with `--data-dir` on a tmpfs mount achieves most of the same
result and works on EVERY shipped version today, with no new flags: flash sees zero writes,
fsync is a RAM-speed no-op (the 0.5 ms / 92 msg/s row above IS a tmpfs measurement), and,
unlike memory mode, the data dir SURVIVES a broker stop, crash, or upgrade as long as the
machine stays up (broker-restart survival on tmpfs was verified as part of the #443 baseline:
a message published before a broker kill was delivered after restart). The full operational
surface keeps working too: `peek`/`dump`/`scrub`/`repair` and the offline admin verbs can
inspect the stopped broker's tmpfs directory until the reboot wipes it.

What tmpfs does NOT give you is the explicit contract: a tmpfs mount LOOKS like durable
storage to every tool and every operator downstream (the materialized-config line says
`storage=disk` and shows a real path), nothing forces a byte cap (an uncapped log fills the
mount or the mount fills RAM), and the loss-on-reboot property lives in /etc/fstab rather
than in the broker invocation. Memory mode is the same trade made fail-closed and
self-describing: the dedicated `--ephemeral-loss-ack` consent, the mandatory
`--max-total-bytes` RAM bound, the `storage=memory` echo, and no mount provisioning at all.

Rule of thumb: tmpfs when you want restart survival within an uptime or offline
inspection on a stopped broker; `--storage memory` when you want the ephemeral contract
explicit, machine-checkable, and impossible to mistake for durability; the SD card (the
default) when acked data must survive a reboot.

## Cross-references

- [CLI.md](CLI.md): the canonical, exhaustive flag map (type, default, unit) for
  every `serve` knob named here, each cited to its `main.rs` constant, plus the
  `IRONBUS_*` env-var mapping.
- [WAL.md](WAL.md): the segment-roll / overflow mechanics, the
  `EDGE_SEGMENT_BYTES` note (the 8 MiB value is now selectable via
  `--profile edge-tiny`, #87), and what #135 specifies but the code does not
  implement.
- [SLO.md](SLO.md): the steady-state RAM ceiling (64 MiB, #115) and write
  amplification (#19) targets, both marked as stated targets not yet ratified.
- [THREAT_MODEL.md](THREAT_MODEL.md): the resource-exhaustion mitigations the
  RAM knobs back (bounded group names, connections, frame sizes).

## Follow-ups (not yet shipped)

- **#19**: ratifies the write-amplification target against a measured baseline
  on the reference edge device.
- **#380 / #106**: the MUTATING wire `CONFIG SET` / `SAVE` admin verbs (the
  runtime config-change surface) wait on connection-scoped auth. The
  validate-whole-then-swap `--config` re-read engine ships (#382) and runs both
  as a startup self-check and on a runtime trigger: SIGHUP re-reads `--config` at
  runtime and applies the live-reloadable subset (the retention bounds + the
  disk-full policy) to the running broker (#380).
- **#12 write-path wiring**: DONE (#387 runtime, #430 wiring). `serve
  --compression lz4` (the default) compresses each compressible payload of 64
  bytes or more on the produce path; `dump` shows the real stored codec and
  the client decompresses transparently on deliver. A workload of
  already-compressed or encrypted payloads pays the per-record compression
  attempt as pure waste (the never-expand guard stores them raw anyway), so
  `--compression none` is the right call for it; note the attempt runs on the
  single-writer produce path, before the fsync, so its CPU cost adds directly
  to produce latency.
