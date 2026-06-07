# Edge tuning: the hardware constraint to knob mapping

This document maps each edge hardware constraint to the specific shipped `serve`
knob(s) that honor it, with a recommended edge value and the reasoning. It is the
operator-facing companion to the flag-and-default reference in
[CLI.md](CLI.md), the WAL and overflow mechanics in [WAL.md](WAL.md), the
target table in [SLO.md](SLO.md), and the resource-exhaustion mitigations in
[THREAT_MODEL.md](THREAT_MODEL.md). It does not introduce or duplicate any flag;
every flag below is defined canonically in CLI.md and verified against the
`main.rs` and `engine.rs` constants.

## Honesty up front: these are recommended MANUAL settings, not an auto profile

There is no `--profile` flag and no auto-selected "edge" or "tiny" profile in the
shipped binary. The README and #135 describe segments defaulting to "64 MiB or
8 MiB on the edge profile", but **there is no profile selection in the code**: the
default segment size is always 64 MiB. An `EDGE_SEGMENT_BYTES` constant (8 MiB)
exists in `crates/ironbus-core/src/format.rs`, but it is **unwired**. To get the
8 MiB edge segment size today you must pass `--max-segment-bytes 8388608`
explicitly (see [WAL.md](WAL.md), the discrepancies section, and the flag table
at the end of that doc).

Likewise, the broader TOML config file, named profiles, and hot reload are
SEPARATE follow-ups (#85 / #87 / #88) and not yet implemented; the env-var layer
(`IRONBUS_<FLAG>`) is the only config surface beyond flags. The auto-selected RAM
budget itself (the 64 MiB ceiling itemized into a per-buffer budget with a
refuse-to-boot guard) is the deliverable of #115 and is likewise NOT yet wired:
SLO.md lists it as a stated target, not a shipped guard.

So everything below is a set of RECOMMENDED MANUAL flag values an operator passes
on the `serve` command line (or via the matching `IRONBUS_*` env var). When the
auto-profile lands (#115 for the RAM budget, #87 for profile selection), these
become the values a `--profile tiny`-style switch would set for you.

## The constraint table

Every recommended value below is a real, currently-accepted flag value. Defaults
and ranges are cited from [CLI.md](CLI.md), which in turn cites the `main.rs` /
`engine.rs` constants. "Edge value" is a recommendation for a constrained device,
not a hard requirement.

| Hardware constraint | Knob(s) | Default | Recommended edge value | Why |
|---|---|---|---|---|
| **Limited RAM** (e.g. the 64 MiB ceiling, #115) | `--max-segment-bytes` | `67108864` (64 MiB); min `4096` | `8388608` (8 MiB) | The active segment is buffered/served from memory; an 8 MiB roll size (the unwired `EDGE_SEGMENT_BYTES` value) keeps the working set small and bounds the largest single in-memory region. |
| | `--consumer-credit` | `64`; min `1` | `64` (default, or lower) | Caps the per-CONNECTION un-acked message count. The default is already small and memory-justified; keep it or lower it on a very tight box. |
| | `--consumer-credit-bytes` | `8388608` (8 MiB); `0` = unlimited | `8388608` (8 MiB) | The per-CONNECTION un-acked BYTE budget. This is the firm RAM-side bound: a large-payload consumer cannot blow the ceiling despite a small message count, since a fetch stops once in-flight bytes reach the budget (hard floor of one message so it never wedges). Do NOT set `0` on the edge. |
| | `--max-in-flight` | `1024`; min `1` | a few hundred or fewer | The per-GROUP max-ack-pending window. Lower it so the in-flight set across a group cannot pin many records' worth of lease state in memory at once. |
| | `--max-groups` | `1024`; `0` = unlimited | `1024` (default) or lower | Caps live work-groups so a client cannot exhaust memory by naming endless groups (#240; see THREAT_MODEL.md "unbounded group names"). Keep the non-zero default; never `0` on the edge. |
| | `--max-total-bytes` | `0` = unlimited | a disk-sized cap, e.g. `268435456` (256 MiB) | A hard durable-log byte cap. It bounds disk, not RSS directly, but a bounded log keeps the in-memory derived offset index (rebuilt from the log on startup) small, so it composes with the RAM bound. |
| **Flash wear / slow storage** | `--checkpoint-interval` | `1024` (messages) | `1024` (default) or higher | The cursor is checkpointed after it advances this many offsets, so the checkpoint write rate stays far below one write per ack (edge flash endurance). A larger value writes the checkpoint less often (at the cost of redelivering more after an abrupt crash); do NOT lower it toward 1 on flash. |
| | `--max-total-bytes` | `0` = unlimited | a disk-sized cap (as above) | Bounds total durable bytes so the log does not grow until the device fills; the drop-new shed backstop. |
| | `--max-retained-bytes` / `--max-age-ms` / `--max-messages` | `0` = off (each) | enable at least one, sized to the device | Retention reaps whole old, fully-consumed sealed segments (consumer-safe, never below the slowest consumer, never the active segment). Bounding the on-disk footprint bounds the rewrite/erase volume the flash sees over time (write amplification, #19). |
| | `--disk-full-policy` | `drop-new` | `drop-new` (default) | When `--max-total-bytes` is hit, drop-new sheds the over-cap produce and preserves older accepted data, avoiding the extra force-reap writes (and the consumer truncation) that `drop-oldest` incurs. |
| **Limited CPU** | (single-writer, always on) | n/a | n/a | Produces serialize through one writer and one `fdatasync` at a time; there is no thread-count knob to tune. Keep `--max-connections` (default `256`) modest so accept/decode work stays bounded. |
| | compression codec | n/a (lz4_flex is the design default; zstd opt-in) | n/a | Per the #139 decision, lz4_flex (cheap, pure Rust) is the default codec and zstd is opt-in only behind a feature, never on the default path. NOTE: on-disk compression has NOT landed (the offline reader prints `codec = none`); there is no `serve` codec flag today, so this is a design choice, not a knob you set. |
| **Intermittent power** | `fdatasync` before ack (always on) | n/a | n/a | Every acknowledged durable write is `fdatasync`'d before the ack, so a power loss never loses an acknowledged write. This is the always-on default; the README's `interval` / `none` modes are NOT exposed as `serve` flags, so you cannot accidentally weaken it from the command line. |
| | `--disk-full-policy` | `drop-new` | `drop-new` (default) | On a device that may brown out mid-write, drop-new avoids the extra reaping writes of `drop-oldest`; the older accepted (and already-`fdatasync`'d) data is preserved. |
| | graceful shutdown (always on, #195) | n/a | n/a | SIGINT / SIGTERM / SIGHUP stops accepting, flushes every work-group's committed cursor, and exits 0, so a clean shutdown does not redelivery-replay acked work. Un-acked in-flight messages still correctly redeliver (at-least-once). |
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
under the device's RAM ceiling. The auto-itemized per-buffer budget that
provably sums under 64 MiB with a refuse-to-boot guard is the #115 deliverable
and is not yet shipped; until then the operator does this sizing by hand.

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

## Cross-references

- [CLI.md](CLI.md): the canonical, exhaustive flag map (type, default, unit) for
  every `serve` knob named here, each cited to its `main.rs` constant, plus the
  `IRONBUS_*` env-var mapping.
- [WAL.md](WAL.md): the segment-roll / overflow mechanics, the unwired
  `EDGE_SEGMENT_BYTES` note, and what #135 specifies but the code does not yet
  implement.
- [SLO.md](SLO.md): the steady-state RAM ceiling (64 MiB, #115) and write
  amplification (#19) targets, both marked as stated targets not yet ratified.
- [THREAT_MODEL.md](THREAT_MODEL.md): the resource-exhaustion mitigations the
  RAM knobs back (bounded group names, connections, frame sizes).

## Follow-ups (not yet shipped)

- **#115**: the `tiny` profile RAM budget (the 64 MiB ceiling itemized into a
  per-buffer budget with a refuse-to-boot guard). Until it lands, the RAM sizing
  above is manual.
- **#87** (with #85 / #88): the named-profile selection (and the TOML config
  file and hot reload). Until it lands, there is no `--profile` switch; you pass
  the individual flags.
- **#19**: ratifies the write-amplification target against a measured baseline
  on the reference edge device.
