# Backpressure: time-in-queue shedding, retry budgets, and load shedding

The normative design spec for two backpressure controls IronBus needs to protect
tail latency and bound load under overload without per-device tuning:

1. **CoDel time-in-queue (sojourn) shedding plus a depth-and-byte backstop**
   (#68): shed by how long a message has waited, not by how deep the queue is, so
   the control is rate-independent, with a sojourn-independent hard backstop that
   bounds memory when a fully stalled drain produces no sojourn samples at all.
2. **Retry budget, explicit load shedding, and a do-not-retry wire signal** (#69):
   cap retries at 10% of a client's request rate, signal a machine-actionable
   `retry_after_ms` / `shed` hint on the error frame, brake the fire-and-forget
   tier with a separate token bucket, and limit egress to downstream sinks with an
   AIMD concurrency limiter, so backpressure can never amplify into a retry storm.

Both descend from the backpressure-and-overload parent (#10). Their parameters
flow through the configuration system (#14) and their observability flows through
the resilience-observability contract (#16, see [METRICS.md](METRICS.md)).

> **Specified, not implemented.** Read this honestly. IronBus **today** ships a
> narrower backpressure surface: the drop-new / drop-oldest disk-full overflow
> policy on the durable log (#10, #13, #82) and the per-connection consumer credit
> window (#65, #275). Those are real and cited below. **Everything in this
> document beyond them is a design, not running code**: CoDel sojourn shedding,
> the suspend-reset, the retry budget, the `retry_after_ms` / `shed` wire fields,
> the fire-and-forget token bucket, and the egress AIMD limiter are SPECIFIED
> here, not built. The wire fields in particular require a frozen-protocol
> extension (#11) that has not landed; see [What this changes on the wire](#what-this-changes-on-the-wire-11).
> Where a control already exists this document says so and cites the source; where
> it does not, it says "specified."

## Contents

- [What exists today (the honest baseline)](#what-exists-today-the-honest-baseline)
- [Part A: CoDel time-in-queue shedding (#68)](#part-a-codel-time-in-queue-shedding-68)
  - [The signal: sojourn, not depth](#the-signal-sojourn-not-depth)
  - [The CoDel control law](#the-codel-control-law)
  - [TARGET and INTERVAL: defaults, per-topic, clamped](#target-and-interval-defaults-per-topic-clamped)
  - [The monotonic sojourn clock and the suspend reset](#the-monotonic-sojourn-clock-and-the-suspend-reset)
  - [The depth-and-byte backstop](#the-depth-and-byte-backstop)
  - [Why the backstop bounds memory under a fully stalled drain](#why-the-backstop-bounds-memory-under-a-fully-stalled-drain)
- [Part B: retry budget, shedding, and do-not-retry signaling (#69)](#part-b-retry-budget-shedding-and-do-not-retry-signaling-69)
  - [The per-client retry budget (10% / 60 s)](#the-per-client-retry-budget-10-60-s)
  - [The `retry_after_ms` and `shed` wire signal](#the-retry_after_ms-and-shed-wire-signal)
  - [The fire-and-forget token bucket](#the-fire-and-forget-token-bucket)
  - [The egress AIMD concurrency limiter](#the-egress-aimd-concurrency-limiter)
  - [Why backpressure cannot amplify into a retry storm](#why-backpressure-cannot-amplify-into-a-retry-storm)
- [Configuration keys (#14)](#configuration-keys-14)
- [Metrics (#16)](#metrics-16)
- [What this changes on the wire (#11)](#what-this-changes-on-the-wire-11)
- [See also](#see-also)

---

## What exists today (the honest baseline)

Two backpressure mechanisms are implemented and verified in the source. Both of
the specs below extend, but do not replace, them.

- **Durable-log overflow policy (drop-new / drop-oldest).** A hard byte cap on the
  durable log (`LogConfig::max_total_bytes`, `serve --max-total-bytes`, `0` =
  unlimited) rejects an over-cap produce before any write with the non-fatal
  `StorageError::AtCapacity`. The engine's `EngineConfig::disk_full_policy` decides
  what happens: `DropNew` (default) sheds the new write and increments
  `ironbus_produce_rejected_total`; `DropOldest` force-reaps the oldest sealed
  segment to make room and surfaces a one-time `Poll::Truncated` to any consumer it
  reaped past (`ironbus_segments_force_reaped_total`). Source:
  `crates/ironbus-server/src/engine.rs`, `crates/ironbus-storage/src/log.rs`. See
  [WAL.md](WAL.md) and RR-03 in [RISK_REGISTER.md](RISK_REGISTER.md).
- **Per-connection consumer credit.** Each connection holds at most
  `consumer_credit` un-acked messages (default 64) and `consumer_credit_bytes`
  un-acked bytes (default 8 MiB), derived from the connection-scoped `leased` set,
  so one stuck consumer pins only its own slots and never starves a peer. Source:
  `crates/ironbus-server/src/session.rs` (#65, #275). See RR-01 in
  [RISK_REGISTER.md](RISK_REGISTER.md).

Honesty about terminology: the README and the acceptance harness describe overflow
as "spill to disk then shed" past a "ring." For a single durable log there is no
separate in-memory ring or second spill buffer to spill *into*: the active segment
is already on disk, so "spill then shed" collapses to "shed" at the byte cap (see
[WAL.md](WAL.md), "never spill-into-a-second-log"). The depth-and-byte backstop in
Part A is therefore specified against the **durable-log byte cap that exists today**
plus a future per-topic in-memory enqueue **ring** that the CoDel queue introduces;
where it names `ring_capacity` it names a *specified* per-topic bound, not a current
code symbol.

---

## Part A: CoDel time-in-queue shedding (#68)

### The signal: sojourn, not depth

The wrong signal for shedding is queue **depth**. A depth threshold that is right
for a fast drain is wrong for a slow one: the same 1000-message backlog is healthy
behind a 100k msg/s consumer and catastrophic behind a 10 msg/s consumer. Depth
shedding therefore needs per-device tuning, which the edge fleet cannot supply.

The right signal is **sojourn**: how long the message at the head of the queue has
actually waited. Sojourn is rate-independent. A 5 ms sojourn means the same thing
regardless of drain rate, payload size, or device class, so a single sojourn target
is correct on every node with no per-device tuning. This is the core claim of CoDel
(Controlled Delay, RFC 8289), the AQM algorithm IronBus adopts here.

### The CoDel control law

IronBus implements the RFC 8289 control law, per topic, over the topic's enqueue
ring:

1. **Measure sojourn at dequeue.** When a message is pulled from the ring to be
   appended (or delivered), its sojourn is `now_monotonic - enqueue_monotonic`,
   clamped to `>= 0` (see [the sojourn clock](#the-monotonic-sojourn-clock-and-the-suspend-reset)).
2. **Track the minimum sojourn over a sliding window.** CoDel sheds on the
   **minimum** sojourn over the current `INTERVAL`, never the instantaneous or
   average value. The minimum is the part of the delay that is *standing* queue
   (real, persistent backlog) rather than a transient burst that drains on its own.
   A single fast dequeue in the window resets "are we above target," so a bursty
   but healthy queue never sheds.
3. **Arm when the minimum stays above TARGET for a full INTERVAL.** If the minimum
   sojourn stays `> TARGET` for an entire `INTERVAL`, the topic enters the
   **dropping state**: the standing delay is real and shedding begins.
4. **Drop at the control-law spacing.** In the dropping state, the next drop is
   scheduled at a spacing of `INTERVAL / sqrt(count)`, where `count` is the number
   of drops in this dropping episode. The `sqrt` law makes the control increasingly
   aggressive the longer the overload persists (the inter-drop interval shrinks as
   `count` grows), then backs off as the minimum sojourn falls back under TARGET and
   the topic leaves the dropping state. This is the RFC 8289 `control_law`.
5. **Exit when sojourn recovers.** A measured sojourn `<= TARGET` (or an empty
   queue) takes the topic out of the dropping state; `count` decays so the next
   episode does not start over-aggressive.

A shed under CoDel routes a record into the topic's configured overflow disposition
(the same drop-new / drop-oldest decision the byte cap uses today), so a CoDel shed
is never a silent loss: it increments a counter (see [Metrics](#metrics-16)) exactly
like every other resilience event under the #16 contract.

### TARGET and INTERVAL: defaults, per-topic, clamped

The two CoDel constants ship with the RFC 8289 recommended defaults and require no
per-device tuning:

| constant | default | meaning |
|----------|---------|---------|
| `TARGET` | 5 ms | the acceptable standing sojourn; shedding begins only above it |
| `INTERVAL` | 100 ms | the window the minimum must stay above TARGET before shedding, and the base drop spacing |

Both are exposed **per topic** through #14 so an operator can tighten a
latency-critical topic or loosen a bulk one. Both are **clamped** so a
misconfiguration cannot disable or pathologically misfire the control:

- `TARGET` is clamped to `[1 ms, 1 s]`. Below 1 ms the control would shed on
  scheduling jitter alone; above 1 s it would never protect tail latency.
- `INTERVAL` is clamped to `[20 ms, 10 s]`. Below 20 ms the window is shorter than
  realistic burst durations (false shedding); above 10 s the control reacts too
  slowly to bound a growing backlog.

A value outside the clamp is **silently clamped to the nearest bound, not
rejected**, so a topic config can never refuse to start over a CoDel value, and the
effective value is reported (see [Metrics](#metrics-16)). The defaults satisfy the
"no per-device tuning" criterion directly: a fresh node with no per-topic override
runs RFC 8289 defaults that are correct across drain rates by construction.

### The monotonic sojourn clock and the suspend reset

Sojourn is a **duration**, so it is measured with the monotonic clock, never the
wall clock. The clock seam already exists:
`Clock::now_monotonic_nanos()` in `crates/ironbus-core/src/clock.rs`, whose own doc
comment names "queue sojourn" as a monotonic-clock use. The engine reads the
enqueue timestamp from `now_monotonic_nanos()` at enqueue and the dequeue timestamp
from `now_monotonic_nanos()` at dequeue; sojourn is their difference. Three
properties make this robust on a sleeping edge device:

1. **Monotonic, never wall.** The monotonic clock never moves backwards within a
   run (the seam guarantees it; even `ManualClock::advance_millis` saturates and
   never wraps), so a wall-clock NTP step or a backwards jump can never make a
   sojourn negative or absurdly large. The wall clock (`now_unix_millis`) is used
   only for the record's stored timestamp, never for sojourn.
2. **Clamped `>= 0`.** As a belt-and-suspenders guard against any clock anomaly
   (a non-monotonic platform clock, a reordered read), the sojourn is clamped to
   `>= 0` before it feeds the control law. A clamped-to-zero sojourn simply reads as
   "no standing delay," which is the safe direction (it cannot trigger a false
   shed).
3. **Interval reset across a suspend/resume gap.** An edge device that suspends
   (deep sleep, power management) and resumes hours later would, on resume, measure
   a multi-hour sojourn for whatever sat in the ring across the sleep, and CoDel
   would immediately enter the dropping state and shed a burst of messages that were
   never actually contended, only asleep. To prevent this, the control detects a
   **suspend gap**: if the monotonic clock advances by more than a gap threshold
   (a small multiple of `INTERVAL`, e.g. several seconds) between two control
   evaluations with no intervening dequeue activity, the CoDel **interval window is
   reset** (the dropping state cleared, the window restarted, `count` reset) and the
   sojourns measured across the gap are discarded rather than fed to the control
   law. A device that was merely asleep resumes with a clean window and does not
   misfire. The gap detection is itself monotonic-clock based, so it cannot be
   spoofed by a wall-clock step.

### The depth-and-byte backstop

CoDel sheds on sojourn, and sojourn is only **sampled at dequeue**. A queue that
is being actively drained, even slowly, produces sojourn samples and CoDel bounds
its tail latency. But a queue whose drain is **fully stalled** (the consumer is
gone, the downstream sink is wedged, nothing is ever dequeued) produces **no sojourn
samples at all**, so CoDel sees no signal and never sheds, while producers keep
enqueueing. CoDel alone cannot bound memory under a total stall. This is the known
limitation of any time-in-queue control, and it is why a sojourn-independent
backstop is mandatory.

The backstop is a hard **depth and byte** bound, checked at **enqueue**, entirely
independent of sojourn:

- **Depth.** When the topic's enqueue ring reaches its capacity bound
  (`ring_capacity`, a specified per-topic message bound), the next enqueue fires the
  topic's overflow policy **regardless of sojourn**.
- **Bytes.** When the spill tier reaches its byte cap (the durable-log byte cap
  `max_total_bytes` that exists today, generalized to the per-topic enqueue path),
  the next enqueue fires the overflow policy **regardless of sojourn**.

The overflow policy the backstop fires is exactly the existing one: drop-new (shed
the new enqueue) or drop-oldest (evict the oldest to make room), the same
`disk_full_policy` decision and the same counters. The backstop is **clock- and
sojourn-independent by construction**: it reads only depth and byte counts at
enqueue, so a clock step, a suspend, or a total drain stall cannot disable it.

### Why the backstop bounds memory under a fully stalled drain

This is the proof-of-intent #68 requires. Consider the worst case: the drain is
fully stalled (zero dequeues), so CoDel samples nothing and never sheds, and
producers enqueue at an unbounded rate. Memory is bounded as follows:

- Every enqueue increments the ring depth and the byte total. Neither can be
  decremented without a dequeue, and there are none.
- The backstop is checked **at every enqueue**, before the message is admitted. The
  moment depth reaches `ring_capacity` **or** bytes reach the byte cap, the overflow
  policy fires on that enqueue and every subsequent one.
- Under **drop-new** the over-cap enqueue is rejected and **nothing is admitted**,
  so depth never exceeds `ring_capacity` and bytes never exceed the cap. Resident
  memory for the topic is bounded by `min(ring_capacity messages, byte cap)`,
  independent of producer rate and independent of how long the stall lasts.
- Under **drop-oldest** each over-cap enqueue evicts exactly one existing entry
  before admitting the new one, so depth and bytes hold at the cap (a one-in /
  one-out steady state). Resident memory is again bounded by the cap; the eviction
  is counted as a force-reap / truncation so the loss is never silent.

In both cases the bound holds with **zero dequeues** and **zero sojourn samples**,
which is exactly the case CoDel cannot cover. The two controls compose: CoDel bounds
**latency** while the queue drains, the backstop bounds **memory** when it does not.
Neither can substitute for the other, and the backstop's independence from the clock
means a clock anomaly that confuses CoDel never disables the memory bound.

---

## Part B: retry budget, shedding, and do-not-retry signaling (#69)

### The per-client retry budget (10% / 60 s)

Naive retries are the classic overload-to-collapse amplifier: when a broker sheds
1% of requests and every shed is retried, and those retries are also shed and
retried, the offered load multiplies until the broker collapses. The fix, from the
Google SRE "Handling Overload" chapter, is **adaptive throttling**: a client caps
its own retries as a fraction of its recent request rate, so retries can add only a
bounded multiple to the offered load.

IronBus specifies a **per-client retry budget of 10% of that client's request rate
over a sliding 60-second window**. Concretely, the client (and the broker, see
below) tracks over a 60 s sliding window:

- `requests`: total requests the client issued.
- `accepts`: requests the broker accepted (did not shed).

The SRE accept-based throttling probability is
`max(0, (requests - K * accepts) / (requests + 1))` with `K ~ 2`. A client throttles
a retry (drops it locally rather than sending) with that probability. With `K = 2`,
a client whose requests are all being accepted retries freely; as the accept rate
falls, the client's own retry rate is throttled toward the budget, so the
**aggregate retry rate stays bounded to roughly 10% of the request rate**. The 10%
figure is the budget the 60 s window enforces: sustained retries above 10% of the
request rate are throttled at the source.

The budget is enforced **on both sides**:

- **Client-side** (in the client library, the first line of defense): the client
  throttles its own retries against its local window before a retry ever reaches the
  wire, so a well-behaved client never sends a storm.
- **Broker-side** (the enforcement that does not trust the client): the broker keeps
  the same per-client window and **re-checks** the budget. A client that ignores the
  client-side throttle (a buggy or hostile reimplementation) is shed broker-side
  with an explicit do-not-retry signal (below), so the budget holds even against a
  client that does not honor it. The broker-side window is per-client; with no
  authenticated client identity today (#106 is specified, not implemented), the
  per-client key is the connection / source the broker can attribute, and the
  control tightens to per-identity once #106 lands.

### The `retry_after_ms` and `shed` wire signal

When the broker rejects a request, a bare error tells the client nothing about
**whether or when** to retry, so every client guesses, and the guesses amplify. The
broker therefore signals a **machine-actionable** hint on the error / nak frame.
Two fields are specified (the wire encoding is owned by #11; this document specifies
the fields, their semantics, and their sentinels, not their byte offsets):

| field | type | meaning |
|-------|------|---------|
| `retry_after_ms` | u32 | how long the client should wait before retrying. `0` = **may retry now** (apply normal backoff). `0xFFFFFFFF` (the sentinel) = **do not retry**; this request was shed and a retry will also be shed. Any other value = wait at least this many milliseconds before retrying. |
| `shed` | bool | `true` if this rejection is a deliberate **load-shed** (the broker chose to drop it to protect itself), as opposed to a request-level error (malformed, unauthorized, out-of-range). A client distinguishes "I was shed under load, back off" from "my request was wrong, fixing the input is the right response." |

The `do-not-retry` sentinel (`0xFFFFFFFF`) is the machine-actionable counterpart to
the retry budget: when the broker has decided a request must not be retried (it was
shed and the budget is exhausted, or the broker is in a state where retrying cannot
help), it says so explicitly, and a budget-respecting client stops rather than
guessing. `shed = true` with `retry_after_ms = 0xFFFFFFFF` is the canonical
"shed, do not retry" signal; `shed = true` with a finite `retry_after_ms` is "shed,
retry after this delay"; `shed = false` is an ordinary request error that retrying
will not fix.

These fields extend the existing wire vocabulary. Today the only rejection frame is
`Err` (tag 12), a bare UTF-8 message with no structured retry hint, and `Nack` is a
client-to-server op carried on the `Ack` frame (see [CONTRACTS.md](CONTRACTS.md)).
The structured `retry_after_ms` / `shed` fields are a **future extension of the
server-to-client error path** and require the frozen protocol (#11) to add them; see
[What this changes on the wire](#what-this-changes-on-the-wire-11).

### The fire-and-forget token bucket

A QoS-0-equivalent fire-and-forget tier (a producer that does not wait for a
`PubAck`) can flood the broker faster than any acked path, and because it is never
credited it cannot be slowed by the consumer-credit window that brakes the durable
path. Left ungoverned, a fire-and-forget flood can evict or starve credited,
acked traffic, which is the opposite of the priority order a durable broker owes its
clients.

The fire-and-forget tier is therefore governed by a **separate per-connection token
bucket**, distinct from the durable-path credit:

| parameter | default | meaning |
|-----------|---------|---------|
| message rate | 5000 msg/s | tokens refilled at this message rate |
| byte rate | 5 MiB/s | tokens refilled at this byte rate |
| refill granularity | 100 ms | the bucket refills every 100 ms (so the burst ceiling is ~500 messages / ~512 KiB) |

A fire-and-forget message consumes one message token and `payload_size` byte tokens;
when either bucket is empty the message is **shed** (with the `shed` signal above,
if the tier is one that gets a response) rather than admitted. The two critical
properties:

- **It caps the uncontrolled tier.** The bucket bounds the fire-and-forget rate to
  the configured ceiling regardless of how fast the producer sends, so the
  QoS-0-equivalent path can no longer bypass the brake.
- **It cannot evict credited traffic.** The token bucket gates only the
  fire-and-forget admission path. It has no authority to evict, reorder, or starve
  messages on the credited (acked, durable) path: a depleted fire-and-forget bucket
  sheds fire-and-forget messages and nothing else. Credited traffic flows on its own
  path under its own credit window, untouched. This is the priority guarantee #69
  requires: the uncontrolled tier is capped, and capping it never costs the
  controlled tier.

### The egress AIMD concurrency limiter

When IronBus forwards to a downstream sink (a DLQ sink, a future replication or
bridge target), a **static** concurrency limit hammers a degraded downstream: if the
sink slows down, a fixed 16-way concurrency keeps 16 requests in flight against a
target that is already failing, deepening the failure. The fix is an **adaptive**
concurrency limit that backs off when the downstream degrades and recovers when it
heals, modeled on TCP congestion control (AIMD).

The egress limiter specifies:

- A **static floor of 16** concurrent in-flight requests as the starting and
  minimum-by-default operating point.
- An **AIMD** adjustment **bounded to `[4, 128]`**: **additive increase** of `+1`
  after a clean window (a window with no failure signal), **multiplicative decrease**
  of `x0.5` on a failure signal (a timeout, an HTTP `429 Too Many Requests`, or an
  HTTP `503 Service Unavailable`). The limit never drops below 4 (so a transient
  blip cannot collapse throughput to zero) and never rises above 128 (so it cannot
  overwhelm even a healthy downstream).
- The limiter is defined **behind an interface** so a smarter gradient estimator
  (Vegas-style or Gradient2, which infer the limit from RTT gradients rather than
  explicit failure signals) can be **deferred** and slotted in later without changing
  the egress call sites. AIMD is the v1 estimator; the interface is the seam.

When the limit is reached, an egress request waits or is shed per the topic's
overflow disposition; a shed egress is counted (see [Metrics](#metrics-16)). The
`+1 / x0.5` law is the standard AIMD that converges to a fair, stable operating point
and reacts fast to a degrading downstream (halving) while probing for recovery slowly
(additive), which is exactly the asymmetry a degraded sink needs.

### Why backpressure cannot amplify into a retry storm

This is the proof-of-intent #69 requires. The claim is that under sustained
overload, the offered load (including retries) stays bounded to a small constant
multiple of the genuine request rate, so backpressure damps rather than amplifies.
The argument composes the four controls:

1. **The retry budget bounds the retry multiplier.** With the 10% / 60 s budget
   enforced client-side **and** broker-side, retries add at most ~10% to the offered
   load: a client that exceeds the budget is throttled at the source, and a client
   that ignores its own throttle is shed broker-side. The aggregate offered load is
   therefore bounded to ~1.1x the genuine request rate, not the unbounded geometric
   growth of unthrottled retry-on-every-shed. This is the core anti-amplification
   bound.
2. **The do-not-retry signal terminates futile retries.** When the broker sets
   `retry_after_ms = 0xFFFFFFFF` (`shed = true`), a budget-respecting client stops
   retrying that request entirely, so a shed request does not even consume its share
   of the 10% budget on a retry that cannot succeed. This removes the retries that
   are pure waste, tightening the bound further.
3. **The fire-and-forget bucket caps the uncontrolled tier.** The one path that the
   retry budget does not directly govern (fire-and-forget, which does not wait for a
   reply and so does not retry in the usual sense) is independently capped by its
   token bucket and cannot evict credited traffic, so it cannot become an
   amplification channel either.
4. **The egress limiter prevents downstream-induced amplification.** A degrading
   downstream halves the egress limit rather than piling on, so a slow sink does not
   convert into a backlog that itself triggers more shedding and more retries
   upstream.

Composed, every amplification path is bounded: the acked path by the retry budget
and the do-not-retry signal, the fire-and-forget path by the token bucket, and the
egress path by AIMD. There is no path by which a shed multiplies into more sheds
without passing through a control that caps it, so backpressure damps the offered
load instead of amplifying it. Note honestly that this is a **design argument over
the specified controls**, not a measured result; ratifying it against a real
overload benchmark (the #111 macro-bench, see [SLO.md](SLO.md)) is follow-up work
once the controls are implemented.

---

## Configuration keys (#14)

All keys below are **specified**, not yet wired. They follow the existing `serve`
flag and `DEFAULT_*` constant conventions (see [CLI.md](CLI.md)); the exact
spellings are fixed when the controls are implemented under #14. CoDel keys are
per-topic and clamped; the others are per-connection or global as noted.

| key (specified) | scope | default | clamp / bounds | control |
|-----------------|-------|---------|----------------|---------|
| `codel_target_ms` | per topic | 5 ms | `[1 ms, 1 s]` | CoDel TARGET (#68) |
| `codel_interval_ms` | per topic | 100 ms | `[20 ms, 10 s]` | CoDel INTERVAL (#68) |
| `ring_capacity` | per topic | (specified) | message count | depth backstop (#68) |
| `ring_byte_cap` | per topic | (the existing `max_total_bytes` byte cap) | bytes | byte backstop (#68) |
| `retry_budget_ratio` | per client | 0.10 (10%) | `[0, 1]` | retry budget (#69) |
| `retry_budget_window_ms` | per client | 60000 (60 s) | sliding window | retry budget (#69) |
| `fire_and_forget_msg_rate` | per connection | 5000 msg/s | rate | token bucket (#69) |
| `fire_and_forget_byte_rate` | per connection | 5 MiB/s | rate | token bucket (#69) |
| `fire_and_forget_refill_ms` | per connection | 100 ms | refill granularity | token bucket (#69) |
| `egress_limit` | global / per sink | 16 (static floor) | AIMD `[4, 128]` | egress limiter (#69) |

A CoDel value outside its clamp is silently clamped to the nearest bound (never a
startup error), consistent with the "no per-device tuning" and "cannot refuse to
start" criteria.

## Metrics (#16)

All metrics below are **specified** additions to the resilience-observability
contract in [METRICS.md](METRICS.md). Each follows that contract: a shed is never
silent, every shed-counter name is `ironbus_*_total` and would join the frozen
taxonomy (`FROZEN_RESILIENCE_COUNTERS`) as a deliberate, test-gated addition;
estimate / ratio / limit values are **gauges** (no `_total` suffix), so they stay
out of the frozen counter set by construction, matching how the existing gauges are
handled.

**CoDel (#68):**

| metric (specified) | kind | meaning |
|--------------------|------|---------|
| `ironbus_codel_shed_total{topic}` | counter | records shed by the CoDel sojourn control |
| `ironbus_codel_backstop_shed_total{topic}` | counter | records shed by the depth/byte backstop (sojourn-independent) |
| `ironbus_codel_sojourn_estimate_ms{topic}` | gauge | the current minimum-sojourn estimate the control law is acting on |
| `ironbus_codel_interval_resets_total{topic}` | counter | suspend-gap interval resets (a sleeping device that did not misfire) |

Splitting the CoDel shed from the backstop shed lets an operator see *which* control
fired: a rising `codel_shed_total` is standing latency, a rising
`backstop_shed_total` is a stalled drain that CoDel could not see.

**Retry / shedding / egress (#69):**

| metric (specified) | kind | meaning |
|--------------------|------|---------|
| `ironbus_retry_shed_total{side}` | counter | retries shed by the budget (`side` = `client` or `broker`) |
| `ironbus_fire_and_forget_shed_total` | counter | fire-and-forget messages shed by the token bucket |
| `ironbus_egress_shed_total{sink}` | counter | egress requests shed at the concurrency limit |
| `ironbus_retry_ratio` | gauge | the observed retry rate as a fraction of the request rate (the 10%-budget signal) |
| `ironbus_egress_limit{sink}` | gauge | the current AIMD egress concurrency limit (between 4 and 128) |

`ironbus_retry_ratio` makes the anti-amplification claim observable: an operator can
watch it stay near or below the 10% budget under overload. `ironbus_egress_limit`
makes the AIMD backoff visible (it halves when a sink degrades, climbs back as it
heals).

## What this changes on the wire (#11)

The `retry_after_ms` and `shed` fields are the **only** part of this design that
touches the frozen wire protocol, and they are **not** in the protocol today. The
frozen frame surface (see [CONTRACTS.md](CONTRACTS.md)) carries one rejection frame,
`Err` (tag 12), a bare UTF-8 message with no structured retry hint, and the client
nack op on the `Ack` frame already carries a `delay_ms` in the **client-to-server**
direction (a client telling the broker how long to delay a redelivery), which is a
different thing from the broker telling the client whether and when to retry.

Adding `retry_after_ms` / `shed` is a **forward-compatible extension** of the
server-to-client error path, and it must be specified and frozen under #11 before it
is implemented:

- The envelope is already forward-compatible (an unknown frame type still frames by
  length and is skippable), and the `RecordFlags` precedent shows unknown bits are
  preserved on read, so a structured error body or a new error frame can be added
  without breaking an old reader.
- The fields are specified here at the **semantic** level (the two values, their
  types, the `0` and `0xFFFFFFFF` sentinels, the `shed` boolean). The **byte
  encoding** (a new structured error frame, or additional fields appended to a
  versioned `Err` body) is owned by #11 and fixed there, with the frozen-tag /
  frozen-field tests extended exactly as every prior wire change was (see the
  `type_tags_have_their_exact_frozen_wire_values` precedent in
  `crates/ironbus-proto/src/frame.rs`).

Until that #11 extension lands, the retry budget can still be enforced (it is an
accounting control, and the client-side half needs no wire change), but the broker
can only signal a shed through the existing bare `Err`; the structured,
machine-actionable hint is the part that waits on #11.

## See also

- [WAL.md](WAL.md): the implemented drop-new / drop-oldest overflow policy this spec
  extends, and why "spill then shed" collapses to "shed" on a single durable log.
- [METRICS.md](METRICS.md): the resilience-observability contract (#16) the new
  shed counters and gauges plug into, and the frozen-taxonomy rule they follow.
- [CONTRACTS.md](CONTRACTS.md): the frozen wire frame the `retry_after_ms` / `shed`
  fields extend (the `Err` frame and the `Ack`/nack `delay_ms`).
- [THREAT_MODEL.md](THREAT_MODEL.md): the DoS and resource-exhaustion threat rows
  (T7) these controls harden, and the implemented connection cap / credit / disk-cap
  bounds they compose with.
- [RISK_REGISTER.md](RISK_REGISTER.md): RR-01 (per-consumer occupancy) and RR-03
  (disk exhaustion), the implemented baseline this design builds on.
- [EDGE_TUNING.md](EDGE_TUNING.md): the edge hardware-to-knob mapping these new keys
  extend.
- `crates/ironbus-core/src/clock.rs`: the monotonic clock seam
  (`Clock::now_monotonic_nanos`) the sojourn measurement is built on.
