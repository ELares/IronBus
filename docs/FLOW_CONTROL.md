# Wire flow control: the FLOW credit body and the producer PFLOW direction

This document is the normative specification for IronBus wire-level flow control:
the consumer-direction credit the `Flow` frame carries, and the producer-direction
backpressure (PFLOW: a byte/second budget and a one-bit pause) that the same frame
type is designed to carry. It freezes the **carrier** (the exact `Flow` body layout
and its field semantics) and the **wire-visible state machine** (the credit
accounting, the zero-credit hold, the reconnect reset, the producer pause and
drop-and-report behavior). It does NOT redefine policy values: the drop disposition
is owned by the backpressure parent (#10, see [BACKPRESSURE.md](BACKPRESSURE.md)),
and the lease and ack timing that the credit composes with are owned by the
delivery model (#9, see the consumer state machine in
[diagrams/05-consumer-state-machine.pdf](diagrams/05-consumer-state-machine.pdf)).

This is the architecture deliverable for issue #72 (parent #11). It is a frozen-frame
extension: the consumer credit half is **implemented today** in its reduced form (a
bare four-byte credit), and the producer PFLOW half is **specified, not implemented**.
The sections below mark each part honestly.

> **Status: the consumer credit carrier exists today; the producer PFLOW
> direction and the structured body are specified, not implemented (#72-impl /
> #11).** IronBus **today** ships a `Flow` frame (tag 10) whose body is a single
> four-byte little-endian `u32` credit and nothing else: there is no direction
> flag, no byte budget, and no pause bit on the wire. The credit accounting, the
> zero-credit hold, and the reconnect reset described in
> [Part 1](#part-1-the-consumer-credit-direction-flow) are **real and cited to the
> source**. The structured body, the PFLOW producer direction, the byte budget,
> and the pause bit in [Part 2](#part-2-the-producer-direction-pflow) and
> [Part 3](#part-3-negotiation-and-compatibility-11) are a **design**: the frame
> body that carries them is empty of those fields in the binary, and the wiring is
> the implementation residual owned by #11 / #72-impl. This document specifies the
> architecture; it never claims a field exists when it does not.

---

## Contents

- [What exists today (the honest baseline)](#what-exists-today-the-honest-baseline)
- [Part 1: the consumer credit direction (FLOW)](#part-1-the-consumer-credit-direction-flow)
  - [The frozen FLOW body layout](#the-frozen-flow-body-layout)
  - [The encoding rule: fixed-width little-endian, the #11 canonical form](#the-encoding-rule-fixed-width-little-endian-the-11-canonical-form)
  - [Credit accounting: decrement on send, restore on ack](#credit-accounting-decrement-on-send-restore-on-ack)
  - [The zero-credit hold (deliver nothing, never drop)](#the-zero-credit-hold-deliver-nothing-never-drop)
  - [The reconnect credit-reset rule](#the-reconnect-credit-reset-rule)
- [Part 2: the producer direction (PFLOW)](#part-2-the-producer-direction-pflow)
  - [The PFLOW body fields](#the-pflow-body-fields)
  - [The byte/second budget and the one-bit pause](#the-bytesecond-budget-and-the-one-bit-pause)
  - [Fire-and-forget drop-and-report with a grace window](#fire-and-forget-drop-and-report-with-a-grace-window)
  - [What a producer sees when paused or over budget](#what-a-producer-sees-when-paused-or-over-budget)
  - [Tie to the BACKPRESSURE.md drop model](#tie-to-the-backpressuremd-drop-model)
- [Part 3: negotiation and compatibility (#11)](#part-3-negotiation-and-compatibility-11)
- [Failure considerations](#failure-considerations)
- [See also](#see-also)

---

## What exists today (the honest baseline)

Two flow-control facts are implemented and verified in the source.

- **The `Flow` frame (tag 10) carries a four-byte credit and nothing else.** The
  server decodes the body as `u32::from_le_bytes` and rejects any other length with
  `"flow credit must be a u32"`. There is no direction flag, no byte field, and no
  pause bit on the wire. Source: `crates/ironbus-server/src/session.rs`
  (`Session::handle_flow`), and the frozen tag is pinned by
  `type_tags_have_their_exact_frozen_wire_values` in
  `crates/ironbus-proto/src/frame.rs`. The frame is **client to server only**; the
  reply to a `Flow` is a stream of `Deliver` frames (tag 13) terminated by a
  `FlowEnd` (tag 16) whose body is the delivered count as a four-byte LE `u32`.
- **Per-connection consumer credit binds every fetch.** A connection holds at most
  `consumer_credit` un-acked messages (`DEFAULT_CONSUMER_CREDIT` = 64, NOT 65535)
  and at most `consumer_credit_bytes` un-acked payload bytes
  (`DEFAULT_CONSUMER_CREDIT_BYTES` = 8 MiB; `0` = unlimited), derived from the
  connection-scoped `leased` set. A `Flow` fetch delivers at most
  `min(requested_credit, message ceiling - already held, byte budget remaining,
  whatever the group makes available)`, with a hard floor of one message so a
  single over-budget message never wedges the consumer. Source:
  `crates/ironbus-server/src/engine.rs` (`DEFAULT_CONSUMER_CREDIT`,
  `DEFAULT_CONSUMER_CREDIT_BYTES`), `crates/ironbus-server/src/session.rs` (#65,
  #275). See [BACKPRESSURE.md](BACKPRESSURE.md), "What exists today," and
  [CONTRACTS.md](CONTRACTS.md), the `Flow` row.

The producer-direction PFLOW (a byte/second budget and a pause signal toward a
producer) is **absent on the wire today**. [CONTRACTS.md](CONTRACTS.md) records this
plainly: the draft `FLOW` carried `direction, credit-or-bytes_per_sec, pause`, but
the real `Flow` body is a single four-byte credit, and "the producer-flow (PFLOW) /
pause direction of `Flow` ... carry empty or reduced bodies today; ... producer flow
control [is] future work." This document is the design that future work freezes
against.

---

## Part 1: the consumer credit direction (FLOW)

The consumer credit direction is the **request-n** half of flow control: a consumer
tells the broker how many messages it is ready to receive, and the broker delivers
at most that many. This is the same model as MQTT 5 `Receive Maximum` and Reactive
Streams `request(n)`: the consumer, not the broker, sets the in-flight ceiling, so a
slow consumer can never be overrun.

### The frozen FLOW body layout

The `Flow` body is a structured record whose **leading field is byte-for-byte the
credit that ships today**, so the structured form is a pure forward-compatible
extension, not a reinterpretation. The frozen layout:

| field        | type    | width | semantics |
|--------------|---------|-------|-----------|
| `credits`    | u32 LE  | 4     | the requested in-flight grant: the number of additional messages the consumer is ready to receive on this fetch. This is the only field present today; the server reads exactly these four bytes (`u32::from_le_bytes`). |
| `dir_flags`  | u8      | 1     | direction and option bits (see below). **Absent today** (a four-byte body has no fifth byte); a reader that sees only four bytes treats `dir_flags` as `0` (the consumer-credit direction, no options). |
| `byte_credits` | u32 LE | 4    | OPTIONAL: a per-fetch byte grant, mirroring `consumer_credit_bytes`. **Absent today.** Present only when `dir_flags` bit 1 (`HAS_BYTE_CREDITS`) is set. `0` means "no byte grant on this fetch" (the standing per-connection byte budget still binds). |
| `misc`       | u8      | 1     | OPTIONAL reserved option byte for future per-fetch flags. **Absent today.** Present only when `dir_flags` bit 2 (`HAS_MISC`) is set. All bits reserved, MUST be sent `0` and ignored on read until a bit is defined. |

The `dir_flags` byte, when present:

| bit | name | meaning |
|-----|------|---------|
| 0 | `DIR_PRODUCER` | `0` = consumer-credit direction (this Part); `1` = producer direction (PFLOW, [Part 2](#part-2-the-producer-direction-pflow)). On a consumer-credit `Flow`, this bit is `0`. |
| 1 | `HAS_BYTE_CREDITS` | `1` if a `byte_credits` u32 follows. |
| 2 | `HAS_MISC` | `1` if a `misc` byte follows. |
| 3-7 | reserved | MUST be sent `0`; a reader MUST ignore them (forward-compatible: an unknown option bit set by a newer peer does not fail the frame). |

The fields are length-discriminated by `dir_flags`, not by a trailing-bytes scan, so
the body is self-describing: a four-byte body is `credits` alone (the form on the
wire today), a five-byte body is `credits` + `dir_flags`, and the optional tail is
present exactly when its flag bit says so. A body shorter than four bytes is
malformed and rejected exactly as today (`"flow credit must be a u32"`).

This layout realizes the shape issue #72 calls for, `[u8 dir_flags][varint
credits][varint bytes?][u8 misc]`, reordered and re-typed to IronBus's actual frozen
wire conventions: `credits` leads (so the existing four-byte body is the prefix of
the extended body, making the extension additive rather than a reinterpretation),
and every integer is a **fixed-width little-endian** field, not a LEB128 varint, per
the next section.

### The encoding rule: fixed-width little-endian, the #11 canonical form

IronBus's frozen wire format uses **no variable-length integers anywhere**. Every
multi-byte field is a fixed-width little-endian `u8`, `u16`, `u32`, or `u64`.
[CONTRACTS.md](CONTRACTS.md), "Conventions," states it directly: "There are no
variable-length integers (varints) anywhere in the shipped format ... (The draft
posited LEB128 varints on the wire; the implementation does not use them.)" The ADR
index records the same decision for the envelope (`docs/adr/INDEX.md`: "no varints
anywhere").

Issue #72's prose names the credit and byte fields as `varint`, inherited from the
original #137 draft's `FlowFrame` (`credit` and `bytes_per_sec` as LEB128 varints,
visible in `diagrams/08-contract-models-er.dot`). That draft was **superseded** by
the shipped fixed-width format. To stay consistent with #11 as it actually froze,
this spec adopts the **fixed-width little-endian** encoding as the canonical form:

- `credits` and `byte_credits` are each a fixed four-byte LE `u32`. They are NOT
  LEB128.
- The canonical-form rule that #11 enforces for variable fields elsewhere (a length
  is the minimal fixed-width type that holds it, no redundant encoding, no
  alternate spelling of the same value) is satisfied trivially here because a
  fixed-width LE integer has exactly one encoding: there is no non-canonical
  redundant form to reject, which is precisely why IronBus chose fixed-width over
  LEB128 (a varint has multiple non-minimal encodings of the same value, a
  canonical-form footgun the fixed-width format does not have).
- A reader MUST reject a body that is not one of the valid lengths
  (`4`, `5`, `5 + 4` with `HAS_BYTE_CREDITS`, `5 + 1` with `HAS_MISC`,
  `5 + 4 + 1` with both), and trailing bytes beyond the fields the flags select are
  rejected, matching the strict "trailing bytes are rejected" rule the `Ack` body
  already follows in [CONTRACTS.md](CONTRACTS.md).

If a future protocol revision genuinely needs a varint here, that is a #11 decision
recorded in [COMPATIBILITY.md](COMPATIBILITY.md) and the version registry
([compat/versions.md](compat/versions.md)), not a property this spec assumes. As
frozen, the FLOW body is fixed-width LE.

### Credit accounting: decrement on send, restore on ack

The credit is an **in-flight grant**, decremented per delivered message and restored
per ack. The accounting is exactly the implemented per-connection model
(`crates/ironbus-server/src/session.rs`), stated here as the normative rule:

- **The ceiling is per connection, and NEGOTIATED (#292).** Each connection has a
  standing message ceiling `consumer_credit` (default 64) and a byte budget
  `consumer_credit_bytes` (default 8 MiB; `0` = unlimited). The effective ceiling for a
  connection is the NEGOTIATED value `min(client request, server cap)`: the client MAY
  request a credit in its `Connect` body, the server clamps it to its cap (or substitutes
  its default when the client requests nothing), and advertises the negotiated value in
  `Info` (see [Part 3](#part-3-negotiation-and-compatibility-11) and
  [CONTRACTS.md](CONTRACTS.md) `ConnectBody`/`InfoBody`). The negotiated value is fixed at
  `Connect` time (read LOCALLY off the engine handle, no actor round-trip, so the handshake
  cannot head-of-line-block behind a stalled produce), and an old client that sends an empty
  `Connect` simply gets the server default. The connection's `leased` set IS the in-flight
  accounting: its size is the messages in flight, and the sum of its entries' payload bytes is
  the bytes in flight.
- **Decrement on send.** Each `Deliver` the broker streams for a `Flow` inserts the
  message into `leased`, occupying one message slot and its payload bytes. The
  remaining message credit at any instant is `ceiling - leased.len()`; the remaining
  byte budget is `consumer_credit_bytes - in_flight_bytes` (when the budget is set).
  A single `Flow` fetch delivers at most
  `min(requested_credits, ceiling - already_held, byte_budget_remaining, what the
  group makes available)`, with a **hard floor of one message** so a single
  over-budget message never wedges the consumer.
- **Restore on ack.** An `Ack` (commit), a successful `Nack`/`Term`, the per-batch
  prune of committed offsets, and the expiry-and-redelivery accounting each remove
  the offset from `leased`, restoring BOTH the message slot and the message's bytes
  to the connection's available credit. A `Nack` that requeues frees the slot for a
  later redelivery; the redelivered copy is recounted against whichever connection
  next claims it (#65 redelivery accounting, `Session::release_stale_leases`).
- **The grant is additive, not a level.** A `Flow` requests `credits` MORE messages;
  it does not set the absolute in-flight level. The effective batch is bounded by
  the remaining credit, so a consumer that requests more than it can hold simply
  gets `remaining`, never more than the ceiling. This matches Reactive Streams
  `request(n)` (cumulative demand), bounded by the per-connection ceiling so demand
  can never exceed the safe in-flight window.

The byte budget composes with the message count by `min`: the effective per-`Flow`
credit is `min(message credits remaining, byte credits remaining)`, floored at one
message, so whichever runs out first binds and a fleet of tiny messages cannot
overrun the byte budget while a few large messages cannot overrun the message count.

### The zero-credit hold (deliver nothing, never drop)

When a connection's remaining credit is zero (it holds `ceiling` un-acked messages,
or its byte budget is exhausted), a `Flow` fetch **delivers nothing and drops
nothing**. The leased messages stay leased; the unfetched messages stay in the
durable log, available, and are delivered on the next `Flow` or after an `Ack`
restores a slot. Concretely:

- At zero remaining message credit the delivery loop body never runs, so a saturated
  consumer gets an **empty batch** (a `FlowEnd` with count `0`) even when messages
  are available. The broker **holds**; it never drops leased or available traffic to
  make a zero-credit consumer "keep up."
- This is the structural-backpressure tenet: an overwhelmed consumer slows delivery
  to itself, and the durable log absorbs the backlog under its own retention and
  overflow rules ([WAL.md](WAL.md)), not by discarding a consumer's messages. Drop,
  when it happens, is a durable-log overflow decision (drop-new / drop-oldest, #10,
  #13), never a consequence of a held credit window.
- The hold is **per connection**: because the credit and the `leased` set are
  per-connection, one stuck consumer pins only its own slots and never reduces a
  peer's available deliveries (per-consumer isolation, #65). A lease timeout (#9)
  ensures one stuck consumer's leases eventually expire and redeliver, so a single
  wedged consumer cannot block the shared log forever.

### The reconnect credit-reset rule

Credit is **per connection and never carried across connections.** On a new
connection the credit is re-advertised from scratch:

- A fresh connection starts with an **empty `leased` set** and therefore the **full
  ceiling** available. The server fixes that connection's NEGOTIATED `consumer_credit` /
  `consumer_credit_bytes` (#292: `min(client request, server cap)`, or the server default
  when the client requests nothing) at its `Connect` and caches them for that connection
  only; a re-`Connect` re-negotiates idempotently. The negotiation is per connection, so the
  re-advertise-from-scratch rule holds: a new connection's credit is its own negotiated value,
  never inherited.
- The broker **never** carries a previous connection's in-flight count, its `leased`
  set, or any "outstanding credit" into the new connection. The new connection's
  flow control is computed entirely from its own (initially empty) `leased` set.
- The messages the old connection had leased but not acked are governed by the lease
  timeout (#9): they expire and become available for redelivery to whichever
  connection next fetches the group, counted against THAT connection's credit. The
  reconnecting consumer simply issues a fresh `Flow` and refills its window from
  zero in-flight.

This is the explicit mitigation for the dominant failure mode #72 names (credit
desync after reconnect, a silent delivery stall): because credit is always
re-advertised per connect and never inherited, there is no stale outstanding count
that could leave the new connection believing it has zero credit when it has full
credit, or vice versa. The in-flight-versus-granted gauge (#16, see
[METRICS.md](METRICS.md)) makes any residual desync observable rather than silent.

---

## Part 2: the producer direction (PFLOW)

> **Specified, not implemented.** Nothing in this Part exists on the wire today. The
> `Flow` body carries no `dir_flags`, no byte budget, and no pause bit; the producer
> path has no flow-control frame at all. This is the design the #11 / #72-impl wiring
> freezes against.

The producer direction (PFLOW) is the **slow-the-source** half of flow control: the
server signals a producer to slow or stop its fire-and-forget publishes when the
broker is under pressure (disk-spill or memory pressure per #10). It is the same
`Flow` frame type with `dir_flags` bit 0 (`DIR_PRODUCER`) set, sent **server to
client** (the opposite direction from the consumer credit `Flow`). It is, by design,
a hint a well-behaved producer honors, backed by a fire-and-forget drop the broker
enforces unilaterally, so an ill-behaved producer cannot evade it.

### The PFLOW body fields

A PFLOW `Flow` (server to client, `dir_flags` bit 0 set) carries:

| field        | type    | width | semantics |
|--------------|---------|-------|-----------|
| `credits`    | u32 LE  | 4     | reserved on a PFLOW frame; sent `0` and ignored (the producer direction is governed by the byte budget and pause, not a message count). It occupies the leading slot so the body's fixed prefix is identical to a consumer `Flow`. |
| `dir_flags`  | u8      | 1     | `DIR_PRODUCER` (bit 0) set. `HAS_BYTE_CREDITS` (bit 1) set when a byte budget follows; `HAS_MISC` (bit 2) set when the pause byte follows. |
| `byte_credits` | u32 LE | 4    | the byte/SECOND budget: the producer's fire-and-forget publish rate ceiling in bytes per second. `0xFFFFFFFF` (the sentinel) = **unlimited** (the default; no producer throttle). Any other value is the per-second byte budget the producer SHOULD not exceed. Present when `HAS_BYTE_CREDITS` is set. |
| `misc`       | u8      | 1     | the producer option byte. Bit 0 = `PAUSE` (the one-bit pause signal): `1` = pause fire-and-forget publishing now, `0` = resume. Bits 1-7 reserved, sent `0`, ignored on read. Present when `HAS_MISC` is set. |

This reuses the consumer-credit body's frozen field positions exactly: `credits`
leads, `dir_flags` discriminates, `byte_credits` is the per-second budget (reusing
the same slot the consumer direction uses for a per-fetch byte grant), and `misc`
carries the pause bit. The shape is the issue's `[u8 dir_flags][varint
credits][varint bytes?][u8 misc]` realized in fixed-width LE with the leading-credit
ordering of Part 1.

### The byte/second budget and the one-bit pause

- **The byte/second budget** is a rate ceiling on the producer's fire-and-forget
  (un-acked, QoS-0-equivalent) publishes. Default **unlimited** (`byte_credits =
  0xFFFFFFFF`, or simply no PFLOW frame ever sent). The broker asserts a finite
  budget only under pressure, lowering the producer's offered rate toward what the
  durable log and memory can absorb. The budget is advisory toward a well-behaved
  producer and enforced by the fire-and-forget token bucket on the broker side (next
  section), so the budget binds whether or not the producer honors the hint.
- **The one-bit pause** (`misc` bit 0, `PAUSE`) is the hard stop: `PAUSE = 1` tells
  the producer to stop fire-and-forget publishing entirely, `PAUSE = 0` resumes.
  Pause is **clear by default** and asserted by the broker only under disk-spill or
  memory pressure (#10). It is a single bit because the producer's only two
  meaningful states are "send within budget" and "stop"; the budget handles the
  gradation between them.
- **Both are per connection and re-advertised per connect.** Exactly like consumer
  credit, a producer's PFLOW state is connection-scoped: a fresh connection starts
  with the default (unlimited budget, pause clear) and the broker re-asserts any
  throttle on the new connection from scratch. No PFLOW state carries across a
  reconnect.

### Fire-and-forget drop-and-report with a grace window

The enforcement that makes PFLOW honest (a producer cannot evade it by ignoring the
hint) is the **fire-and-forget token bucket** already specified in
[BACKPRESSURE.md](BACKPRESSURE.md), "The fire-and-forget token bucket." This document
does NOT redefine it; it ties the PFLOW wire signal to it:

- Fire-and-forget publishes are governed by a separate per-connection token bucket
  (default 5000 msg/s, 5 MiB/s, 100 ms refill, per BACKPRESSURE.md), distinct from
  the durable-path consumer credit. A fire-and-forget message consumes one message
  token and `payload_size` byte tokens.
- **Drop-and-report, never block.** When the bucket is empty (or PFLOW pause is
  asserted past the grace window below), an over-budget fire-and-forget publish is
  **dropped**, with a reported-loss counter increment
  (`ironbus_fire_and_forget_shed_total`, BACKPRESSURE.md / [METRICS.md](METRICS.md)),
  per the #16 contract that no shed is ever silent. The broker **never blocks its
  accept loop** to apply producer backpressure: an overload resolves to
  drop-and-report, which is the structural-backpressure tenet (a stuck producer path
  must never wedge the broker's read loop).
- **The grace window.** A producer that has just been told to pause needs a moment to
  observe and obey the signal (the pause `Flow` is in flight, and the producer may
  have publishes already queued). PFLOW therefore allows a **grace window** after a
  pause or budget reduction is asserted, during which fire-and-forget publishes that
  exceed the new limit are still accepted (subject to the token bucket) rather than
  immediately dropped, giving a well-behaved producer time to back off. A producer
  that **ignores pause beyond the grace window** has its over-limit fire-and-forget
  publishes dropped-and-reported. The grace window is a #14 tunable; its default is
  fixed when the control is implemented (a small multiple of the token bucket's
  100 ms refill granularity is the natural scale).
- **Leased (acked) publishes are exempt from producer drop.** PFLOW and the
  fire-and-forget bucket govern only the un-acked fire-and-forget tier. A producer
  that waits for a `PubAck` is flow-controlled by the normal durable path (the
  produce either commits and is acked, or is rejected at the durable-log byte cap
  with `StorageError::AtCapacity` -> the `"at capacity"` `Err`, drop-new / drop-oldest
  per #10). The token bucket "has no authority to evict, reorder, or starve messages
  on the credited path" (BACKPRESSURE.md): capping the uncontrolled tier never costs
  the controlled tier.

### What a producer sees when paused or over budget

- **Paused (PFLOW `PAUSE = 1`):** a well-behaved producer stops fire-and-forget
  publishing until it receives a PFLOW `Flow` with `PAUSE = 0`. If it keeps
  publishing past the grace window, its fire-and-forget publishes are dropped (no
  `PubAck` was ever expected, so the drop is silent to the producer except via the
  reported-loss counter and, where the tier gets a response, the `shed` hint below).
- **Over the byte/second budget:** fire-and-forget publishes above the rate are
  shed by the token bucket. The producer's accept loop is never blocked; it simply
  loses the over-rate messages, counted by `ironbus_fire_and_forget_shed_total`.
- **Acked publishes are unaffected** by pause or budget: they flow on the credited
  path. The only backpressure an acked producer sees is the durable-log overflow
  (`"at capacity"`), which is the #10 disk-full policy, not PFLOW.
- **The structured `shed` / `retry_after_ms` hint** (BACKPRESSURE.md, "The
  `retry_after_ms` and `shed` wire signal") is the machine-actionable companion: when
  a tier that gets a response is shed, the broker can set `shed = true` (and a
  `retry_after_ms`, with `0xFFFFFFFF` meaning do-not-retry) so the producer
  distinguishes "shed under load, back off" from "my request was malformed." That
  signal is itself a #11 wire extension (specified, not implemented), tracked in
  BACKPRESSURE.md; PFLOW and it are complementary backpressure carriers.

### Tie to the BACKPRESSURE.md drop model

PFLOW does not introduce a new drop policy. Every drop it causes is one of the two
existing dispositions, so this spec **cannot contradict** the backpressure model:

- A **fire-and-forget shed** (the bucket empty, or pause ignored past the grace
  window) routes through the topic's configured overflow disposition, the same
  drop-new / drop-oldest `disk_full_policy` decision the durable byte cap uses
  (BACKPRESSURE.md, "A shed under CoDel routes a record into the topic's configured
  overflow disposition"). Drop-new sheds the new publish; drop-oldest is a durable-log
  decision and does not apply to an un-admitted fire-and-forget message (there is no
  durable entry to evict yet), so a fire-and-forget over-budget shed is a drop-new of
  the new message, counted, never silent.
- PFLOW's pause is asserted "only under disk-spill or memory pressure per #10," the
  same trigger that arms the durable overflow and the CoDel control. PFLOW is the
  **producer-facing signal** of that pressure; CoDel (sojourn shedding) and the
  depth-and-byte backstop are the **broker-internal** controls that bound latency and
  memory. They compose: PFLOW slows the source, CoDel sheds standing-latency
  records, and the backstop bounds memory under a fully stalled drain. None of the
  three overrides the durable-log drop policy; they all funnel into it.

---

## Part 3: negotiation and compatibility (#11)

This is a **frozen-frame extension** tied to #11. The architecture (the body layout,
the field semantics, the state machine) is frozen by this document; the **wiring**
(emitting and parsing the extended body, asserting PFLOW from the broker, the
producer-side honor logic, and the #14 keys) is the **implementation residual owned
by #11 / #72-impl**. The frame body is empty of these fields today, and this document
does not claim otherwise.

The extension is forward-compatible by construction, so it lands without breaking an
old reader:

- **The leading field is unchanged.** The structured FLOW body's first four bytes are
  the `credits` `u32` that ships today. An old server that reads only four bytes gets
  exactly today's behavior (a consumer-credit fetch); a new server that reads more
  bytes interprets the structured form. The four-byte body is a strict prefix of the
  extended body, so the extension is additive, never a reinterpretation of existing
  bytes.
- **Unknown bits and optional fields are tolerated.** Reserved `dir_flags` and `misc`
  bits MUST be sent `0` and ignored on read, the same forward-compatible discipline
  `RecordFlags` already uses (unknown flag bits are preserved on read, see
  [CONTRACTS.md](CONTRACTS.md) / [COMPATIBILITY.md](COMPATIBILITY.md)). A newer peer
  that sets an option bit an older peer does not understand does not break the older
  peer's framing.
- **The frame tags are already frozen.** `Flow` (10) and `FlowEnd` (16) are real
  frozen wire bytes, pinned by `type_tags_have_their_exact_frozen_wire_values` in
  `crates/ironbus-proto/src/frame.rs`. PFLOW reuses the `Flow` tag with the direction
  bit; it does NOT add a new frame type, so the frozen tag set is unchanged.
- **Capability negotiation is the #11 handshake residual; per-consumer CREDIT
  negotiation already rides the handshake (#292).** Whether a connection supports the
  structured FLOW body and PFLOW is, in the fully-wired design, advertised in the
  `Connect` / `Info` handshake. Those bodies are **no longer empty**: since #292 they
  carry the per-consumer credit negotiation in a versioned, length-prefixed,
  forward-compatible body (`ConnectBody`/`InfoBody`, see [CONTRACTS.md](CONTRACTS.md)),
  so the effective `consumer_credit` / `consumer_credit_bytes` is negotiated
  `min(client request, server cap)` rather than only a server default. The structured-FLOW
  capability bit and the `min(client, server)` WIRE-VERSION negotiation are still the #11
  handshake residual the version registry tracks
  ([compat/versions.md](compat/versions.md)), now as FUTURE fields appended to the #292
  handshake body (which tolerates unknown trailing bytes) rather than to an empty one. Until
  that lands, a server emits the bare four-byte FLOW body and never asserts PFLOW, which is
  exactly the behavior in the binary today.

In short: the **carrier and the state machine are frozen here** (the #72 architecture
deliverable); the **bytes on the wire and the broker/producer logic are the #11 /
#72-impl implementation residual**.

---

## Failure considerations

- **Credit desync after reconnect (the dominant failure).** A consumer that
  reconnects could stall silently if the broker carried a stale outstanding-credit
  count into the new connection. The reconnect reset rule
  ([Part 1](#the-reconnect-credit-reset-rule)) forecloses it: credit is always
  re-advertised per connect and never inherited, the new connection's window is
  computed from its own empty `leased` set, and the lease timeout (#9) redelivers the
  old connection's un-acked messages. The in-flight-versus-granted gauge (#16) makes
  any residual desync observable.
- **A producer ignoring pause must never block the broker.** PFLOW resolves a
  producer overload to drop-and-report on the fire-and-forget tier
  ([Part 2](#fire-and-forget-drop-and-report-with-a-grace-window)), never a blocked
  accept loop, so a misbehaving producer degrades only its own fire-and-forget
  traffic and cannot wedge the broker or starve the credited path.
- **One stuck consumer must not block the shared log.** Per-connection credit
  isolation (#65) plus the lease timeout (#9) ensure a wedged consumer pins only its
  own slots and its leases eventually expire and redeliver, so the shared durable log
  keeps draining to its peers.
- **The grace window must not become a bypass.** The grace window
  ([Part 2](#fire-and-forget-drop-and-report-with-a-grace-window)) is bounded and
  small (a multiple of the 100 ms token-bucket refill); it gives a well-behaved
  producer time to obey a pause, but the token bucket still binds during it, so the
  window can tolerate a brief burst without becoming an unbounded escape from the
  rate ceiling.

---

## See also

- [BACKPRESSURE.md](BACKPRESSURE.md): the overload-control parent (#10). The
  fire-and-forget token bucket PFLOW enforces against, the CoDel sojourn control and
  depth-and-byte backstop PFLOW composes with, the drop-new / drop-oldest disposition
  every PFLOW shed funnels into, and the `retry_after_ms` / `shed` companion wire
  signal.
- [CONTRACTS.md](CONTRACTS.md): the frozen wire frame surface (the `Flow` tag-10 row
  and its four-byte credit body, the `FlowEnd` tag-16 row, the no-varints fixed-width
  convention, and the "producer flow control is future work" note this document
  designs).
- [COMPATIBILITY.md](COMPATIBILITY.md) and [compat/versions.md](compat/versions.md):
  the forward-compatibility rules (frozen tags, unknown-bit preservation) and the
  `min(client, server)` wire-version negotiation whose handshake wiring is the shared
  #11 residual.
- [METRICS.md](METRICS.md): the resilience-observability contract (#16) the
  fire-and-forget shed counter and the in-flight-versus-granted gauge plug into.
- [WAL.md](WAL.md): the durable-log overflow policy (drop-new / drop-oldest) that a
  held zero-credit window backs onto and that every PFLOW shed funnels into.
- `crates/ironbus-server/src/session.rs`: `Session::handle_flow` (the implemented
  consumer-credit accounting), the per-connection `leased` set, and
  `release_stale_leases` (#65 redelivery accounting).
- `crates/ironbus-server/src/engine.rs`: `DEFAULT_CONSUMER_CREDIT` (64) and
  `DEFAULT_CONSUMER_CREDIT_BYTES` (8 MiB), the standing per-connection ceilings.
- `crates/ironbus-proto/src/frame.rs`: the frozen `FrameType` tags
  (`Flow` = 10, `FlowEnd` = 16) and the `type_tags_have_their_exact_frozen_wire_values`
  test that pins them.
