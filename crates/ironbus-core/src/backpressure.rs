// SPDX-License-Identifier: MIT OR Apache-2.0
//! Pure, IO-free backpressure controls (#68, #69, #10): the CoDel time-in-queue shedding
//! controller, the egress AIMD concurrency limiter, the fire-and-forget token bucket, and the
//! per-client retry budget.
//!
//! This module owns only the math and the state machines that `docs/BACKPRESSURE.md` specifies;
//! it performs no IO, spawns no thread, and reads no clock. Every method that is time-based takes
//! the current MONOTONIC time in nanoseconds as a parameter, which the server reads from the
//! [`Clock`](crate::clock::Clock) seam (`now_monotonic_nanos`) and threads in. That keeps the
//! controllers deterministic under the simulation and unit-testable against a `ManualClock`-derived
//! nanosecond stream, never the wall clock.
//!
//! The four controllers compose into the broker's overload defense:
//!
//! - [`Codel`] sheds a NEW produce when the queue's standing sojourn (the time the head record has
//!   actually waited) stays above the TARGET for a full INTERVAL (RFC 8289). It is the load-based
//!   (latency) complement to the byte-cap shed: it bounds tail latency while the queue drains.
//! - [`AimdLimiter`] adapts a downstream-egress concurrency limit up additively after a clean
//!   window and down multiplicatively on a failure, modeled on TCP congestion control, bounded to a
//!   configured `[min, max]`.
//! - [`TokenBucket`] caps the fire-and-forget (un-credited) admission rate so the uncontrolled tier
//!   cannot bypass the credit brake.
//! - [`RetryBudget`] bounds the redelivery/retry work to a fraction of a client's request rate (the
//!   Google SRE accept-based adaptive throttle), so a storm of nacks cannot starve forward progress.
//!
//! None of these EVER drops an already-accepted record: a shed rejects NEW work only. The
//! durability and ack path is untouched (I2 holds); see `docs/BACKPRESSURE.md`, "No data loss".

/// The default CoDel TARGET sojourn in milliseconds (RFC 8289 recommended): the acceptable standing
/// queue delay. Shedding begins only when the standing sojourn stays above this. `0` DISABLES CoDel.
pub const DEFAULT_CODEL_TARGET_MS: u64 = 5;

/// The default CoDel INTERVAL in milliseconds (RFC 8289 recommended): the window the minimum sojourn
/// must stay above TARGET before shedding, and the base drop spacing.
pub const DEFAULT_CODEL_INTERVAL_MS: u64 = 100;

/// The lower clamp on the CoDel TARGET (1 ms): below this the control would shed on scheduling
/// jitter alone.
pub const CODEL_TARGET_MIN_MS: u64 = 1;
/// The upper clamp on the CoDel TARGET (1 s): above this it would never protect tail latency.
pub const CODEL_TARGET_MAX_MS: u64 = 1_000;
/// The lower clamp on the CoDel INTERVAL (20 ms): below this the window is shorter than realistic
/// bursts (false shedding).
pub const CODEL_INTERVAL_MIN_MS: u64 = 20;
/// The upper clamp on the CoDel INTERVAL (10 s): above this the control reacts too slowly to bound a
/// growing backlog.
pub const CODEL_INTERVAL_MAX_MS: u64 = 10_000;

/// Nanoseconds per millisecond, for the millisecond-config to nanosecond-clock conversions.
const NANOS_PER_MS: u64 = 1_000_000;

/// Clamps a CoDel TARGET (milliseconds) into `[CODEL_TARGET_MIN_MS, CODEL_TARGET_MAX_MS]`. A `0`
/// (the "disabled" sentinel) is returned unchanged so the caller can treat it as "off"; any other
/// out-of-range value is clamped to the nearest bound, never rejected (the "cannot refuse to start
/// over a CoDel value" criterion of #14).
#[must_use]
pub fn clamp_codel_target_ms(target_ms: u64) -> u64 {
    if target_ms == 0 {
        return 0;
    }
    target_ms.clamp(CODEL_TARGET_MIN_MS, CODEL_TARGET_MAX_MS)
}

/// Clamps a CoDel INTERVAL (milliseconds) into `[CODEL_INTERVAL_MIN_MS, CODEL_INTERVAL_MAX_MS]`. A
/// `0` is returned unchanged (CoDel disabled overall); any other value is clamped to the nearest
/// bound, never rejected.
#[must_use]
pub fn clamp_codel_interval_ms(interval_ms: u64) -> u64 {
    if interval_ms == 0 {
        return 0;
    }
    interval_ms.clamp(CODEL_INTERVAL_MIN_MS, CODEL_INTERVAL_MAX_MS)
}

/// The integer square root of `n` (floor), by Newton's method. Used for the RFC 8289
/// `INTERVAL / sqrt(count)` drop spacing without pulling in floating point (which `ironbus-core`
/// keeps off the hot path and out of the deterministic sim). Returns `0` for `0`.
#[must_use]
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    // Newton's method converges from above; seed with a power-of-two upper bound on the root so the
    // iteration is monotone-decreasing and terminates. `n.ilog2()` is defined for n >= 1.
    let mut x = 1u64 << (n.ilog2() / 2 + 1);
    loop {
        // `x` is always >= 1 here, so the division never divides by zero.
        let next = (x + n / x) / 2;
        if next >= x {
            return x;
        }
        x = next;
    }
}

/// The CoDel (Controlled Delay, RFC 8289) time-in-queue shedding controller for one queue (#68).
///
/// CoDel sheds by how long the head record has actually waited (its SOJOURN), not by queue depth,
/// so a single TARGET is correct across drain rates with no per-device tuning. The controller is
/// pure: the caller measures sojourn from the monotonic clock seam (`dequeue - enqueue`, clamped
/// `>= 0`) and feeds it to [`Codel::sojourn`] at dequeue; [`Codel::sojourn`] returns whether THIS
/// record should be shed under the control law. A sojourn `<= TARGET` (or an empty queue, signaled
/// by [`Codel::on_empty`]) takes the queue out of the dropping state.
///
/// Disabled when `target_nanos == 0` or `interval_nanos == 0`: [`Codel::sojourn`] then never sheds
/// and the controller is a no-op, so a broker that leaves CoDel off behaves exactly as before.
#[derive(Clone, Copy, Debug)]
pub struct Codel {
    /// The TARGET sojourn in nanoseconds (the clamped config converted at construction). `0`
    /// disables the controller.
    target_nanos: u64,
    /// The INTERVAL in nanoseconds (the clamped config). `0` disables the controller.
    interval_nanos: u64,
    /// The monotonic instant (nanos) at which the current above-TARGET window will have lasted a
    /// full INTERVAL, so the controller may enter the dropping state. `None` while the standing
    /// sojourn is at or below TARGET (the window is not open).
    first_above_time: Option<u64>,
    /// Whether the controller is currently in the dropping (shedding) state.
    dropping: bool,
    /// The monotonic instant (nanos) at which the NEXT drop is scheduled while dropping. The
    /// `INTERVAL / sqrt(count)` control law sets it forward after each drop.
    drop_next: u64,
    /// The number of drops in the current dropping episode, the `count` of the control law. It
    /// decays (rather than resetting to zero) when a new episode starts soon after the last, so the
    /// next episode does not start over-aggressive (RFC 8289).
    count: u64,
    /// The `count` value at the end of the last dropping episode, used to seed a quickly-following
    /// new episode (the RFC 8289 `lastcount`).
    last_count: u64,
    /// The most recent monotonic instant (nanos) the controller observed any activity at (a sojourn
    /// sample or an emptiness signal), for the suspend-gap reset. `None` until the first activity.
    last_activity: Option<u64>,
    /// The number of suspend-gap interval resets the controller has performed (a sleeping device
    /// that did not misfire). Surfaced as a metric.
    interval_resets: u64,
    /// The most recent sojourn the controller acted on, in nanoseconds (the minimum-sojourn estimate
    /// the control law is acting on), for the observability gauge.
    last_sojourn_nanos: u64,
}

impl Codel {
    /// Builds a CoDel controller from a TARGET and INTERVAL in MILLISECONDS. The values are clamped
    /// (`target` to `[1 ms, 1 s]`, `interval` to `[20 ms, 10 s]`) and a `0` for EITHER disables the
    /// controller entirely (it never sheds), so a broker that does not configure CoDel keeps its
    /// historical behavior. The values are converted to nanoseconds to match the monotonic clock
    /// seam.
    #[must_use]
    pub fn from_millis(target_ms: u64, interval_ms: u64) -> Codel {
        let target_ms = clamp_codel_target_ms(target_ms);
        let interval_ms = clamp_codel_interval_ms(interval_ms);
        Codel {
            target_nanos: target_ms.saturating_mul(NANOS_PER_MS),
            interval_nanos: interval_ms.saturating_mul(NANOS_PER_MS),
            first_above_time: None,
            dropping: false,
            drop_next: 0,
            count: 0,
            last_count: 0,
            last_activity: None,
            interval_resets: 0,
            last_sojourn_nanos: 0,
        }
    }

    /// Whether the controller is enabled (a non-zero TARGET and INTERVAL). A disabled controller
    /// never sheds.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.target_nanos != 0 && self.interval_nanos != 0
    }

    /// The effective (clamped) TARGET in milliseconds, for the materialized-config log and the
    /// observability surface. `0` when disabled.
    #[must_use]
    pub fn target_ms(&self) -> u64 {
        self.target_nanos / NANOS_PER_MS
    }

    /// The effective (clamped) INTERVAL in milliseconds. `0` when disabled.
    #[must_use]
    pub fn interval_ms(&self) -> u64 {
        self.interval_nanos / NANOS_PER_MS
    }

    /// The current minimum-sojourn estimate the control law is acting on, in MILLISECONDS, for the
    /// `ironbus_codel_sojourn_estimate_ms` gauge.
    #[must_use]
    pub fn sojourn_estimate_ms(&self) -> u64 {
        self.last_sojourn_nanos / NANOS_PER_MS
    }

    /// The number of suspend-gap interval resets so far (a sleeping device that resumed without
    /// misfiring), for the `ironbus_codel_interval_resets_total` counter.
    #[must_use]
    pub fn interval_resets(&self) -> u64 {
        self.interval_resets
    }

    /// The suspend-gap threshold: a multiple of INTERVAL beyond which a jump in the monotonic clock
    /// with no intervening activity is treated as a suspend/resume gap (not real contention), so the
    /// window is reset and the across-gap sojourns are discarded. RFC 8289 has no suspend notion;
    /// this is the IronBus edge-device addition (the doc's "a small multiple of INTERVAL, e.g.
    /// several seconds"). Saturating, so a huge INTERVAL cannot overflow.
    fn suspend_gap_nanos(&self) -> u64 {
        // 16x INTERVAL: with the default 100 ms INTERVAL that is 1.6 s, comfortably above a real
        // burst yet well inside a deep-sleep gap.
        self.interval_nanos.saturating_mul(16)
    }

    /// Detects and applies a suspend-gap reset. If the monotonic clock advanced past the suspend-gap
    /// threshold since the last observed activity, the dropping state, the above-TARGET window, and
    /// `count` are cleared (the across-gap sojourns are not real contention, only sleep), the reset
    /// counter is bumped, and the function returns `true`. Always records `now` as the latest
    /// activity. Called at the start of every control evaluation.
    fn maybe_reset_for_suspend(&mut self, now_nanos: u64) -> bool {
        let reset = match self.last_activity {
            Some(prev) if now_nanos.saturating_sub(prev) > self.suspend_gap_nanos() => {
                self.first_above_time = None;
                self.dropping = false;
                self.count = 0;
                self.last_count = 0;
                self.interval_resets = self.interval_resets.saturating_add(1);
                true
            }
            _ => false,
        };
        self.last_activity = Some(now_nanos);
        reset
    }

    /// Signals that the queue drained to empty at `now_nanos`. An empty queue has no standing delay,
    /// so the above-TARGET window is closed and the dropping state is left. Also records activity for
    /// the suspend-gap detector, so a queue that empties and then sleeps does not misfire on resume.
    pub fn on_empty(&mut self, now_nanos: u64) {
        self.maybe_reset_for_suspend(now_nanos);
        self.first_above_time = None;
        if self.dropping {
            self.dropping = false;
        }
        self.last_sojourn_nanos = 0;
    }

    /// Feeds one dequeue SOJOURN (nanoseconds, already clamped `>= 0` by the caller) measured at
    /// `now_nanos` (the monotonic dequeue instant) and returns `true` if THIS record should be shed
    /// under the CoDel control law.
    ///
    /// The control law (RFC 8289):
    /// 1. A sojourn at or below TARGET (or a disabled controller) closes the above-TARGET window and
    ///    leaves the dropping state: no shed.
    /// 2. A sojourn above TARGET opens the window; once it has stayed above TARGET for a full
    ///    INTERVAL the controller enters the dropping state.
    /// 3. While dropping, a shed fires when `now >= drop_next`; the next drop is scheduled at
    ///    `INTERVAL / sqrt(count)` (the `sqrt` law tightens the spacing the longer overload lasts).
    ///
    /// The caller, on a `true`, routes the NEW record into the queue's overflow disposition (drop-new
    /// or drop-oldest), exactly like the byte-cap shed, so a CoDel shed is never a silent loss and is
    /// counted by the caller.
    pub fn sojourn(&mut self, sojourn_nanos: u64, now_nanos: u64) -> bool {
        if !self.is_enabled() {
            return false;
        }
        self.maybe_reset_for_suspend(now_nanos);
        self.last_sojourn_nanos = sojourn_nanos;

        if sojourn_nanos <= self.target_nanos {
            // Below TARGET: no standing delay. Close the window and leave the dropping state.
            self.first_above_time = None;
            self.dropping = false;
            return false;
        }

        // Above TARGET: open (or keep) the window. The window arms when the sojourn has been above
        // TARGET continuously for a full INTERVAL.
        let armed = match self.first_above_time {
            None => {
                self.first_above_time = Some(now_nanos.saturating_add(self.interval_nanos));
                false
            }
            Some(at) => now_nanos >= at,
        };

        if self.dropping {
            // Already shedding: fire on the scheduled spacing and reschedule by the control law.
            if now_nanos >= self.drop_next {
                self.count = self.count.saturating_add(1);
                self.schedule_next_drop(now_nanos);
                return true;
            }
            return false;
        }

        if armed {
            // Enter the dropping state. Seed `count` from the previous episode if it ended recently
            // (within a couple of control laws), so a flapping overload does not restart aggressive.
            self.enter_dropping(now_nanos);
            return true;
        }
        false
    }

    /// Enters the dropping state at `now_nanos`, seeding `count` per RFC 8289 (carry the previous
    /// episode's count if it ended recently, else restart at 1) and scheduling the first drop now.
    fn enter_dropping(&mut self, now_nanos: u64) {
        self.dropping = true;
        // RFC 8289: if a new dropping episode starts within two control-law spacings of the last
        // one, resume near the previous count (the overload never really cleared); otherwise restart.
        let recent =
            now_nanos.saturating_sub(self.drop_next) < self.interval_nanos.saturating_mul(2);
        self.count = if recent && self.last_count > 2 {
            self.last_count.saturating_sub(2)
        } else {
            1
        };
        self.schedule_next_drop(now_nanos);
    }

    /// Schedules the next drop at `now + INTERVAL / sqrt(count)` (the RFC 8289 control law). `count`
    /// is at least 1 here, so the spacing is at most one INTERVAL and shrinks as overload persists.
    fn schedule_next_drop(&mut self, now_nanos: u64) {
        let root = isqrt(self.count).max(1);
        let spacing = (self.interval_nanos / root).max(1);
        self.drop_next = now_nanos.saturating_add(spacing);
        self.last_count = self.count;
    }
}

/// The AIMD (additive-increase / multiplicative-decrease) egress concurrency limiter (#69).
///
/// A static concurrency limit hammers a degraded downstream; this adapts the limit to the
/// downstream's health, modeled on TCP congestion control: `+1` after a clean window, `x0.5` on a
/// failure signal (a timeout / 429 / 503). The limit is bounded to `[min, max]` so a transient blip
/// cannot collapse throughput to zero and a recovery cannot overwhelm even a healthy sink.
///
/// The limiter is defined behind this small struct so a smarter gradient estimator (Vegas-style)
/// can be slotted in later without changing the call sites; AIMD is the v1 estimator (the seam the
/// doc names).
#[derive(Clone, Copy, Debug)]
pub struct AimdLimiter {
    /// The current concurrency limit (between `min` and `max`).
    limit: u32,
    /// The hard floor: the limit never drops below this on a decrease (default 4).
    min: u32,
    /// The hard ceiling: the limit never rises above this on an increase (default 128).
    max: u32,
}

/// The default static egress concurrency floor / starting point (#69): 16 in-flight requests.
pub const DEFAULT_EGRESS_LIMIT: u32 = 16;
/// The AIMD lower bound on the egress limit (#69): a transient blip cannot collapse below this.
pub const EGRESS_LIMIT_MIN: u32 = 4;
/// The AIMD upper bound on the egress limit (#69): a recovery cannot probe above this.
pub const EGRESS_LIMIT_MAX: u32 = 128;

impl AimdLimiter {
    /// Builds an AIMD limiter starting at `start`, bounded to `[min, max]`. The start is clamped
    /// into the bounds, and a degenerate `min > max` is normalized (the start then pins to `max`),
    /// so the limiter can never be constructed into an unusable state.
    #[must_use]
    pub fn new(start: u32, min: u32, max: u32) -> AimdLimiter {
        let max = max.max(1);
        let min = min.clamp(1, max);
        AimdLimiter {
            limit: start.clamp(min, max),
            min,
            max,
        }
    }

    /// The default egress limiter: starts at [`DEFAULT_EGRESS_LIMIT`] (16), bounded to
    /// `[EGRESS_LIMIT_MIN, EGRESS_LIMIT_MAX]` (`[4, 128]`).
    #[must_use]
    pub fn default_egress() -> AimdLimiter {
        AimdLimiter::new(DEFAULT_EGRESS_LIMIT, EGRESS_LIMIT_MIN, EGRESS_LIMIT_MAX)
    }

    /// The current concurrency limit.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Additive increase: raise the limit by one after a clean window (a window with no failure
    /// signal), capped at `max`. Idempotent at the ceiling.
    pub fn on_success(&mut self) {
        self.limit = self.limit.saturating_add(1).min(self.max);
    }

    /// Multiplicative decrease: halve the limit on a failure signal (a timeout, a 429, or a 503),
    /// floored at `min`. Halving rounds down but never below `min`, so the throughput cannot collapse
    /// to zero.
    pub fn on_failure(&mut self) {
        self.limit = (self.limit / 2).max(self.min);
    }
}

/// The default per-consumer in-flight CREDIT FLOOR (#552): the window an auto-tuning consumer starts
/// at and never drops below. Held at the historical static default (64) so a never-keeping-up consumer
/// behaves exactly as the pre-#552 fixed window did; a consumer that DRAINS its window grows past this
/// toward [`DEFAULT_CREDIT_CEILING`].
pub const DEFAULT_CREDIT_FLOOR: u32 = 64;

/// The default per-consumer in-flight CREDIT CEILING (#552): the high, Kafka-class window a
/// keeping-up consumer's auto-tune grows TOWARD, so single-consumer throughput on a fast/loopback link
/// is no longer pinned at the old 64/RTT (the #464/#532 co-floor). It is the WORST-CASE in-flight
/// message count the refuse-to-boot RAM guard must charge (`crate`-external: `ironbus_server::rss`),
/// so it is a bounded, defensible number rather than the protocol max: 2048 messages, well past 64 yet
/// firmly capped, and ALWAYS dominated by the per-consumer BYTE budget when one is set (the byte budget
/// remains the firm RAM bound; the count merely auto-tunes UNDER it).
pub const DEFAULT_CREDIT_CEILING: u32 = 2048;

/// The additive-increase STEP the credit auto-tune adds to the window after a clean keep-up window
/// (#552). Larger than the AIMD's `+1` so a keeping-up consumer reaches the ceiling in a handful of
/// drained batches rather than thousands of acks (the window must FILL THE PIPE quickly to remove the
/// loopback floor, where a `+1`-per-ack climb from 64 to 2048 would itself be a throughput drag). The
/// decrease stays multiplicative (halve), preserving the AIMD asymmetry: grow steadily, back off fast.
pub const CREDIT_AUTOTUNE_STEP: u32 = 64;

/// The auto-tuning per-consumer byte+count CREDIT flow-control window (#552, V2-M1).
///
/// First-principles: a STATIC small credit window caps a consumer's in-flight to far below the
/// bandwidth-delay product, so on a fast/loopback link throughput is pinned at `window/RTT` — the
/// 64/RTT loopback floor the #464 fair-consume bench and the #532 follow-up surfaced. A SELF-GROWING
/// window fills the pipe: it climbs toward a high ceiling while the consumer keeps up and backs off
/// under backpressure, exactly the TCP-congestion intuition the egress [`AimdLimiter`] already
/// encodes. This reuses that limiter rather than inventing a second controller; it differs only in
/// (a) the domain — the per-CONSUMER in-flight credit window, not the downstream-sink concurrency —
/// and (b) a brisker additive step ([`CREDIT_AUTOTUNE_STEP`]) so the climb itself is not a drag.
///
/// The growth is BOUNDED two ways, so it can never blow RAM: the window never exceeds `ceiling`
/// (default [`DEFAULT_CREDIT_CEILING`]), and — the FIRM bound — the caller intersects the window with
/// the per-consumer BYTE budget on every Flow, so the worst-case in-flight BYTES stay
/// `min(window, byte_budget/avg_record)` worth, capped by the byte budget. The refuse-to-boot RAM
/// guard charges the `ceiling` (the worst-case count) against `MAX_FRAME_LEN` when the byte budget is
/// OFF, so the guard stays TRUTHFUL: a config with no byte budget and a high ceiling is honestly
/// refused under a small RAM ceiling rather than waved through.
///
/// At-least-once is untouched: a larger window only means MORE messages may be in flight at once, each
/// still leased and committed exactly as before. The window is purely a delivery-pacing bound; it
/// never changes which records are leased, acked, or redelivered.
#[derive(Clone, Copy, Debug)]
pub struct CreditAutotuner {
    /// The underlying AIMD state machine (#69 reuse): `limit` is the current credit window, bounded to
    /// `[floor, ceiling]`. The auto-tune drives it through [`AimdLimiter::on_failure`] (halve) and a
    /// stepped additive increase (see [`CreditAutotuner::keep_up`]).
    aimd: AimdLimiter,
    /// The additive-increase step applied on a keep-up window (cached so the increase is a single add).
    step: u32,
}

impl CreditAutotuner {
    /// Builds a credit auto-tuner that starts at `floor`, grows by `step` toward `ceiling` on each
    /// keep-up window, and halves toward `floor` on backpressure. A degenerate `floor > ceiling` is
    /// normalized by [`AimdLimiter::new`] (the window pins to the ceiling), and a `0` step is floored
    /// to one, so the controller can never be constructed into a non-growing state.
    #[must_use]
    pub fn new(floor: u32, ceiling: u32, step: u32) -> CreditAutotuner {
        CreditAutotuner {
            // Start AT the floor: a consumer that never keeps up behaves as the historical fixed window.
            aimd: AimdLimiter::new(floor, floor, ceiling),
            step: step.max(1),
        }
    }

    /// The default credit auto-tuner (#552): floor [`DEFAULT_CREDIT_FLOOR`] (64, the historical static
    /// window), ceiling [`DEFAULT_CREDIT_CEILING`] (2048), step [`CREDIT_AUTOTUNE_STEP`] (64). A
    /// keeping-up consumer grows from 64 to 2048 in a handful of drained windows; a slow one stays at
    /// 64.
    #[must_use]
    pub fn default_credit() -> CreditAutotuner {
        CreditAutotuner::new(
            DEFAULT_CREDIT_FLOOR,
            DEFAULT_CREDIT_CEILING,
            CREDIT_AUTOTUNE_STEP,
        )
    }

    /// Builds a credit auto-tuner whose ceiling is `ceiling` (the negotiated per-consumer window cap)
    /// and whose floor is `min(DEFAULT_CREDIT_FLOOR, ceiling)`, so a consumer whose negotiated ceiling
    /// is BELOW the default floor (a tightly-bounded edge consumer, or a `--consumer-credit` set under
    /// 64) is never started above its own cap. The step is [`CREDIT_AUTOTUNE_STEP`]. This is the
    /// session-facing constructor: the ceiling is the negotiated `credit_ceiling`, the firm bound the
    /// RAM guard also charges.
    #[must_use]
    pub fn with_ceiling(ceiling: u32) -> CreditAutotuner {
        CreditAutotuner::new(
            DEFAULT_CREDIT_FLOOR.min(ceiling.max(1)),
            ceiling,
            CREDIT_AUTOTUNE_STEP,
        )
    }

    /// The current credit window: the most un-acked messages the consumer may hold in flight right
    /// now, BEFORE the byte budget intersects it (the caller still bounds by the byte budget on every
    /// Flow, the firm RAM bound). Always within `[floor, ceiling]`.
    #[must_use]
    pub fn window(&self) -> u32 {
        self.aimd.limit()
    }

    /// The auto-tune CEILING: the highest the window can ever grow to, the worst-case in-flight COUNT
    /// the RAM guard charges. Exposed so the guard's term and the gauge read the SAME number the
    /// controller is bounded by (no drift).
    #[must_use]
    pub fn ceiling(&self) -> u32 {
        self.aimd.max
    }

    /// KEEP-UP signal (#552): the consumer drained its window without stalling (a clean batch with no
    /// would-block), so GROW the window by [`CreditAutotuner::step`] toward the ceiling. Stepped (not
    /// `+1`) so the climb fills the pipe quickly. Idempotent at the ceiling.
    pub fn keep_up(&mut self) {
        // Reuse the AIMD ceiling clamp: add the step, then pin to the ceiling. `min` is the floor here,
        // so the add can only ever raise the window (the floor is the start, never re-imposed on grow).
        self.aimd.limit = self.aimd.limit.saturating_add(self.step).min(self.aimd.max);
    }

    /// BACK-OFF signal (#552): the consumer is not draining (a would-block at the window with a
    /// near-full in-flight set, or a nack), so multiplicatively DECREASE the window (halve, floored at
    /// the floor). The AIMD asymmetry — grow steadily, back off fast — sheds a slow consumer's window
    /// smoothly instead of oscillating, and the floor guarantees forward progress (it never collapses
    /// below the historical static window).
    pub fn back_off(&mut self) {
        self.aimd.on_failure();
    }
}

/// A token bucket rate limiter for the fire-and-forget (un-credited) admission tier (#69).
///
/// The QoS-0-equivalent path is never credited, so it cannot be braked by the consumer-credit
/// window; left ungoverned it can flood the broker and starve credited traffic. This bucket caps it
/// to a configured message and byte rate. It is pure: the caller passes the monotonic time at each
/// admission and the bucket refills lazily from the elapsed time (no background timer). A message
/// consumes one message token and `payload` byte tokens; when EITHER bucket is empty the message is
/// shed (the caller signals it). It governs ONLY the fire-and-forget path, so a depleted bucket can
/// never evict credited traffic (the doc's priority guarantee).
///
/// Disabled when `msg_rate == 0` AND `byte_rate == 0`: [`TokenBucket::try_admit`] then always admits
/// (the tier is ungoverned), so an operator who does not configure it keeps the historical behavior.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    /// Message tokens refilled per second (the steady-state message rate). `0` disables the message
    /// dimension.
    msg_rate_per_sec: u64,
    /// Byte tokens refilled per second (the steady-state byte rate). `0` disables the byte
    /// dimension.
    byte_rate_per_sec: u64,
    /// The burst ceiling on message tokens (the most that can accumulate), derived from the rate and
    /// the refill granularity.
    msg_burst: u64,
    /// The burst ceiling on byte tokens.
    byte_burst: u64,
    /// Available message tokens, scaled by [`Self::SCALE`] for sub-token refill precision.
    msg_tokens: u64,
    /// Available byte tokens, scaled by [`Self::SCALE`].
    byte_tokens: u64,
    /// The monotonic instant (nanos) tokens were last refilled, or `None` until the first admission
    /// anchors the clock.
    last_refill: Option<u64>,
}

impl TokenBucket {
    /// Fixed-point scale for the token counts, so a fractional refill (fewer than one token per
    /// nanosecond) accumulates precisely without floating point.
    const SCALE: u64 = 1_000_000;

    /// Builds a fire-and-forget token bucket with a message rate (msg/s) and a byte rate (bytes/s),
    /// refilling on `refill_ms` granularity (which sizes the burst ceiling: `rate * refill_ms /
    /// 1000`). A `0` for BOTH rates disables the bucket (the tier is ungoverned), matching the
    /// "behaves as today unless configured" default. A `0` refill granularity is treated as the
    /// 100 ms default so the burst ceiling is always well-defined.
    #[must_use]
    pub fn new(msg_rate_per_sec: u64, byte_rate_per_sec: u64, refill_ms: u64) -> TokenBucket {
        let refill_ms = if refill_ms == 0 { 100 } else { refill_ms };
        // The burst ceiling is one refill window's worth of tokens (at least one), so a steady
        // producer at the rate never blocks but a burst is capped to ~one window.
        let msg_burst = (msg_rate_per_sec.saturating_mul(refill_ms) / 1000).max(1);
        let byte_burst = (byte_rate_per_sec.saturating_mul(refill_ms) / 1000).max(1);
        TokenBucket {
            msg_rate_per_sec,
            byte_rate_per_sec,
            msg_burst,
            byte_burst,
            // Start full so a quiet broker's first burst is admitted up to the ceiling.
            msg_tokens: msg_burst.saturating_mul(Self::SCALE),
            byte_tokens: byte_burst.saturating_mul(Self::SCALE),
            last_refill: None,
        }
    }

    /// Whether the bucket is enabled (at least one rate is non-zero). A disabled bucket always
    /// admits.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.msg_rate_per_sec != 0 || self.byte_rate_per_sec != 0
    }

    /// Refills both token buckets from the time elapsed since the last refill, capped at the burst
    /// ceiling. Lazy: called at each admission with the current monotonic time, so no background
    /// timer is needed. A backwards or equal `now` (the monotonic clock never goes backwards, but be
    /// defensive) adds nothing.
    fn refill(&mut self, now_nanos: u64) {
        let Some(last) = self.last_refill else {
            self.last_refill = Some(now_nanos);
            return;
        };
        let elapsed = now_nanos.saturating_sub(last);
        if elapsed == 0 {
            return;
        }
        self.last_refill = Some(now_nanos);
        // tokens added = rate_per_sec * elapsed_nanos / 1e9, in SCALE units:
        //   added_scaled = rate * elapsed * SCALE / 1e9
        // Compute as (rate * SCALE / 1e9) is lossy, so scale elapsed first; saturate on overflow.
        let add_scaled = |rate: u64| -> u64 {
            let num = rate.saturating_mul(elapsed);
            // num * SCALE / 1e9, reassociated to keep precision and avoid overflow on realistic rates.
            num.saturating_mul(Self::SCALE) / 1_000_000_000
        };
        let msg_cap = self.msg_burst.saturating_mul(Self::SCALE);
        let byte_cap = self.byte_burst.saturating_mul(Self::SCALE);
        self.msg_tokens = self
            .msg_tokens
            .saturating_add(add_scaled(self.msg_rate_per_sec))
            .min(msg_cap);
        self.byte_tokens = self
            .byte_tokens
            .saturating_add(add_scaled(self.byte_rate_per_sec))
            .min(byte_cap);
    }

    /// Tries to admit one fire-and-forget message of `payload_bytes` at monotonic time `now_nanos`.
    /// Refills lazily, then consumes one message token and `payload_bytes` byte tokens if BOTH are
    /// available, returning `true` (admitted). When either bucket is empty it returns `false` (shed)
    /// and consumes nothing. A disabled bucket always admits. The byte dimension is skipped when the
    /// byte rate is `0` (only the message rate binds), and vice versa.
    pub fn try_admit(&mut self, payload_bytes: u64, now_nanos: u64) -> bool {
        if !self.is_enabled() {
            return true;
        }
        self.refill(now_nanos);
        let need_msg = Self::SCALE; // one message token, scaled.
        let need_bytes = payload_bytes.saturating_mul(Self::SCALE);
        let msg_ok = self.msg_rate_per_sec == 0 || self.msg_tokens >= need_msg;
        let byte_ok = self.byte_rate_per_sec == 0 || self.byte_tokens >= need_bytes;
        if msg_ok && byte_ok {
            if self.msg_rate_per_sec != 0 {
                self.msg_tokens -= need_msg;
            }
            if self.byte_rate_per_sec != 0 {
                self.byte_tokens = self.byte_tokens.saturating_sub(need_bytes);
            }
            true
        } else {
            false
        }
    }
}

/// The per-client retry budget (#69): the Google SRE accept-based adaptive throttle over a sliding
/// window.
///
/// The control bounds a client's retries to a fraction of its request rate so retries can add only a
/// bounded multiple to the offered load (no overload-to-collapse amplification). It tracks two
/// counts over a sliding `window` of monotonic time: `requests` (total requests issued) and
/// `accepts` (requests the broker accepted, i.e. did not shed). The throttle probability for a retry
/// is the SRE formula `max(0, (requests - K * accepts) / (requests + 1))` with `K = 2`.
///
/// This is pure and deterministic: rather than draw a random number (which `ironbus-core` must not
/// do, to stay reproducible in the sim), [`RetryBudget::should_throttle`] is given the comparison
/// directly via a deterministic accumulator (a token-style budget), so the SAME stream of calls
/// always makes the SAME decision. The broker uses it as the broker-side re-check; the client
/// library would mirror it.
///
/// Disabled when `ratio_per_million == 0`: [`RetryBudget::should_throttle`] then never throttles.
#[derive(Clone, Copy, Debug)]
pub struct RetryBudget {
    /// The budget ratio in PARTS PER MILLION (so a `0.10` budget is `100_000`), avoiding floats. `0`
    /// disables the budget.
    ratio_per_million: u64,
    /// The sliding window length in nanoseconds.
    window_nanos: u64,
    /// Requests issued in the current window (decayed at the window boundary).
    requests: u64,
    /// Requests the broker accepted in the current window.
    accepts: u64,
    /// Retries permitted so far in the current window (the deterministic budget counter): a retry is
    /// throttled when permitting it would push the retry count above the budget the formula allows.
    retries_allowed: u64,
    /// The monotonic instant (nanos) the current window started, or `None` until the first event.
    window_start: Option<u64>,
}

/// The default retry-budget ratio in parts per million (#69): 10% (`100_000`).
pub const DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION: u64 = 100_000;
/// The default retry-budget sliding window in milliseconds (#69): 60 s.
pub const DEFAULT_RETRY_BUDGET_WINDOW_MS: u64 = 60_000;
/// The SRE accept-multiplier `K` (#69): `K = 2` lets a client whose requests are mostly accepted
/// retry freely, and throttles toward the budget as the accept rate falls.
const RETRY_BUDGET_K: u64 = 2;

impl RetryBudget {
    /// Builds a retry budget from a ratio in parts-per-million and a window in MILLISECONDS. A `0`
    /// ratio disables the budget (no retry is ever throttled), so a broker that does not configure it
    /// behaves as today. A `0` window is treated as the 60 s default so the sliding window is always
    /// well-defined.
    #[must_use]
    pub fn new(ratio_per_million: u64, window_ms: u64) -> RetryBudget {
        let window_ms = if window_ms == 0 {
            DEFAULT_RETRY_BUDGET_WINDOW_MS
        } else {
            window_ms
        };
        RetryBudget {
            ratio_per_million: ratio_per_million.min(1_000_000),
            window_nanos: window_ms.saturating_mul(NANOS_PER_MS),
            requests: 0,
            accepts: 0,
            retries_allowed: 0,
            window_start: None,
        }
    }

    /// Whether the budget is enabled (a non-zero ratio). A disabled budget never throttles.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.ratio_per_million != 0
    }

    /// Rolls the sliding window if `now` is past its end, decaying the counts. A simple tumbling
    /// window (reset at the boundary) is used rather than a per-event ring, which keeps the control
    /// pure and O(1); the doc's "sliding 60 s window" is approximated by the tumble, which is the
    /// conservative choice (it never under-counts retries within a window).
    fn roll(&mut self, now_nanos: u64) {
        match self.window_start {
            None => self.window_start = Some(now_nanos),
            Some(start) if now_nanos.saturating_sub(start) >= self.window_nanos => {
                self.requests = 0;
                self.accepts = 0;
                self.retries_allowed = 0;
                self.window_start = Some(now_nanos);
            }
            Some(_) => {}
        }
    }

    /// Records one ORIGINAL request the broker accepted (did not shed) at `now`. Feeds both the
    /// `requests` and `accepts` counts, so a healthy client (everything accepted) has a zero throttle
    /// probability.
    pub fn record_accept(&mut self, now_nanos: u64) {
        self.roll(now_nanos);
        self.requests = self.requests.saturating_add(1);
        self.accepts = self.accepts.saturating_add(1);
    }

    /// Records one request the broker SHED at `now` (a request, not an accept). Raises `requests`
    /// without `accepts`, which is what drives the throttle probability up.
    pub fn record_shed(&mut self, now_nanos: u64) {
        self.roll(now_nanos);
        self.requests = self.requests.saturating_add(1);
    }

    /// The observed retry rate as a fraction of the request rate, in parts-per-million, for the
    /// `ironbus_retry_ratio` gauge. It is the share of requests that were NOT accepted (the sheds),
    /// which is what the budget bounds. `0` when there have been no requests yet.
    #[must_use]
    pub fn observed_ratio_per_million(&self) -> u64 {
        if self.requests == 0 {
            return 0;
        }
        let shed = self.requests.saturating_sub(self.accepts);
        shed.saturating_mul(1_000_000) / self.requests
    }

    /// Decides whether to THROTTLE (drop) a retry at `now`, counting the retry as a request. Returns
    /// `true` to throttle. The decision is the deterministic budget form of the SRE throttle: a retry
    /// is permitted only while the number of retries permitted this window stays within the budget
    /// the SRE formula allows for the current `requests` / `accepts`, i.e. while
    /// `retries_allowed < (requests - K * accepts)` and the budget ratio is not yet exhausted. A
    /// permitted retry also counts as a request (it WAS issued to the broker). A throttled retry is
    /// NOT issued, so it does not count as a request.
    pub fn should_throttle(&mut self, now_nanos: u64) -> bool {
        if !self.is_enabled() {
            // The retry is issued; count it as a request that was accepted-or-not by the budget.
            self.record_shed(now_nanos);
            return false;
        }
        self.roll(now_nanos);
        // The SRE numerator: requests minus K*accepts, floored at zero. While this is zero (the
        // client's requests are mostly being accepted) no retry is throttled.
        let numerator = self
            .requests
            .saturating_sub(RETRY_BUDGET_K.saturating_mul(self.accepts));
        // The budget ceiling on permitted retries this window: ratio * requests.
        let budget = self.requests.saturating_mul(self.ratio_per_million) / 1_000_000;
        if numerator == 0 || self.retries_allowed < budget {
            // Permit the retry: it is issued to the broker, so it counts as a request (a shed-pending
            // one until the broker accepts it).
            self.retries_allowed = self.retries_allowed.saturating_add(1);
            self.requests = self.requests.saturating_add(1);
            false
        } else {
            true
        }
    }
}

/// The default fsync-headroom admission window in BYTES (#378): the most un-fsynced (buffered but
/// not yet durable) record bytes the write frontier may run ahead of the durable frontier before a
/// new produce is throttled (the group-commit flush is forced first) or, if a flush cannot drain it,
/// shed. `0` DISABLES the headroom (the un-fsynced frontier is bounded only by the existing controls:
/// under `sync` the group-commit boundary already drains it every batch; under a relaxed level only
/// the `interval` window or a roll/shutdown does). The shipped default is `0` (OFF), so a zero-config
/// broker behaves exactly as today; an operator opts in to a tight RAM / loss-window bound.
pub const DEFAULT_WAL_FSYNC_HEADROOM_BYTES: u64 = 0;

/// The pure, IO-free fsync-headroom admission credit (#378, refining the #67 / #177 WAL backpressure
/// seam). It bounds how far the BUFFERED (appended-but-not-yet-`fdatasync`'d) write frontier may run
/// ahead of the DURABLE (synced) frontier, so a producer outrunning fsync cannot grow an unbounded
/// un-fsynced backlog (a memory guard under any level, and a bounded-loss-window guard under a
/// relaxed durability level).
///
/// This is the BYTE-dimension complement to the CoDel admission (#336): CoDel sheds on standing
/// QUEUE LATENCY (sojourn), this sheds on the un-fsynced BACKLOG SIZE. The two compose without
/// interaction: each is consulted before the append and either admits or sheds NEW work only, so
/// neither ever drops an already-accepted record (I2 holds).
///
/// The frontier itself is owned by the storage log (`unsynced_bytes()`, the #341 relaxed-durability
/// tracking): this type only does the threshold MATH, so it stays IO-free and lives in core. The
/// caller passes the current un-fsynced backlog and the new record's logical bytes; the decision is
/// whether ADMITTING this record would push the backlog past the configured headroom.
///
/// A `headroom_bytes` of `0` is DISABLED ([`FsyncHeadroom::is_enabled`] is false and every admission
/// is granted), the safe default. A non-zero headroom is the opt-in tight bound.
#[derive(Clone, Copy, Debug)]
pub struct FsyncHeadroom {
    /// The configured un-fsynced byte headroom. `0` = DISABLED (unbounded, the safe default).
    headroom_bytes: u64,
}

impl FsyncHeadroom {
    /// Builds the admission credit from the configured byte headroom. `0` disables it (the un-fsynced
    /// frontier is unbounded by this control), which is the backward-compatible default.
    #[must_use]
    pub fn new(headroom_bytes: u64) -> FsyncHeadroom {
        FsyncHeadroom { headroom_bytes }
    }

    /// Whether the headroom is ENABLED (a non-zero bound). When disabled every admission is granted,
    /// so a zero-config broker is unchanged.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.headroom_bytes != 0
    }

    /// The configured headroom in bytes (`0` = disabled), for the observability gauge.
    #[must_use]
    pub fn headroom_bytes(&self) -> u64 {
        self.headroom_bytes
    }

    /// The admission decision for a NEW produce, given the CURRENT un-fsynced backlog
    /// (`unsynced_now`, the storage frontier `unsynced_bytes()`) and the new record's `record_bytes`
    /// (its logical key + headers + payload, the same units the backlog is measured in). Returns
    /// `true` to ADMIT, `false` to throttle/shed.
    ///
    /// Disabled (`headroom_bytes == 0`) always admits. When enabled, the rule is: admit unless there
    /// is ALREADY a non-empty backlog AND appending this record would push the backlog PAST the
    /// headroom. The "already a non-empty backlog" guard is the NO-WEDGE floor: when the backlog is
    /// empty the record is always admitted even if it alone exceeds the headroom (a single record
    /// larger than the whole headroom must still make progress, exactly like the per-consumer
    /// byte-credit's one-message floor), because the caller's contract is to DRAIN the backlog (force
    /// a group-commit flush, which resets `unsynced_now` to `0`) before consulting this again, so a
    /// shed only ever happens when a drain is possible and still insufficient.
    ///
    /// Pure: no IO, no clock, no allocation. The caller composes it with the drain (a `commit_batch`
    /// flush) so the actual control law is "flush first, then admit-or-shed", and this method is the
    /// shed half.
    #[must_use]
    pub fn would_admit(&self, unsynced_now: u64, record_bytes: u64) -> bool {
        if self.headroom_bytes == 0 {
            // Disabled: the frontier is unbounded by this control, so every produce is admitted.
            return true;
        }
        if unsynced_now == 0 {
            // The no-wedge floor: an empty backlog always admits the next record, even one larger
            // than the whole headroom, so the broker can never deadlock on an oversized produce.
            return true;
        }
        // A non-empty backlog: admit only if the new record fits within the remaining headroom.
        // Saturating add so an enormous record can never wrap into a false admit.
        unsynced_now.saturating_add(record_bytes) <= self.headroom_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = NANOS_PER_MS;

    // ---- isqrt ----

    #[test]
    fn isqrt_is_floor_of_the_real_root() {
        for n in [0u64, 1, 2, 3, 4, 8, 9, 15, 16, 24, 25, 100, 101, 1_000_000] {
            let r = isqrt(n);
            assert!(r * r <= n, "isqrt({n})={r} too big");
            assert!((r + 1) * (r + 1) > n, "isqrt({n})={r} too small");
        }
    }

    // ---- CoDel clamps ----

    #[test]
    fn codel_clamps_target_and_interval_but_zero_disables() {
        assert_eq!(clamp_codel_target_ms(0), 0, "zero disables, not clamped");
        assert_eq!(clamp_codel_target_ms(0), 0);
        assert_eq!(clamp_codel_target_ms(1), 1);
        assert_eq!(clamp_codel_target_ms(5), 5);
        assert_eq!(
            clamp_codel_target_ms(10_000),
            CODEL_TARGET_MAX_MS,
            "above clamp"
        );
        assert_eq!(clamp_codel_target_ms(1), CODEL_TARGET_MIN_MS);
        assert_eq!(clamp_codel_interval_ms(0), 0);
        assert_eq!(
            clamp_codel_interval_ms(5),
            CODEL_INTERVAL_MIN_MS,
            "below clamp"
        );
        assert_eq!(clamp_codel_interval_ms(100), 100);
        assert_eq!(
            clamp_codel_interval_ms(1_000_000),
            CODEL_INTERVAL_MAX_MS,
            "above clamp"
        );
    }

    #[test]
    fn a_disabled_codel_never_sheds() {
        let mut c = Codel::from_millis(0, 100);
        assert!(!c.is_enabled());
        // Even a huge sojourn never sheds when disabled.
        for t in 0..1000 {
            assert!(
                !c.sojourn(10 * MS, t * MS),
                "disabled CoDel must never shed"
            );
        }
    }

    // ---- CoDel control law ----

    #[test]
    fn codel_does_not_shed_under_normal_load() {
        // A queue whose sojourn stays at or below TARGET never sheds, regardless of how long it runs.
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        for _ in 0..10_000 {
            now += MS;
            // 1 ms sojourn, well under the 5 ms target.
            assert!(!c.sojourn(MS, now), "no shed under target");
        }
        assert_eq!(c.interval_resets(), 0);
    }

    #[test]
    fn codel_does_not_shed_a_brief_burst_under_the_interval() {
        // A sojourn above TARGET for LESS than one INTERVAL must not shed (a transient burst).
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        // Above target (10 ms) but only for 50 ms (< 100 ms interval): never arms.
        for _ in 0..50 {
            now += MS;
            assert!(
                !c.sojourn(10 * MS, now),
                "a sub-interval burst must not shed"
            );
        }
        // Then it drops back under target and the window resets.
        now += MS;
        assert!(!c.sojourn(MS, now));
    }

    #[test]
    fn codel_sheds_under_sustained_overload_past_the_target_for_an_interval() {
        // Sustained sojourn above TARGET for a full INTERVAL enters the dropping state and sheds.
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        let mut shed = false;
        // Feed 10 ms sojourns (above the 5 ms target) for 300 ms (3 intervals).
        for _ in 0..300 {
            now += MS;
            if c.sojourn(10 * MS, now) {
                shed = true;
            }
        }
        assert!(shed, "sustained overload past the target must shed");
        assert!(
            c.sojourn_estimate_ms() >= 5,
            "the sojourn estimate is observable"
        );
    }

    #[test]
    fn codel_drop_spacing_tightens_as_overload_persists() {
        // The number of drops in a fixed wall-clock window grows as overload persists (the
        // INTERVAL/sqrt(count) law tightens the spacing).
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        let mut drops_first = 0u64;
        let mut drops_later = 0u64;
        // First 500 ms of overload.
        for i in 0..1000 {
            now += MS;
            if c.sojourn(20 * MS, now) {
                if i < 500 {
                    drops_first += 1;
                } else {
                    drops_later += 1;
                }
            }
        }
        assert!(
            drops_later >= drops_first,
            "drop rate must not fall while overload persists"
        );
        assert!(drops_first >= 1, "at least one drop in the first window");
    }

    #[test]
    fn codel_exits_dropping_when_sojourn_recovers() {
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        // Drive into dropping.
        for _ in 0..300 {
            now += MS;
            let _ = c.sojourn(20 * MS, now);
        }
        // Recovery: a below-target sojourn leaves the dropping state and never sheds again while low.
        now += MS;
        assert!(!c.sojourn(MS, now), "a recovered sojourn exits dropping");
        for _ in 0..200 {
            now += MS;
            assert!(!c.sojourn(MS, now), "no shed once recovered");
        }
    }

    #[test]
    fn codel_resets_the_window_across_a_suspend_gap() {
        // A long monotonic jump with no intervening activity (a deep sleep) resets the window so the
        // device does not shed a burst on resume.
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        // Build the above-target window most of the way, but not yet armed.
        now += 50 * MS;
        assert!(!c.sojourn(10 * MS, now));
        // The device sleeps for an hour, then resumes and the first record has a huge sojourn.
        now += 3_600_000 * MS;
        // The huge sojourn is discarded (suspend reset), so this resume does NOT shed.
        assert!(
            !c.sojourn(10 * MS, now),
            "a suspend-gap resume must not shed"
        );
        assert_eq!(c.interval_resets(), 1, "the reset is counted");
    }

    #[test]
    fn codel_on_empty_clears_the_window() {
        let mut c = Codel::from_millis(5, 100);
        let mut now = 0u64;
        // Open the window above target.
        for _ in 0..50 {
            now += MS;
            let _ = c.sojourn(10 * MS, now);
        }
        // The queue drains: the window closes.
        now += MS;
        c.on_empty(now);
        // A fresh above-target run must take a full interval again before it sheds.
        let mut shed = false;
        for _ in 0..50 {
            now += MS;
            if c.sojourn(10 * MS, now) {
                shed = true;
            }
        }
        assert!(!shed, "after on_empty a sub-interval run must not shed");
    }

    // ---- AIMD ----

    #[test]
    fn aimd_additive_increase_and_multiplicative_decrease_within_bounds() {
        let mut a = AimdLimiter::default_egress();
        assert_eq!(a.limit(), 16);
        // Additive increase by one per clean window.
        a.on_success();
        assert_eq!(a.limit(), 17);
        a.on_success();
        assert_eq!(a.limit(), 18);
        // Multiplicative decrease halves.
        a.on_failure();
        assert_eq!(a.limit(), 9);
        a.on_failure();
        assert_eq!(a.limit(), 4, "halves toward the floor");
        a.on_failure();
        assert_eq!(a.limit(), 4, "never below the floor of 4");
    }

    #[test]
    fn aimd_never_exceeds_the_ceiling() {
        let mut a = AimdLimiter::default_egress();
        for _ in 0..1000 {
            a.on_success();
        }
        assert_eq!(a.limit(), 128, "additive increase caps at 128");
    }

    #[test]
    fn aimd_recovers_additively_after_a_decrease() {
        let mut a = AimdLimiter::default_egress();
        a.on_failure(); // 8
        assert_eq!(a.limit(), 8);
        a.on_success(); // 9
        a.on_success(); // 10
        assert_eq!(a.limit(), 10, "additive recovery climbs slowly");
    }

    #[test]
    fn aimd_normalizes_a_degenerate_min_max() {
        let a = AimdLimiter::new(50, 100, 10); // min > max
        assert!(
            a.limit() <= 10,
            "start is clamped into the normalized bounds"
        );
        assert!(a.limit() >= 1);
    }

    // ---- credit auto-tune (#552) ----

    #[test]
    fn credit_autotune_starts_at_the_floor() {
        let a = CreditAutotuner::default_credit();
        assert_eq!(
            a.window(),
            DEFAULT_CREDIT_FLOOR,
            "a fresh consumer starts at the historical static window (64)"
        );
        assert_eq!(a.ceiling(), DEFAULT_CREDIT_CEILING);
    }

    #[test]
    fn credit_autotune_grows_past_64_toward_the_ceiling_for_a_keeping_up_consumer() {
        // The CORE #552 claim: a consumer that keeps draining its window grows the window WELL past the
        // old 64 floor (so throughput is no longer pinned at 64/RTT), reaching the high ceiling.
        let mut a = CreditAutotuner::default_credit();
        assert_eq!(a.window(), 64);
        a.keep_up();
        assert!(
            a.window() > 64,
            "one keep-up window must grow the credit past the old 64 floor, got {}",
            a.window()
        );
        for _ in 0..1000 {
            a.keep_up();
        }
        assert_eq!(
            a.window(),
            DEFAULT_CREDIT_CEILING,
            "a perpetually-keeping-up consumer climbs to the ceiling, not pinned at 64"
        );
    }

    #[test]
    fn credit_autotune_never_exceeds_the_ceiling() {
        let mut a = CreditAutotuner::new(64, 300, 64);
        for _ in 0..100 {
            a.keep_up();
        }
        assert_eq!(a.window(), 300, "growth is capped at the ceiling");
        assert_eq!(a.ceiling(), 300);
    }

    #[test]
    fn credit_autotune_backs_off_multiplicatively_under_backpressure() {
        // A non-draining consumer's window halves toward the floor (grow steadily, back off fast), but
        // never below the floor, so forward progress is guaranteed.
        let mut a = CreditAutotuner::default_credit();
        for _ in 0..1000 {
            a.keep_up();
        }
        assert_eq!(a.window(), 2048);
        a.back_off();
        assert_eq!(a.window(), 1024, "back-off halves the window");
        a.back_off();
        assert_eq!(a.window(), 512);
        for _ in 0..20 {
            a.back_off();
        }
        assert_eq!(
            a.window(),
            DEFAULT_CREDIT_FLOOR,
            "back-off never collapses below the floor (forward progress guaranteed)"
        );
    }

    #[test]
    fn credit_autotune_floor_never_exceeds_a_low_negotiated_ceiling() {
        // A consumer whose negotiated ceiling is BELOW the default floor (a tightly-bounded edge
        // consumer) is never started above its own cap, and never grows past it.
        let mut a = CreditAutotuner::with_ceiling(8);
        assert_eq!(a.window(), 8, "the start is clamped to the low ceiling");
        for _ in 0..100 {
            a.keep_up();
        }
        assert_eq!(a.window(), 8, "growth is capped at the negotiated ceiling");
    }

    // ---- token bucket ----

    #[test]
    fn a_disabled_token_bucket_always_admits() {
        let mut b = TokenBucket::new(0, 0, 100);
        assert!(!b.is_enabled());
        for t in 0..1000 {
            assert!(
                b.try_admit(1_000_000, t),
                "disabled bucket admits everything"
            );
        }
    }

    #[test]
    fn token_bucket_caps_the_message_rate_and_refills() {
        // 5000 msg/s, 100 ms refill => burst ~500. Start full, drain the burst, then it sheds until
        // tokens refill.
        let mut b = TokenBucket::new(5000, 0, 100);
        let now = 0u64;
        let mut admitted = 0u64;
        // Drain at t=0: at most the burst ceiling is admitted.
        for _ in 0..1000 {
            if b.try_admit(0, now) {
                admitted += 1;
            }
        }
        assert!(
            (400..=600).contains(&admitted),
            "burst capped near 500, got {admitted}"
        );
        // Immediately after draining, it sheds.
        assert!(!b.try_admit(0, now), "an empty bucket sheds");
        // 100 ms later, ~500 tokens refilled.
        let later = 100 * MS;
        let mut refilled = 0u64;
        for _ in 0..1000 {
            if b.try_admit(0, later) {
                refilled += 1;
            }
        }
        assert!(
            refilled >= 400,
            "tokens refilled after the window, got {refilled}"
        );
    }

    #[test]
    fn token_bucket_byte_dimension_sheds_a_big_payload() {
        // 5 MiB/s, 100 ms => ~512 KiB burst. A 1 MiB payload exceeds the byte burst and is shed even
        // when message tokens are available.
        let mut b = TokenBucket::new(5000, 5 * 1024 * 1024, 100);
        assert!(
            !b.try_admit(1024 * 1024, 0),
            "an over-burst payload is shed on bytes"
        );
        // A small payload is admitted.
        assert!(b.try_admit(1024, 0), "a small payload fits the byte burst");
    }

    // ---- retry budget ----

    #[test]
    fn a_disabled_retry_budget_never_throttles() {
        let mut r = RetryBudget::new(0, 60_000);
        assert!(!r.is_enabled());
        for t in 0..1000 {
            assert!(
                !r.should_throttle(t * MS),
                "disabled budget never throttles"
            );
        }
    }

    #[test]
    fn retry_budget_lets_a_healthy_client_retry_freely() {
        // A client whose requests are all accepted has a zero throttle numerator, so its occasional
        // retry is never throttled.
        let mut r = RetryBudget::new(DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION, 60_000);
        let now = 0u64;
        for _ in 0..1000 {
            r.record_accept(now);
        }
        assert_eq!(r.observed_ratio_per_million(), 0, "no sheds observed yet");
        // A burst of retries: with accepts == requests the SRE numerator is 0, so none is throttled.
        for _ in 0..100 {
            assert!(!r.should_throttle(now), "a healthy client retries freely");
        }
    }

    #[test]
    fn retry_budget_throttles_a_storm_when_accepts_collapse() {
        // When the broker sheds most requests (accepts collapse), the retry numerator goes positive
        // and the budget throttles retries past the 10% ceiling.
        let mut r = RetryBudget::new(DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION, 60_000);
        let now = 0u64;
        // 1000 requests, all shed (no accepts): requests=1000, accepts=0.
        for _ in 0..1000 {
            r.record_shed(now);
        }
        assert!(
            r.observed_ratio_per_million() > 0,
            "sheds are observed in the ratio"
        );
        // Now hammer retries: most must be throttled (the budget bounds them to ~10%).
        let mut throttled = 0u64;
        let mut allowed = 0u64;
        for _ in 0..1000 {
            if r.should_throttle(now) {
                throttled += 1;
            } else {
                allowed += 1;
            }
        }
        assert!(
            throttled > allowed,
            "most retries throttled under a storm: {throttled} vs {allowed}"
        );
        assert!(throttled > 0, "the budget actually throttles");
    }

    #[test]
    fn retry_budget_window_rolls_and_decays() {
        let mut r = RetryBudget::new(DEFAULT_RETRY_BUDGET_RATIO_PER_MILLION, 1000); // 1 s window
        let now = 0u64;
        for _ in 0..100 {
            r.record_shed(now);
        }
        assert!(r.observed_ratio_per_million() > 0);
        // Past the window, the counts decay to zero.
        let later = 2000 * MS; // 2 s, past the 1 s window
        r.record_accept(later);
        // After the roll, only the single accept remains: ratio is back near zero.
        assert_eq!(
            r.observed_ratio_per_million(),
            0,
            "the window decayed the sheds"
        );
    }

    // ---- fsync headroom (#378) ----

    #[test]
    fn fsync_headroom_disabled_admits_everything() {
        // The SAFE DEFAULT: a `0` headroom is OFF, so every produce is admitted regardless of the
        // backlog (a zero-config broker is unchanged).
        let h = FsyncHeadroom::new(0);
        assert!(!h.is_enabled());
        assert!(h.would_admit(0, 100));
        assert!(h.would_admit(u64::MAX, u64::MAX), "disabled never sheds");
    }

    #[test]
    fn fsync_headroom_admits_within_the_window() {
        // Enabled: while the backlog plus the new record stays within the headroom, admit.
        let h = FsyncHeadroom::new(1000);
        assert!(h.is_enabled());
        assert_eq!(h.headroom_bytes(), 1000);
        assert!(h.would_admit(0, 500), "empty backlog always admits");
        assert!(h.would_admit(500, 500), "exactly at the headroom admits");
        assert!(h.would_admit(400, 100), "within the headroom admits");
    }

    #[test]
    fn fsync_headroom_sheds_past_the_window_with_a_nonempty_backlog() {
        // The shed: a NON-EMPTY backlog plus the new record exceeds the headroom, so the new produce
        // is throttled/shed (the caller drains first; this is the post-drain shed half).
        let h = FsyncHeadroom::new(1000);
        assert!(
            !h.would_admit(600, 500),
            "600 + 500 > 1000 with a non-empty backlog sheds"
        );
        assert!(
            !h.would_admit(1000, 1),
            "already at the headroom sheds the next"
        );
    }

    #[test]
    fn fsync_headroom_never_wedges_on_an_oversized_record() {
        // The NO-WEDGE floor: an EMPTY backlog admits the next record even if it alone exceeds the
        // whole headroom, so a single record larger than the headroom still makes progress (the
        // caller will have drained the backlog to empty before re-consulting).
        let h = FsyncHeadroom::new(1000);
        assert!(
            h.would_admit(0, 5000),
            "an oversized record on an empty backlog still admits (no deadlock)"
        );
    }

    #[test]
    fn fsync_headroom_saturates_and_never_wraps_into_a_false_admit() {
        // A huge record on a non-empty backlog must not wrap the add into a small value that would
        // falsely admit; the saturating add keeps the comparison correct.
        let h = FsyncHeadroom::new(1000);
        assert!(
            !h.would_admit(1, u64::MAX),
            "u64::MAX + 1 saturates above the headroom, so it sheds, never wraps"
        );
    }
}
