// SPDX-License-Identifier: MIT OR Apache-2.0
//! Delivery policy: the ack vocabulary, max-deliver poison detection, and nack backoff.
//!
//! This is the pure decision layer of the consumer model. It defines the ack vocabulary,
//! decides when a repeatedly-failing message becomes poison (and must move to the
//! dead-letter queue rather than redeliver forever), and computes how long to wait before
//! a nacked message is retried. Applying each verb's effect to the lease and cursor, and
//! the durable side (appending to the DLQ topic and tombstoning the source in-flight entry
//! under one fsync with idempotent recovery), is the server's job; this module owns only
//! the IO-free policy that drives them.

/// A per-message acknowledgement verb issued by a consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckVerb {
    /// Processing succeeded: commit the message and never redeliver it.
    Ack,
    /// Processing failed: retry. An optional `delay_nanos` requests redelivery sooner (or
    /// later) than simply waiting out the visibility timeout.
    Nack {
        /// How long to defer the retry, in nanoseconds of monotonic time.
        delay_nanos: u64,
    },
    /// Work is still in progress: extend the lease by one visibility window.
    Progress,
    /// Stop redelivering without sending to the dead-letter queue (an intentional drop).
    Term,
}

/// What to do with a message at delivery time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Deliver this attempt to a consumer.
    Deliver,
    /// The message has now been delivered more than `max_deliver` times: route it to the
    /// dead-letter queue and stop redelivering it.
    DeadLetter,
}

/// An invalid [`DeliveryConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `max_deliver` was zero (unlimited) without the explicit opt-in. Unlimited delivery
    /// lets a poison message redeliver forever, so it must be chosen deliberately.
    UnlimitedDeliverNotAllowed,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::UnlimitedDeliverNotAllowed => write!(
                f,
                "max_deliver = 0 (unlimited) requires allow_unlimited_deliver"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The delivery tunables for one consumer or work-group.
#[derive(Clone, Debug)]
pub struct DeliveryConfig {
    max_deliver: u32,
    allow_unlimited: bool,
    backoff_nanos: Vec<u64>,
    attempts_flush_redeliveries: u32,
}

impl DeliveryConfig {
    /// The default cap on delivery attempts before a message is dead-lettered.
    pub const DEFAULT_MAX_DELIVER: u32 = 5;

    /// The default redelivery-driven attempt-count flush threshold (#547): once at least this
    /// many REDELIVERY grants (attempts >= 2, the poison-relevant events) have accumulated in a
    /// group since its attempt counts were last durable, the server's per-pass checkpoint seam
    /// writes the attempt snapshot even though the cursor has not advanced. `1` (the default)
    /// makes every pass that granted a redelivery end with one amortized snapshot write, so the
    /// durable count lags the true count by AT MOST the redeliveries of a single in-progress
    /// pass — bounded in deliveries, never in wall-clock or cursor distance. First deliveries
    /// (attempt 1, the hot path) never trip it, so a healthy workload pays nothing.
    pub const DEFAULT_ATTEMPTS_FLUSH_REDELIVERIES: u32 = 1;

    /// Builds a delivery config.
    ///
    /// `max_deliver` caps delivery attempts; the `max_deliver + 1`-th attempt is poison
    /// and dead-lettered. A `max_deliver` of zero, OR of `u32::MAX` (the value at which the
    /// lease delivery counter saturates, so the cap could never fire), means unlimited and
    /// is rejected unless `allow_unlimited` is set. `backoff_nanos` is the escalating
    /// per-attempt nack delay schedule, indexed by attempt and clamped to its last entry;
    /// empty means no delay.
    ///
    /// # Errors
    /// Returns [`ConfigError::UnlimitedDeliverNotAllowed`] for an unguarded unlimited cap.
    pub fn new(
        max_deliver: u32,
        allow_unlimited: bool,
        backoff_nanos: Vec<u64>,
    ) -> Result<DeliveryConfig, ConfigError> {
        // Both 0 and u32::MAX are effectively unlimited: 0 by definition, and u32::MAX
        // because the lease delivery counter saturates there, so `deliveries > max` can
        // never fire and a poison message would redeliver forever. Both need the opt-in.
        if (max_deliver == 0 || max_deliver == u32::MAX) && !allow_unlimited {
            return Err(ConfigError::UnlimitedDeliverNotAllowed);
        }
        Ok(DeliveryConfig {
            max_deliver,
            allow_unlimited,
            backoff_nanos,
            attempts_flush_redeliveries: Self::DEFAULT_ATTEMPTS_FLUSH_REDELIVERIES,
        })
    }

    /// Overrides the redelivery-driven attempt-count flush threshold (#547), returning the
    /// config for chaining. `0` DISABLES the delivery-driven trigger entirely (the attempt
    /// counts then persist only on the legacy cadence: cursor-interval, clean disconnect,
    /// graceful shutdown, and eviction — the pre-#547 behavior, whose un-persisted lag is
    /// unbounded in redeliveries). A larger value amortizes further: the durable count may lag
    /// the true count by up to `n - 1` FULLY-ACCUMULATED redeliveries plus the current pass's
    /// grants, and `MaxDeliver -> DLQ` fires correspondingly later (never never) after a crash.
    /// The default ([`Self::DEFAULT_ATTEMPTS_FLUSH_REDELIVERIES`], 1) is the tight, safe bound.
    #[must_use]
    pub fn with_attempts_flush_redeliveries(mut self, n: u32) -> DeliveryConfig {
        self.attempts_flush_redeliveries = n;
        self
    }

    /// The redelivery-driven attempt-count flush threshold (#547): flush the durable attempt
    /// snapshot once this many redelivery grants have accumulated since the last flush; `0`
    /// means the delivery-driven trigger is disabled.
    #[must_use]
    pub fn attempts_flush_redeliveries(&self) -> u32 {
        self.attempts_flush_redeliveries
    }

    /// The configured delivery cap (`0` means unlimited).
    #[must_use]
    pub fn max_deliver(&self) -> u32 {
        self.max_deliver
    }

    /// Whether unlimited delivery is enabled.
    #[must_use]
    pub fn allows_unlimited(&self) -> bool {
        self.allow_unlimited
    }

    /// The disposition for a message whose delivery count is now `deliveries` (1-based,
    /// as returned by the lease grant). It is dead-lettered once it exceeds `max_deliver`;
    /// an unlimited cap (`0`) never dead-letters.
    #[must_use]
    pub fn disposition(&self, deliveries: u32) -> Disposition {
        if self.max_deliver != 0 && deliveries > self.max_deliver {
            Disposition::DeadLetter
        } else {
            Disposition::Deliver
        }
    }

    /// The backoff delay before retrying a message nacked on its `attempt`-th delivery
    /// (1-based). The schedule escalates by attempt and clamps to its final entry; an
    /// empty schedule means no extra delay (retry as soon as the visibility timeout or an
    /// explicit nack delay allows).
    #[must_use]
    pub fn nack_backoff(&self, attempt: u32) -> u64 {
        if self.backoff_nanos.is_empty() {
            return 0;
        }
        let last = self.backoff_nanos.len() - 1;
        let idx = usize::try_from(attempt.saturating_sub(1))
            .unwrap_or(usize::MAX)
            .min(last);
        self.backoff_nanos[idx]
    }

    /// The retry delay actually applied to a nack on its `attempt`-th delivery: an
    /// explicit per-nack delay (from [`AckVerb::Nack`]) takes precedence over the schedule;
    /// when none is given, the schedule's [`nack_backoff`](Self::nack_backoff) applies.
    #[must_use]
    pub fn effective_nack_delay(&self, attempt: u32, explicit_delay: Option<u64>) -> u64 {
        explicit_delay.unwrap_or_else(|| self.nack_backoff(attempt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn config(max: u32, backoff: Vec<u64>) -> DeliveryConfig {
        DeliveryConfig::new(max, false, backoff).unwrap()
    }

    #[test]
    fn delivers_up_to_the_cap_then_dead_letters() {
        let c = config(3, vec![]);
        assert_eq!(c.disposition(1), Disposition::Deliver);
        assert_eq!(c.disposition(2), Disposition::Deliver);
        assert_eq!(c.disposition(3), Disposition::Deliver);
        assert_eq!(c.disposition(4), Disposition::DeadLetter);
        assert_eq!(c.disposition(100), Disposition::DeadLetter);
    }

    #[test]
    fn unlimited_requires_opt_in_and_never_dead_letters() {
        assert_eq!(
            DeliveryConfig::new(0, false, vec![]).unwrap_err(),
            ConfigError::UnlimitedDeliverNotAllowed
        );
        let c = DeliveryConfig::new(0, true, vec![]).unwrap();
        assert_eq!(c.disposition(1), Disposition::Deliver);
        assert_eq!(c.disposition(1_000_000), Disposition::Deliver);
    }

    #[test]
    fn backoff_escalates_then_clamps_to_the_last_entry() {
        let c = config(5, vec![10, 50, 200]);
        assert_eq!(c.nack_backoff(1), 10);
        assert_eq!(c.nack_backoff(2), 50);
        assert_eq!(c.nack_backoff(3), 200);
        assert_eq!(c.nack_backoff(4), 200, "clamps to the last entry");
        assert_eq!(c.nack_backoff(99), 200);
        // attempt 0 is treated as the first.
        assert_eq!(c.nack_backoff(0), 10);
    }

    #[test]
    fn an_empty_backoff_schedule_means_no_delay() {
        let c = config(5, vec![]);
        assert_eq!(c.nack_backoff(1), 0);
        assert_eq!(c.nack_backoff(10), 0);
    }

    #[test]
    fn deliver_once_then_dead_letter_with_a_cap_of_one() {
        let c = config(1, vec![]);
        assert_eq!(c.disposition(1), Disposition::Deliver);
        assert_eq!(c.disposition(2), Disposition::DeadLetter);
    }

    #[test]
    fn a_saturated_delivery_count_still_dead_letters_under_a_finite_cap() {
        let c = config(5, vec![]);
        // The lease counter saturates at u32::MAX; a finite cap below it still fires.
        assert_eq!(c.disposition(u32::MAX), Disposition::DeadLetter);
    }

    #[test]
    fn max_deliver_of_u32_max_is_unlimited_and_needs_the_opt_in() {
        // u32::MAX could never dead-letter (the lease counter saturates there), so it is
        // treated as unlimited.
        assert_eq!(
            DeliveryConfig::new(u32::MAX, false, vec![]).unwrap_err(),
            ConfigError::UnlimitedDeliverNotAllowed
        );
        let c = DeliveryConfig::new(u32::MAX, true, vec![]).unwrap();
        assert_eq!(c.disposition(u32::MAX), Disposition::Deliver);
    }

    #[test]
    fn a_single_element_schedule_and_extreme_attempts_do_not_panic() {
        let c = config(5, vec![42]);
        assert_eq!(c.nack_backoff(0), 42);
        assert_eq!(c.nack_backoff(1), 42);
        assert_eq!(c.nack_backoff(u32::MAX), 42);
    }

    #[test]
    fn an_explicit_nack_delay_overrides_the_schedule() {
        let c = config(5, vec![10, 50, 200]);
        // No explicit delay: the schedule applies.
        assert_eq!(c.effective_nack_delay(2, None), 50);
        // An explicit delay wins, even zero (retry immediately).
        assert_eq!(c.effective_nack_delay(2, Some(7)), 7);
        assert_eq!(c.effective_nack_delay(2, Some(0)), 0);
    }

    #[test]
    fn the_attempts_flush_threshold_defaults_to_one_and_is_overridable() {
        // The safe default (#547): every accumulated redelivery makes the attempt snapshot due.
        let c = config(5, vec![]);
        assert_eq!(
            c.attempts_flush_redeliveries(),
            DeliveryConfig::DEFAULT_ATTEMPTS_FLUSH_REDELIVERIES
        );
        assert_eq!(c.attempts_flush_redeliveries(), 1);
        // Amortize (a nack-storm-heavy deployment) or disable (0, the legacy cadence) explicitly.
        assert_eq!(
            config(5, vec![])
                .with_attempts_flush_redeliveries(8)
                .attempts_flush_redeliveries(),
            8
        );
        assert_eq!(
            config(5, vec![])
                .with_attempts_flush_redeliveries(0)
                .attempts_flush_redeliveries(),
            0
        );
    }

    #[test]
    fn the_ack_vocabulary_is_distinct() {
        assert_ne!(AckVerb::Ack, AckVerb::Term);
        assert_ne!(AckVerb::Nack { delay_nanos: 0 }, AckVerb::Progress);
        assert_eq!(
            AckVerb::Nack { delay_nanos: 5 },
            AckVerb::Nack { delay_nanos: 5 }
        );
    }

    proptest! {
        /// A message is dead-lettered exactly when a finite cap is exceeded.
        #[test]
        fn dead_letter_iff_a_finite_cap_is_exceeded(
            // Generate only VALID configs directly: max == 0 (unlimited) requires the opt-in,
            // so force `allow` true there. The earlier `prop_assume!(max != 0 || allow)`
            // rejected ~2.5% of inputs, which exhausts proptest's global-reject budget under a
            // deep (nightly) sweep; constraining the strategy rejects nothing.
            (max, allow) in (0u32..20, any::<bool>())
                .prop_map(|(max, allow)| (max, allow || max == 0)),
            deliveries in 1u32..40,
        ) {
            let c = DeliveryConfig::new(max, allow, vec![]).unwrap();
            let expected = if max != 0 && deliveries > max {
                Disposition::DeadLetter
            } else {
                Disposition::Deliver
            };
            prop_assert_eq!(c.disposition(deliveries), expected);
        }

        /// nack_backoff matches the contract stated directly (not the implementation's
        /// index arithmetic): attempts 1..=len map to schedule[0..len], everything beyond
        /// len clamps to the last entry, attempt 0 is treated as the first, and an empty
        /// schedule is always 0.
        #[test]
        fn backoff_matches_the_contract(
            schedule in prop::collection::vec(0u64..1000, 0..8),
            attempt in 0u32..50,
        ) {
            let c = DeliveryConfig::new(5, false, schedule.clone()).unwrap();
            let delay = c.nack_backoff(attempt);
            let expected = if schedule.is_empty() {
                0
            } else {
                let one_based = usize::try_from(attempt).unwrap().max(1);
                schedule[one_based.min(schedule.len()) - 1]
            };
            prop_assert_eq!(delay, expected);
        }
    }
}
