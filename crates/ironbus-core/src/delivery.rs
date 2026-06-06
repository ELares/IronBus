// SPDX-License-Identifier: MIT OR Apache-2.0
//! Delivery policy: the ack vocabulary, max-deliver poison detection, and nack backoff.
//!
//! This is the pure decision layer of the consumer model. It says what each ack verb
//! means, when a repeatedly-failing message becomes poison (and must move to the
//! dead-letter queue rather than redeliver forever), and how long to wait before a
//! nacked message is retried. The durable side, appending to the DLQ topic and
//! tombstoning the source in-flight entry under one fsync with idempotent recovery, is
//! the server's job; this module owns only the IO-free policy it drives.

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
    /// The message has now failed `max_deliver` times: route it to the dead-letter queue
    /// and stop redelivering it.
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
}

impl DeliveryConfig {
    /// The default cap on delivery attempts before a message is dead-lettered.
    pub const DEFAULT_MAX_DELIVER: u32 = 5;

    /// Builds a delivery config.
    ///
    /// `max_deliver` caps delivery attempts; the `max_deliver + 1`-th attempt is poison
    /// and dead-lettered. A `max_deliver` of zero means unlimited and is rejected unless
    /// `allow_unlimited` is set. `backoff_nanos` is the escalating per-attempt nack delay
    /// schedule, indexed by attempt and clamped to its last entry; empty means no delay.
    ///
    /// # Errors
    /// Returns [`ConfigError::UnlimitedDeliverNotAllowed`] for an unguarded unlimited cap.
    pub fn new(
        max_deliver: u32,
        allow_unlimited: bool,
        backoff_nanos: Vec<u64>,
    ) -> Result<DeliveryConfig, ConfigError> {
        if max_deliver == 0 && !allow_unlimited {
            return Err(ConfigError::UnlimitedDeliverNotAllowed);
        }
        Ok(DeliveryConfig {
            max_deliver,
            allow_unlimited,
            backoff_nanos,
        })
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
            max in 0u32..20,
            allow in any::<bool>(),
            deliveries in 1u32..40,
        ) {
            prop_assume!(max != 0 || allow);
            let c = DeliveryConfig::new(max, allow, vec![]).unwrap();
            let expected = if max != 0 && deliveries > max {
                Disposition::DeadLetter
            } else {
                Disposition::Deliver
            };
            prop_assert_eq!(c.disposition(deliveries), expected);
        }

        /// nack_backoff never indexes out of bounds and clamps to the last entry; on a
        /// non-decreasing schedule the delay is non-decreasing in attempt.
        #[test]
        fn backoff_clamps_and_is_monotonic_on_a_sorted_schedule(
            mut schedule in prop::collection::vec(0u64..1000, 0..8),
            attempt in 0u32..50,
        ) {
            schedule.sort_unstable();
            let c = DeliveryConfig::new(5, false, schedule.clone()).unwrap();
            let delay = c.nack_backoff(attempt);
            if schedule.is_empty() {
                prop_assert_eq!(delay, 0);
            } else {
                prop_assert_eq!(delay, *schedule.last().unwrap().min(
                    &schedule[(attempt.saturating_sub(1) as usize).min(schedule.len() - 1)]
                ));
                // Non-decreasing in attempt on a sorted schedule.
                if attempt >= 1 {
                    prop_assert!(c.nack_backoff(attempt) >= c.nack_backoff(attempt - 1));
                }
            }
        }
    }
}
