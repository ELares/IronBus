// SPDX-License-Identifier: MIT OR Apache-2.0
//! The single-topic queue engine: the synchronous heart that wires the durable log to the
//! consumer primitives.
//!
//! It owns a [`Log`] (durable storage) plus, for one work-group, an [`AckCursor`]
//! (committed offset), a [`LeaseTable`] (in-flight visibility-timeout leases), and a
//! [`DeliveryConfig`] (max-deliver and backoff). [`Engine::produce`] appends a message and
//! makes it durable before returning; [`Engine::poll`] hands out the next deliverable
//! message under a fencing token; [`Engine::ack`] commits it. A message left unacked past
//! its visibility timeout is redelivered on a later poll, and a message that exceeds
//! max-deliver is parked (skipped, the dead-letter advisory) rather than looping forever.
//!
//! The engine is synchronous and deterministic: the caller supplies monotonic time
//! (`now`, nanoseconds) on each call, so it is fully testable without a runtime. The async
//! network server wraps it; one append actor owns the engine, which keeps the single-writer
//! rule. Delivery flow control is a sliding window of `max_in_flight` offsets above the
//! committed cursor (the max-ack-pending bound), so in-flight work never grows unbounded.

use ironbus_core::clock::Clock;
use ironbus_core::cursor::AckCursor;
use ironbus_core::delivery::{DeliveryConfig, Disposition};
use ironbus_core::lease::{AckOutcome, Claim, LeaseConfig, LeaseTable, LeaseToken};
use ironbus_core::types::Offset;
use ironbus_storage::fs::Filesystem;
use ironbus_storage::log::{Append, Log, LogConfig};
use ironbus_storage::segment::{OwnedRecord, StorageError};

/// Tunables for an [`Engine`].
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// The storage log configuration.
    pub log: LogConfig,
    /// The lease (visibility timeout and hard cap) configuration.
    pub lease: LeaseConfig,
    /// The delivery (max-deliver and backoff) configuration.
    pub delivery: DeliveryConfig,
    /// The max-ack-pending window: at most this many offsets above the committed cursor
    /// may be in flight at once. Bounds in-flight work and the poll scan.
    pub max_in_flight: u32,
}

/// A message handed to a consumer by [`Engine::poll`], plus the token to ack it with.
#[derive(Clone, Debug)]
pub struct Delivery {
    /// The log offset of the message.
    pub offset: Offset,
    /// The fencing token to carry on the ack.
    pub token: LeaseToken,
    /// How many times this message has now been delivered (starts at 1).
    pub deliveries: u32,
    /// The message itself.
    pub record: OwnedRecord,
}

/// The result of a [`Engine::poll`].
#[derive(Clone, Debug)]
pub enum Poll {
    /// A message to deliver to a consumer.
    Message(Delivery),
    /// A message that exceeded max-deliver was parked (committed past, not redelivered).
    /// The caller emits the dead-letter advisory and, later, writes it to the DLQ topic.
    Parked {
        /// The offset that was parked.
        offset: Offset,
        /// The parked message.
        record: OwnedRecord,
    },
    /// Nothing is deliverable right now (all caught up, or the in-flight window is full).
    Idle,
}

/// The result of an [`Engine::ack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckResult {
    /// The ack matched the current lease; the message is committed.
    Acked,
    /// The token was stale (already acked, or redelivered); the ack was ignored.
    Fenced,
}

/// A single-topic, single-work-group queue engine.
pub struct Engine<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    cursor: AckCursor,
    leases: LeaseTable,
    delivery: DeliveryConfig,
    max_in_flight: u32,
}

impl<F: Filesystem, C: Clock> Engine<F, C> {
    /// Opens the engine, recovering the durable log. The committed cursor and the lease
    /// table start empty: a restart redelivers everything (the durable consumer cursor is
    /// follow-up work), which is safe at-least-once behavior.
    ///
    /// # Errors
    /// Propagates a storage error from opening the log.
    pub fn open(fs: F, clock: C, config: EngineConfig) -> Result<Engine<F, C>, StorageError> {
        let log = Log::open(fs, clock, config.log)?;
        Ok(Engine {
            log,
            cursor: AckCursor::new(),
            leases: LeaseTable::new(config.lease),
            delivery: config.delivery,
            max_in_flight: config.max_in_flight,
        })
    }

    /// Appends a message and makes it durable before returning its offset (so a producer's
    /// ack is post-fsync).
    ///
    /// # Errors
    /// Propagates a storage error from the append or sync.
    pub fn produce(&mut self, message: &Append<'_>) -> Result<Offset, StorageError> {
        let offset = self.log.append(message)?;
        self.log.sync()?;
        Ok(offset)
    }

    /// Claims and returns the next deliverable message, or [`Poll::Idle`] if none is
    /// available within the in-flight window. A poison message (over max-deliver) is parked
    /// and reported as [`Poll::Parked`].
    ///
    /// # Errors
    /// Propagates a storage error from reading the record.
    pub fn poll(&mut self, now: u64) -> Result<Poll, StorageError> {
        let committed = self.cursor.committed().get();
        let flushed = self.log.flushed_offset().get();
        // The delivery window: at most `max_in_flight` offsets above the committed cursor,
        // and never past the durable end.
        let window_end = committed
            .saturating_add(u64::from(self.max_in_flight))
            .min(flushed);

        let mut offset = committed;
        while offset < window_end {
            let off = Offset::new(offset);
            if self.cursor.is_acked(off) {
                offset += 1;
                continue;
            }
            match self.leases.claim(off, now) {
                Claim::InFlight => {
                    offset += 1;
                }
                Claim::Exhausted => return Ok(Poll::Idle),
                Claim::Granted { token, deliveries } => {
                    let Some(record) = self.log.read_from(off, 1)?.into_iter().next() else {
                        // Unreachable: `off` is below the flushed offset, so a record exists.
                        return Ok(Poll::Idle);
                    };
                    return Ok(match self.delivery.disposition(deliveries) {
                        Disposition::Deliver => Poll::Message(Delivery {
                            offset: off,
                            token,
                            deliveries,
                            record,
                        }),
                        Disposition::DeadLetter => {
                            // Park: drop the lease and commit past it so it never redelivers.
                            self.leases.ack(&token);
                            self.cursor.ack(off);
                            Poll::Parked {
                                offset: off,
                                record,
                            }
                        }
                    });
                }
            }
        }
        Ok(Poll::Idle)
    }

    /// Acks the message named by `token`: removes its lease (fenced if stale) and advances
    /// the committed cursor over any newly contiguous prefix.
    pub fn ack(&mut self, token: &LeaseToken) -> AckResult {
        match self.leases.ack(token) {
            AckOutcome::Acked => {
                self.cursor.ack(token.offset);
                AckResult::Acked
            }
            AckOutcome::Fenced => AckResult::Fenced,
        }
    }

    /// The committed offset: every offset below it is acked, and where a restart resumes.
    #[must_use]
    pub fn committed_offset(&self) -> Offset {
        self.cursor.committed()
    }

    /// The number of messages currently in flight (leased, not yet acked).
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.leases.in_flight()
    }

    /// Consumes the engine and returns its filesystem, so the log can be reopened.
    #[must_use]
    pub fn into_filesystem(self) -> F {
        self.log.into_filesystem()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::types::RecordFlags;
    use ironbus_storage::fs::InMemoryFs;

    fn config(max_in_flight: u32, max_deliver: u32) -> EngineConfig {
        EngineConfig {
            log: LogConfig::default(),
            // 30 ns visibility, 100 ns cap, so tests advance time in small integers.
            lease: LeaseConfig {
                visibility_nanos: 30,
                hard_cap_nanos: 100,
            },
            delivery: DeliveryConfig::new(max_deliver, false, vec![]).unwrap(),
            max_in_flight,
        }
    }

    fn open(config: EngineConfig) -> Engine<InMemoryFs, ManualClock> {
        Engine::open(InMemoryFs::new(), ManualClock::new(), config).unwrap()
    }

    fn produce(e: &mut Engine<InMemoryFs, ManualClock>, payload: &[u8]) -> Offset {
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        })
        .unwrap()
    }

    fn message(poll: Poll) -> Delivery {
        match poll {
            Poll::Message(d) => d,
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn produce_poll_ack_advances_the_cursor() {
        let mut e = open(config(10, 5));
        assert_eq!(produce(&mut e, b"a"), Offset::new(0));
        assert_eq!(produce(&mut e, b"b"), Offset::new(1));

        let d0 = message(e.poll(0).unwrap());
        assert_eq!(d0.offset, Offset::new(0));
        assert_eq!(d0.record.payload, b"a");
        assert_eq!(d0.deliveries, 1);
        assert_eq!(e.ack(&d0.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));

        let d1 = message(e.poll(0).unwrap());
        assert_eq!(d1.offset, Offset::new(1));
        assert_eq!(e.ack(&d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(2));

        assert!(matches!(e.poll(0).unwrap(), Poll::Idle));
    }

    #[test]
    fn an_in_flight_message_is_not_redelivered_until_it_expires() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let d = message(e.poll(0).unwrap());
        // Still within the visibility window: nothing else to deliver.
        assert!(matches!(e.poll(10).unwrap(), Poll::Idle));
        // Past the 30 ns window: redelivered with a higher delivery count and a new token.
        let d2 = message(e.poll(40).unwrap());
        assert_eq!(d2.offset, Offset::new(0));
        assert_eq!(d2.deliveries, 2);
        assert_ne!(d2.token.generation, d.token.generation);
        // The original token can no longer ack (fenced); the redelivered one can.
        assert_eq!(e.ack(&d.token), AckResult::Fenced);
        assert_eq!(e.ack(&d2.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));
    }

    #[test]
    fn out_of_order_acks_advance_the_cursor_over_the_contiguous_prefix() {
        let mut e = open(config(10, 5));
        for p in [b"a", b"b", b"c"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        let d1 = message(e.poll(0).unwrap());
        let d2 = message(e.poll(0).unwrap());
        // Ack out of order: 1, then 2, then 0.
        e.ack(&d1.token);
        assert_eq!(
            e.committed_offset(),
            Offset::new(0),
            "0 still unacked, cannot advance"
        );
        e.ack(&d2.token);
        assert_eq!(e.committed_offset(), Offset::new(0));
        e.ack(&d0.token);
        assert_eq!(
            e.committed_offset(),
            Offset::new(3),
            "0 acked: jumps over 1 and 2"
        );
    }

    #[test]
    fn the_in_flight_window_bounds_delivery() {
        let mut e = open(config(2, 5)); // max 2 in flight
        for p in [b"a", b"b", b"c", b"d"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        let _d1 = message(e.poll(0).unwrap());
        // Window full (offsets 0 and 1 in flight); nothing more even though c, d exist.
        assert!(matches!(e.poll(0).unwrap(), Poll::Idle));
        assert_eq!(e.in_flight(), 2);
        // Acking 0 slides the window forward; offset 2 becomes deliverable.
        e.ack(&d0.token);
        let d2 = message(e.poll(0).unwrap());
        assert_eq!(d2.offset, Offset::new(2));
    }

    #[test]
    fn a_message_over_max_deliver_is_parked() {
        let mut e = open(config(10, 1)); // max_deliver 1
        produce(&mut e, b"poison");
        // First delivery.
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.deliveries, 1);
        // Expire without acking; the second delivery exceeds max_deliver and is parked.
        match e.poll(40).unwrap() {
            Poll::Parked { offset, record } => {
                assert_eq!(offset, Offset::new(0));
                assert_eq!(record.payload, b"poison");
            }
            other => panic!("expected Parked, got {other:?}"),
        }
        // The poison message is committed past and never redelivers.
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert!(matches!(e.poll(80).unwrap(), Poll::Idle));
    }

    #[test]
    fn reopen_recovers_the_durable_log_and_redelivers_uncommitted_messages() {
        let mut e = open(config(10, 5));
        for p in [b"a", b"b"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token); // ack 0, but the cursor is not durable yet
        let fs = e.into_filesystem();

        // Reopen: the log is recovered, but the committed cursor resets, so everything
        // redelivers (at-least-once; the durable cursor is follow-up work).
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(0));
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::new(0));
        assert_eq!(d.record.payload, b"a");
        let d_b = message(e.poll(0).unwrap());
        assert_eq!(d_b.record.payload, b"b");
    }
}
