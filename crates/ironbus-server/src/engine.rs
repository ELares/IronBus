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
use ironbus_core::lease::{
    AckOutcome, Claim, ExtendOutcome, LeaseConfig, LeaseTable, LeaseToken, NackOutcome,
};
use ironbus_core::types::Offset;
use ironbus_storage::checkpoint::Checkpoint;
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
    /// Checkpoint the committed cursor after it advances at least this many offsets since the
    /// last checkpoint, bounding how many messages a crash redelivers. A value of 0 is treated
    /// as 1 (checkpoint on every advance). A clean disconnect also flushes the cursor.
    pub checkpoint_interval: u64,
}

/// An error from the engine.
#[derive(Debug)]
pub enum EngineError {
    /// A storage-layer error (append, sync, recovery, or read).
    Storage(StorageError),
    /// `max_in_flight` was zero, which would deliver nothing: rejected at open.
    ZeroMaxInFlight,
    /// The lease generation space is exhausted (after `u64::MAX` grants, unreachable in any
    /// real deployment): the engine refuses to deliver rather than silently wedge.
    GenerationExhausted,
    /// An internal invariant broke: a deliverable offset had no record in the log.
    MissingRecord {
        /// The offset that should have held a record.
        offset: u64,
    },
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EngineError::Storage(e) => write!(f, "storage error: {e}"),
            EngineError::ZeroMaxInFlight => write!(f, "max_in_flight must be greater than zero"),
            EngineError::GenerationExhausted => write!(f, "lease generation space is exhausted"),
            EngineError::MissingRecord { offset } => {
                write!(f, "no record at deliverable offset {offset}")
            }
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EngineError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StorageError> for EngineError {
    fn from(e: StorageError) -> Self {
        EngineError::Storage(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Storage(StorageError::Io(e))
    }
}

impl EngineError {
    /// Whether this error leaves the engine permanently unusable, the writer is frozen or
    /// an internal invariant broke, so a caller should stop rather than keep retrying.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            EngineError::GenerationExhausted
                | EngineError::MissingRecord { .. }
                | EngineError::Storage(StorageError::WriterFrozen)
        )
    }
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

/// The outcome of [`Engine::nack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NackResult {
    /// The message was requeued for redelivery (immediately, or after the requested delay).
    Requeued,
    /// The token was stale (already acked, or redelivered); the nack was ignored.
    Fenced,
}

/// The outcome of [`Engine::progress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressResult {
    /// The lease deadline was extended by one visibility window.
    Extended,
    /// The hard cap from the attempt start has been reached; the lease cannot be extended
    /// further and will expire (and the message redeliver) on schedule.
    CapReached,
    /// The token was stale (already acked, or redelivered); the progress was ignored.
    Fenced,
}

/// A single-topic, single-work-group queue engine.
pub struct Engine<F: Filesystem, C: Clock> {
    log: Log<F, C>,
    cursor: AckCursor,
    leases: LeaseTable,
    delivery: DeliveryConfig,
    max_in_flight: u32,
    checkpoint: Checkpoint<F::File>,
    checkpoint_interval: u64,
    last_checkpointed: u64,
}

/// The file name of the work-group's durable committed-cursor checkpoint.
const CURSOR_CHECKPOINT: &str = "cursor.ckpt";

impl<F: Filesystem, C: Clock> Engine<F, C> {
    /// Opens the engine, recovering the durable log and the durable committed cursor (so a
    /// restart resumes from the last checkpoint, redelivering only the uncommitted tail).
    /// The lease table starts empty, so anything that was in flight at the crash
    /// redelivers, which is safe at-least-once behavior.
    ///
    /// # Errors
    /// Returns [`EngineError::ZeroMaxInFlight`] for a zero window, or a storage error from
    /// opening the log or the cursor checkpoint.
    pub fn open(fs: F, clock: C, config: EngineConfig) -> Result<Engine<F, C>, EngineError> {
        if config.max_in_flight == 0 {
            return Err(EngineError::ZeroMaxInFlight);
        }
        let log = Log::open(fs, clock, config.log)?;

        // Open (creating if absent) the cursor checkpoint through the log's filesystem.
        let checkpoint_file = {
            let fs = log.filesystem();
            if fs.exists(CURSOR_CHECKPOINT)? {
                fs.open(CURSOR_CHECKPOINT)?
            } else {
                let file = fs.create_new(CURSOR_CHECKPOINT)?;
                fs.sync_dir()?; // the new file's directory entry must be durable
                file
            }
        };
        let (checkpoint, recovered) = Checkpoint::open(checkpoint_file)?;
        // The committed cursor is the LEADING 8 little-endian bytes of the payload; reading
        // a prefix (not requiring an exact length) keeps recovery working once the payload
        // is extended to also carry the resilience counters, rather than silently resetting
        // the cursor to zero and redelivering the whole log.
        let recovered_offset = recovered
            .as_deref()
            .and_then(|p| p.get(..8))
            .and_then(|s| <[u8; 8]>::try_from(s).ok())
            .map_or(0, u64::from_le_bytes);
        let flushed = log.flushed_offset().get();
        // The committed cursor can never legitimately exceed the durable log head; if it
        // does, the log recovered below a valid checkpoint (corruption/truncation). Clamping
        // down is at-least-once-safe (duplicates, never loss), but assert loudly in debug.
        debug_assert!(
            recovered_offset <= flushed,
            "checkpoint committed {recovered_offset} exceeds the durable head {flushed}"
        );
        let committed = recovered_offset.min(flushed);

        Ok(Engine {
            log,
            cursor: AckCursor::resume(Offset::new(committed)),
            leases: LeaseTable::new(config.lease),
            delivery: config.delivery,
            max_in_flight: config.max_in_flight,
            checkpoint,
            checkpoint_interval: config.checkpoint_interval,
            last_checkpointed: committed,
        })
    }

    /// Durably records the current committed offset, so a later [`Engine::open`] resumes
    /// from here. The checkpoint is an optimization: it may lag the true committed cursor
    /// (a crash then redelivers a few already-processed messages, which at-least-once
    /// permits), but it never records an offset that was not committed.
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    pub fn checkpoint_cursor(&mut self) -> Result<(), EngineError> {
        let committed = self.cursor.committed().get();
        // Skip a redundant write when nothing advanced since the last checkpoint, so a forced
        // checkpoint (e.g. on a connection close that did no acking) is a no-op.
        if committed > self.last_checkpointed {
            self.checkpoint.write(&committed.to_le_bytes())?;
            self.last_checkpointed = committed;
        }
        Ok(())
    }

    /// Checkpoints the committed cursor if it has advanced at least `checkpoint_interval`
    /// offsets since the last checkpoint, returning whether a checkpoint was written. This
    /// bounds how many messages a crash redelivers to roughly `checkpoint_interval` while
    /// keeping the checkpoint write rate far below one per ack (edge flash endurance).
    ///
    /// # Errors
    /// Propagates a storage error from writing the checkpoint.
    pub fn maybe_checkpoint(&mut self) -> Result<bool, EngineError> {
        let committed = self.cursor.committed().get();
        if committed.saturating_sub(self.last_checkpointed) >= self.checkpoint_interval.max(1) {
            self.checkpoint.write(&committed.to_le_bytes())?;
            self.last_checkpointed = committed;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Appends a message and makes it durable before returning its offset (so a producer's
    /// ack is post-fsync).
    ///
    /// # Errors
    /// Propagates a storage error from the append or sync.
    pub fn produce(&mut self, message: &Append<'_>) -> Result<Offset, EngineError> {
        let offset = self.log.append(message)?;
        self.log.sync()?;
        Ok(offset)
    }

    /// Claims and returns the next deliverable message, or [`Poll::Idle`] if none is
    /// available within the in-flight window. A poison message (over max-deliver) is parked
    /// and reported as [`Poll::Parked`].
    ///
    /// # Errors
    /// Returns [`EngineError::GenerationExhausted`] if the lease space is exhausted, or a
    /// storage error from reading the record.
    pub fn poll(&mut self, now: u64) -> Result<Poll, EngineError> {
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
                Claim::Exhausted => return Err(EngineError::GenerationExhausted),
                Claim::Granted { token, deliveries } => {
                    let Some(record) = self.log.read_from(off, 1)?.into_iter().next() else {
                        // Unreachable: `off` is below the flushed offset, so a record exists.
                        // Surface it loudly rather than silently stalling if an invariant breaks.
                        return Err(EngineError::MissingRecord { offset });
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

    /// Like [`Engine::poll`] but reads the current monotonic time from the engine's own
    /// clock, so the caller does not have to supply it.
    ///
    /// # Errors
    /// As [`Engine::poll`].
    pub fn poll_now(&mut self) -> Result<Poll, EngineError> {
        let now = self.log.now_monotonic();
        self.poll(now)
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

    /// Nacks the message named by `token`: requeues it for redelivery after `delay_ms`
    /// (immediately if zero), fencing the nacking holder. The `MaxDeliver` / dead-letter
    /// decision is made by [`Engine::poll`] when the message is next claimed, so a message
    /// nacked past its delivery cap is parked rather than looping. `MaxDeliver` is enforced
    /// there, not here.
    ///
    /// # Errors
    /// Returns [`EngineError::GenerationExhausted`] if the lease generation space is spent.
    pub fn nack(&mut self, token: &LeaseToken, delay_ms: u64) -> Result<NackResult, EngineError> {
        let now = self.log.now_monotonic();
        // Convert the wire delay (milliseconds) to the monotonic-nanosecond units the lease
        // deadlines use, saturating rather than overflowing on an absurd delay.
        let delay_nanos = delay_ms.saturating_mul(1_000_000);
        Ok(match self.leases.nack(token, now, delay_nanos) {
            NackOutcome::Requeued { .. } => NackResult::Requeued,
            NackOutcome::Fenced => NackResult::Fenced,
            NackOutcome::Exhausted => return Err(EngineError::GenerationExhausted),
        })
    }

    /// Terminates delivery of the message named by `token`: an intentional drop that commits
    /// past it so it never redelivers and is NOT dead-lettered. Mechanically a commit, like
    /// [`Engine::ack`], and distinct only in the caller's intent (a future metrics or
    /// dead-letter-policy split can diverge them); sharing the commit path keeps the cursor
    /// and lease invariants identical to a normal ack.
    pub fn term(&mut self, token: &LeaseToken) -> AckResult {
        self.ack(token)
    }

    /// Extends the lease named by `token` by one visibility window (the consumer is still
    /// working), clamped to the hard cap from the attempt start. A stale token is fenced; a
    /// lease already at its cap returns [`ProgressResult::CapReached`].
    pub fn progress(&mut self, token: &LeaseToken) -> ProgressResult {
        let now = self.log.now_monotonic();
        match self.leases.extend(token, now) {
            ExtendOutcome::Extended(_) => ProgressResult::Extended,
            ExtendOutcome::CapReached => ProgressResult::CapReached,
            ExtendOutcome::Fenced => ProgressResult::Fenced,
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
            checkpoint_interval: 1024,
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
    fn open_rejects_a_zero_in_flight_window() {
        // `matches!` avoids needing `Engine: Debug` for the Ok side.
        assert!(matches!(
            Engine::open(InMemoryFs::new(), ManualClock::new(), config(0, 5)),
            Err(EngineError::ZeroMaxInFlight)
        ));
    }

    #[test]
    fn the_default_max_deliver_parks_only_on_the_sixth_claim() {
        // max_deliver = 5: delivered exactly 5 times, parked on the 6th claim.
        let mut e = open(config(10, 5));
        produce(&mut e, b"poison");
        let mut now = 0u64;
        for expected in 1..=5u32 {
            let d = message(e.poll(now).unwrap());
            assert_eq!(d.deliveries, expected);
            now += 40; // expire each attempt without acking
        }
        // The sixth claim exceeds max_deliver and parks.
        match e.poll(now).unwrap() {
            Poll::Parked { offset, .. } => assert_eq!(offset, Offset::new(0)),
            other => panic!("expected Parked on the 6th, got {other:?}"),
        }
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert_eq!(e.in_flight(), 0, "a parked message holds no lease");
    }

    #[test]
    fn a_full_retry_then_ack_cycle_works() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"x");
        let d1 = message(e.poll(0).unwrap());
        assert_eq!(d1.deliveries, 1);
        let d2 = message(e.poll(40).unwrap()); // expired, redelivered
        assert_eq!(d2.deliveries, 2);
        let d3 = message(e.poll(80).unwrap()); // expired again, redelivered
        assert_eq!(d3.deliveries, 3);
        // Finally ack the latest token; earlier tokens are fenced.
        assert_eq!(e.ack(&d1.token), AckResult::Fenced);
        assert_eq!(e.ack(&d2.token), AckResult::Fenced);
        assert_eq!(e.ack(&d3.token), AckResult::Acked);
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert_eq!(e.in_flight(), 0);
    }

    #[test]
    fn in_flight_never_exceeds_the_window_under_out_of_order_churn() {
        let mut e = open(config(3, 5)); // window of 3
        for _ in 0..20 {
            produce(&mut e, b"m");
        }
        let mut now = 0u64;
        let mut held: Vec<LeaseToken> = Vec::new();
        for round in 0..40 {
            // Deliver as much as the window allows.
            while let Poll::Message(d) = e.poll(now).unwrap() {
                held.push(d.token);
            }
            assert!(
                e.in_flight() <= 3,
                "in_flight {} exceeded the window",
                e.in_flight()
            );
            // Ack one held token out of order (the middle one), if any.
            if !held.is_empty() {
                let idx = (round * 7 + 1) % held.len();
                let tok = held.remove(idx);
                e.ack(&tok);
            }
            now += 5;
        }
        assert!(e.in_flight() <= 3);
    }

    #[test]
    fn checkpoint_then_reopen_resumes_from_the_committed_offset() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Consume and ack the first two, then checkpoint the cursor.
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        let d1 = message(e.poll(0).unwrap());
        e.ack(&d1.token);
        assert_eq!(e.committed_offset(), Offset::new(2));
        e.checkpoint_cursor().unwrap();
        let fs = e.into_filesystem();

        // Reopen: the committed cursor resumes at 2, so only the uncommitted tail (c)
        // redelivers, NOT a and b, and nothing in [2, flushed) is skipped.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(2));
        // Drain the whole window: exactly offset 2 ("c") is deliverable.
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push((d.offset.get(), d.record.payload.clone()));
        }
        assert_eq!(
            delivered,
            vec![(2, b"c".to_vec())],
            "only the uncommitted tail redelivers"
        );
    }

    #[test]
    fn messages_produced_after_a_checkpoint_survive_and_deliver_after_reopen() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"a");
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token); // committed = 1
        e.checkpoint_cursor().unwrap();
        // Produce more AFTER the checkpoint; these are durable but uncommitted.
        produce(&mut e, b"b");
        produce(&mut e, b"c");
        let fs = e.into_filesystem();

        // Reopen: resume at 1, and the post-checkpoint tail (b, c) must all survive.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push((d.offset.get(), d.record.payload.clone()));
        }
        assert_eq!(
            delivered,
            vec![(1, b"b".to_vec()), (2, b"c".to_vec())],
            "no produced-and-durable message is lost across the restart"
        );
    }

    #[test]
    fn a_fully_consumed_checkpointed_queue_is_idle_after_reopen() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b"] {
            produce(&mut e, p);
        }
        for _ in 0..2 {
            let d = message(e.poll(0).unwrap());
            e.ack(&d.token);
        }
        assert_eq!(e.committed_offset(), Offset::new(2));
        e.checkpoint_cursor().unwrap();
        let fs = e.into_filesystem();

        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(2));
        assert!(
            matches!(e.poll(0).unwrap(), Poll::Idle),
            "nothing left to deliver"
        );
    }

    #[test]
    fn a_stale_checkpoint_only_redelivers_the_uncheckpointed_tail() {
        let mut e = open(config(10, 5));
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        // Ack 0, checkpoint (committed=1), then ack 1 WITHOUT a second checkpoint.
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        e.checkpoint_cursor().unwrap();
        let d1 = message(e.poll(0).unwrap());
        e.ack(&d1.token);
        assert_eq!(e.committed_offset(), Offset::new(2));
        let fs = e.into_filesystem();

        // The checkpoint lagged at 1, so reopen resumes at 1 and redelivers b (already
        // processed) and c: a lagging checkpoint costs duplicates, never loss.
        let mut e = Engine::open(fs, ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::new(1));
        assert_eq!(d.record.payload, b"b");
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

    #[cfg(unix)]
    #[test]
    fn durable_cursor_resumes_on_a_real_directory() {
        use ironbus_storage::fs::StdFs;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let put = |e: &mut Engine<StdFs, ManualClock>, payload: &[u8]| {
            e.produce(&Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: b"",
                headers: b"",
                payload,
            })
            .unwrap();
        };

        let mut e =
            Engine::open(StdFs::new(root.clone()), ManualClock::new(), config(10, 5)).unwrap();
        put(&mut e, b"a");
        put(&mut e, b"b");
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        e.checkpoint_cursor().unwrap();
        drop(e);

        let mut e = Engine::open(StdFs::new(root), ManualClock::new(), config(10, 5)).unwrap();
        assert_eq!(e.committed_offset(), Offset::new(1));
        let d = message(e.poll(0).unwrap());
        assert_eq!(d.offset, Offset::new(1));
        assert_eq!(d.record.payload, b"b");
    }

    #[test]
    fn a_nacked_message_redelivers_with_an_escalated_delivery_count() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"work");
        // poll_now and nack share the engine's own clock, so a zero-delay nack is reclaimable
        // at the same instant and redelivers on the next poll.
        let d0 = message(e.poll_now().unwrap());
        assert_eq!(d0.deliveries, 1);
        assert_eq!(e.nack(&d0.token, 0).unwrap(), NackResult::Requeued);
        // The nacking token is fenced: a late ack cannot commit the unprocessed message.
        assert_eq!(e.ack(&d0.token), AckResult::Fenced);
        // Redelivered: same offset, escalated delivery count, a fresh generation.
        let d1 = message(e.poll_now().unwrap());
        assert_eq!(d1.offset, d0.offset);
        assert_eq!(d1.deliveries, 2);
        assert_ne!(d1.token.generation, d0.token.generation);
        // The fresh token commits normally.
        assert_eq!(e.ack(&d1.token), AckResult::Acked);
        assert_eq!(e.committed_offset().get(), 1);
    }

    #[test]
    fn a_stale_nack_is_fenced() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"work");
        let d0 = message(e.poll_now().unwrap());
        e.ack(&d0.token); // commit, so the token is now stale
        assert_eq!(e.nack(&d0.token, 0).unwrap(), NackResult::Fenced);
    }

    #[test]
    fn term_drops_the_message_without_redelivery() {
        let mut e = open(config(10, 5));
        produce(&mut e, b"drop-me");
        let d = message(e.poll_now().unwrap());
        // Term is an intentional drop: it commits past the message (cursor advances) so it
        // never redelivers, the same mechanism as ack.
        assert_eq!(e.term(&d.token), AckResult::Acked);
        assert_eq!(e.committed_offset().get(), 1);
        assert!(matches!(e.poll_now().unwrap(), Poll::Idle));
        // A stale term is fenced (no double-commit).
        assert_eq!(e.term(&d.token), AckResult::Fenced);
    }

    #[test]
    fn progress_extends_the_lease_then_caps_at_the_hard_cap() {
        // config(_, _) sets visibility 30 ns, hard cap 100 ns. Use an Arc<ManualClock> the
        // test advances, since progress reads the engine's own clock.
        let clock = std::sync::Arc::new(ManualClock::new());
        let mut e = Engine::open(
            InMemoryFs::new(),
            std::sync::Arc::clone(&clock),
            config(10, 5),
        )
        .unwrap();
        // The produce test helper is monomorphic over ManualClock, so inline it for this
        // Arc<ManualClock> engine.
        e.produce(&Append {
            timestamp_ms: 0,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload: b"slow",
        })
        .unwrap();
        // Deliver at t=0: deadline 30, attempt_start 0, hard cap at t=100.
        let d = message(e.poll_now().unwrap());
        // At t=25, progress extends the deadline to 55 (< cap), so it stays in flight.
        clock.advance_monotonic_nanos(25);
        assert_eq!(e.progress(&d.token), ProgressResult::Extended);
        assert!(
            matches!(e.poll_now().unwrap(), Poll::Idle),
            "still leased after extend"
        );
        // At t=100 (attempt_start + hard cap), progress can no longer extend.
        clock.advance_monotonic_nanos(75);
        assert_eq!(e.progress(&d.token), ProgressResult::CapReached);
        // A stale token is fenced.
        e.ack(&d.token);
        assert_eq!(e.progress(&d.token), ProgressResult::Fenced);
    }

    #[test]
    fn maybe_checkpoint_bounds_replay_and_reopen_resumes() {
        // interval = 2: a single ack does not reach the threshold (reopen would redeliver),
        // but the second ack does and persists the cursor, so reopen resumes past both. This
        // is the bounded-replay-window contract.
        let mut c = config(10, 5);
        c.checkpoint_interval = 2;
        let mut e = open(c);
        for p in [&b"a"[..], b"b", b"c"] {
            produce(&mut e, p);
        }
        let d0 = message(e.poll(0).unwrap());
        e.ack(&d0.token);
        assert_eq!(e.committed_offset(), Offset::new(1));
        assert!(
            !e.maybe_checkpoint().unwrap(),
            "1 < interval 2: no checkpoint yet"
        );

        let d1 = message(e.poll(0).unwrap());
        e.ack(&d1.token);
        assert_eq!(e.committed_offset(), Offset::new(2));
        assert!(
            e.maybe_checkpoint().unwrap(),
            "2 >= interval 2: checkpoints"
        );

        let fs = e.into_filesystem();
        let mut c2 = config(10, 5);
        c2.checkpoint_interval = 2;
        let mut e = Engine::open(fs, ManualClock::new(), c2).unwrap();
        // The checkpoint persisted committed = 2, so only the uncommitted tail (c) redelivers.
        assert_eq!(e.committed_offset(), Offset::new(2));
        let mut delivered = Vec::new();
        while let Poll::Message(d) = e.poll(0).unwrap() {
            delivered.push(d.offset.get());
        }
        assert_eq!(
            delivered,
            vec![2],
            "only the uncheckpointed tail redelivers"
        );
    }
}
