// SPDX-License-Identifier: MIT OR Apache-2.0
//! The bounded Level-2 produce-confirm registry (#497, part of #499): the per-offset map that
//! turns a CONSUMER ack into a server->producer `ProduceConfirm`.
//!
//! ## What it is
//!
//! Level 2 (server+client ack) of the tunable produce ack-level spectrum (#499) confirms a publish
//! only after a CONSUMER has acked it: the record is DURABLE first (the ordinary Level-1 `PubAck`,
//! I2), and THEN, when a consumer drains and acks it, the producer is told `ProduceConfirm{offset,
//! status = consumed}`. This structure is the bridge between the two halves. On an L2 produce the
//! caller [`ConfirmRegistry::register`]s the durable offset against the producer's stable connection
//! id; when the DESIGNATED consumer group's committed cursor later advances past that offset the
//! caller calls [`ConfirmRegistry::confirm_up_to`], which moves the entry to a READY terminal the
//! producer drains.
//!
//! ## Why a single DESIGNATED group (not "any"/"all")
//!
//! A record is delivered to EVERY consumer group; "consumed" is therefore ambiguous unless we pick
//! ONE group to mean it. Keying the confirm to whichever group acks FIRST ("any group") is
//! non-deterministic and lets an unrelated group race the confirm; firing only after ALL groups ack
//! ("all groups") is unbounded (groups come and go, and a never-subscribed group would pin the
//! confirm forever). So the confirm is keyed to ONE designated group, chosen by the engine
//! (the default/broadcast group unless an operator names another), exactly the group whose
//! cursor-commit the caller hooks. This keeps "consumed" well-defined and the registry bounded.
//!
//! ## Failure modes (all terminal, all bounded)
//!
//! - **No consumer ever acks** -> the entry ages past the TTL and the idle/retention sweep
//!   ([`ConfirmRegistry::sweep_timed_out`]) fires `status = timed_out`.
//! - **Dead-lettered / force-reaped before any ack** -> the caller calls
//!   [`ConfirmRegistry::terminate`] with `status = dead_lettered`, so the producer learns the
//!   confirmation can never be satisfied instead of waiting out the whole TTL.
//! - **Producer disconnects** -> [`ConfirmRegistry::drop_member`] removes every entry for that
//!   connection (pending AND ready): nobody is waiting, so no terminal is produced.
//! - **The registry is full** -> a [`ConfirmRegistry::register`] at the cap evicts the OLDEST
//!   pending entry as `status = dropped` (drop-oldest), so a slow or absent consumer can never grow
//!   it without bound (the same threat class as the dedup window cap and the lease-heap bound). The
//!   READY queue is bounded the same way: an over-cap ready terminal drops the oldest ready one.
//!
//! ## Time and IO
//!
//! PURE and IO-free, like [`crate::cursor::AckCursor`] and [`crate::dedup::DedupRegistry`]: the
//! caller supplies monotonic time (`now`, nanoseconds, from the clock seam) on register/sweep, so an
//! NTP wall-clock step never mis-expires a confirm (I6). The registry is in-memory and session-scoped
//! (lost on restart): a producer awaiting an L2 confirm across a broker crash sees its blocking call
//! time out, which is the correct signal (the broker has no memory of the wait), while the record
//! itself stayed durable via its Level-1 `PubAck`. Restoring L2 waits across a restart would need a
//! durable confirm log and is out of scope here.
//!
//! ## Memory
//!
//! Both the pending map and the ready queue are HARD-capped ([`ConfirmConfig::max_pending`]), and
//! the TTL bounds how long any single pending entry lives. The total worst case is thus
//! `2 * max_pending` entries, each a fixed `(u64 offset, u64 member, u64 instant[, u8 status])`, so
//! the structure costs nothing until a producer opts into Level 2 and can never OOM the node it runs
//! on. See `docs/RAM_BUDGET.md`.

use crate::types::Offset;
use std::collections::BTreeMap;
use std::collections::VecDeque;

/// The default cap on the number of PENDING (and, separately, READY) Level-2 confirms a broker holds
/// at once (#497). Past it a fresh [`ConfirmRegistry::register`] drop-oldests the eldest pending
/// confirm (and an over-cap ready terminal drop-oldests the eldest ready one), so a slow or absent
/// consumer can never grow the registry without bound. Sized generously for a real in-flight L2
/// window on an edge node while keeping the worst-case memory a small, fixed budget.
pub const DEFAULT_MAX_PENDING: usize = 65_536;

/// The default TTL for a pending Level-2 confirm, in NANOSECONDS of monotonic time (#497): a confirm
/// no consumer acks within this window is swept to `status = timed_out`, so a producer awaiting it is
/// never told to wait forever. Five minutes is comfortably above a slow consumer's drain latency yet
/// finite, matching the dedup window's "finite but generous" sizing.
pub const DEFAULT_CONFIRM_TTL_NANOS: u64 = 5 * 60 * 1_000_000_000;

/// The terminal status of a Level-2 confirm, mirroring the wire
/// [`ironbus_proto`-style](crate) `produce_confirm_status` values (#494) WITHOUT a dependency on the
/// proto crate (core stays proto-free). The server maps each variant to the corresponding wire byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmStatus {
    /// A consumer in the designated group acked the record: the Level-2 produce is confirmed (the
    /// success terminal). Maps to the wire `CONSUMED` (0).
    Consumed,
    /// No consumer acked within the TTL: the confirmation timed out (a non-success terminal). Maps to
    /// the wire `TIMED_OUT` (1).
    TimedOut,
    /// The record was dead-lettered (poison / force-reaped) before any ack, so the confirmation can
    /// never be satisfied (a non-success terminal). Maps to the wire `DEAD_LETTERED` (2).
    DeadLettered,
    /// The registry evicted this pending confirm under its cap (drop-oldest) before any consumer
    /// acked: a bounded-registry shed, surfaced as a terminal so the producer stops waiting rather
    /// than blocking out the whole TTL. Maps to the wire `DEAD_LETTERED` (2) (a non-success terminal:
    /// the record stayed durable, but the broker no longer tracks its consumed confirmation).
    Dropped,
}

/// A READY Level-2 confirm: a terminal outcome whose producer connection has not yet drained it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyConfirm {
    /// The durable offset the confirm is keyed to (the offset the producer's `PubAck` returned).
    pub offset: u64,
    /// The producer connection's stable id (the same id [`ConfirmRegistry::register`] recorded), so
    /// the caller routes the terminal to the right producer and nobody else.
    pub member: u64,
    /// The terminal status to report to the producer.
    pub status: ConfirmStatus,
}

/// Tunables for a [`ConfirmRegistry`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmConfig {
    /// The hard cap on PENDING confirms (and, separately, on READY confirms): at the pending cap a
    /// fresh register drop-oldests the eldest pending entry; at the ready cap a fresh terminal
    /// drop-oldests the eldest ready entry. `0` is treated as 1 (a hard floor of one) so the registry
    /// is always usable.
    pub max_pending: usize,
    /// The TTL for a pending confirm, in NANOSECONDS of monotonic time: a confirm older than this on
    /// a sweep is timed out. `0` DISABLES the TTL sweep (only the cap bounds the registry).
    pub ttl_nanos: u64,
}

impl Default for ConfirmConfig {
    fn default() -> ConfirmConfig {
        ConfirmConfig {
            max_pending: DEFAULT_MAX_PENDING,
            ttl_nanos: DEFAULT_CONFIRM_TTL_NANOS,
        }
    }
}

/// One pending Level-2 confirm: which producer is waiting and when it was registered (for the TTL).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    /// The producer connection's stable id.
    member: u64,
    /// The monotonic instant (nanoseconds, clock seam) the confirm was registered, the TTL anchor.
    registered_nanos: u64,
}

/// The bounded per-offset Level-2 produce-confirm registry (#497).
///
/// `pending` keys a producer's awaited confirm by the record's durable offset; `ready` queues the
/// terminal outcomes a producer connection has not yet drained. Both are hard-bounded by
/// [`ConfirmConfig::max_pending`]; the TTL bounds how long a pending entry lives. The structure is
/// pure and IO-free (the caller supplies monotonic time), and empty until a producer opts into
/// Level 2, so a broker no producer uses Level 2 on pays nothing.
#[derive(Clone, Debug, Default)]
pub struct ConfirmRegistry {
    config: ConfirmConfig,
    /// Pending confirms keyed by durable offset. `BTreeMap` so [`ConfirmRegistry::confirm_up_to`]
    /// drains the contiguous prefix below a committed watermark in offset order without a scan of the
    /// whole map, and so the OLDEST-offset drop-oldest victim under the cap is the map's first key
    /// (offsets are assigned monotonically, so the lowest offset is the earliest-registered entry).
    pending: BTreeMap<u64, Pending>,
    /// Terminal confirms awaiting drain by their producer connection, oldest first.
    ready: VecDeque<ReadyConfirm>,
}

impl ConfirmRegistry {
    /// A fresh, empty registry with the given bounds. A `max_pending` of `0` is floored to 1.
    #[must_use]
    pub fn new(config: ConfirmConfig) -> ConfirmRegistry {
        ConfirmRegistry {
            config: ConfirmConfig {
                max_pending: config.max_pending.max(1),
                ttl_nanos: config.ttl_nanos,
            },
            pending: BTreeMap::new(),
            ready: VecDeque::new(),
        }
    }

    /// The number of PENDING confirms (awaiting a consumer ack, a TTL timeout, or a terminate).
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// The number of READY terminals not yet drained by their producer.
    #[must_use]
    pub fn ready_len(&self) -> usize {
        self.ready.len()
    }

    /// Registers a pending Level-2 confirm: the record at `offset` (already DURABLE, its Level-1
    /// `PubAck` sent) is awaiting a consumer ack, and `member` is the producer connection to notify.
    /// `now` is the clock-seam monotonic instant, the TTL anchor.
    ///
    /// BOUNDED (drop-oldest): if the pending map is already at the cap, the OLDEST pending confirm is
    /// evicted as a `Dropped` terminal (queued ready for ITS producer) before this one is inserted,
    /// so a slow or absent consumer can never grow the registry past the cap. A re-register of an
    /// offset already pending overwrites it (a benign no-op in practice: offsets are unique per
    /// produce), so the map can never hold two entries for one offset.
    pub fn register(&mut self, offset: Offset, member: u64, now: u64) {
        let offset = offset.get();
        // Drop-oldest under the cap, but never evict the very offset we are about to (re-)insert: an
        // overwrite of an existing key does not grow the map, so only a genuinely NEW key past the cap
        // forces an eviction. Loop in case the cap was lowered below the current size.
        while self.pending.len() >= self.config.max_pending && !self.pending.contains_key(&offset) {
            // `pop_first` removes the LOWEST-offset entry, i.e. the earliest-registered pending confirm
            // (offsets are monotonic), without an `expect`-guarded re-lookup. Evict it as a
            // bounded-registry shed terminal. `None` is unreachable (the loop guard proved the map is
            // non-empty), but handling it as `break` keeps the method panic-free by construction.
            let Some((victim_offset, victim)) = self.pending.pop_first() else {
                break;
            };
            self.push_ready(ReadyConfirm {
                offset: victim_offset,
                member: victim.member,
                status: ConfirmStatus::Dropped,
            });
        }
        self.pending.insert(
            offset,
            Pending {
                member,
                registered_nanos: now,
            },
        );
    }

    /// Fires a `Consumed` terminal for every pending confirm whose offset is STRICTLY BELOW
    /// `committed` (the designated group's freshly-advanced committed watermark, EXCLUSIVE), moving
    /// each to the ready queue. This is the cursor-commit hook: the caller invokes it after the
    /// designated group's `AckCursor` advances (an ack, a cumulative ack), so a confirm fires exactly
    /// when the record it keys becomes consumed. Returns the number of confirms fired.
    ///
    /// Draining the BELOW-watermark prefix (not an exact-offset match) is what makes the hook correct
    /// under out-of-order acks: the committed watermark is the offset below which EVERY record is
    /// acked, so any pending confirm below it is genuinely consumed, and an out-of-order ack that does
    /// not yet advance the watermark correctly fires nothing.
    pub fn confirm_up_to(&mut self, committed: Offset) -> usize {
        let committed = committed.get();
        let mut fired = 0;
        // Drain the contiguous low-offset prefix below the watermark. `BTreeMap` keeps the keys
        // sorted, so peeking the first key and `pop_first`ing it stops at the first offset at or above
        // `committed` without scanning the rest and without an `expect`-guarded re-lookup.
        while self
            .pending
            .first_key_value()
            .is_some_and(|(&o, _)| o < committed)
        {
            let Some((offset, pending)) = self.pending.pop_first() else {
                break;
            };
            self.push_ready(ReadyConfirm {
                offset,
                member: pending.member,
                status: ConfirmStatus::Consumed,
            });
            fired += 1;
        }
        fired
    }

    /// Terminates the pending confirm at `offset` with `status` (a non-`Consumed` terminal), moving it
    /// to the ready queue. The caller uses this when a record can never be consumed: it was
    /// dead-lettered or force-reaped before any consumer acked it ([`ConfirmStatus::DeadLettered`]).
    /// A no-op (returns `false`) if no confirm is pending for `offset` (it already fired, timed out,
    /// or was never an L2 produce).
    pub fn terminate(&mut self, offset: Offset, status: ConfirmStatus) -> bool {
        let offset = offset.get();
        match self.pending.remove(&offset) {
            Some(pending) => {
                self.push_ready(ReadyConfirm {
                    offset,
                    member: pending.member,
                    status,
                });
                true
            }
            None => false,
        }
    }

    /// Terminates every pending confirm whose offset is STRICTLY BELOW `floor` with `status` (a
    /// non-`Consumed` terminal), moving each to the ready queue. The caller uses this when a SPAN of
    /// records can never be consumed: the disk-full drop-oldest policy force-reaped the oldest
    /// segment(s) out from under every consumer, so every pending confirm below the new
    /// earliest-retained offset is unsatisfiable. Returns the number terminated. Like
    /// [`ConfirmRegistry::confirm_up_to`], it drains the contiguous low-offset prefix in order without
    /// scanning the whole map.
    pub fn terminate_below(&mut self, floor: Offset, status: ConfirmStatus) -> usize {
        let floor = floor.get();
        let mut terminated = 0;
        while self
            .pending
            .first_key_value()
            .is_some_and(|(&o, _)| o < floor)
        {
            let Some((offset, pending)) = self.pending.pop_first() else {
                break;
            };
            self.push_ready(ReadyConfirm {
                offset,
                member: pending.member,
                status,
            });
            terminated += 1;
        }
        terminated
    }

    /// Sweeps out every pending confirm older than the TTL, firing a `TimedOut` terminal for each, the
    /// "no consumer ever acks" failure mode. `now` is the clock-seam monotonic instant. A no-op when
    /// the TTL is disabled (`ttl_nanos == 0`). Returns the number timed out. Called from the engine's
    /// existing idle/retention tick, so it adds no new timer.
    pub fn sweep_timed_out(&mut self, now: u64) -> usize {
        if self.config.ttl_nanos == 0 {
            return 0;
        }
        let ttl = self.config.ttl_nanos;
        // Collect the timed-out offsets first (we cannot mutate the map while iterating it). The
        // collection is bounded by `max_pending`, the same bound the whole registry lives under.
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now.saturating_sub(p.registered_nanos) >= ttl)
            .map(|(&offset, _)| offset)
            .collect();
        for offset in &expired {
            if let Some(pending) = self.pending.remove(offset) {
                self.push_ready(ReadyConfirm {
                    offset: *offset,
                    member: pending.member,
                    status: ConfirmStatus::TimedOut,
                });
            }
        }
        expired.len()
    }

    /// Removes every entry (PENDING and READY) for a producer connection that has disconnected, the
    /// "producer disconnect" failure mode: nobody is waiting on `member` any more, so no terminal is
    /// produced (the entries are simply dropped). Returns the number of entries removed. Bounds the
    /// registry against a producer that opens L2 produces then vanishes.
    pub fn drop_member(&mut self, member: u64) -> usize {
        let before = self.pending.len() + self.ready.len();
        self.pending.retain(|_, p| p.member != member);
        self.ready.retain(|r| r.member != member);
        before - (self.pending.len() + self.ready.len())
    }

    /// Drains every READY terminal for `member` (a producer connection draining its confirms on its
    /// own pass), in oldest-first order, removing them from the queue. Other producers' ready
    /// terminals are left in place. Returns the drained terminals (possibly empty).
    pub fn drain_ready_for(&mut self, member: u64) -> Vec<ReadyConfirm> {
        // Partition the queue: keep the ready terminals for OTHER members, take this member's. Rebuild
        // preserving order so a producer that drains repeatedly still sees FIFO confirms.
        let mut mine = Vec::new();
        let mut others = VecDeque::with_capacity(self.ready.len());
        for r in self.ready.drain(..) {
            if r.member == member {
                mine.push(r);
            } else {
                others.push_back(r);
            }
        }
        self.ready = others;
        mine
    }

    /// Pushes a terminal onto the ready queue, BOUNDED the same way as the pending map: at the cap the
    /// OLDEST ready terminal is dropped (a producer that never drains its confirms cannot grow the
    /// queue without bound). A dropped-from-ready terminal is simply discarded: the producer either
    /// disconnected or stopped reading, so there is nobody to deliver it to anyway.
    fn push_ready(&mut self, confirm: ReadyConfirm) {
        while self.ready.len() >= self.config.max_pending {
            self.ready.pop_front();
        }
        self.ready.push_back(confirm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn off(n: u64) -> Offset {
        Offset::new(n)
    }

    fn cfg(max_pending: usize, ttl_nanos: u64) -> ConfirmConfig {
        ConfirmConfig {
            max_pending,
            ttl_nanos,
        }
    }

    #[test]
    fn a_consumer_ack_past_the_offset_fires_a_consumed_confirm() {
        let mut r = ConfirmRegistry::new(ConfirmConfig::default());
        r.register(off(5), 1, 0);
        assert_eq!(r.pending_len(), 1);
        // A committed watermark at or below the offset fires nothing (not yet consumed).
        assert_eq!(
            r.confirm_up_to(off(5)),
            0,
            "watermark == offset is exclusive"
        );
        assert_eq!(r.pending_len(), 1);
        // A watermark PAST the offset fires the consumed confirm.
        assert_eq!(r.confirm_up_to(off(6)), 1);
        assert_eq!(r.pending_len(), 0);
        let ready = r.drain_ready_for(1);
        assert_eq!(
            ready,
            vec![ReadyConfirm {
                offset: 5,
                member: 1,
                status: ConfirmStatus::Consumed,
            }]
        );
    }

    #[test]
    fn confirm_up_to_fires_the_whole_below_watermark_prefix_in_order() {
        let mut r = ConfirmRegistry::new(ConfirmConfig::default());
        for n in [3, 7, 4, 10] {
            r.register(off(n), 1, 0);
        }
        // Committing past 8 fires 3, 4, 7 (below 8) but leaves 10.
        assert_eq!(r.confirm_up_to(off(8)), 3);
        let ready = r.drain_ready_for(1);
        assert_eq!(
            ready.iter().map(|c| c.offset).collect::<Vec<_>>(),
            vec![3, 4, 7],
            "fired in ascending offset order"
        );
        assert_eq!(r.pending_len(), 1, "offset 10 still pending");
    }

    #[test]
    fn a_timed_out_confirm_fires_when_no_consumer_acks_within_the_ttl() {
        let mut r = ConfirmRegistry::new(cfg(16, 1_000));
        r.register(off(0), 9, 0);
        // Before the TTL: nothing.
        assert_eq!(r.sweep_timed_out(999), 0);
        assert_eq!(r.pending_len(), 1);
        // At/after the TTL: timed out.
        assert_eq!(r.sweep_timed_out(1_000), 1);
        assert_eq!(r.pending_len(), 0);
        let ready = r.drain_ready_for(9);
        assert_eq!(ready[0].status, ConfirmStatus::TimedOut);
        // A disabled TTL never times anything out.
        let mut r2 = ConfirmRegistry::new(cfg(16, 0));
        r2.register(off(0), 1, 0);
        assert_eq!(r2.sweep_timed_out(u64::MAX), 0);
        assert_eq!(r2.pending_len(), 1);
    }

    #[test]
    fn a_dead_letter_terminates_the_pending_confirm() {
        let mut r = ConfirmRegistry::new(ConfirmConfig::default());
        r.register(off(2), 4, 0);
        assert!(r.terminate(off(2), ConfirmStatus::DeadLettered));
        assert_eq!(r.pending_len(), 0);
        let ready = r.drain_ready_for(4);
        assert_eq!(ready[0].status, ConfirmStatus::DeadLettered);
        // Terminating an unknown offset is a no-op.
        assert!(!r.terminate(off(99), ConfirmStatus::DeadLettered));
    }

    #[test]
    fn a_producer_disconnect_drops_its_pending_and_ready_entries() {
        let mut r = ConfirmRegistry::new(ConfirmConfig::default());
        r.register(off(0), 1, 0); // member 1 pending
        r.register(off(1), 2, 0); // member 2 pending
        r.terminate(off(1), ConfirmStatus::DeadLettered); // member 2 now ready
        r.register(off(2), 1, 0); // member 1 second pending
                                  // Member 1 disconnects: both its pending entries gone, member 2's ready terminal stays.
        let removed = r.drop_member(1);
        assert_eq!(removed, 2);
        assert!(r.drain_ready_for(1).is_empty());
        assert_eq!(r.drain_ready_for(2).len(), 1, "member 2 untouched");
    }

    #[test]
    fn the_pending_registry_is_bounded_drop_oldest_under_the_cap() {
        let mut r = ConfirmRegistry::new(cfg(3, 0));
        // Fill to the cap.
        r.register(off(0), 1, 0);
        r.register(off(1), 1, 0);
        r.register(off(2), 1, 0);
        assert_eq!(r.pending_len(), 3);
        // The fourth evicts the OLDEST (offset 0) as a Dropped terminal.
        r.register(off(3), 1, 0);
        assert_eq!(r.pending_len(), 3, "still capped");
        let ready = r.drain_ready_for(1);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].offset, 0);
        assert_eq!(ready[0].status, ConfirmStatus::Dropped);
        // The surviving pending offsets are the three newest.
        assert_eq!(r.confirm_up_to(off(4)), 3);
        let fired: Vec<u64> = r.drain_ready_for(1).iter().map(|c| c.offset).collect();
        assert_eq!(fired, vec![1, 2, 3]);
    }

    #[test]
    fn a_re_register_of_a_pending_offset_does_not_grow_or_evict() {
        let mut r = ConfirmRegistry::new(cfg(2, 0));
        r.register(off(0), 1, 0);
        r.register(off(1), 1, 0);
        // Re-registering an existing offset overwrites, never evicts (the map does not grow).
        r.register(off(1), 2, 5);
        assert_eq!(r.pending_len(), 2);
        assert!(r.drain_ready_for(1).is_empty(), "no eviction happened");
        // The overwrite took the new member.
        assert_eq!(r.confirm_up_to(off(2)), 2);
        let members: Vec<u64> = r.drain_ready_for(2).iter().map(|c| c.member).collect();
        assert_eq!(members, vec![2], "offset 1 now routes to member 2");
    }

    #[test]
    fn the_ready_queue_is_bounded() {
        let mut r = ConfirmRegistry::new(cfg(2, 0));
        // Terminate more confirms than the ready cap; the oldest ready ones drop.
        for n in 0..5 {
            r.register(off(n), 1, 0);
            r.terminate(off(n), ConfirmStatus::DeadLettered);
        }
        assert!(r.ready_len() <= 2, "ready queue capped");
    }

    #[test]
    fn drain_ready_preserves_fifo_and_isolates_members() {
        let mut r = ConfirmRegistry::new(ConfirmConfig::default());
        r.register(off(0), 1, 0);
        r.register(off(1), 2, 0);
        r.register(off(2), 1, 0);
        r.confirm_up_to(off(3));
        // Member 1 sees its two confirms in FIFO offset order; member 2 sees its one.
        let m1: Vec<u64> = r.drain_ready_for(1).iter().map(|c| c.offset).collect();
        assert_eq!(m1, vec![0, 2]);
        let m2: Vec<u64> = r.drain_ready_for(2).iter().map(|c| c.offset).collect();
        assert_eq!(m2, vec![1]);
        // Draining again yields nothing.
        assert!(r.drain_ready_for(1).is_empty());
    }
}
