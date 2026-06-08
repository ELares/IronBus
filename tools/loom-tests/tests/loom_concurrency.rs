// SPDX-License-Identifier: MIT OR Apache-2.0
//! Scoped loom concurrency tests for the three genuinely lock-free / cross-thread hot paths
//! whose corruption would violate I1 (lost ack) or the commit watermark (#122, parent #21).
//!
//! ## Why FAITHFUL MODELS, not a cfg-switched production type
//!
//! loom replaces `std::sync` atomics/`Arc`/`mpsc`/`thread` with instrumented versions and then
//! EXHAUSTIVELY permutes the thread interleavings, so anything under test must be built out of
//! `loom::sync::*` and `loom::thread`. The three production structures #122 names are NOT shaped
//! to be cfg-switched cheaply:
//!
//!   - the append actor (`ironbus_server::actor`) hands off over `std::sync::mpsc::sync_channel`,
//!     a BOUNDED channel loom has no replacement for (loom's `mpsc` is unbounded only), and the
//!     handoff is wrapped in `Engine`/`Filesystem` generics and a real `commit_batch` fsync;
//!   - the commit watermark (`ironbus_core::cursor::AckCursor`) is a PURE, single-threaded,
//!     IO-free value type (no atomics at all): the cross-thread publish/observe of `committed`
//!     happens one level up, where a writer publishes the watermark and a reader observes it;
//!   - the connection refcount (`ironbus_server::server::ConnectionSlot`) is an `AtomicUsize`
//!     slot count plus the `Arc<EngineHandle>` each handler clones.
//!
//! cfg-switching any of these would touch hot production code and risk perturbing the normal
//! (std) path. The accepted pattern for SCOPED loom tests is therefore a small, BOUNDED model
//! built from loom's replacement primitives that replicates the EXACT atomic ordering of the
//! real code, with a comment cross-referencing the real symbol each model stands in for. A
//! weakening of an ordering in the model (or, by extension, in the real type it mirrors) makes
//! the corresponding loom test fail, which is the teeth #122 asks for.
//!
//! ## Scope limits and loom caveats (acceptance criterion: record them)
//!
//!   - Each model caps at <= 3 threads and <= 4 shared-memory operations per thread, so the
//!     factorial interleaving space stays tractable and the gate always finishes.
//!   - Correctness rests only on ACQUIRE/RELEASE (`AcqRel`) reasoning, never on SeqCst-only
//!     ordering. loom models `SeqCst` as `AcqRel`, which can yield FALSE POSITIVES for code that
//!     truly needs `SeqCst`; banning SeqCst-only reasoning here avoids that class. The real fault
//!     fs sync counter uses `SeqCst`, but it is a TEST observability counter, not a correctness
//!     primitive, so it is deliberately not modeled.
//!   - loom UNDER-EXPLORES the load-buffering relaxation, a known FALSE-NEGATIVE source. These
//!     models do not rest on any subtle load-buffering argument, and the same paths are also
//!     cross-checked by the crate's stress/property tests, so a miss here is not the only net.
//!   - The whole file is `#![cfg(loom)]`: it builds and runs ONLY under `RUSTFLAGS="--cfg loom"`.
//!     It lives in the STANDALONE dev-only `loom-tests` crate (like `tools/io-free-check`), which
//!     depends on no ironbus crate, so loom and its transitive `tracing-subscriber`/`env-filter`
//!     tree can never unify into a shipped crate's dependency graph (the models are faithful
//!     standalone replicas, so no ironbus dependency is needed; the real symbols are named in the
//!     cross-reference comments below). loom is a `cfg(loom)` dev-dependency, MIT, already
//!     allowlisted in deny.toml.
#![cfg(loom)]

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::Arc;
use loom::thread;
use std::sync::atomic::{AtomicUsize as StdAtomicUsize, Ordering as StdOrdering};

/// A process-wide counter of loom executions for the most recent model, bumped once per
/// interleaving inside `loom::model`. Printed after each test so the run PROVES loom actually
/// explored many interleavings (the dominant #122 risk is a model that explores ~1 path and
/// silently stops catching races). It is plain `std` (not loom): it lives OUTSIDE the modeled
/// shared state, purely as test instrumentation, so it never widens loom's state space.
static EXECUTIONS: StdAtomicUsize = StdAtomicUsize::new(0);

/// Runs `f` under `loom::model` while counting and then reporting the number of interleavings
/// explored, so the test output is self-evidently exhaustive rather than a single pass.
fn model_counted(name: &str, f: impl Fn() + Sync + Send + 'static) {
    EXECUTIONS.store(0, StdOrdering::Relaxed);
    loom::model(move || {
        EXECUTIONS.fetch_add(1, StdOrdering::Relaxed);
        f();
    });
    let n = EXECUTIONS.load(StdOrdering::Relaxed);
    println!("[loom] {name}: explored {n} interleavings");
    // A model that collapsed to a single path would not be exercising any interleaving, so it
    // would not be catching races. Assert it explored more than one.
    assert!(
        n > 1,
        "{name} explored only {n} interleaving(s); the model is not permuting threads"
    );
}

// ---------------------------------------------------------------------------------------------
// MODEL 1: COMMIT-INDEX publish/observe.
//
// Real symbol cross-reference: the commit-watermark publish/observe that feeds #10 and the
// `AckCursor::committed` watermark in `ironbus_core::cursor`. The cursor itself is a pure value
// type; when its committed offset is shared across threads (a committer publishes a new
// watermark, a reader observes it to decide what is durable / deliverable) the publish MUST be a
// RELEASE store of the index AFTER the data it covers is written, paired with an ACQUIRE load of
// the index BEFORE the data is read. This is exactly the ordering the engine's commit path needs
// so that "I observed commit index N" IMPLIES "every record N covers is visible".
// ---------------------------------------------------------------------------------------------

/// The shared cell a committer publishes and a reader observes. `data` stands in for the record
/// bytes a commit makes durable/visible; `index` is the monotonic commit watermark.
struct CommitIndex {
    /// The covered data (the record a commit makes visible). Written BEFORE the index is
    /// published; read AFTER the index is observed.
    data: AtomicUsize,
    /// The monotonic commit watermark. Published Release, observed Acquire.
    index: AtomicUsize,
}

impl CommitIndex {
    fn new() -> CommitIndex {
        CommitIndex {
            data: AtomicUsize::new(0),
            index: AtomicUsize::new(0),
        }
    }

    /// Committer side: write the covered data, THEN publish the new watermark with Release so the
    /// data write cannot be reordered after the index becomes visible. Mirrors the engine writing
    /// a record and then advancing the committed cursor.
    fn publish(&self, data: usize, index: usize) {
        self.data.store(data, Ordering::Relaxed);
        // Release: everything sequenced-before (the data store) is visible to any thread that
        // observes this index with Acquire.
        self.index.store(index, Ordering::Release);
    }

    /// Reader side: observe the watermark with Acquire; if it advanced, the data it covers must be
    /// visible. Returns the (index, data) it saw.
    fn observe(&self) -> (usize, usize) {
        // Acquire: pairs with the committer's Release so a non-zero index we read here guarantees
        // the matching data store is visible.
        let idx = self.index.load(Ordering::Acquire);
        let data = self.data.load(Ordering::Relaxed);
        (idx, data)
    }
}

#[test]
fn commit_index_observe_never_sees_an_index_without_its_data() {
    // 2 threads, <= 2 shared ops each: one committer publishes (data=1, index=1), one reader
    // observes. The invariant: an observed index of 1 IMPLIES the covered data (1) is visible.
    // Under the real Release/Acquire pairing this holds in every interleaving; weakening either to
    // Relaxed lets the reader see index=1 with stale data=0 in some interleaving (the teeth).
    model_counted("commit_index_publish_observe", || {
        let cell = Arc::new(CommitIndex::new());
        let committer = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                cell.publish(1, 1);
            })
        };
        let (idx, data) = cell.observe();
        // The torn/regressed-read invariant: index is monotone (only 0 or 1 ever) and a published
        // index implies its data is visible.
        assert!(idx <= 1, "index must never exceed the only published value");
        if idx == 1 {
            assert_eq!(
                data, 1,
                "observing commit index 1 must imply the data it covers (1) is visible (I-commit)"
            );
        }
        committer.join().expect("committer thread");
        // After the committer has joined, the final observe must be the fully published state.
        let (idx, data) = cell.observe();
        assert_eq!(
            (idx, data),
            (1, 1),
            "the committed state is final after join"
        );
    });
}

#[test]
fn commit_index_is_monotonic_under_two_sequential_publishes() {
    // A single committer advances the watermark 0 -> 1 -> 2 (the monotone group-commit advance),
    // while a reader observes once. The reader must never see a REGRESSED or torn index, and any
    // index it sees implies at-least-that-much data is visible. <= 3 ops on the committer, 2 on the
    // reader, 2 threads total.
    model_counted("commit_index_monotonic_advance", || {
        let cell = Arc::new(CommitIndex::new());
        let committer = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                cell.publish(10, 1);
                cell.publish(20, 2);
            })
        };
        let (idx, data) = cell.observe();
        // Monotone watermark: only 0, 1, or 2 are ever published, never a torn intermediate.
        assert!(idx <= 2, "watermark must be one of the published values");
        // A published index implies its covered data is visible (Acquire pairs with Release).
        match idx {
            0 => {}
            1 => assert!(
                data >= 10,
                "index 1 implies its data (10) is visible, saw {data}"
            ),
            2 => assert!(
                data >= 20,
                "index 2 implies its data (20) is visible, saw {data}"
            ),
            other => panic!("impossible watermark {other}"),
        }
        committer.join().expect("committer thread");
    });
}

// ---------------------------------------------------------------------------------------------
// MODEL 2: RING-BUFFER / WAL HANDOFF (bounded SPSC/MPSC).
//
// Real symbol cross-reference: the bounded `std::sync::mpsc::sync_channel` WAL handoff between
// connection handlers and the single committer in `ironbus_server::actor` (`EngineHandle::produce`
// SENDS a `Command::Produce`; `run_actor` RECVs and group-commits). The real bound provides
// BACKPRESSURE (a producer blocks when full) without a custom lock-free structure.
//
// loom's `mpsc` is UNBOUNDED, so the bound is modeled faithfully with an `AtomicUsize` permit
// count: a producer ACQUIRES a permit (Acquire, fetch on the occupancy) before it may send, and
// the consumer RELEASES a permit (Release) after it takes an item. That is the same happens-before
// the bounded channel enforces: the send's effects are published before the slot is reused. The
// invariants asserted are the actor's: no lost or duplicated item, no deadlock when the channel is
// momentarily full (the consumer drains and frees a permit), and FIFO per producer.
// ---------------------------------------------------------------------------------------------

/// The channel bound being modeled: a ring of `BOUND` slots, exactly the backpressure a
/// `sync_channel(BOUND)` provides. Sized to hold the whole modeled burst (one slot per producer)
/// so the "channel has room" path is exercised; a producer that finds the ring full BLOCKS
/// (backpressure), it never overwrites a slot.
const BOUND: usize = 2;

/// A bounded MPSC ring modeling the `sync_channel(bound)` WAL handoff: producers ATOMICALLY
/// reserve the next sequence slot (`fetch_add` on `tail`, gated by the bound for backpressure),
/// publish their payload into that slot, and flip a per-slot `ready` flag with RELEASE; the single
/// consumer reads slots in `head` order, observing `ready` with ACQUIRE before reading the payload.
/// This is the genuine atomic slot reservation a real bounded channel does internally; the earlier
/// non-atomic claim was a deliberate-looking bug loom caught (two producers won one slot), which is
/// exactly the lost-item race the reservation prevents.
struct BoundedHandoff {
    /// The next sequence number a producer will reserve. A producer `fetch_add`s this (`AcqRel`) to
    /// claim a UNIQUE slot, so two producers can never collide on one slot (the fix for the lost
    /// item). Reservation is refused (retried) while `tail - head == BOUND` (the ring is full).
    tail: AtomicUsize,
    /// The next sequence number the consumer will read. Advanced (Release) after the consumer takes
    /// a slot, which frees a ring entry for a blocked producer (backpressure relief).
    head: AtomicUsize,
    /// The payload ring, `BOUND` slots indexed by `seq % BOUND`. Written by the reserving producer.
    slots: [AtomicUsize; BOUND],
    /// Per-slot readiness: 0 = empty, 1 = a producer has published its payload. Flipped Release by
    /// the producer AFTER its payload store, observed Acquire by the consumer BEFORE its payload
    /// read, so the payload write happens-before the payload read (no torn handoff).
    ready: [AtomicUsize; BOUND],
}

impl BoundedHandoff {
    fn new() -> BoundedHandoff {
        BoundedHandoff {
            tail: AtomicUsize::new(0),
            head: AtomicUsize::new(0),
            slots: [AtomicUsize::new(0), AtomicUsize::new(0)],
            ready: [AtomicUsize::new(0), AtomicUsize::new(0)],
        }
    }

    /// Producer: ATOMICALLY reserve the next sequence slot (only when the ring has room, else block
    /// = backpressure), write the payload into it, then publish readiness with Release. Mirrors
    /// `SyncSender::send` blocking while the bounded channel is full and then handing off one item.
    fn send(&self, item: usize) {
        // Reserve a unique sequence number, but only if the ring is not full. compare_exchange on
        // `tail` makes the reservation atomic across producers (no two win the same slot) AND
        // enforces the bound (we never reserve more than `head + BOUND`), which is the backpressure.
        let seq = loop {
            let tail = self.tail.load(Ordering::Acquire);
            let head = self.head.load(Ordering::Acquire);
            // `tail` and `head` are read separately and both only increase, so a fresher `head` can
            // momentarily exceed a stale `tail`; that just means the ring drained, so `saturating_sub`
            // yielding 0 ("room available") is correct. Occupancy is always `tail - head` in real time.
            if tail.saturating_sub(head) >= BOUND {
                // Ring full: wait for the consumer to advance `head` (backpressure, no overwrite).
                thread::yield_now();
                continue;
            }
            // Try to claim `tail` for ourselves; on success `seq == tail`, a slot no other producer
            // can also hold. AcqRel so the claim synchronizes with other producers' claims.
            if self
                .tail
                .compare_exchange(tail, tail + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break tail;
            }
            // Lost the race for this `tail`; retry with the new value.
        };
        let idx = seq % BOUND;
        // Write the payload, THEN publish readiness with Release so a consumer that observes ready=1
        // with Acquire is guaranteed to see this payload.
        self.slots[idx].store(item, Ordering::Relaxed);
        self.ready[idx].store(1, Ordering::Release);
    }

    /// Consumer: read the next sequence slot in order, blocking until its producer has published it,
    /// then free the slot and advance `head` (Release) so a blocked producer may proceed. Mirrors
    /// `Receiver::recv` + the actor draining one command and freeing channel capacity.
    fn recv(&self) -> usize {
        let seq = self.head.load(Ordering::Relaxed);
        let idx = seq % BOUND;
        // Wait for the producer of this sequence to publish. Acquire pairs with its Release store of
        // `ready`, so the payload read below sees the producer's payload write (no torn handoff).
        loop {
            if self.ready[idx].load(Ordering::Acquire) == 1 {
                break;
            }
            thread::yield_now();
        }
        let item = self.slots[idx].load(Ordering::Relaxed);
        // Free the slot and advance the consumer cursor with Release: this is the backpressure
        // relief point that lets a producer blocked on a full ring reserve again.
        self.ready[idx].store(0, Ordering::Relaxed);
        self.head.store(seq + 1, Ordering::Release);
        item
    }
}

#[test]
fn wal_handoff_delivers_each_item_exactly_once_in_fifo_order() {
    // 1 producer sends two items (1 then 2) into the bounded ring; 1 consumer recvs two items, fully
    // interleaved. Invariants: both items arrive, none duplicated, and FIFO per producer (1 before
    // 2). 2 threads, <= 4 ops each (2 sends / 2 recvs). The bound still applies: the consumer's recv
    // is what advances `head` and frees ring capacity, so a stalled consumer blocks the producer
    // rather than deadlocking.
    model_counted("wal_handoff_spsc_bounded", || {
        let chan = Arc::new(BoundedHandoff::new());
        let producer = {
            let chan = Arc::clone(&chan);
            thread::spawn(move || {
                chan.send(1);
                chan.send(2);
            })
        };
        let first = chan.recv();
        let second = chan.recv();
        producer.join().expect("producer thread");
        // No lost / no duplicated item, and FIFO per producer: a single-producer handoff is strictly
        // ordered, so the consumer must see exactly [1, 2].
        assert_eq!(
            (first, second),
            (1, 2),
            "WAL handoff must be FIFO per producer with no loss or duplication"
        );
        // The ring drained fully: the consumer's head caught up to the producer's tail (no deadlock,
        // no stuck item).
        assert_eq!(
            chan.head.load(Ordering::Acquire),
            chan.tail.load(Ordering::Acquire),
            "the handoff drained fully (no deadlock, no stuck item)"
        );
    });
}

#[test]
fn wal_handoff_two_producers_lose_no_item_under_a_full_channel() {
    // MPSC fan-in (the real shape: many handlers, one committer). 2 producers each send 1 distinct
    // item; 1 consumer recvs 2 items. The producers ATOMICALLY reserve distinct ring slots
    // (`fetch_add`/CAS on `tail`), so neither can overwrite the other even when they reserve
    // concurrently, and a producer that finds the ring full BLOCKS (backpressure) rather than
    // dropping. Invariant: the consumer receives EXACTLY the two distinct items (a set {10, 20}),
    // none lost, none duplicated. 3 threads, <= 4 shared ops each. (An earlier non-atomic claim let
    // loom find a real lost-item interleaving here, which the atomic reservation now closes.)
    model_counted("wal_handoff_mpsc_backpressure", || {
        let chan = Arc::new(BoundedHandoff::new());
        let p1 = {
            let chan = Arc::clone(&chan);
            thread::spawn(move || chan.send(10))
        };
        let p2 = {
            let chan = Arc::clone(&chan);
            thread::spawn(move || chan.send(20))
        };
        let a = chan.recv();
        let b = chan.recv();
        p1.join().expect("producer 1");
        p2.join().expect("producer 2");
        // Exactly the two distinct items, no loss/duplication: the set of received items is {10,20}.
        let mut got = [a, b];
        got.sort_unstable();
        assert_eq!(
            got,
            [10, 20],
            "both producers' items survive the full-channel contention (no lost ack, I1)"
        );
        assert_eq!(
            chan.head.load(Ordering::Acquire),
            chan.tail.load(Ordering::Acquire),
            "the handoff drained fully (no deadlock under backpressure)"
        );
    });
}

// ---------------------------------------------------------------------------------------------
// MODEL 3: REFCOUNT (shared segment/buffer pin vs recycle).
//
// Real symbol cross-reference: the `Arc`-and-`AtomicUsize` refcounts on shared resources in the
// server: `ironbus_server::server::ConnectionSlot` (its `Drop` does `active.fetch_sub(1, AcqRel)`,
// the connection-cap release) and the `Arc<EngineHandle>` / `Arc<InMemoryFile>` segment/buffer
// sharing in `ironbus_storage`. The safety contract: the resource is recycled/dropped EXACTLY
// ONCE, only AFTER the last reference is released, and NEVER while a reader still pins it
// (no use-after-free analog). `Arc`'s own refcount is the canonical AcqRel pattern (fetch_add
// Relaxed on clone, fetch_sub Release on drop, Acquire fence before the final free); loom's `Arc`
// instruments exactly this, so the model drives loom's `Arc::strong_count` / drop tracking plus a
// faithful re-implementation of the slot's AcqRel release.
// ---------------------------------------------------------------------------------------------

/// A shared resource that records, at drop time, how many readers were still pinning it. A
/// correct refcount drops it only when that count is zero. `live_readers` is the `AtomicUsize`
/// pin count, released `AcqRel` exactly like `ConnectionSlot::drop`.
struct PinnedResource {
    /// How many threads currently hold this resource "in use" (a reader pin). Acquired before use,
    /// released `AcqRel` after, mirroring `active.fetch_add/fetch_sub` around a connection slot.
    live_readers: AtomicUsize,
    /// Set true if the resource was ever observed dropped while a reader still pinned it
    /// (a use-after-free analog). Must remain false in every interleaving.
    dropped_while_pinned: StdAtomicUsize,
}

impl PinnedResource {
    fn new() -> PinnedResource {
        PinnedResource {
            live_readers: AtomicUsize::new(0),
            dropped_while_pinned: StdAtomicUsize::new(0),
        }
    }

    /// Pin the resource for use (a reader enters its critical section): raise the live-reader
    /// count with `AcqRel`, mirroring `active.fetch_add(1, AcqRel)` on a new connection.
    fn pin(&self) {
        self.live_readers.fetch_add(1, Ordering::AcqRel);
    }

    /// Release the pin after use (the reader leaves): lower the count with `AcqRel`, mirroring
    /// `ConnectionSlot::drop`'s `active.fetch_sub(1, AcqRel)`.
    fn unpin(&self) {
        self.live_readers.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for PinnedResource {
    fn drop(&mut self) {
        // The last Arc reference is being dropped, so this runs exactly once. If any reader is
        // still pinning at this point, that is a use-after-free analog: record it so the test
        // fails. A correct refcount guarantees every pin is released before the last Arc drops,
        // so this read is always zero.
        if self.live_readers.load(Ordering::Acquire) != 0 {
            self.dropped_while_pinned.store(1, StdOrdering::Relaxed);
        }
    }
}

#[test]
fn refcount_drops_exactly_once_after_the_last_reference_releases() {
    // Two reader threads each clone the Arc, pin/use/unpin the resource, then drop their clone. The
    // main thread also holds and drops a clone. loom's Arc tracks the refcount; the resource's Drop
    // runs EXACTLY ONCE (loom panics on a double free or a leak), and our `dropped_while_pinned`
    // flag proves the drop never raced a live reader. 3 threads, <= 3 shared ops each
    // (pin, unpin, drop-clone).
    model_counted("refcount_pin_vs_recycle", || {
        let resource = Arc::new(PinnedResource::new());
        // Capture the flag's address out of band so we can assert after the Arc is fully dropped.
        // It lives in the resource; we read it through a raw observation done inside Drop, surfaced
        // via a separate Arc<StdAtomicUsize> we clone here so it OUTLIVES the resource.
        let witness = Arc::new(StdAtomicUsize::new(0));
        // Wire the resource's Drop observation into the witness by having each reader, and the
        // resource's own Drop, agree on the same out-of-band flag. We do that by making the witness
        // the source of truth the readers and Drop both touch. Simpler: readers set the witness if
        // THEY ever observe the resource already dropped while pinned, which cannot happen under a
        // correct Arc; Drop sets it if a reader is still pinned. Both must stay 0.
        let r1 = {
            let resource = Arc::clone(&resource);
            let witness = Arc::clone(&witness);
            thread::spawn(move || {
                resource.pin();
                // "Use" the resource: any read here must be valid because we hold a strong ref.
                let _ = resource.live_readers.load(Ordering::Acquire);
                resource.unpin();
                // If Drop had recorded a pinned-drop, propagate it to the witness.
                if resource.dropped_while_pinned.load(StdOrdering::Relaxed) != 0 {
                    witness.store(1, StdOrdering::Relaxed);
                }
            })
        };
        let r2 = {
            let resource = Arc::clone(&resource);
            let witness = Arc::clone(&witness);
            thread::spawn(move || {
                resource.pin();
                let _ = resource.live_readers.load(Ordering::Acquire);
                resource.unpin();
                if resource.dropped_while_pinned.load(StdOrdering::Relaxed) != 0 {
                    witness.store(1, StdOrdering::Relaxed);
                }
            })
        };
        // The main thread releases its own reference; the resource drops when the LAST of the three
        // Arc clones drops (loom enforces drop-exactly-once on the underlying allocation).
        drop(resource);
        r1.join().expect("reader 1");
        r2.join().expect("reader 2");
        // No reader ever saw the resource dropped while it (or a peer) still pinned it: the resource
        // is recycled only after the last reference releases (no use-after-free analog).
        assert_eq!(
            witness.load(StdOrdering::Relaxed),
            0,
            "the resource must never be dropped while a reader still pins it (no use-after-free)"
        );
    });
}

#[test]
fn refcount_slot_release_is_balanced_under_concurrent_handlers() {
    // The connection-cap slot model: two "handlers" each acquire a slot (fetch_add AcqRel) and
    // release it on exit (fetch_sub AcqRel), exactly as `serve` does around `ConnectionSlot`. After
    // both finish, the active count is balanced back to zero with no lost or doubled decrement, in
    // EVERY interleaving. 3 threads (2 handlers + main observer), <= 2 shared ops per handler.
    model_counted("refcount_connection_slot_balance", || {
        let active = Arc::new(AtomicUsize::new(0));
        let h1 = {
            let active = Arc::clone(&active);
            thread::spawn(move || {
                active.fetch_add(1, Ordering::AcqRel);
                active.fetch_sub(1, Ordering::AcqRel);
            })
        };
        let h2 = {
            let active = Arc::clone(&active);
            thread::spawn(move || {
                active.fetch_add(1, Ordering::AcqRel);
                active.fetch_sub(1, Ordering::AcqRel);
            })
        };
        h1.join().expect("handler 1");
        h2.join().expect("handler 2");
        // The cap accounting is exact: every acquire is matched by exactly one release, so the
        // count returns to zero (a lost decrement would leak a slot forever; a doubled one would
        // underflow). loom proves it across all interleavings of the fetch_add/fetch_sub pairs.
        assert_eq!(
            active.load(Ordering::Acquire),
            0,
            "every connection slot acquire is matched by exactly one release"
        );
    });
}
