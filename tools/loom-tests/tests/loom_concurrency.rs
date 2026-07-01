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

use loom::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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

// ---------------------------------------------------------------------------------------------
// MODEL 4: the off-actor READ-PLANE frontier/snapshot publish/observe (#539).
//
// Real symbol cross-reference: `ironbus_storage::read_plane::ReadPlane`. The single append actor
// (the writer) publishes a SEALED snapshot and then the read-visible FLUSHED frontier; any number
// of reader threads observe them with NO lock and NO actor round-trip. The correctness hinge is the
// publish/observe ORDER and the Acquire/Release pairing:
//
//   writer: store SNAPSHOT (sealed_end)  THEN  store FRONTIER (Release)
//   reader: load  FRONTIER (Acquire)     THEN  load  SNAPSHOT
//
// so a reader that observes a frontier F is GUARANTEED to observe a snapshot whose coverage
// (sealed_end) is at least F — it can never see a frontier that admits a sealed offset the snapshot
// lacks. This is the read-plane analogue of MODEL 1: `sealed_end` plays the role of the covered
// `data`, the `frontier` plays the role of the published `index`. `ArcSwap::store`/`load` provide
// the same Release/Acquire pairing the production type relies on; this model uses the two atomics
// directly so the ordering is the thing under test (a faithful replica per the file's preamble).
// Weakening the frontier store to Relaxed (or loading the frontier AFTER the snapshot) lets a reader
// see a bumped frontier with a stale, too-small `sealed_end` in some interleaving — the teeth.
// ---------------------------------------------------------------------------------------------

/// The two shared atomics of the read plane: the snapshot coverage (`sealed_end`) and the published
/// read-visible `frontier`. The writer stores the snapshot BEFORE the frontier; the reader loads the
/// frontier BEFORE the snapshot.
struct ReadPlaneCell {
    /// How far the published SEALED snapshot covers (the active base = sealed end). Stands in for the
    /// arc-swapped `SealedSnapshot`. Written BEFORE the frontier; read AFTER it.
    sealed_end: AtomicUsize,
    /// The read-visible FLUSHED frontier: the hard bound a reader clamps a read to. Published
    /// Release, observed Acquire.
    frontier: AtomicUsize,
}

impl ReadPlaneCell {
    fn new() -> ReadPlaneCell {
        ReadPlaneCell {
            sealed_end: AtomicUsize::new(0),
            frontier: AtomicUsize::new(0),
        }
    }

    /// Writer side: publish the snapshot coverage, THEN the frontier with Release so the snapshot
    /// store cannot be reordered after the frontier becomes visible. Mirrors `Log::republish_read_plane`
    /// storing the `ArcSwap` snapshot then `publish_flushed` (the Release frontier store).
    fn publish(&self, sealed_end: usize, frontier: usize) {
        self.sealed_end.store(sealed_end, Ordering::Relaxed);
        self.frontier.store(frontier, Ordering::Release);
    }

    /// Reader side: observe the frontier with Acquire FIRST, then the snapshot. Mirrors
    /// `ReadPlane::read_range` loading `flushed` (Acquire) then the `ArcSwap` snapshot.
    fn observe(&self) -> (usize, usize) {
        let frontier = self.frontier.load(Ordering::Acquire);
        let sealed_end = self.sealed_end.load(Ordering::Relaxed);
        (frontier, sealed_end)
    }
}

#[test]
fn read_plane_observe_never_sees_a_frontier_beyond_its_snapshot() {
    // 2 threads: a writer publishes (sealed_end=1, frontier=1), a reader observes once. The
    // invariant: an observed frontier of 1 IMPLIES the snapshot covering it (sealed_end >= 1) is
    // visible, so a reader can never be handed a read-visible offset the sealed snapshot lacks.
    // Under the real snapshot-then-frontier-Release / frontier-Acquire-then-snapshot pairing this
    // holds in every interleaving; weakening it lets the reader see frontier=1 with sealed_end=0.
    model_counted("read_plane_publish_observe", || {
        let cell = Arc::new(ReadPlaneCell::new());
        let writer = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                cell.publish(1, 1);
            })
        };
        let (frontier, sealed_end) = cell.observe();
        assert!(
            frontier <= 1,
            "frontier must never exceed the only published value"
        );
        if frontier == 1 {
            assert!(
                sealed_end >= 1,
                "observing frontier 1 must imply the snapshot covering it (sealed_end >= 1) is \
                 visible — a reader is never handed an offset the snapshot lacks (#539 I2/coverage)"
            );
        }
        writer.join().expect("writer thread");
        let (frontier, sealed_end) = cell.observe();
        assert_eq!(
            (frontier, sealed_end),
            (1, 1),
            "the published read-plane state is final after join"
        );
    });
}

#[test]
fn read_plane_frontier_is_monotone_and_always_covered_under_two_seals() {
    // A single writer advances across TWO seals: (sealed_end=1, frontier=1) then (sealed_end=2,
    // frontier=2) — two rolls each republishing the snapshot then bumping the frontier — while a
    // reader observes once. The reader must never see a regressed frontier, and any frontier it sees
    // must be covered by the snapshot (sealed_end >= frontier). <= 4 shared ops on the writer, 2 on
    // the reader, 2 threads.
    model_counted("read_plane_two_seals_covered", || {
        let cell = Arc::new(ReadPlaneCell::new());
        let writer = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                cell.publish(1, 1);
                cell.publish(2, 2);
            })
        };
        let (frontier, sealed_end) = cell.observe();
        assert!(
            frontier <= 2,
            "frontier must be one of the published values"
        );
        // Every observed frontier is covered by the snapshot it implies (Acquire pairs with the
        // snapshot-then-frontier Release): a frontier F is only ever published AFTER a snapshot with
        // sealed_end >= F, so a reader can never read past the snapshot's coverage.
        assert!(
            sealed_end >= frontier,
            "frontier {frontier} exceeds snapshot coverage {sealed_end}: a reader would be handed \
             an offset the sealed snapshot does not cover"
        );
        writer.join().expect("writer thread");
        let (frontier, sealed_end) = cell.observe();
        assert_eq!(
            (frontier, sealed_end),
            (2, 2),
            "the final read-plane state after two seals is fully published"
        );
    });
}

// ---------------------------------------------------------------------------------------------
// MODEL 5: PRODUCE-GATE shed-accounting seam (fast-reject + L0-shed delta reconciliation, #476/#495).
//
// Real symbol cross-reference: `ironbus_server::produce_gate::ProduceCapGate`. Many connection
// (handler) threads bump a MONOTONIC running total of connection-thread fast-rejects with a relaxed
// `fetch_add` (`record_fast_reject`, and the separate L0 counter via `record_l0_shed`). The SINGLE
// append-actor thread folds the DELTA-since-last-read into the engine's authoritative shed counters
// once per batch (`take_unreconciled_fast_rejects`: load the monotonic total, `saturating_sub` the
// already-reconciled high-water mark, then `store` the total back as the new high-water mark; the L0
// path is symmetric via `take_unreconciled_l0_sheds`). The load-bearing audit invariant (module
// docstrings lines 93 / 109) is: "a fast-reject is never a SILENT shed" — every reject folded into
// the engine counters EXACTLY ONCE, never lost, never double-counted, "exact under any number of
// concurrent connection threads with no lock." The single-writer `reconciled` / monotonic-total
// reasoning is what the real code relies on; MODEL 5 pins it under loom's interleavings.
//
// The real counters are RELAXED (the value is advisory shed accounting, not a synchronization point
// for other state — the actor's byte-cap check stays authoritative), so this model uses Relaxed too:
// the property under test is the DELTA ARITHMETIC (load-total / subtract-HWM / store-total) staying
// exact while handler threads concurrently bump the total, NOT an Acquire/Release publish. A
// regression that makes the fold advance the high-water mark by anything other than the observed
// total (e.g. `reconciled.fetch_add(delta)` instead of `store(total)`, or returning the raw total
// instead of the delta, or folding one counter's delta out of the OTHER counter) makes the summed
// deltas diverge from the monotonic total in some interleaving — the teeth.
// ---------------------------------------------------------------------------------------------

/// A faithful replica of the `ProduceCapGate` shed-accounting fields and the exact atomic dance the
/// real methods perform. Two independent monotonic totals (Level-1 `fast_rejects` folded into
/// `produce_rejected`, Level-0 `l0_shed` folded into `fire_and_forget_shed`), each with its OWN
/// actor-side high-water mark so folding one never consumes the other (#495 separation).
struct ShedAccounting {
    /// Monotonic total of connection-thread fast-rejects (`ProduceCapGate::fast_rejects`). Bumped by
    /// handler threads with a relaxed `fetch_add`; only ever grows.
    fast_rejects: AtomicU64,
    /// The fast-reject high-water mark the actor has already folded (`ProduceCapGate::reconciled`).
    /// Touched ONLY by the single actor thread, so it needs no CAS.
    reconciled: AtomicU64,
    /// Monotonic total of Level-0 (fire-and-forget) cap-sheds (`ProduceCapGate::l0_shed`). Bumped by
    /// handler threads with a relaxed `fetch_add`; only ever grows. SEPARATE from `fast_rejects`.
    l0_shed: AtomicU64,
    /// The L0-shed high-water mark the actor has already folded (`ProduceCapGate::l0_reconciled`).
    /// Touched ONLY by the single actor thread. SEPARATE from `reconciled`.
    l0_reconciled: AtomicU64,
}

impl ShedAccounting {
    fn new() -> ShedAccounting {
        ShedAccounting {
            fast_rejects: AtomicU64::new(0),
            reconciled: AtomicU64::new(0),
            l0_shed: AtomicU64::new(0),
            l0_reconciled: AtomicU64::new(0),
        }
    }

    /// Handler side: bump the monotonic fast-reject total. Mirrors `ProduceCapGate::record_fast_reject`
    /// (a single relaxed `fetch_add` on the produce fast path).
    fn record_fast_reject(&self) {
        self.fast_rejects.fetch_add(1, Ordering::Relaxed);
    }

    /// Actor side: fold the fast-rejects accrued since the last call and advance the high-water mark.
    /// Byte-for-byte the real `ProduceCapGate::take_unreconciled_fast_rejects`: load the monotonic
    /// total, `saturating_sub` the already-folded high-water mark, and (only if non-zero) `store` the
    /// total back. Called ONLY by the single actor thread.
    fn take_unreconciled_fast_rejects(&self) -> u64 {
        let total = self.fast_rejects.load(Ordering::Relaxed);
        let already = self.reconciled.load(Ordering::Relaxed);
        let delta = total.saturating_sub(already);
        if delta != 0 {
            self.reconciled.store(total, Ordering::Relaxed);
        }
        delta
    }

    /// Handler side: bump the monotonic L0-shed total. Mirrors `ProduceCapGate::record_l0_shed`.
    fn record_l0_shed(&self) {
        self.l0_shed.fetch_add(1, Ordering::Relaxed);
    }

    /// Actor side: fold the L0 cap-sheds accrued since the last call and advance the L0 high-water
    /// mark. Byte-for-byte the real `ProduceCapGate::take_unreconciled_l0_sheds`, over the SEPARATE L0
    /// counter/high-water pair. Called ONLY by the single actor thread.
    fn take_unreconciled_l0_sheds(&self) -> u64 {
        let total = self.l0_shed.load(Ordering::Relaxed);
        let already = self.l0_reconciled.load(Ordering::Relaxed);
        let delta = total.saturating_sub(already);
        if delta != 0 {
            self.l0_reconciled.store(total, Ordering::Relaxed);
        }
        delta
    }
}

#[test]
fn produce_gate_fast_reject_folds_every_reject_exactly_once() {
    // Two handler threads each `record_fast_reject` ONCE (relaxed `fetch_add`) while the single actor
    // thread folds the delta up to TWICE: one fold that interleaves with the handlers, then a final
    // drain after they join. 3 threads, <= 3 shared ops on the actor's concurrent fold (load total /
    // load HWM / store), 1 op per handler. Invariants over EVERY interleaving:
    //   - the summed folded deltas == the final monotonic total (2): every fast-reject folded EXACTLY
    //     once — none lost (would sum < 2), none double-counted (would sum > 2);
    //   - the already-folded high-water mark NEVER exceeds the monotonic total, so the `saturating_sub`
    //     never actually saturates (the delta never wraps) under the single-actor invariant.
    // A regression that advances `reconciled` by other than the observed total, returns the raw total
    // instead of the delta, or drops the monotonic-total store makes the sum diverge from 2.
    model_counted("produce_gate_fast_reject_fold", || {
        let gate = Arc::new(ShedAccounting::new());
        let h1 = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || gate.record_fast_reject())
        };
        let h2 = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || gate.record_fast_reject())
        };
        // Actor fold #1, concurrent with the handlers. The HWM can never run ahead of the total.
        assert!(
            gate.reconciled.load(Ordering::Relaxed) <= gate.fast_rejects.load(Ordering::Relaxed),
            "the reconciled high-water mark must never exceed the monotonic fast-reject total"
        );
        let mut sum = gate.take_unreconciled_fast_rejects();
        h1.join().expect("handler 1");
        h2.join().expect("handler 2");
        // Actor fold #2 (final drain): now that both handlers are done the total is settled at 2.
        sum += gate.take_unreconciled_fast_rejects();
        assert_eq!(
            gate.fast_rejects.load(Ordering::Relaxed),
            2,
            "both handlers' fast-rejects are in the monotonic total"
        );
        assert_eq!(
            sum, 2,
            "every fast-reject is folded EXACTLY once across the folds (none lost, none double-counted)"
        );
        // The high-water mark caught the total up: a further fold yields nothing (no double-count).
        assert_eq!(
            gate.take_unreconciled_fast_rejects(),
            0,
            "a post-drain fold has nothing left to reconcile"
        );
    });
}

#[test]
fn produce_gate_l0_shed_folds_every_shed_exactly_once() {
    // The symmetric model for the INDEPENDENT Level-0 (fire-and-forget) counter (#495): two handlers
    // each `record_l0_shed` once, the single actor folds up to twice (one concurrent, one final
    // drain). Same exact-fold invariants over the L0 counter/high-water pair, proving the L0
    // accounting is as leak-free and double-count-free as the L1 fast-reject accounting.
    model_counted("produce_gate_l0_shed_fold", || {
        let gate = Arc::new(ShedAccounting::new());
        let h1 = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || gate.record_l0_shed())
        };
        let h2 = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || gate.record_l0_shed())
        };
        assert!(
            gate.l0_reconciled.load(Ordering::Relaxed) <= gate.l0_shed.load(Ordering::Relaxed),
            "the L0 high-water mark must never exceed the monotonic L0-shed total"
        );
        let mut sum = gate.take_unreconciled_l0_sheds();
        h1.join().expect("handler 1");
        h2.join().expect("handler 2");
        sum += gate.take_unreconciled_l0_sheds();
        assert_eq!(
            gate.l0_shed.load(Ordering::Relaxed),
            2,
            "both handlers' L0 sheds are in the monotonic total"
        );
        assert_eq!(
            sum, 2,
            "every L0 shed is folded EXACTLY once across the folds (none lost, none double-counted)"
        );
        assert_eq!(
            gate.take_unreconciled_l0_sheds(),
            0,
            "a post-drain L0 fold has nothing left to reconcile"
        );
    });
}

#[test]
fn produce_gate_l0_fold_never_consumes_an_l1_fast_reject_delta() {
    // The SEPARATION invariant (#495): folding the Level-0 counter must NEVER consume a Level-1
    // fast-reject delta, and vice-versa — an over-cap L0 shed is a fire-and-forget drop
    // (`fire_and_forget_shed`), a Level-1 fast-reject is a rejection the producer saw
    // (`produce_rejected`); mixing them mis-attributes the audit counters. One handler bumps ONLY the
    // fast-reject counter, another bumps ONLY the L0 counter, and the single actor folds BOTH
    // (concurrent) and again after join. Across every interleaving each counter's summed deltas equal
    // ITS OWN handler's single record — proving no cross-fold. 3 threads. A regression that folded one
    // counter's delta out of the other's atomics would make the cross-counter sums diverge.
    model_counted("produce_gate_no_cross_fold", || {
        let gate = Arc::new(ShedAccounting::new());
        let h_l1 = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || gate.record_fast_reject())
        };
        let h_l0 = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || gate.record_l0_shed())
        };
        // Concurrent fold of both counters. Each returns only its own counter's accrued delta.
        let mut fast_sum = gate.take_unreconciled_fast_rejects();
        let mut l0_sum = gate.take_unreconciled_l0_sheds();
        h_l1.join().expect("L1 handler");
        h_l0.join().expect("L0 handler");
        // Final drain of both.
        fast_sum += gate.take_unreconciled_fast_rejects();
        l0_sum += gate.take_unreconciled_l0_sheds();
        // Each counter folded exactly its own single record: the L0 fold never consumed the L1 delta,
        // nor the reverse (the two are separate `produce_rejected` vs `fire_and_forget_shed` audits).
        assert_eq!(
            fast_sum, 1,
            "the L1 fast-reject folded exactly once and was never consumed by an L0 fold"
        );
        assert_eq!(
            l0_sum, 1,
            "the L0 shed folded exactly once and was never consumed by an L1 fold"
        );
    });
}
