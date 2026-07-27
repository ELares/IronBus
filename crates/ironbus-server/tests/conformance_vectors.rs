// SPDX-License-Identifier: MIT OR Apache-2.0
//! The SEMANTICS conformance vector harness (#35).
//!
//! This integration test loads the language-agnostic vector suite from
//! `tests/vectors/semantics.json` and runs every vector's input operation sequence against the REAL
//! [`ironbus_server::engine::Engine`], asserting the observed outputs (offsets, redeliveries, stable
//! error codes, cursor positions, dedup flags, trim signals) match the vector's expected outputs
//! EXACTLY. A vector whose expected output does not match the real engine fails the test, so the
//! vectors GATE the semantics: they are the executable spec the parent #3 contract promises.
//!
//! This is the BEHAVIORAL semantics suite, distinct from the on-disk FORMAT corpus
//! (`ironbus-core/tests/conformance_corpus.rs`, #45): that pins record/segment BYTES; this pins
//! observable QUEUE BEHAVIOR.
//!
//! ## Determinism
//!
//! Time flows ONLY through the injected [`ManualClock`] (the clock seam): every operation carries an
//! explicit monotonic `now` (nanoseconds) the harness sets on the shared clock before the call, and
//! the engine reads time exclusively from that clock. There are NO real sleeps and NO wall-clock
//! reads, so a lease expiry, a dedup-window age-out, and a trim are all driven by advancing logical
//! time. The suite is therefore reproducible bit-for-bit on a slow edge CI box (the #35 failure
//! consideration). The engine runs over an [`InMemoryFs`], so there is no disk nondeterminism either.
//!
//! ## Teeth
//!
//! The harness actually CHECKS: `a_deliberately_wrong_vector_fails_the_harness` feeds a vector whose
//! expected output is wrong and asserts the harness reports a mismatch, so a harness that silently
//! passed everything would itself fail here.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use ironbus_core::clock::{Clock, ManualClock};
use ironbus_core::dedup::DedupConfig;
use ironbus_core::delivery::DeliveryConfig;
use ironbus_core::keyshared::{KeyOrdering, MemberId};
use ironbus_core::lease::{LeaseConfig, LeaseToken};
use ironbus_core::types::{Offset, RecordFlags};
use ironbus_server::codes::ErrorCode;
use ironbus_server::engine::{
    AppendOutcome, DedupRequest, DiskFullPolicy, Engine, EngineConfig, Poll,
};
use ironbus_storage::fs::InMemoryFs;
use ironbus_storage::log::{Append, LogConfig};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// The vector schema (the language-agnostic contract).
// ---------------------------------------------------------------------------

/// The whole suite file: a documented header plus the list of vectors.
#[derive(Debug, Deserialize)]
struct Suite {
    /// Free-form documentation of the suite (ignored by the harness, present for readers).
    #[allow(dead_code)]
    description: String,
    /// The ordered list of conformance vectors.
    vectors: Vec<Vector>,
}

/// One conformance vector: a name, the engine setup, and the input/expected operation sequence.
#[derive(Debug, Deserialize)]
struct Vector {
    /// The unique, stable vector name (the gate pins these).
    name: String,
    /// Which #35 category this vector covers (for the coverage assertion below).
    category: String,
    /// Free-form prose describing the property under test.
    #[allow(dead_code)]
    description: String,
    /// The engine configuration for this vector.
    #[serde(default)]
    setup: Setup,
    /// The ordered input operations with their expected observable outputs.
    steps: Vec<Step>,
}

/// The engine setup knobs a vector may override. Every field defaults to a small, integer-friendly
/// value so a vector states only what it cares about.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct Setup {
    /// The lease visibility window in NANOSECONDS of monotonic time (the redelivery seam).
    visibility_nanos: u64,
    /// The lease hard cap in nanoseconds.
    hard_cap_nanos: u64,
    /// The max-ack-pending window: at most this many offsets in flight above the committed cursor.
    max_in_flight: u32,
    /// The max-deliver poison cap (a message past this is dead-lettered, not redelivered).
    max_deliver: u32,
    /// The dedup count bound (most `(msg_id, offset)` entries one producer window keeps).
    dedup_max_ids: usize,
    /// The dedup time bound in nanoseconds (`0` disables the time bound).
    dedup_window_nanos: u64,
    /// The durable-log byte cap (`0` = unlimited). Set with `disk_full_policy = "drop_oldest"` to
    /// drive a trim.
    max_total_bytes: u64,
    /// The per-segment byte cap, so a small log rolls several segments (needed to force-reap).
    max_segment_bytes: u64,
    /// The disk-full overflow policy: `"drop_new"` (default) or `"drop_oldest"` (drives trim).
    disk_full_policy: String,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            visibility_nanos: 30,
            hard_cap_nanos: 100,
            max_in_flight: 16,
            max_deliver: 5,
            dedup_max_ids: 8,
            dedup_window_nanos: 1_000,
            max_total_bytes: 0,
            max_segment_bytes: LogConfig::default().max_segment_bytes,
            disk_full_policy: "drop_new".to_string(),
        }
    }
}

/// One step: an input operation plus its expected observable output. Tagged by `op`.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Step {
    /// Configure a group's ordering mode (`none` or `key_shared`). Server-side mode wiring.
    SetKeyOrdering { group: String, ordering: String },
    /// Mark a group broadcast (or clear it). Expects an optional error `code`.
    SetBroadcast {
        group: String,
        broadcast: bool,
        #[serde(default)]
        expect_code: Option<String>,
    },
    /// Register an active subscriber (the broadcast group-of-one cap). Expects an optional `code`.
    Subscribe {
        group: String,
        member: u64,
        #[serde(default)]
        expect_code: Option<String>,
    },
    /// Add a key-shared member to a group's router.
    JoinMember { group: String, member: u64 },
    /// Remove a key-shared member (reshuffles only its keys).
    LeaveMember { group: String, member: u64 },
    /// Produce a record (no dedup). Expects the assigned `offset`.
    Produce {
        #[serde(default)]
        key: String,
        payload: String,
        expect_offset: u64,
    },
    /// Produce with an opt-in dedup identity. Expects an `outcome`: `appended` (with `offset`),
    /// `duplicate` (with the ORIGINAL `offset`), or `fenced`.
    ProduceDedup {
        #[serde(default)]
        producer_id: String,
        #[serde(default)]
        epoch: u64,
        msg_id: String,
        payload: String,
        outcome: String,
        #[serde(default)]
        offset: Option<u64>,
    },
    /// Poll a group at monotonic `now`. Expects an `outcome`: `message` / `idle` / `parked` /
    /// `truncated`, with the relevant fields (offset, deliveries, key, `earliest_retained`,
    /// skipped, code).
    Poll {
        #[serde(default = "default_group")]
        group: String,
        now: u64,
        #[serde(default)]
        member: Option<u64>,
        outcome: String,
        #[serde(default)]
        expect_offset: Option<u64>,
        #[serde(default)]
        expect_deliveries: Option<u32>,
        #[serde(default)]
        expect_key: Option<String>,
        #[serde(default)]
        expect_earliest_retained: Option<u64>,
        #[serde(default)]
        expect_skipped: Option<u64>,
        #[serde(default)]
        expect_code: Option<String>,
        /// Bind the delivered lease token under this label so a later ack/nack can name it.
        #[serde(default)]
        bind: Option<String>,
    },
    /// Ack a previously-bound lease token. Expects an `outcome`: `acked` or, for a foreign/stale
    /// token, `not_owned` (which the harness checks carries `ERR_ACK_NOT_OWNED`).
    Ack {
        #[serde(default = "default_group")]
        group: String,
        token: String,
        outcome: String,
    },
    /// Nack a bound token, requeueing it. Expects `requeued` or `not_owned`.
    Nack {
        #[serde(default = "default_group")]
        group: String,
        token: String,
        outcome: String,
    },
    /// Cumulative-ack a broadcast group up to (exclusive) `up_to`. Expects `ok` or an error `code`.
    CumulativeAck {
        #[serde(default = "default_group")]
        group: String,
        up_to: u64,
        outcome: String,
        #[serde(default)]
        expect_code: Option<String>,
    },
    /// Assert a group's committed cursor position (a broadcast/competing cursor read).
    ExpectCommitted {
        #[serde(default = "default_group")]
        group: String,
        offset: u64,
    },
}

fn default_group() -> String {
    String::new()
}

// ---------------------------------------------------------------------------
// The harness: drive the real engine, return a mismatch on the first divergence.
// ---------------------------------------------------------------------------

/// Runs one vector against the real engine over an injected clock, returning `Ok(())` if every step
/// matched its expected output, or `Err(reason)` describing the FIRST divergence. The test asserts
/// `Ok(())`; the teeth test asserts a known-wrong vector returns `Err`.
fn run_vector(vector: &Vector) -> Result<(), String> {
    let clock = Arc::new(ManualClock::new());
    let config = build_config(&vector.setup);
    let mut engine: Engine<InMemoryFs, Arc<ManualClock>> =
        Engine::open(InMemoryFs::new(), Arc::clone(&clock), config)
            .map_err(|e| format!("engine open failed: {e}"))?;
    // The labelled lease tokens a Poll bound, so a later Ack/Nack can name the exact delivery.
    let mut tokens: HashMap<String, LeaseToken> = HashMap::new();

    for (i, step) in vector.steps.iter().enumerate() {
        run_step(&mut engine, &clock, &mut tokens, step)
            .map_err(|e| format!("step {i} ({}): {e}", step_kind(step)))?;
    }
    Ok(())
}

/// A short label for a step, for the mismatch message.
fn step_kind(step: &Step) -> &'static str {
    match step {
        Step::SetKeyOrdering { .. } => "set_key_ordering",
        Step::SetBroadcast { .. } => "set_broadcast",
        Step::Subscribe { .. } => "subscribe",
        Step::JoinMember { .. } => "join_member",
        Step::LeaveMember { .. } => "leave_member",
        Step::Produce { .. } => "produce",
        Step::ProduceDedup { .. } => "produce_dedup",
        Step::Poll { .. } => "poll",
        Step::Ack { .. } => "ack",
        Step::Nack { .. } => "nack",
        Step::CumulativeAck { .. } => "cumulative_ack",
        Step::ExpectCommitted { .. } => "expect_committed",
    }
}

#[allow(clippy::too_many_lines)]
fn run_step(
    engine: &mut Engine<InMemoryFs, Arc<ManualClock>>,
    clock: &Arc<ManualClock>,
    tokens: &mut HashMap<String, LeaseToken>,
    step: &Step,
) -> Result<(), String> {
    match step {
        Step::SetKeyOrdering { group, ordering } => {
            let ord = match ordering.as_str() {
                "none" => KeyOrdering::None,
                "key_shared" => KeyOrdering::KeyShared,
                other => return Err(format!("unknown ordering `{other}`")),
            };
            engine
                .set_key_ordering_in(group, ord)
                .map_err(|e| format!("set_key_ordering rejected: {}", e.code()))?;
            Ok(())
        }
        Step::SetBroadcast {
            group,
            broadcast,
            expect_code,
        } => {
            let result = engine.set_broadcast_in(group, *broadcast);
            check_unit_result("set_broadcast", &result, expect_code.as_deref())
        }
        Step::Subscribe {
            group,
            member,
            expect_code,
        } => {
            let result = engine.subscribe_in(group, MemberId::new(*member));
            check_unit_result("subscribe", &result, expect_code.as_deref())
        }
        Step::JoinMember { group, member } => {
            engine.join_member_in(group, MemberId::new(*member));
            Ok(())
        }
        Step::LeaveMember { group, member } => {
            engine.leave_member_in(group, MemberId::new(*member));
            Ok(())
        }
        Step::Produce {
            key,
            payload,
            expect_offset,
        } => {
            let append = Append {
                timestamp_ms: 0,
                flags: RecordFlags::EMPTY,
                key: key.as_bytes(),
                headers: b"",
                payload: payload.as_bytes(),
            };
            let offset = engine
                .produce(&append)
                .map_err(|e| format!("produce errored: {}", e.code()))?;
            expect_eq("offset", &offset.get(), expect_offset)
        }
        Step::ProduceDedup {
            producer_id,
            epoch,
            msg_id,
            payload,
            outcome,
            offset,
        } => run_produce_dedup(
            engine,
            producer_id,
            *epoch,
            msg_id,
            payload,
            outcome,
            *offset,
        ),
        Step::Poll {
            group,
            now,
            member,
            outcome,
            expect_offset,
            expect_deliveries,
            expect_key,
            expect_earliest_retained,
            expect_skipped,
            expect_code,
            bind,
        } => {
            // Drive logical time on the SHARED injected clock to exactly `now`, then poll. No sleep.
            set_monotonic(clock, *now);
            let poll = match member {
                Some(m) => engine.poll_in_member(group, MemberId::new(*m), *now),
                None => engine.poll_in(group, *now),
            }
            .map_err(|e| format!("poll errored: {}", e.code()))?;
            check_poll(
                &poll,
                outcome,
                *expect_offset,
                *expect_deliveries,
                expect_key.as_deref(),
                *expect_earliest_retained,
                *expect_skipped,
                expect_code.as_deref(),
                bind.as_deref(),
                tokens,
            )
        }
        Step::Ack {
            group,
            token,
            outcome,
        } => {
            let tok = *tokens
                .get(token)
                .ok_or_else(|| format!("unbound token `{token}`"))?;
            let result = engine.ack_in(group, &tok);
            check_ack_outcome("ack", result, outcome)
        }
        Step::Nack {
            group,
            token,
            outcome,
        } => {
            let tok = *tokens
                .get(token)
                .ok_or_else(|| format!("unbound token `{token}`"))?;
            let result = engine
                .nack_in(group, &tok, u64::MAX)
                .map_err(|e| format!("nack errored: {}", e.code()))?;
            check_nack_outcome(result, outcome)
        }
        Step::CumulativeAck {
            group,
            up_to,
            outcome,
            expect_code,
        } => {
            let result = engine.cumulative_ack_in(group, Offset::new(*up_to));
            match (outcome.as_str(), result) {
                ("ok", Ok(())) => Ok(()),
                ("ok", Err(e)) => Err(format!("expected ok, got error {}", e.code())),
                ("error", Ok(())) => Err("expected an error, got ok".to_string()),
                ("error", Err(e)) => {
                    expect_code_match("cumulative_ack", e.code(), expect_code.as_deref())
                }
                (other, _) => Err(format!("unknown cumulative_ack outcome `{other}`")),
            }
        }
        Step::ExpectCommitted { group, offset } => expect_eq(
            "committed",
            &engine.committed_offset_in(group).get(),
            offset,
        ),
    }
}

/// Drives the opt-in dedup produce path and checks the outcome (appended / duplicate / fenced).
fn run_produce_dedup(
    engine: &mut Engine<InMemoryFs, Arc<ManualClock>>,
    producer_id: &str,
    epoch: u64,
    msg_id: &str,
    payload: &str,
    outcome: &str,
    offset: Option<u64>,
) -> Result<(), String> {
    let append = Append {
        timestamp_ms: 0,
        flags: RecordFlags::EMPTY,
        key: b"",
        headers: b"",
        payload: payload.as_bytes(),
    };
    let dedup = DedupRequest {
        producer_id: producer_id.as_bytes(),
        epoch,
        msg_id: msg_id.as_bytes(),
        seq: None,
    };
    let appended = engine
        .append_no_sync_dedup(&append, Some(dedup))
        .map_err(|e| format!("dedup produce errored: {}", e.code()))?;
    // A produce path always commits the batch so the record is durable (matching `produce`).
    engine
        .commit_batch()
        .map_err(|e| format!("commit_batch errored: {}", e.code()))?;
    match (outcome, appended) {
        ("appended", AppendOutcome::Appended(o)) => {
            check_outcome_code(ErrorCode::OK, None)?;
            expect_opt("offset", o.get(), offset)
        }
        ("duplicate", AppendOutcome::Duplicate(o)) => {
            // A benign dedup hit carries the stable DUPLICATE signal code and the ORIGINAL offset.
            check_outcome_code(ErrorCode::DUPLICATE, None)?;
            expect_opt("offset", o.get(), offset)
        }
        ("fenced", AppendOutcome::Fenced { .. }) => {
            check_outcome_code(ErrorCode::ERR_PRODUCER_FENCED, None)
        }
        (want, got) => Err(format!("expected dedup outcome `{want}`, got {got:?}")),
    }
}

// ---------------------------------------------------------------------------
// Outcome checkers (each returns Err with a precise reason on a mismatch).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn check_poll(
    poll: &Poll,
    outcome: &str,
    expect_offset: Option<u64>,
    expect_deliveries: Option<u32>,
    expect_key: Option<&str>,
    expect_earliest_retained: Option<u64>,
    expect_skipped: Option<u64>,
    expect_code: Option<&str>,
    bind: Option<&str>,
    tokens: &mut HashMap<String, LeaseToken>,
) -> Result<(), String> {
    match (outcome, poll) {
        ("message", Poll::Message(d)) => {
            expect_opt("offset", d.offset.get(), expect_offset)?;
            if let Some(want) = expect_deliveries {
                expect_eq("deliveries", &d.deliveries, &want)?;
            }
            if let Some(want) = expect_key {
                let got = String::from_utf8_lossy(&d.record.key).to_string();
                expect_eq_str("key", &got, want)?;
            }
            if let Some(label) = bind {
                tokens.insert(label.to_string(), d.token);
            }
            Ok(())
        }
        ("idle", Poll::Idle) => Ok(()),
        ("parked", Poll::Parked { offset, .. }) => {
            expect_opt("offset", offset.get(), expect_offset)
        }
        (
            "truncated",
            Poll::Truncated {
                earliest_retained,
                skipped,
            },
        ) => {
            // A below-trim-horizon read surfaces the stable OFFSET_TRIMMED signal code.
            expect_code_match("poll", ErrorCode::OFFSET_TRIMMED, expect_code)?;
            if let Some(want) = expect_earliest_retained {
                expect_eq("earliest_retained", &earliest_retained.get(), &want)?;
            }
            if let Some(want) = expect_skipped {
                expect_eq("skipped", skipped, &want)?;
            }
            Ok(())
        }
        (want, got) => Err(format!("expected poll `{want}`, got {got:?}")),
    }
}

fn check_ack_outcome(
    verb: &str,
    result: ironbus_server::engine::AckResult,
    outcome: &str,
) -> Result<(), String> {
    use ironbus_server::engine::AckResult;
    match (outcome, result) {
        ("acked", AckResult::Acked) => Ok(()),
        // A foreign / stale lease ack is fenced: the engine maps it to ERR_ACK_NOT_OWNED.
        ("not_owned", AckResult::Fenced) => check_outcome_code(ErrorCode::ERR_ACK_NOT_OWNED, None),
        (want, got) => Err(format!("{verb}: expected `{want}`, got {got:?}")),
    }
}

fn check_nack_outcome(
    result: ironbus_server::engine::NackResult,
    outcome: &str,
) -> Result<(), String> {
    use ironbus_server::engine::NackResult;
    match (outcome, result) {
        ("requeued", NackResult::Requeued) => Ok(()),
        ("not_owned", NackResult::Fenced) => check_outcome_code(ErrorCode::ERR_ACK_NOT_OWNED, None),
        (want, got) => Err(format!("nack: expected `{want}`, got {got:?}")),
    }
}

/// Checks a `Result<(), EngineError>` op against an optional expected error code: `None` requires
/// success, `Some(code)` requires that exact stable code.
fn check_unit_result(
    verb: &str,
    result: &Result<(), ironbus_server::engine::EngineError>,
    expect_code: Option<&str>,
) -> Result<(), String> {
    match (result, expect_code) {
        (Ok(()), None) => Ok(()),
        (Ok(()), Some(code)) => Err(format!("{verb}: expected error `{code}`, got ok")),
        (Err(e), None) => Err(format!("{verb}: expected ok, got error {}", e.code())),
        (Err(e), Some(want)) => expect_code_match(verb, e.code(), Some(want)),
    }
}

/// Asserts an observed stable code equals an EXPECTED literal string, when the vector named one.
/// A `None` expectation is vacuously satisfied (the code is still the engine's, just unasserted).
fn check_outcome_code(observed: ErrorCode, expect: Option<&str>) -> Result<(), String> {
    match expect {
        None => Ok(()),
        Some(want) => expect_eq_str("code", observed.as_str(), want),
    }
}

fn expect_code_match(verb: &str, observed: ErrorCode, expect: Option<&str>) -> Result<(), String> {
    match expect {
        None => Ok(()),
        Some(want) => {
            if observed.as_str() == want {
                Ok(())
            } else {
                Err(format!(
                    "{verb}: expected code `{want}`, got `{}`",
                    observed.as_str()
                ))
            }
        }
    }
}

fn expect_eq<T: PartialEq + std::fmt::Debug>(field: &str, got: &T, want: &T) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{field}: expected {want:?}, got {got:?}"))
    }
}

fn expect_eq_str(field: &str, got: &str, want: &str) -> Result<(), String> {
    if got == want {
        Ok(())
    } else {
        Err(format!("{field}: expected `{want}`, got `{got}`"))
    }
}

/// Like [`expect_eq`] but the expected value is OPTIONAL: a `None` expectation skips the check (the
/// vector did not pin the offset), a `Some` asserts equality.
fn expect_opt(field: &str, got: u64, want: Option<u64>) -> Result<(), String> {
    match want {
        None => Ok(()),
        Some(w) => expect_eq(field, &got, &w),
    }
}

/// Sets the SHARED injected monotonic clock to exactly `now` nanoseconds (advancing forward; the
/// monotonic clock never moves backwards, so a vector's `now` values are non-decreasing). This is
/// the ONLY time source the engine reads, so the suite has no real sleeps.
fn set_monotonic(clock: &Arc<ManualClock>, now: u64) {
    let current = clock.now_monotonic_nanos();
    if now > current {
        clock.advance_monotonic_nanos(now - current);
    }
}

fn build_config(setup: &Setup) -> EngineConfig {
    let policy = match setup.disk_full_policy.as_str() {
        "drop_oldest" => DiskFullPolicy::DropOldest,
        _ => DiskFullPolicy::DropNew,
    };
    EngineConfig {
        min_splice_bytes: 0,
        consume_longpoll_ms: 0,
        storage_mode: ironbus_storage::shared_wal::StorageMode::PerStreamLogs,
        log: LogConfig {
            max_segment_bytes: setup.max_segment_bytes,
            max_total_bytes: setup.max_total_bytes,
            ..LogConfig::default()
        },
        lease: LeaseConfig {
            visibility_nanos: setup.visibility_nanos,
            hard_cap_nanos: setup.hard_cap_nanos,
        },
        delivery: DeliveryConfig::new(setup.max_deliver, false, vec![])
            .expect("the vector's max_deliver is a valid delivery config"),
        max_in_flight: setup.max_in_flight,
        consumer_credit: 64,
        consumer_credit_bytes: 0,
        checkpoint_interval: 1024,
        max_acked_ahead_runs: 1024,
        max_retained_bytes: 0,
        max_age_ms: 0,
        max_messages: 0,
        disk_full_policy: policy,
        max_groups: 1024,
        // Named-stream cap OFF (#863, `0` = unlimited): the conformance vectors assume the
        // historical unbounded behavior, so the golden bytes are unchanged by the cap.
        max_streams: 0,
        max_open_streams: 0,
        // Per-stream consumer-metric cap (#600): observability only, does not affect the golden bytes.
        max_metric_streams: 1024,
        group_idle_evict_ms: 0,
        ram_ceiling_bytes: 0,
        dedup: DedupConfig {
            max_ids: setup.dedup_max_ids,
            window_nanos: setup.dedup_window_nanos,
            max_producers: 4096,
        },
        // The conformance vectors exercise the default durable level (#341): ack-implies-durable.
        durability_level: ironbus_server::engine::DurabilityLevel::Sync,
        flush_interval_ms: 0,
        flush_max_bytes: 0,
        // Backpressure controls (#68, #69) default to inert, so these test/config builders keep
        // the historical behavior (CoDel off, retry budget off, fire-and-forget ungoverned).
        codel_target_ms: 0,
        codel_interval_ms: 0,
        retry_budget_ratio_per_million: 0,
        retry_budget_window_ms: 0,
        fire_and_forget_msg_rate: 0,
        fire_and_forget_byte_rate: 0,
        fire_and_forget_refill_ms: 0,
        egress_limit: 0,
        wal_fsync_headroom_bytes: 0,
        sync_max_dirty_bytes: 0,
        // Compression OFF (#430): the frozen conformance vectors pin the uncompressed layout.
        compression: ironbus_core::compress::Codec::None,
        // V2-M4 routing richness defaults to inert here (#549/#551): no message TTL, no
        // dead-letter exchange (the existing fixed-DLQ behavior) — back-compat byte-identical.
        default_message_ttl_ms: 0,
        max_delay_ms: 0,
        dead_letter_exchange: None,
        dead_letter_expired: false,
    }
}

// ---------------------------------------------------------------------------
// The tests.
// ---------------------------------------------------------------------------

fn load_suite() -> Suite {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("semantics.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read vector file {}: {e}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse vector file {}: {e}", path.display()))
}

#[test]
fn every_semantics_vector_matches_the_real_engine() {
    let suite = load_suite();
    assert!(!suite.vectors.is_empty(), "the suite must not be empty");
    for vector in &suite.vectors {
        if let Err(reason) = run_vector(vector) {
            panic!("vector `{}` FAILED: {reason}", vector.name);
        }
    }
}

#[test]
fn every_category_is_covered_and_names_are_unique() {
    // Pin the #35 categories so a future edit that DROPS a category's coverage fails here, not
    // silently. Every category in this set must have at least one vector, and every vector's
    // category must be in this set.
    let suite = load_suite();
    let required = [
        "ordering",
        "redelivery",
        "dedup",
        "ack_rejection",
        "key_routing",
        "broadcast",
        "trim",
    ];
    let mut seen: HashMap<&str, usize> = HashMap::new();
    let mut names: HashSet<&str> = HashSet::new();
    for v in &suite.vectors {
        assert!(
            names.insert(v.name.as_str()),
            "duplicate vector name `{}`",
            v.name
        );
        assert!(
            required.contains(&v.category.as_str()),
            "vector `{}` has an unknown category `{}`",
            v.name,
            v.category
        );
        *seen.entry(v.category.as_str()).or_insert(0) += 1;
    }
    for cat in required {
        assert!(
            seen.get(cat).copied().unwrap_or(0) > 0,
            "no vector covers the `{cat}` category"
        );
    }
}

#[test]
fn a_deliberately_wrong_vector_fails_the_harness() {
    // TEETH: a vector whose expected output is WRONG must fail the harness, proving the harness
    // actually checks the engine's output rather than rubber-stamping. Here the produce really
    // assigns offset 0, but the vector claims offset 99, so `run_vector` must report a mismatch.
    let wrong: Vector = serde_json::from_value(serde_json::json!({
        "name": "intentionally-wrong",
        "category": "ordering",
        "description": "a produce that claims the wrong offset",
        "setup": {},
        "steps": [
            { "op": "produce", "payload": "x", "expect_offset": 99 }
        ]
    }))
    .expect("the inline teeth vector parses");
    let result = run_vector(&wrong);
    assert!(
        result.is_err(),
        "a wrong expected output must fail the harness, but it passed"
    );
    let reason = result.unwrap_err();
    assert!(
        reason.contains("offset") && reason.contains("99"),
        "the mismatch must name the offending field and value, got: {reason}"
    );
}

#[test]
fn a_right_vector_passes_the_same_harness() {
    // The positive twin of the teeth test: the SAME single-step shape with the CORRECT expected
    // offset passes, so the teeth test's failure is the wrong value, not a broken harness.
    let right: Vector = serde_json::from_value(serde_json::json!({
        "name": "intentionally-right",
        "category": "ordering",
        "description": "a produce that claims the correct offset",
        "setup": {},
        "steps": [
            { "op": "produce", "payload": "x", "expect_offset": 0 }
        ]
    }))
    .expect("the inline vector parses");
    assert!(run_vector(&right).is_ok());
}
