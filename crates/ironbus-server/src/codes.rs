// SPDX-License-Identifier: MIT OR Apache-2.0
//! The STABLE semantics error/outcome codes (#35): the pinned, language-agnostic vocabulary the
//! conformance vectors assert against.
//!
//! The engine's behavioral contract (the parent #3 design) names a handful of OBSERVABLE rejection
//! and signal outcomes: a cumulative ack on a competing group is refused, a foreign-lease ack is
//! not owned, a read below the trim horizon is trimmed, a zombie producer is fenced, and so on.
//! Before #35 those outcomes were carried as ad-hoc prose [`crate::engine::EngineError`] Display
//! strings (surfaced to a client via `Err` replies) or as untyped status bytes (a fenced ack is a
//! `0` on the wire). Prose drifts and a status byte is anonymous, so neither is a stable contract a
//! second implementation or an external client can assert against.
//!
//! This module FORMALIZES those outcomes as stable string constants ([`ErrorCode`]). The codes are
//! NORMATIVE: once shipped they never change spelling, so the conformance vectors
//! (`tests/vectors/semantics.json`) and any external client may pin them. The mapping from the
//! engine's typed outcomes to a code is the single source of truth:
//!
//! - [`ErrorCode::of_engine_error`] maps every [`crate::engine::EngineError`] variant to its code.
//! - The non-error observable outcomes that are NOT an `EngineError` (a fenced/foreign ack, a
//!   producer-epoch fence, a benign dedup hit, a below-trim-horizon read) each have a named
//!   constant the harness asserts the engine's behavior maps to.
//!
//! The change is ADDITIVE: it introduces codes and a mapping but does NOT alter the existing
//! `EngineError` Display text, the wire `Err` bodies, or the status bytes, so every existing test
//! and the frozen wire stay byte-for-byte unchanged. A later wire error-code scheme (a numeric tag
//! on the `Err` frame) can adopt these same constants without a second taxonomy.

use crate::engine::EngineError;

/// A stable, NORMATIVE semantics outcome code (#35): a short `SCREAMING_SNAKE_CASE` token that names
/// an observable engine behavior the conformance contract pins. The string spelling is frozen, so
/// the conformance vectors and any external client may assert against it.
///
/// The `ERR_*` codes name a REJECTION (a verb the engine refused); the bare codes ([`Self::OK`],
/// [`Self::DUPLICATE`], [`Self::OFFSET_TRIMMED`], [`Self::OFFSET_COMPACTED`]) name a non-error
/// observable SIGNAL (a success, a benign dedup hit, a below-trim-horizon read, a key-compaction
/// hole crossing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    /// The stable string spelling of this code (e.g. `"ERR_CUMULATIVE_ACK_NOT_ALLOWED"`). Frozen:
    /// the conformance vectors assert against exactly this text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    // ----- non-error observable signals -----

    /// A verb succeeded (an ack committed, a cumulative ack advanced or was an idempotent no-op, a
    /// fresh produce was appended). The generic body-less success.
    pub const OK: ErrorCode = ErrorCode("OK");

    /// A BENIGN dedup hit (#33): a produce whose `msg_id` was already in the producer's window, so
    /// the broker returned the ORIGINAL offset WITHOUT appending a second copy (`duplicate = true`,
    /// a success, never an error). Not an `EngineError`: it is an `AppendOutcome::Duplicate`.
    pub const DUPLICATE: ErrorCode = ErrorCode("DUPLICATE");

    /// A read fell BELOW the trim/retention horizon (#82, #84): the consumer's cursor was reaped out
    /// from under it, so the engine reset the cursor up to the earliest retained offset and surfaced
    /// the skip ONCE (the `Poll::Truncated` advisory). Not an `EngineError`: it is an observable
    /// poll outcome the consumer learns its lost span from. The contract's `OFFSET_TRIMMED`.
    #[allow(non_upper_case_globals)]
    pub const OFFSET_TRIMMED: ErrorCode = ErrorCode("OFFSET_TRIMMED");

    /// A read crossed a key-COMPACTION hole (#337, #411): one or more INTERIOR offsets were removed by
    /// compaction (a later record for the same key superseded them), so they are permanently absent
    /// mid-stream while the surrounding segment is present. The engine advances the cursor past the
    /// `[from, to)` run and surfaces it ONCE as the `Poll::Compacted` signal, which the session maps
    /// to a `GapMarker(reason = COMPACTED)` for a gap-marker-capable consumer (a non-capable consumer
    /// advances silently). Not an `EngineError` and NOT a loss (the latest-value-per-key view is
    /// intact, the cursor still reaches head, no `LossReport`): it is the consumer-facing, non-loss
    /// twin of `OFFSET_TRIMMED`. The contract's `OFFSET_COMPACTED`.
    #[allow(non_upper_case_globals)]
    pub const OFFSET_COMPACTED: ErrorCode = ErrorCode("OFFSET_COMPACTED");

    // ----- rejection codes (one per EngineError, plus the fenced-ack / producer-fence outcomes) -----

    /// A cumulative ack was refused because the group is a COMPETING (or `key_shared`, or unknown,
    /// or not-marked-broadcast) work-group (#63). Maps [`EngineError::CumulativeAckOnWorkGroup`].
    pub const ERR_CUMULATIVE_ACK_NOT_ALLOWED: ErrorCode =
        ErrorCode("ERR_CUMULATIVE_ACK_NOT_ALLOWED");

    /// An ack/nack/term/progress named a lease this consumer does NOT own: a token never delivered
    /// to it, or a stale generation whose message already redelivered or was acked (the engine
    /// returns `AckResult::Fenced` / `NackResult::Fenced`, the wire status `0`). The contract's
    /// `ERR_ACK_NOT_OWNED`.
    pub const ERR_ACK_NOT_OWNED: ErrorCode = ErrorCode("ERR_ACK_NOT_OWNED");

    /// A broadcast cumulative ack named an `up_to` outside the retained window (#288). Maps
    /// [`EngineError::CumulativeAckOutOfRange`].
    pub const ERR_CUMULATIVE_ACK_OUT_OF_RANGE: ErrorCode =
        ErrorCode("ERR_CUMULATIVE_ACK_OUT_OF_RANGE");

    /// A second subscriber or an unsafe flip to broadcast violated the group-of-one invariant
    /// (#288). Maps [`EngineError::BroadcastGroupBusy`].
    pub const ERR_BROADCAST_GROUP_BUSY: ErrorCode = ErrorCode("ERR_BROADCAST_GROUP_BUSY");

    /// A flip to broadcast named the default/empty group, which can never be broadcast (#288). Maps
    /// [`EngineError::BroadcastGroupNotNamed`].
    pub const ERR_BROADCAST_GROUP_NOT_NAMED: ErrorCode = ErrorCode("ERR_BROADCAST_GROUP_NOT_NAMED");

    /// An ephemeral/durable mode conflict on a work-group name (#771): an ephemeral subscribe named
    /// a group that is live as durable or carries durable state, or a durable subscribe named a
    /// group that is live as ephemeral. Maps [`EngineError::EphemeralGroupConflict`].
    pub const ERR_EPHEMERAL_GROUP_CONFLICT: ErrorCode = ErrorCode("ERR_EPHEMERAL_GROUP_CONFLICT");

    /// A new named work-group exceeded the per-engine group cap (#240). Maps
    /// [`EngineError::TooManyGroups`].
    pub const ERR_TOO_MANY_GROUPS: ErrorCode = ErrorCode("ERR_TOO_MANY_GROUPS");

    /// A new named stream exceeded the per-engine resident-stream cap (#863). Maps
    /// [`EngineError::TooManyStreams`].
    pub const ERR_TOO_MANY_STREAMS: ErrorCode = ErrorCode("ERR_TOO_MANY_STREAMS");

    /// A work-group name was empty, too long, or non-graphic ASCII (#240). Maps
    /// [`EngineError::InvalidGroupName`].
    pub const ERR_INVALID_GROUP_NAME: ErrorCode = ErrorCode("ERR_INVALID_GROUP_NAME");

    /// A NAMED stream name was empty, too long, or non-graphic ASCII (#676). Maps
    /// [`EngineError::InvalidStreamName`].
    pub const ERR_INVALID_STREAM_NAME: ErrorCode = ErrorCode("ERR_INVALID_STREAM_NAME");

    /// A consume/ack/commit targeted a NAMED stream that was never declared (#676). Maps
    /// [`EngineError::UnknownStream`].
    pub const ERR_UNKNOWN_STREAM: ErrorCode = ErrorCode("ERR_UNKNOWN_STREAM");

    /// A client PRODUCE targeted a READ-ONLY cross-cluster MIRROR stream (#623): a mirror's only writer
    /// is the geo mirror-apply path, so a client produce is rejected. Maps
    /// [`EngineError::MirrorReadOnly`].
    pub const ERR_MIRROR_READ_ONLY: ErrorCode = ErrorCode("ERR_MIRROR_READ_ONLY");

    /// A subject or bind pattern was not valid #567 grammar (#585). Maps
    /// [`EngineError::InvalidSubject`].
    pub const ERR_INVALID_SUBJECT: ErrorCode = ErrorCode("ERR_INVALID_SUBJECT");

    /// A `BindSubject` was refused because the resulting binding set would exceed the routing trie's
    /// fork bound (#585/#568). Maps [`EngineError::BindRejected`].
    pub const ERR_BIND_REJECTED: ErrorCode = ErrorCode("ERR_BIND_REJECTED");

    /// A `BindSubject` was refused because the resulting binding table's durable snapshot would
    /// exceed its checkpoint slot (#1106) — the fail-closed durable-size twin of the fork bound; the
    /// previous table stays installed and durable. Maps [`EngineError::BindingTableFull`].
    pub const ERR_BINDING_TABLE_FULL: ErrorCode = ErrorCode("ERR_BINDING_TABLE_FULL");

    /// A subject-addressed publish resolved to NO bound stream — the fail-closed reject, NOT a silent
    /// drop (#585). Maps [`EngineError::NoStreamForSubject`].
    pub const ERR_NO_STREAM_FOR_SUBJECT: ErrorCode = ErrorCode("ERR_NO_STREAM_FOR_SUBJECT");

    /// A subject-addressed publish resolved to two-or-more bound streams under the single-home default
    /// (#585). Maps [`EngineError::AmbiguousSubject`].
    pub const ERR_AMBIGUOUS_SUBJECT: ErrorCode = ErrorCode("ERR_AMBIGUOUS_SUBJECT");

    /// A produce presented a STALE producer epoch (a zombie session reusing an old `producer_id`,
    /// #33): the broker rejects it (`AppendOutcome::Fenced`, the wire `fenced: stale producer
    /// epoch`). Not an `EngineError`: it is an `AppendOutcome`. The contract's `ERR_PRODUCER_FENCED`.
    pub const ERR_PRODUCER_FENCED: ErrorCode = ErrorCode("ERR_PRODUCER_FENCED");

    /// A sequenced idempotent produce presented an OUT-OF-ORDER sequence (`seq > last-accepted + 1`,
    /// a gap, V2-M8): the broker rejects it (`AppendOutcome::OutOfOrder`, the wire `out-of-order
    /// producer sequence`), the Kafka `OutOfOrderSequence` semantics, so a later retry of a skipped
    /// seq cannot double-append. Not an `EngineError`: it is an `AppendOutcome`. The contract's
    /// `ERR_OUT_OF_ORDER_SEQUENCE`.
    pub const ERR_OUT_OF_ORDER_SEQUENCE: ErrorCode = ErrorCode("ERR_OUT_OF_ORDER_SEQUENCE");

    /// A produce was shed because the durable log is at its byte cap (the drop-new shed). Maps an
    /// at-capacity [`EngineError::Storage`].
    pub const ERR_AT_CAPACITY: ErrorCode = ErrorCode("ERR_AT_CAPACITY");

    /// A clustered `C2-fsync` produce could not be quorum-committed because the partition's parked-ack
    /// backlog is at its cap (#864/#883): an unsatisfiable ISR is already withholding the cap's worth of
    /// acks, so the data plane refused to park another (the honest unavailable-over-unsafe signal) rather
    /// than grow toward OOM or ack a record durable only on the leader. A genuinely RETRYABLE condition —
    /// the producer backs off and retries once the ISR recovers. Not an `EngineError` and not an
    /// `AppendOutcome`: it is the [`AckDisposition::Rejected`](crate::cluster::dataplane::AckDisposition)
    /// gate outcome, tagged directly at its reply site. The contract's `ERR_NOT_ENOUGH_ISR`.
    pub const ERR_NOT_ENOUGH_ISR: ErrorCode = ErrorCode("ERR_NOT_ENOUGH_ISR");

    /// The lease generation space is exhausted (unreachable in practice). Maps
    /// [`EngineError::GenerationExhausted`].
    pub const ERR_GENERATION_EXHAUSTED: ErrorCode = ErrorCode("ERR_GENERATION_EXHAUSTED");

    /// An internal invariant broke (a deliverable offset had no record). Maps
    /// [`EngineError::MissingRecord`].
    pub const ERR_MISSING_RECORD: ErrorCode = ErrorCode("ERR_MISSING_RECORD");

    /// `max_in_flight` was zero, rejected at open. Maps [`EngineError::ZeroMaxInFlight`].
    pub const ERR_ZERO_MAX_IN_FLIGHT: ErrorCode = ErrorCode("ERR_ZERO_MAX_IN_FLIGHT");

    /// A generic storage error (not one of the named-above storage outcomes). Maps the residual
    /// [`EngineError::Storage`].
    pub const ERR_STORAGE: ErrorCode = ErrorCode("ERR_STORAGE");

    /// A transactional half-message verb was rejected by the lifecycle (#640): an unknown/spent txn
    /// id, a conflicting resolve (commit-after-rollback / rollback-after-commit, refused not flipped),
    /// too many prepared, or an over-long id. Maps [`EngineError::Txn`].
    pub const ERR_TXN: ErrorCode = ErrorCode("ERR_TXN");

    /// A back-check answer (`TxnCheckResult`, #640 part 2) was REFUSED on ownership: the answering
    /// connection does not own the in-doubt txn's listener group (it registered no listener, or a
    /// different group), so it may not resolve it. The txn is left Prepared on its back-check schedule.
    /// Maps [`EngineError::TxnCheckUnauthorized`].
    pub const ERR_TXN_CHECK_UNAUTHORIZED: ErrorCode = ErrorCode("ERR_TXN_CHECK_UNAUTHORIZED");

    /// A publish carried a delayed-delivery request over the broker's configured maximum delay
    /// (V2-M4, #555): rejected fail-closed at the produce boundary (nothing appended), never
    /// silently clamped. Maps [`EngineError::DelayTooLong`].
    pub const ERR_DELAY_TOO_LONG: ErrorCode = ErrorCode("ERR_DELAY_TOO_LONG");

    /// A publish carried a raw broker-only `DUE1` due-instant block in its wire headers (V2-M4,
    /// #555 injection hardening): rejected fail-closed — only the broker mints `DUE1`; accepting
    /// it from the wire would bypass the max-delay bound and the broker-clock anchor. A wire
    /// produce must carry a `DLY1` relative delay request. Maps [`EngineError::DueTimeInjected`].
    pub const ERR_INVALID_DELAY_HEADER: ErrorCode = ErrorCode("ERR_INVALID_DELAY_HEADER");

    /// Maps an [`EngineError`] to its stable code. The single source of truth the conformance
    /// vectors and any wire error-code scheme share. A storage error is split into the two named
    /// outcomes ([`Self::ERR_AT_CAPACITY`] for the byte-cap shed) plus the residual
    /// [`Self::ERR_STORAGE`], so a shed is a stable, distinct code rather than an anonymous storage
    /// fault.
    #[must_use]
    pub fn of_engine_error(error: &EngineError) -> ErrorCode {
        match error {
            EngineError::CumulativeAckOnWorkGroup => Self::ERR_CUMULATIVE_ACK_NOT_ALLOWED,
            EngineError::CumulativeAckOutOfRange { .. } => Self::ERR_CUMULATIVE_ACK_OUT_OF_RANGE,
            EngineError::BroadcastGroupBusy { .. } => Self::ERR_BROADCAST_GROUP_BUSY,
            EngineError::BroadcastGroupNotNamed { .. } => Self::ERR_BROADCAST_GROUP_NOT_NAMED,
            EngineError::EphemeralGroupConflict { .. } => Self::ERR_EPHEMERAL_GROUP_CONFLICT,
            EngineError::TooManyGroups { .. } => Self::ERR_TOO_MANY_GROUPS,
            EngineError::TooManyStreams { .. } => Self::ERR_TOO_MANY_STREAMS,
            EngineError::InvalidGroupName => Self::ERR_INVALID_GROUP_NAME,
            EngineError::InvalidStreamName { .. } => Self::ERR_INVALID_STREAM_NAME,
            EngineError::MirrorReadOnly { .. } => Self::ERR_MIRROR_READ_ONLY,
            EngineError::UnknownStream { .. } => Self::ERR_UNKNOWN_STREAM,
            EngineError::InvalidSubject(_) => Self::ERR_INVALID_SUBJECT,
            EngineError::BindRejected(_) => Self::ERR_BIND_REJECTED,
            EngineError::BindingTableFull { .. } => Self::ERR_BINDING_TABLE_FULL,
            EngineError::NoStreamForSubject { .. } => Self::ERR_NO_STREAM_FOR_SUBJECT,
            EngineError::AmbiguousSubject { .. } => Self::ERR_AMBIGUOUS_SUBJECT,
            EngineError::GenerationExhausted => Self::ERR_GENERATION_EXHAUSTED,
            EngineError::MissingRecord { .. } => Self::ERR_MISSING_RECORD,
            EngineError::ZeroMaxInFlight => Self::ERR_ZERO_MAX_IN_FLIGHT,
            EngineError::Txn(_) => Self::ERR_TXN,
            EngineError::TxnCheckUnauthorized => Self::ERR_TXN_CHECK_UNAUTHORIZED,
            EngineError::DelayTooLong { .. } => Self::ERR_DELAY_TOO_LONG,
            EngineError::DueTimeInjected { .. } => Self::ERR_INVALID_DELAY_HEADER,
            EngineError::Storage(_) if error.is_at_capacity() => Self::ERR_AT_CAPACITY,
            EngineError::Storage(_) => Self::ERR_STORAGE,
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

impl EngineError {
    /// The STABLE semantics code for this error (#35): the normative, frozen token the conformance
    /// vectors assert against, distinct from the human-readable [`core::fmt::Display`] text (which is
    /// not pinned and may be reworded). Delegates to [`ErrorCode::of_engine_error`].
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        ErrorCode::of_engine_error(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_storage::segment::StorageError;

    #[test]
    // #883: the wire `Err` frame now carries the frozen `ErrorCode` token, which the client decodes to
    // a typed `ironbus_proto::err::ServerErrorCode`. The token spellings are duplicated in the proto
    // crate's `from_token` map (the client cannot depend on this crate); this test PINS the two together
    // so a rename here that the proto map misses fails CI. Every code the server places on an `Err`
    // frame — the `EngineError` rejections plus the `AppendOutcome` signals (`ERR_AT_CAPACITY`,
    // `ERR_PRODUCER_FENCED`, `ERR_OUT_OF_ORDER_SEQUENCE`) plus the `AckDisposition` gate reject
    // (`ERR_NOT_ENOUGH_ISR`) — must round-trip through the proto enum.
    fn every_wire_code_is_recognized_by_the_proto_decoder() {
        use ironbus_proto::err::ServerErrorCode;
        let wire_codes = [
            ErrorCode::ERR_CUMULATIVE_ACK_NOT_ALLOWED,
            ErrorCode::ERR_CUMULATIVE_ACK_OUT_OF_RANGE,
            ErrorCode::ERR_BROADCAST_GROUP_BUSY,
            ErrorCode::ERR_BROADCAST_GROUP_NOT_NAMED,
            ErrorCode::ERR_EPHEMERAL_GROUP_CONFLICT,
            ErrorCode::ERR_TOO_MANY_GROUPS,
            ErrorCode::ERR_TOO_MANY_STREAMS,
            ErrorCode::ERR_INVALID_GROUP_NAME,
            ErrorCode::ERR_INVALID_STREAM_NAME,
            ErrorCode::ERR_UNKNOWN_STREAM,
            ErrorCode::ERR_MIRROR_READ_ONLY,
            ErrorCode::ERR_INVALID_SUBJECT,
            ErrorCode::ERR_BIND_REJECTED,
            ErrorCode::ERR_BINDING_TABLE_FULL,
            ErrorCode::ERR_NO_STREAM_FOR_SUBJECT,
            ErrorCode::ERR_AMBIGUOUS_SUBJECT,
            ErrorCode::ERR_GENERATION_EXHAUSTED,
            ErrorCode::ERR_MISSING_RECORD,
            ErrorCode::ERR_ZERO_MAX_IN_FLIGHT,
            ErrorCode::ERR_STORAGE,
            ErrorCode::ERR_TXN,
            ErrorCode::ERR_TXN_CHECK_UNAUTHORIZED,
            ErrorCode::ERR_DELAY_TOO_LONG,
            ErrorCode::ERR_INVALID_DELAY_HEADER,
            ErrorCode::ERR_AT_CAPACITY,
            ErrorCode::ERR_NOT_ENOUGH_ISR,
            ErrorCode::ERR_PRODUCER_FENCED,
            ErrorCode::ERR_OUT_OF_ORDER_SEQUENCE,
        ];
        for code in wire_codes {
            assert!(
                ServerErrorCode::from_token(code.as_str()).is_some(),
                "the proto decoder does not recognize the wire code `{}`",
                code.as_str()
            );
        }
    }

    #[test]
    fn the_named_codes_have_their_frozen_spelling() {
        // The vectors and external clients pin these exact strings: a rename must fail here.
        assert_eq!(
            ErrorCode::ERR_CUMULATIVE_ACK_NOT_ALLOWED.as_str(),
            "ERR_CUMULATIVE_ACK_NOT_ALLOWED"
        );
        assert_eq!(ErrorCode::ERR_ACK_NOT_OWNED.as_str(), "ERR_ACK_NOT_OWNED");
        assert_eq!(ErrorCode::ERR_NOT_ENOUGH_ISR.as_str(), "ERR_NOT_ENOUGH_ISR");
        assert_eq!(ErrorCode::OFFSET_TRIMMED.as_str(), "OFFSET_TRIMMED");
        assert_eq!(ErrorCode::OFFSET_COMPACTED.as_str(), "OFFSET_COMPACTED");
        assert_eq!(
            ErrorCode::ERR_PRODUCER_FENCED.as_str(),
            "ERR_PRODUCER_FENCED"
        );
        assert_eq!(
            ErrorCode::ERR_OUT_OF_ORDER_SEQUENCE.as_str(),
            "ERR_OUT_OF_ORDER_SEQUENCE"
        );
        assert_eq!(ErrorCode::DUPLICATE.as_str(), "DUPLICATE");
        assert_eq!(ErrorCode::OK.as_str(), "OK");
        assert_eq!(
            ErrorCode::ERR_TXN_CHECK_UNAUTHORIZED.as_str(),
            "ERR_TXN_CHECK_UNAUTHORIZED"
        );
    }

    #[test]
    // One literal per EngineError variant: the table grows by one row per variant, so it is inherently
    // long but is a single flat exhaustiveness fixture (not branching logic) — splitting it would only
    // scatter the one mapping it proves.
    #[allow(clippy::too_many_lines)]
    fn every_engine_error_maps_to_a_code() {
        // One representative per variant, so a NEW EngineError variant that forgets its code makes
        // `of_engine_error` non-exhaustive and fails to compile (the match has no wildcard).
        let cases: &[(EngineError, ErrorCode)] = &[
            (
                EngineError::CumulativeAckOnWorkGroup,
                ErrorCode::ERR_CUMULATIVE_ACK_NOT_ALLOWED,
            ),
            (
                EngineError::CumulativeAckOutOfRange {
                    up_to: 9,
                    earliest_retained: 0,
                    durable_head: 3,
                },
                ErrorCode::ERR_CUMULATIVE_ACK_OUT_OF_RANGE,
            ),
            (
                EngineError::BroadcastGroupBusy {
                    group: "g".to_string(),
                },
                ErrorCode::ERR_BROADCAST_GROUP_BUSY,
            ),
            (
                EngineError::BroadcastGroupNotNamed {
                    group: String::new(),
                },
                ErrorCode::ERR_BROADCAST_GROUP_NOT_NAMED,
            ),
            (
                EngineError::EphemeralGroupConflict {
                    group: "g".to_string(),
                },
                ErrorCode::ERR_EPHEMERAL_GROUP_CONFLICT,
            ),
            (
                EngineError::TooManyGroups { max: 8 },
                ErrorCode::ERR_TOO_MANY_GROUPS,
            ),
            (
                EngineError::InvalidGroupName,
                ErrorCode::ERR_INVALID_GROUP_NAME,
            ),
            (
                EngineError::InvalidStreamName {
                    name: "bad name".to_string(),
                },
                ErrorCode::ERR_INVALID_STREAM_NAME,
            ),
            (
                EngineError::UnknownStream {
                    name: "ghost".to_string(),
                },
                ErrorCode::ERR_UNKNOWN_STREAM,
            ),
            (
                EngineError::MirrorReadOnly {
                    name: "mirror-orders".to_string(),
                },
                ErrorCode::ERR_MIRROR_READ_ONLY,
            ),
            (
                EngineError::InvalidSubject(ironbus_core::subject::SubjectError::Empty),
                ErrorCode::ERR_INVALID_SUBJECT,
            ),
            (
                EngineError::BindRejected(ironbus_core::sublist::SublistError::ForkLimitExceeded {
                    worst_case: 2048,
                    limit: 1024,
                }),
                ErrorCode::ERR_BIND_REJECTED,
            ),
            (
                EngineError::BindingTableFull {
                    max_bytes: 60 * 1024,
                },
                ErrorCode::ERR_BINDING_TABLE_FULL,
            ),
            (
                EngineError::NoStreamForSubject {
                    subject: "telemetry.cpu".to_string(),
                },
                ErrorCode::ERR_NO_STREAM_FOR_SUBJECT,
            ),
            (
                EngineError::AmbiguousSubject {
                    subject: "order.us.created".to_string(),
                    matched: 2,
                },
                ErrorCode::ERR_AMBIGUOUS_SUBJECT,
            ),
            (
                EngineError::GenerationExhausted,
                ErrorCode::ERR_GENERATION_EXHAUSTED,
            ),
            (
                EngineError::MissingRecord { offset: 4 },
                ErrorCode::ERR_MISSING_RECORD,
            ),
            (
                EngineError::ZeroMaxInFlight,
                ErrorCode::ERR_ZERO_MAX_IN_FLIGHT,
            ),
            (
                EngineError::Storage(StorageError::AtCapacity {
                    durable_bytes: 64,
                    cap: 32,
                }),
                ErrorCode::ERR_AT_CAPACITY,
            ),
            (
                EngineError::TxnCheckUnauthorized,
                ErrorCode::ERR_TXN_CHECK_UNAUTHORIZED,
            ),
            (
                EngineError::DelayTooLong {
                    requested_ms: 1_000,
                    max_ms: 500,
                },
                ErrorCode::ERR_DELAY_TOO_LONG,
            ),
            (
                EngineError::DueTimeInjected {
                    due_unix_ms: u64::MAX,
                },
                ErrorCode::ERR_INVALID_DELAY_HEADER,
            ),
            (
                EngineError::Storage(StorageError::WriterFrozen),
                ErrorCode::ERR_STORAGE,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.code(), *expected, "wrong code for {err:?}");
        }
    }
}
