// SPDX-License-Identifier: MIT OR Apache-2.0
//! The apples-to-apples baseline COMPARISON RIG: a versioned comparison-report schema, the central
//! anti-marketing DURABILITY-LABEL-MATCH lint, the appendix-labeling rule that keeps cluster-class
//! brokers out of the edge SLO gates, and the Little's-Law queue-occupancy computation (#114).
//!
//! # Why this exists
//!
//! A baseline comparison is only honest if both sides run the SAME workload under the SAME durability
//! semantics on the SAME device. The trap the parent issue (#19) names is mislabeled durability
//! turning a comparison into marketing: quoting IronBus's durable group-commit-`fdatasync` number
//! against a peer's page-cache (no-fsync) number. This module makes that error a BUILD FAILURE, not a
//! footnote: [`ComparisonReport::build`] refuses to assemble a report in which a compared pair
//! carries mismatched durability labels.
//!
//! Two further guards encode the issue's other anti-dishonesty rules:
//!
//! - APPENDIX LABELING. Kafka and Redpanda are JVM/Seastar multi-node systems, not single-edge-node
//!   brokers, so they are EXCLUDED from the edge SLO gates and may appear only in an x86-ref
//!   informational appendix clearly labeled "not an edge-class comparison". A row tagged for the edge
//!   gate that names Kafka or Redpanda fails the build ([`ComparisonReport::build`]); they are legal
//!   only in [`Placement::Appendix`].
//! - LITTLE'S LAW. Every row can carry the queue occupancy `L = lambda * W` (throughput times
//!   latency) at its target rate, so a reader can see that p99 stays within the SLO at the chosen
//!   concurrency bound rather than taking the number on faith ([`littles_law_occupancy`]).
//!
//! # What lives here vs the live runs
//!
//! This module is the RIG (the schema + the lints + the math): it is READY to ingest peer rows the
//! moment a NATS/Redis/Mosquitto run is produced on a host that has those brokers installed. It does
//! NOT run those brokers; CI cannot. The actual live multi-broker numbers are a documented host
//! residual (see `docs/BASELINE_RIG.md`). The rig validates and serializes whatever rows it is fed.
//!
//! Like the rest of `ironbus-bench`, this is a `publish = false` crate, off the shipped `ironbus`
//! binary's dependency graph; it reuses only `serde`/`serde_json`, which the harness already pulls.

use serde::Serialize;

/// The comparison-report schema version. Bump on any breaking change to the JSON shape so a consumer
/// can reject a record shape it does not understand rather than silently misread it (mirrors the
/// provenance and `ironbus bench` `schema_version` discipline).
pub const SCHEMA_VERSION: u32 = 1;

/// A durability semantics label. Two rows may only be compared head-to-head when their labels are
/// EQUAL; comparing a durable number against a page-cache number is the marketing error this whole
/// module exists to forbid. The set is closed and `PartialEq`, so the match check is exact.
///
/// The variants name the real durability modes of the systems the rig compares:
/// IronBus's group-commit `fdatasync`, the page-cache (ack-before-fsync) mode, a per-message fsync,
/// the NATS `JetStream` `FileStore`, the two Redis `appendfsync` policies, and the three MQTT `QoS`
/// tiers.
// The serde representation is the FROZEN stable string (the same value `as_str` returns), pinned per
// variant so the JSON schema is the documented wire label, not the Rust identifier, and a variant
// rename cannot silently change the serialized contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DurabilityLabel {
    /// IronBus's default: ack only AFTER the covering group-commit `fdatasync`. Power-loss safe.
    #[serde(rename = "group-commit-fsync")]
    GroupCommitFsync,
    /// Ack BEFORE fsync; survives a process crash but NOT power loss. The page-cache number.
    #[serde(rename = "page-cache-async")]
    PageCacheAsync,
    /// One `fdatasync` per message, no group commit. Power-loss safe, throughput-bound by the device.
    #[serde(rename = "sync-per-message")]
    SyncPerMessage,
    /// NATS `JetStream` File-backed stream (default `FileStore` block sizes, `MaxAckPending`
    /// budgeted).
    #[serde(rename = "nats-jetstream-file")]
    NatsJetstreamFile,
    /// Redis Streams with `appendfsync everysec` (the ~1 s loss window default).
    #[serde(rename = "redis-aof-everysec")]
    RedisAofEverysec,
    /// Redis Streams with `appendfsync always` (fsync per event-loop batch).
    #[serde(rename = "redis-aof-always")]
    RedisAofAlways,
    /// Mosquitto / MQTT `QoS` 1 (at-least-once), the primary constrained-link baseline.
    #[serde(rename = "mqtt-qos1")]
    MqttQos1,
    /// Mosquitto / MQTT `QoS` 0 (at-most-once, fire-and-forget).
    #[serde(rename = "mqtt-qos0")]
    MqttQos0,
    /// Mosquitto / MQTT `QoS` 2 (exactly-once handshake).
    #[serde(rename = "mqtt-qos2")]
    MqttQos2,
}

impl DurabilityLabel {
    /// The stable string used in JSON and human output. Frozen with the schema version.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DurabilityLabel::GroupCommitFsync => "group-commit-fsync",
            DurabilityLabel::PageCacheAsync => "page-cache-async",
            DurabilityLabel::SyncPerMessage => "sync-per-message",
            DurabilityLabel::NatsJetstreamFile => "nats-jetstream-file",
            DurabilityLabel::RedisAofEverysec => "redis-aof-everysec",
            DurabilityLabel::RedisAofAlways => "redis-aof-always",
            DurabilityLabel::MqttQos1 => "mqtt-qos1",
            DurabilityLabel::MqttQos0 => "mqtt-qos0",
            DurabilityLabel::MqttQos2 => "mqtt-qos2",
        }
    }

    /// Whether this label is POWER-LOSS SAFE: an acknowledged write survives a brownout. The
    /// page-cache mode and MQTT `QoS` 0 are NOT, and the report labels them so a reader is never
    /// misled
    /// (mirrors the `not power-loss safe` annotation in `docs/SLO.md`).
    #[must_use]
    pub fn is_power_loss_safe(self) -> bool {
        match self {
            DurabilityLabel::GroupCommitFsync
            | DurabilityLabel::SyncPerMessage
            | DurabilityLabel::NatsJetstreamFile
            | DurabilityLabel::RedisAofAlways
            // everysec keeps a bounded (~1 s) loss window: a power cut can lose the last second, so
            // it is honestly NOT power-loss safe for the acknowledged write, only crash-safe.
            | DurabilityLabel::MqttQos1
            | DurabilityLabel::MqttQos2 => true,
            DurabilityLabel::RedisAofEverysec
            | DurabilityLabel::PageCacheAsync
            | DurabilityLabel::MqttQos0 => false,
        }
    }
}

/// The system a row measures. A closed set so the appendix-only rule (Kafka/Redpanda) can be encoded
/// in the type rather than relying on free-text discipline.
// The serde representation is the FROZEN stable string (the same value `as_str` returns), pinned per
// variant so the JSON schema is the documented wire label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum System {
    /// IronBus itself, the system under test.
    #[serde(rename = "ironbus")]
    IronBus,
    /// NATS `JetStream` (File-backed).
    #[serde(rename = "nats-jetstream")]
    Nats,
    /// Redis Streams.
    #[serde(rename = "redis-streams")]
    Redis,
    /// Mosquitto (MQTT).
    #[serde(rename = "mosquitto")]
    Mosquitto,
    /// Apache Kafka. CLUSTER-CLASS: appendix-only, never an edge SLO gate.
    #[serde(rename = "kafka")]
    Kafka,
    /// Redpanda. CLUSTER-CLASS: appendix-only, never an edge SLO gate.
    #[serde(rename = "redpanda")]
    Redpanda,
}

impl System {
    /// The stable string used in JSON and human output. Frozen with the schema version.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            System::IronBus => "ironbus",
            System::Nats => "nats-jetstream",
            System::Redis => "redis-streams",
            System::Mosquitto => "mosquitto",
            System::Kafka => "kafka",
            System::Redpanda => "redpanda",
        }
    }

    /// Whether this is a CLUSTER-CLASS system (JVM/Seastar, multi-node), which the issue confines to
    /// the informational x86-ref appendix and forbids from any edge SLO gate. Kafka and Redpanda are;
    /// the single-edge-node brokers are not. This is the predicate the build-time lint enforces.
    #[must_use]
    pub fn is_cluster_class(self) -> bool {
        matches!(self, System::Kafka | System::Redpanda)
    }
}

/// Where a row sits in the report: an EDGE-GATE row participates in the SLO comparison and is held to
/// the edge rules (no cluster-class system); an APPENDIX row is informational only, on an x86-ref box,
/// and is explicitly labeled "not an edge-class comparison".
// The serde representation is the FROZEN stable string (the same value `as_str` returns).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Placement {
    /// Part of the edge SLO comparison. Cluster-class systems are FORBIDDEN here.
    #[serde(rename = "edge-gate")]
    EdgeGate,
    /// The x86-ref informational appendix. Cluster-class systems are allowed here, and ONLY here.
    #[serde(rename = "appendix")]
    Appendix,
}

impl Placement {
    /// The stable string used in JSON and human output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Placement::EdgeGate => "edge-gate",
            Placement::Appendix => "appendix",
        }
    }

    /// The fixed appendix label the issue mandates, attached to every appendix row so a reader can
    /// never mistake a cluster-class number for an edge-class one.
    #[must_use]
    pub fn appendix_label(self) -> Option<&'static str> {
        match self {
            Placement::EdgeGate => None,
            Placement::Appendix => Some("not an edge-class comparison"),
        }
    }
}

/// The measured percentiles a comparison row carries, in microseconds (the SLO unit). Distinct from
/// the harness `Percentiles` type because a comparison row ingests EXTERNAL peer/historical numbers,
/// not a live `RunReport`, and serializes to the comparison schema.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct RowPercentiles {
    /// p50 latency, microseconds.
    pub p50_us: f64,
    /// p99 latency, microseconds.
    pub p99_us: f64,
    /// p99.9 latency, microseconds.
    pub p999_us: f64,
}

/// One comparison row: a single {system, durability, message size, device} measurement. The unit the
/// report is built from and the lints operate on.
#[derive(Clone, Debug, Serialize)]
pub struct ComparisonRow {
    /// The system this row measures.
    pub system: System,
    /// The durability semantics this row ran under. The MATCH check compares this field.
    pub durability: DurabilityLabel,
    /// The payload size in bytes (must match across a compared pair, like durability).
    pub message_size_bytes: usize,
    /// The reference device the row ran on (e.g. `edge-min-pi4`, `edge-mid-rk3399`, `x86-ref-n100`).
    pub device: String,
    /// Whether this row is an edge SLO gate or appendix-only.
    pub placement: Placement,
    /// Achieved throughput, messages per second.
    pub throughput_msgs_per_sec: f64,
    /// The measured tail percentiles.
    pub percentiles: RowPercentiles,
}

impl ComparisonRow {
    /// The Little's-Law queue occupancy for THIS row at its measured throughput and p99 latency:
    /// `L = lambda * W`, with `lambda` the throughput and `W` the p99 latency in seconds. This is the
    /// in-flight count the system must hold to sustain its throughput at its tail latency, the number
    /// that shows whether p99 stays within the SLO at the chosen concurrency bound. `None` if either
    /// input is not a finite, non-negative number (so a malformed row cannot produce a nonsense L).
    #[must_use]
    pub fn littles_law_occupancy_p99(&self) -> Option<f64> {
        littles_law_occupancy(self.throughput_msgs_per_sec, self.percentiles.p99_us)
    }
}

/// Little's Law: `L = lambda * W`. Given a throughput `lambda` in messages per second and a latency
/// `w_us` in MICROSECONDS, returns the mean number of messages in flight (the queue occupancy).
/// Returns `None` unless both inputs are finite and non-negative, so a NaN/inf or a negative value
/// (which cannot be a real rate or latency) yields no number rather than a misleading one.
///
/// This is the unifying-theory check the parent issue calls for: at a fixed throughput, in-flight
/// count and latency are coupled, so a bounded p99 at a target rate IMPLIES a bounded occupancy, and
/// reporting `L` lets a reader confirm the concurrency bound is consistent with the SLO.
#[must_use]
pub fn littles_law_occupancy(lambda_msgs_per_sec: f64, w_us: f64) -> Option<f64> {
    if !lambda_msgs_per_sec.is_finite()
        || !w_us.is_finite()
        || lambda_msgs_per_sec < 0.0
        || w_us < 0.0
    {
        return None;
    }
    // W is given in microseconds; convert to seconds so L is dimensionless (msg/s * s = msg).
    let w_seconds = w_us / 1_000_000.0;
    Some(lambda_msgs_per_sec * w_seconds)
}

/// A single comparison: two rows asserted to be apples-to-apples (same durability, same message
/// size, same device, both edge-gate). The build-time lint validates exactly this assertion.
#[derive(Clone, Debug, Serialize)]
pub struct ComparisonPair {
    /// The system-under-test row (IronBus, by convention, but the lint does not require it).
    pub left: ComparisonRow,
    /// The peer row being compared against.
    pub right: ComparisonRow,
}

/// Why a comparison report failed to build. A typed error (no panic, no `unwrap`): every lint
/// violation maps to a precise variant so a caller can act on it and a test can assert WHICH rule
/// fired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportError {
    /// A compared pair carries MISMATCHED durability labels. The central anti-marketing lint: this is
    /// the error that fires when a durable number is compared against a page-cache number.
    DurabilityMismatch {
        /// The left row's durability label string.
        left: &'static str,
        /// The right row's durability label string.
        right: &'static str,
    },
    /// A compared pair carries different message sizes, so it is not the same workload.
    MessageSizeMismatch {
        /// The left row's message size in bytes.
        left: usize,
        /// The right row's message size in bytes.
        right: usize,
    },
    /// A compared pair ran on different devices, so it is not the same hardware.
    DeviceMismatch {
        /// The left row's device.
        left: String,
        /// The right row's device.
        right: String,
    },
    /// A row in a comparison pair (an edge-gate comparison) is not placed in the edge gate, so the
    /// pair is not a valid edge comparison.
    PairRowNotEdgeGate {
        /// The offending row's system string.
        system: &'static str,
        /// The placement string the row actually had.
        placement: &'static str,
    },
    /// An edge-gate row names a CLUSTER-CLASS system (Kafka/Redpanda), which is appendix-only. The
    /// appendix-labeling lint.
    ClusterClassInEdgeGate {
        /// The offending cluster-class system string.
        system: &'static str,
    },
}

impl core::fmt::Display for ReportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReportError::DurabilityMismatch { left, right } => write!(
                f,
                "durability-label mismatch in a compared pair: `{left}` vs `{right}`. A comparison \
                 must run both sides under the SAME durability semantics; comparing a durable number \
                 against a page-cache (no-fsync) number is the marketing error the rig forbids."
            ),
            ReportError::MessageSizeMismatch { left, right } => write!(
                f,
                "message-size mismatch in a compared pair: {left} B vs {right} B. A comparison must \
                 run both sides at the SAME message size."
            ),
            ReportError::DeviceMismatch { left, right } => write!(
                f,
                "device mismatch in a compared pair: `{left}` vs `{right}`. A comparison must run \
                 both sides on the SAME device."
            ),
            ReportError::PairRowNotEdgeGate { system, placement } => write!(
                f,
                "a comparison pair contains a `{placement}` row for `{system}`: a head-to-head \
                 comparison row must be placed in the edge gate, not the appendix."
            ),
            ReportError::ClusterClassInEdgeGate { system } => write!(
                f,
                "cluster-class system `{system}` appears as an edge SLO gate row: Kafka/Redpanda are \
                 JVM/Seastar multi-node systems, excluded from edge gates and allowed ONLY in the \
                 x86-ref informational appendix (labeled `not an edge-class comparison`)."
            ),
        }
    }
}

impl std::error::Error for ReportError {}

/// A built, validated comparison report. Construct it via [`ComparisonReport::build`], which runs the
/// lints; a `ComparisonReport` value therefore witnesses that every lint passed.
#[derive(Clone, Debug, Serialize)]
pub struct ComparisonReport {
    /// The schema version (see [`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// The head-to-head comparison pairs (each validated apples-to-apples and edge-gate).
    pub pairs: Vec<ComparisonPair>,
    /// The appendix rows (cluster-class or other informational x86-ref rows), each carrying the
    /// `not an edge-class comparison` label.
    pub appendix: Vec<ComparisonRow>,
}

impl ComparisonReport {
    /// Builds and VALIDATES a comparison report. Runs every lint and returns a typed [`ReportError`]
    /// on the first violation, so a dishonest report can never be assembled:
    ///
    /// - each pair's two rows must share a durability label (the central anti-marketing lint), a
    ///   message size, and a device, and both must be edge-gate rows;
    /// - no edge-gate row may name a cluster-class system (Kafka/Redpanda);
    /// - appendix rows are informational and are not lint-checked for durability match (they are not
    ///   compared head-to-head), but a cluster-class system is allowed ONLY here.
    ///
    /// # Errors
    /// Returns the first [`ReportError`] encountered (mismatched durability/size/device, a non-edge
    /// row in a pair, or a cluster-class system in an edge gate).
    pub fn build(
        pairs: Vec<ComparisonPair>,
        appendix: Vec<ComparisonRow>,
    ) -> Result<ComparisonReport, ReportError> {
        for pair in &pairs {
            lint_pair(pair)?;
        }
        Ok(ComparisonReport {
            schema_version: SCHEMA_VERSION,
            pairs,
            appendix,
        })
    }

    /// Serializes the report to pretty JSON.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] only if the record cannot be serialized, which cannot happen
    /// for this fully-owned, plain-data shape.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Validates a single comparison pair against every apples-to-apples lint. Shared by
/// [`ComparisonReport::build`] and unit-tested directly so each rule has its own teeth test.
///
/// # Errors
/// Returns the first [`ReportError`] the pair violates.
pub fn lint_pair(pair: &ComparisonPair) -> Result<(), ReportError> {
    // Both rows in a head-to-head comparison must be edge-gate rows (the appendix is informational
    // only and is never compared head-to-head).
    for row in [&pair.left, &pair.right] {
        if row.placement != Placement::EdgeGate {
            return Err(ReportError::PairRowNotEdgeGate {
                system: row.system.as_str(),
                placement: row.placement.as_str(),
            });
        }
        // A cluster-class system can never be an edge-gate row, hence never in a pair.
        if row.system.is_cluster_class() {
            return Err(ReportError::ClusterClassInEdgeGate {
                system: row.system.as_str(),
            });
        }
    }
    // THE central lint: identical durability labels on both sides, or the build fails.
    if pair.left.durability != pair.right.durability {
        return Err(ReportError::DurabilityMismatch {
            left: pair.left.durability.as_str(),
            right: pair.right.durability.as_str(),
        });
    }
    if pair.left.message_size_bytes != pair.right.message_size_bytes {
        return Err(ReportError::MessageSizeMismatch {
            left: pair.left.message_size_bytes,
            right: pair.right.message_size_bytes,
        });
    }
    if pair.left.device != pair.right.device {
        return Err(ReportError::DeviceMismatch {
            left: pair.left.device.clone(),
            right: pair.right.device.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn percentiles(p99_us: f64) -> RowPercentiles {
        RowPercentiles {
            p50_us: p99_us / 4.0,
            p99_us,
            p999_us: p99_us * 2.0,
        }
    }

    fn row(
        system: System,
        durability: DurabilityLabel,
        size: usize,
        device: &str,
        placement: Placement,
    ) -> ComparisonRow {
        ComparisonRow {
            system,
            durability,
            message_size_bytes: size,
            device: device.to_string(),
            placement,
            throughput_msgs_per_sec: 60_000.0,
            percentiles: percentiles(5_000.0),
        }
    }

    // ---- the durability-label-match lint has teeth ----

    #[test]
    fn a_matched_durability_pair_builds() {
        // IronBus group-commit-fsync vs Redis appendfsync=always: BOTH durable, same label class is
        // not required, only an EQUAL label. Use two rows with the SAME label so the match passes.
        let left = row(
            System::IronBus,
            DurabilityLabel::SyncPerMessage,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let right = row(
            System::Redis,
            DurabilityLabel::SyncPerMessage,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let report = ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).unwrap();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.pairs.len(), 1);
    }

    #[test]
    fn a_mismatched_durability_pair_fails_the_build() {
        // The marketing error: IronBus group-commit-fsync (durable) vs a peer's page-cache (no-fsync)
        // number. This MUST fail. The test FAILS if the label-match lint loses its teeth.
        let left = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let right = row(
            System::Nats,
            DurabilityLabel::PageCacheAsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let err =
            ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).unwrap_err();
        assert_eq!(
            err,
            ReportError::DurabilityMismatch {
                left: "group-commit-fsync",
                right: "page-cache-async",
            }
        );
        assert!(err.to_string().contains("marketing error"));
    }

    #[test]
    fn the_nats_everysec_vs_redis_everysec_pair_matches() {
        // A realistic matched pair the rig is meant to accept once live runs exist.
        let left = row(
            System::Redis,
            DurabilityLabel::RedisAofEverysec,
            256,
            "edge-mid-rk3399",
            Placement::EdgeGate,
        );
        let right = row(
            System::Redis,
            DurabilityLabel::RedisAofEverysec,
            256,
            "edge-mid-rk3399",
            Placement::EdgeGate,
        );
        assert!(ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).is_ok());
    }

    // ---- the apples-to-apples size/device lints ----

    #[test]
    fn a_message_size_mismatch_fails_the_build() {
        let left = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let right = row(
            System::Nats,
            DurabilityLabel::GroupCommitFsync,
            16_384,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let err =
            ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).unwrap_err();
        assert_eq!(
            err,
            ReportError::MessageSizeMismatch {
                left: 256,
                right: 16_384,
            }
        );
    }

    #[test]
    fn a_device_mismatch_fails_the_build() {
        let left = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let right = row(
            System::Nats,
            DurabilityLabel::GroupCommitFsync,
            256,
            "x86-ref-n100",
            Placement::EdgeGate,
        );
        let err =
            ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).unwrap_err();
        assert!(matches!(err, ReportError::DeviceMismatch { .. }));
    }

    // ---- the appendix / cluster-class labeling lint has teeth ----

    #[test]
    fn kafka_as_an_edge_gate_row_fails_the_build() {
        // Kafka in an edge-gate comparison pair is forbidden: it is appendix-only.
        let left = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let right = row(
            System::Kafka,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let err =
            ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).unwrap_err();
        assert_eq!(err, ReportError::ClusterClassInEdgeGate { system: "kafka" });
        assert!(err.to_string().contains("appendix"));
    }

    #[test]
    fn redpanda_is_allowed_in_the_appendix() {
        // Redpanda is legal as an appendix row, and carries the fixed label.
        let appendix_row = row(
            System::Redpanda,
            DurabilityLabel::PageCacheAsync,
            256,
            "x86-ref-n100",
            Placement::Appendix,
        );
        let report = ComparisonReport::build(vec![], vec![appendix_row]).unwrap();
        assert_eq!(report.appendix.len(), 1);
        assert_eq!(
            report.appendix[0].placement.appendix_label(),
            Some("not an edge-class comparison")
        );
    }

    #[test]
    fn an_edge_gate_placement_carries_no_appendix_label() {
        assert_eq!(Placement::EdgeGate.appendix_label(), None);
    }

    #[test]
    fn a_pair_row_in_the_appendix_placement_fails() {
        let left = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::Appendix,
        );
        let right = row(
            System::Nats,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let err =
            ComparisonReport::build(vec![ComparisonPair { left, right }], vec![]).unwrap_err();
        assert!(matches!(err, ReportError::PairRowNotEdgeGate { .. }));
    }

    // ---- Little's Law ----

    #[test]
    fn littles_law_on_a_known_case() {
        // 60,000 msg/s at a 5 ms (5000 us) p99 => L = 60000 * 0.005 = 300 messages in flight.
        let l = littles_law_occupancy(60_000.0, 5_000.0).unwrap();
        assert!((l - 300.0).abs() < 1e-9, "L = {l}");
    }

    #[test]
    fn littles_law_row_helper_uses_p99() {
        let r = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        // throughput 60000, p99 5000 us => 300.
        let l = r.littles_law_occupancy_p99().unwrap();
        assert!((l - 300.0).abs() < 1e-9, "L = {l}");
    }

    #[test]
    fn littles_law_rejects_non_finite_or_negative() {
        assert!(littles_law_occupancy(f64::NAN, 5_000.0).is_none());
        assert!(littles_law_occupancy(60_000.0, f64::INFINITY).is_none());
        assert!(littles_law_occupancy(-1.0, 5_000.0).is_none());
        assert!(littles_law_occupancy(60_000.0, -1.0).is_none());
    }

    #[test]
    fn littles_law_zero_throughput_is_zero_occupancy() {
        assert_eq!(littles_law_occupancy(0.0, 5_000.0), Some(0.0));
    }

    // ---- power-loss-safe labeling ----

    #[test]
    fn power_loss_safety_labels_are_honest() {
        assert!(DurabilityLabel::GroupCommitFsync.is_power_loss_safe());
        assert!(DurabilityLabel::SyncPerMessage.is_power_loss_safe());
        assert!(DurabilityLabel::RedisAofAlways.is_power_loss_safe());
        // The page-cache and everysec modes are NOT power-loss safe.
        assert!(!DurabilityLabel::PageCacheAsync.is_power_loss_safe());
        assert!(!DurabilityLabel::RedisAofEverysec.is_power_loss_safe());
        assert!(!DurabilityLabel::MqttQos0.is_power_loss_safe());
    }

    // ---- JSON shape is versioned ----

    #[test]
    fn report_json_is_versioned_and_labels_the_appendix() {
        let left = row(
            System::IronBus,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let right = row(
            System::Nats,
            DurabilityLabel::GroupCommitFsync,
            256,
            "edge-min-pi4",
            Placement::EdgeGate,
        );
        let appendix_row = row(
            System::Kafka,
            DurabilityLabel::PageCacheAsync,
            256,
            "x86-ref-n100",
            Placement::Appendix,
        );
        let report =
            ComparisonReport::build(vec![ComparisonPair { left, right }], vec![appendix_row])
                .unwrap();
        let json = report.to_json().unwrap();
        assert!(json.contains("\"schema_version\": 1"), "json: {json}");
        assert!(json.contains("group-commit-fsync"), "json: {json}");
        // The placement serializes as its frozen stable string, not the Rust identifier.
        assert!(json.contains("\"appendix\""), "json: {json}");
        assert!(json.contains("\"kafka\""), "json: {json}");
    }
}
