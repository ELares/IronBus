// SPDX-License-Identifier: MIT OR Apache-2.0
//! The PURE, IO-free configuration grammar and validation (#85, #86, #382).
//!
//! This module owns the parts of the configuration system that have NO filesystem
//! or network contact, so they live in the IO-free core and are shared by every
//! layer that needs them (the `serve` flag/env resolver and the TOML config-FILE
//! parser, both in the `ironbus-cli` crate):
//!
//! - the shared LITERAL GRAMMAR for a duration (`int + {ms,s,m,h,d}`, unit-required)
//!   and a binary BYTE SIZE (`int + {B,KiB,MiB,GiB,TiB}`, decimal-SI rejected), both
//!   overflow-checked so a 32/64-bit edge target never silently wraps;
//! - the typed CONFIG-KEY table (`[section].key` -> a kind) and the
//!   reject-unknown-key-with-a-did-you-mean suggestion the strict parser uses;
//! - the per-key TYPE/RANGE checks and the cross-key COUPLED-SET validators
//!   `docs/CONFIG.md` section 4 specifies (the WHOLE config is validated as a unit
//!   before any value is installed).
//!
//! Everything here is a pure function of its inputs: it reads no file, opens no
//! socket, and consults no clock. The byte-level file IO (whole-read, parse the
//! TOML, build the effective config, and the atomic `Arc<Config>` reload swap) is
//! the `ironbus-cli` layer's job; this module is the grammar and the verdict it
//! applies. `docs/CONFIG.md` is the normative specification.

use std::collections::BTreeMap;
use std::fmt;

/// A failure parsing one configuration LITERAL (a duration or a byte size), with
/// enough context for a usage error that names the offending value. Pure: it carries
/// only the borrowed-then-owned text, never a source location (the FILE layer adds the
/// line/column when it knows them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiteralError {
    /// The value carried no recognizable unit suffix (`"100"`, `"5x"`): the grammar is
    /// unit-REQUIRED, so a bare number is rejected rather than guessed.
    MissingUnit {
        /// The raw value as written, for the error message.
        raw: String,
        /// The accepted unit suffixes, for the did-you-mean hint.
        units: &'static str,
    },
    /// The numeric part was empty, not a non-negative integer, or had stray characters
    /// (`"ms"`, `"-5s"`, `"1.5s"`): the grammar is integer-only, no sign, no fraction.
    NotAnInteger {
        /// The raw value as written.
        raw: String,
    },
    /// The unit suffix was not one of the accepted set (`"100sec"`, `"5MB"`): names the
    /// rejected unit so a decimal-SI `MB`/`GB` is caught explicitly.
    UnknownUnit {
        /// The raw value as written.
        raw: String,
        /// The rejected unit suffix.
        unit: String,
        /// The accepted unit suffixes, for the did-you-mean hint.
        units: &'static str,
    },
    /// The integer times its unit multiplier overflowed the target width: rejected rather
    /// than silently wrapping (a 32/64-bit-safe guard for an absurd edge value).
    Overflow {
        /// The raw value as written.
        raw: String,
    },
}

impl fmt::Display for LiteralError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiteralError::MissingUnit { raw, units } => write!(
                f,
                "`{raw}` is missing a unit suffix: a unit is required (one of {units}), \
                 a bare number is rejected"
            ),
            LiteralError::NotAnInteger { raw } => write!(
                f,
                "`{raw}` is not a non-negative integer with a unit suffix (no sign, \
                 no decimal point)"
            ),
            LiteralError::UnknownUnit { raw, unit, units } => write!(
                f,
                "`{raw}` has an unknown unit `{unit}`: the accepted units are {units} \
                 (decimal-SI units like MB/GB are rejected; use the binary KiB/MiB/GiB)"
            ),
            LiteralError::Overflow { raw } => write!(
                f,
                "`{raw}` overflows: the value times its unit multiplier does not fit"
            ),
        }
    }
}

/// The accepted DURATION unit suffixes, for the error hint.
const DURATION_UNITS: &str = "ms, s, m, h, d";
/// The accepted binary BYTE-SIZE unit suffixes, for the error hint.
const BYTE_UNITS: &str = "B, KiB, MiB, GiB, TiB";

/// Splits a literal into its (integer-digits, unit-suffix) parts, or a typed error.
///
/// The split is purely lexical: the leading run of ASCII digits is the integer part and
/// the remainder (trimmed of surrounding whitespace on the whole token by the caller) is
/// the unit. A token with no digits, or one whose digit run does not parse as a `u128`
/// (the widest accumulator, so any in-range `u64` value parses) is [`LiteralError`]. The
/// `units` hint is threaded through for the error.
fn split_literal<'a>(raw: &'a str, units: &'static str) -> Result<(u128, &'a str), LiteralError> {
    let trimmed = raw.trim();
    let digit_end = trimmed
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map_or(trimmed.len(), |(i, _)| i);
    let (digits, unit) = trimmed.split_at(digit_end);
    if digits.is_empty() {
        // No leading digits at all (`"ms"`, `"-5s"`): the integer part is mandatory.
        return Err(LiteralError::NotAnInteger {
            raw: raw.to_string(),
        });
    }
    let value: u128 = digits.parse().map_err(|_| LiteralError::NotAnInteger {
        raw: raw.to_string(),
    })?;
    let unit = unit.trim();
    // A decimal point right after the integer part (`"1.5s"`) is a FRACTION, not a unit:
    // the grammar is integer-only, so this is `NotAnInteger`, not an unknown-unit error.
    if unit.starts_with('.') {
        return Err(LiteralError::NotAnInteger {
            raw: raw.to_string(),
        });
    }
    if unit.is_empty() {
        return Err(LiteralError::MissingUnit {
            raw: raw.to_string(),
            units,
        });
    }
    Ok((value, unit))
}

/// Multiplies a parsed integer by its unit multiplier, rejecting an overflow of `u64`
/// (the width every duration/size knob uses) rather than wrapping. Shared by both literal
/// parsers so the 32/64-bit-safe overflow rule is written once.
fn checked_scale(value: u128, multiplier: u128, raw: &str) -> Result<u64, LiteralError> {
    value
        .checked_mul(multiplier)
        .and_then(|v| u64::try_from(v).ok())
        .ok_or_else(|| LiteralError::Overflow {
            raw: raw.to_string(),
        })
}

/// Parses a DURATION literal (`int + {ms,s,m,h,d}`, unit-REQUIRED) to whole MILLISECONDS.
///
/// The unit is mandatory (a bare `"100"` is [`LiteralError::MissingUnit`], matching the
/// `docs/CONFIG.md` grammar), only the binary-free duration units are accepted, and the
/// integer times the unit's millisecond multiplier is overflow-checked against `u64`
/// (the width every duration knob uses), so an absurd `"999999999999d"` is a clean error,
/// never a silent wrap on a 32-bit edge box.
///
/// # Errors
/// [`LiteralError`] for a missing/unknown unit, a non-integer numeric part, or an overflow.
pub fn parse_duration_ms(raw: &str) -> Result<u64, LiteralError> {
    let (value, unit) = split_literal(raw, DURATION_UNITS)?;
    let multiplier: u128 = match unit {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60 * 1_000,
        "h" => 60 * 60 * 1_000,
        "d" => 24 * 60 * 60 * 1_000,
        other => {
            return Err(LiteralError::UnknownUnit {
                raw: raw.to_string(),
                unit: other.to_string(),
                units: DURATION_UNITS,
            })
        }
    };
    checked_scale(value, multiplier, raw)
}

/// Parses a binary BYTE-SIZE literal (`int + {B,KiB,MiB,GiB,TiB}`, unit-REQUIRED) to BYTES.
///
/// ONLY the binary (power-of-1024) units are accepted: a decimal-SI `"5MB"`/`"5GB"` is a
/// [`LiteralError::UnknownUnit`], never silently coerced, because a byte cap that means
/// "1024 * 1024" must not be mistaken for "1000 * 1000". The unit is mandatory and the
/// product is overflow-checked against `u64`.
///
/// # Errors
/// [`LiteralError`] for a missing/unknown unit (including any decimal-SI unit), a
/// non-integer numeric part, or an overflow.
pub fn parse_byte_size(raw: &str) -> Result<u64, LiteralError> {
    let (value, unit) = split_literal(raw, BYTE_UNITS)?;
    let multiplier: u128 = match unit {
        "B" => 1,
        "KiB" => 1024,
        "MiB" => 1024 * 1024,
        "GiB" => 1024 * 1024 * 1024,
        "TiB" => 1024_u128 * 1024 * 1024 * 1024,
        other => {
            return Err(LiteralError::UnknownUnit {
                raw: raw.to_string(),
                unit: other.to_string(),
                units: BYTE_UNITS,
            })
        }
    };
    checked_scale(value, multiplier, raw)
}

/// The KIND of a configuration value, used by the strict typed-key table to say what each
/// `[section].key` accepts. The FILE parser maps a TOML scalar to one of these and the
/// resolver consumes the typed result; a mismatch is a typed error naming the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// A duration LITERAL string (`"30s"`), parsed by [`parse_duration_ms`] to ms.
    Duration,
    /// A binary byte-size LITERAL string (`"64MiB"`), parsed by [`parse_byte_size`].
    ByteSize,
    /// A plain non-negative integer (no unit), e.g. `consumer_credit = 64`.
    Integer,
    /// A boolean (`true`/`false`).
    Bool,
    /// A free-form string (an enum value, an address, a path): validated by the caller.
    Str,
    /// A list of integers (`backoff_ms = [100, 500]`).
    IntList,
}

/// One row of the typed key table: a fully-qualified `section.key` and the kind it accepts.
/// `docs/CONFIG.md` section 3 is the normative source; this table is the machine-checkable
/// half the strict parser consults to (a) REJECT an unknown key with a did-you-mean and
/// (b) type-check a known one.
#[derive(Debug, Clone, Copy)]
pub struct KeySpec {
    /// The fully-qualified dotted key, e.g. `storage.segment_size`.
    pub key: &'static str,
    /// The value kind the key accepts.
    pub kind: KeyKind,
}

/// The FROZEN typed-key table (`docs/CONFIG.md` section 3, the #14 stability contract).
///
/// Every key an operator may set in the TOML file appears here exactly once, with its
/// kind. The strict parser rejects ANY dotted key not in this table (with the closest
/// match as a did-you-mean), so a typo that would silently disable durability or retention
/// is a fatal config error, not a warn-and-ignore. The reserved-but-unwired `[observability]`
/// and `[auth]` sections (and the SPECIFIED-NOT-YET-A-FIELD `[compression]` set) are
/// intentionally NOT enumerated key-by-key here: a whole reserved SECTION is tolerated by
/// [`is_reserved_section`] so a broker that carries its own #16/#18 config still starts,
/// without this table inventing fields the binary does not wire.
pub const KEY_TABLE: &[KeySpec] = &[
    // The bare top-level `profile` selector (a string enum), the one un-sectioned key.
    KeySpec {
        key: "profile",
        kind: KeyKind::Str,
    },
    // [storage]
    KeySpec {
        key: "storage.segment_size",
        kind: KeyKind::ByteSize,
    },
    KeySpec {
        key: "storage.data_dir",
        kind: KeyKind::Str,
    },
    KeySpec {
        key: "storage.max_total_bytes",
        kind: KeyKind::ByteSize,
    },
    // [durability]
    KeySpec {
        key: "durability.level",
        kind: KeyKind::Str,
    },
    KeySpec {
        key: "durability.flush_interval_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "durability.flush_max_bytes",
        kind: KeyKind::ByteSize,
    },
    KeySpec {
        key: "durability.async_loss_ack",
        kind: KeyKind::Bool,
    },
    // [retention]
    KeySpec {
        key: "retention.max_retained_bytes",
        kind: KeyKind::ByteSize,
    },
    KeySpec {
        key: "retention.max_age_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "retention.max_messages",
        kind: KeyKind::Integer,
    },
    // [backpressure]
    KeySpec {
        key: "backpressure.disk_full_policy",
        kind: KeyKind::Str,
    },
    KeySpec {
        key: "backpressure.consumer_credit",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "backpressure.consumer_credit_bytes",
        kind: KeyKind::ByteSize,
    },
    KeySpec {
        key: "backpressure.max_in_flight",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "backpressure.max_connections",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "backpressure.max_groups",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "backpressure.group_idle_evict_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "backpressure.ram_ceiling_bytes",
        kind: KeyKind::ByteSize,
    },
    KeySpec {
        key: "backpressure.codel_target_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "backpressure.codel_interval_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "backpressure.retry_budget_ratio_per_million",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "backpressure.retry_budget_window_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "backpressure.fire_and_forget_msg_rate",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "backpressure.fire_and_forget_byte_rate",
        kind: KeyKind::ByteSize,
    },
    KeySpec {
        key: "backpressure.fire_and_forget_refill_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "backpressure.egress_limit",
        kind: KeyKind::Integer,
    },
    // [delivery]
    KeySpec {
        key: "delivery.max_deliver",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "delivery.allow_unlimited_deliver",
        kind: KeyKind::Bool,
    },
    KeySpec {
        key: "delivery.backoff_ms",
        kind: KeyKind::IntList,
    },
    KeySpec {
        key: "delivery.visibility_timeout_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "delivery.checkpoint_interval",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "delivery.dedup_max_ids",
        kind: KeyKind::Integer,
    },
    KeySpec {
        key: "delivery.dedup_window_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "delivery.dedup_max_producers",
        kind: KeyKind::Integer,
    },
    // [network]
    KeySpec {
        key: "network.listen",
        kind: KeyKind::Str,
    },
    KeySpec {
        key: "network.health_addr",
        kind: KeyKind::Str,
    },
    KeySpec {
        key: "network.health_allow_public",
        kind: KeyKind::Bool,
    },
    KeySpec {
        key: "network.health_liveness_window_ms",
        kind: KeyKind::Duration,
    },
    KeySpec {
        key: "network.enable_admin",
        kind: KeyKind::Bool,
    },
];

/// True when `section` is a top-level TOML section FROZEN as reserved by the #14 stability
/// contract but whose per-key contents are owned by another issue (so any key under it is
/// tolerated, not rejected as unknown): `[observability]` (#16), `[auth]` (#18), and
/// `[compression]` (#12, SPECIFIED-NOT-YET-A-FIELD). A broker that carries its own
/// observability/security/codec config under these reserved sections still starts; the strict
/// reject-unknown rule applies only to keys under the WIRED sections in [`KEY_TABLE`].
#[must_use]
pub fn is_reserved_section(section: &str) -> bool {
    matches!(section, "observability" | "auth" | "compression")
}

/// Looks up a fully-qualified dotted key in [`KEY_TABLE`], returning its [`KeySpec`].
#[must_use]
pub fn lookup_key(key: &str) -> Option<KeySpec> {
    KEY_TABLE.iter().copied().find(|spec| spec.key == key)
}

/// The closest known key to an unknown `key` by Levenshtein edit distance, for the
/// did-you-mean hint, but ONLY when the nearest is close enough to be a plausible typo
/// (distance <= a third of the key length, min 2), so a wildly different key gets no
/// misleading suggestion. Pure: it ranks the compiled-in [`KEY_TABLE`].
#[must_use]
pub fn did_you_mean(key: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for spec in KEY_TABLE {
        let dist = levenshtein(key, spec.key);
        // `is_none_or` is stable only from 1.82; the workspace MSRV is 1.78, so spell it out.
        let closer = match best {
            None => true,
            Some((_, b)) => dist < b,
        };
        if closer {
            best = Some((spec.key, dist));
        }
    }
    let (candidate, dist) = best?;
    let threshold = (key.len() / 3).max(2);
    if dist <= threshold {
        Some(candidate)
    } else {
        None
    }
}

/// The Levenshtein edit distance between two strings, on `char`s. A small, two-row dynamic
/// program (the keys are short), pure and IO-free.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr: Vec<usize> = vec![0; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// A coupled-set or per-key VALIDATION failure (`docs/CONFIG.md` section 4), distinct from a
/// LITERAL parse error: by the time these fire the values have parsed, but the WHOLE config
/// is invalid as a unit (a cross-key constraint is violated or a single value is out of range).
/// Pure: the caller (CLI/server) maps it onto the usage exit code. A warning is the non-fatal
/// companion (a no-op setting an operator should know about).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(pub String);

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The coupled-set verdict over a fully-resolved config: the fatal errors (any one refuses
/// the boot or keeps the old config on a reload) and the non-fatal warnings (a no-op setting,
/// surfaced but not refused). The caller decides how to render each; the SET is validated as
/// a unit, so this carries EVERY violation, not just the first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigVerdict {
    /// The fatal coupled-set / range violations. A non-empty list refuses the boot (or keeps
    /// the old config on a reload).
    pub errors: Vec<ValidationError>,
    /// The non-fatal warnings (a setting with no effect, e.g. `drop-oldest` with no byte cap).
    pub warnings: Vec<String>,
}

impl ConfigVerdict {
    /// True if no fatal error was found (warnings are allowed).
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// The fully-RESOLVED, typed values the coupled-set validator needs to cross-check, after the
/// flag/env/file/default precedence has produced one effective value per knob. It is a flat,
/// `Copy` view (the validator reads it, never mutates), built by the CLI from its
/// `ServeConfig`. Keeping the validator over this neutral struct (not over the CLI's
/// `ServeConfig`) is what lets it live in the IO-free core and be unit-tested without the CLI.
// The four bools mirror four independent coupled-set inputs (the loss-ack, the explicit-retention
// request, the drop-oldest policy, and the durability-gate switch); each is a distinct cross-key
// signal, not a packed state, so a flat view of them is the right shape rather than an enum.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
pub struct ResolvedConfig {
    /// `storage.segment_size` in bytes.
    pub segment_bytes: u64,
    /// The largest single record the broker accepts, in bytes (the frame ceiling): the
    /// coupled check is `segment_bytes > max_record_bytes + overhead`.
    pub max_record_bytes: u64,
    /// The per-record frame overhead (header + footer) added to `max_record_bytes` in the
    /// segment-fit check.
    pub frame_overhead: u64,
    /// The durability level token (`sync`/`interval`/`async`/`none`).
    pub durability_level: DurabilityLevel,
    /// `durability.flush_interval_ms` in ms (the `interval` time trigger).
    pub flush_interval_ms: u64,
    /// `durability.flush_max_bytes` in bytes (the `interval` byte trigger).
    pub flush_max_bytes: u64,
    /// `durability.async_loss_ack`: the explicit unbounded-loss acknowledgement.
    pub async_loss_ack: bool,
    /// `retention.max_retained_bytes` (0 = off).
    pub max_retained_bytes: u64,
    /// `retention.max_age_ms` (0 = off).
    pub max_age_ms: u64,
    /// `retention.max_messages` (0 = off).
    pub max_messages: u64,
    /// True when an operator explicitly asked for retention (set any retention key) but every
    /// bound resolved to 0: the validator then fires the "retention requested but all off" error.
    pub retention_requested: bool,
    /// `storage.max_total_bytes` (0 = unlimited).
    pub max_total_bytes: u64,
    /// True when `backpressure.disk_full_policy` is `drop-oldest`.
    pub disk_full_policy_drop_oldest: bool,
    /// Run the DURABILITY coupled-set rules (the none/async loss-ack gate and the interval-trigger
    /// check). The CLI sets this `false` because its shipped `validate_durability` already enforces
    /// the gate downstream with the canonical operator messages (and the existing tests expect parse
    /// to succeed and that gate to fire only in `validate_serve_config`); the IO-free unit tests set
    /// it `true` to exercise the durability teeth in the pure core. The non-durability rules
    /// (segment-fit, retention-all-off, drop-oldest warning) always run.
    pub enforce_durability_gate: bool,
}

/// The durability-level token, mirrored from the CLI/server enum so the coupled-set validator
/// can reason about it in the IO-free core (the CLI maps its own arg enum onto this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityLevel {
    /// Ack-after-fdatasync (the safe default).
    Sync,
    /// Bounded-loss interval window.
    Interval,
    /// Unbounded async (opportunistic fsync only).
    Async,
    /// No periodic fsync at all.
    None,
}

impl DurabilityLevel {
    /// The stable token for an error message.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DurabilityLevel::Sync => "sync",
            DurabilityLevel::Interval => "interval",
            DurabilityLevel::Async => "async",
            DurabilityLevel::None => "none",
        }
    }
    /// True for the unbounded-loss levels that need the explicit acknowledgement.
    #[must_use]
    pub fn requires_loss_ack(self) -> bool {
        matches!(self, DurabilityLevel::Async | DurabilityLevel::None)
    }
}

/// Validates the WHOLE resolved config as a UNIT (`docs/CONFIG.md` section 4): every
/// coupled-set rule the design lists, collected into one [`ConfigVerdict`]. PURE and total:
/// it reads the [`ResolvedConfig`] view and returns the verdict; it never refuses, exits, or
/// touches IO (the caller maps a non-empty `errors` onto the usage exit / keep-old-config
/// path). Validating as a set, and collecting EVERY violation, is the invariant that the hot
/// path never sees a half-validated config.
#[must_use]
pub fn validate_coupled_sets(config: &ResolvedConfig) -> ConfigVerdict {
    let mut verdict = ConfigVerdict::default();

    // Coupled set 1: when an explicit max-record cap is configured (`max_record_bytes > 0`), a
    // segment must hold MORE than one max-size record plus its frame overhead, so a record never
    // spans two segments (an INVARIANTS.md invariant, `docs/CONFIG.md` section 4). `max_record_bytes`
    // is SPECIFIED-NOT-YET-A-FIELD: the shipped storage writes an oversized record to its OWN segment,
    // so when no cap is configured (`0`) this check is skipped and the only segment floor is the
    // shipped `>= MIN_MAX_SEGMENT_BYTES` one (enforced at the CLI/log layer). The rule is wired here
    // so the cross-key check is in place the moment a max-record knob lands.
    if config.max_record_bytes > 0 {
        let needed = config
            .max_record_bytes
            .saturating_add(config.frame_overhead);
        if config.segment_bytes <= needed {
            verdict.errors.push(ValidationError(format!(
                "storage.segment_size = {} cannot hold a max-size record: it must be strictly \
                 greater than max_record_bytes ({}) + frame overhead ({}) = {}, so a record \
                 never spans two segments",
                config.segment_bytes, config.max_record_bytes, config.frame_overhead, needed,
            )));
        }
    }

    // Coupled set 3: the unbounded-loss durability levels MUST carry the explicit
    // acknowledgement, and an `interval` level needs at least one positive flush trigger. Run only
    // when `enforce_durability_gate` is set (the CLI defers it to its shipped `validate_durability`).
    if config.enforce_durability_gate {
        if config.durability_level.requires_loss_ack() && !config.async_loss_ack {
            verdict.errors.push(ValidationError(format!(
                "durability.level = \"{}\" requires durability.async_loss_ack = true (the \
                 relaxed levels weaken the ack-implies-durable guarantee; opt in explicitly)",
                config.durability_level.as_str(),
            )));
        }
        if config.durability_level == DurabilityLevel::Interval
            && config.flush_interval_ms == 0
            && config.flush_max_bytes == 0
        {
            verdict.errors.push(ValidationError(
                "durability.level = \"interval\" needs at least one positive flush trigger \
                 (durability.flush_interval_ms or durability.flush_max_bytes above 0); with both \
                 at 0 the window never forces an fdatasync and silently degrades to the unbounded \
                 async behavior"
                    .to_string(),
            ));
        }
    }

    // Coupled set 4: retention REQUESTED but every limit is 0 is a misconfiguration (it would
    // silently leave retention off). All-zero with no request is valid (retention simply off).
    if config.retention_requested
        && config.max_retained_bytes == 0
        && config.max_age_ms == 0
        && config.max_messages == 0
    {
        verdict.errors.push(ValidationError(
            "retention requested but every limit is 0 (retention.max_retained_bytes, \
             retention.max_age_ms, retention.max_messages all disabled); enable at least one bound"
                .to_string(),
        ));
    }

    // Coupled set 5: `drop-oldest` with no byte cap is a no-op (no produce is ever over-cap),
    // so WARN (not refuse) so an operator who expected force-reap learns the cap is missing.
    if config.disk_full_policy_drop_oldest && config.max_total_bytes == 0 {
        verdict.warnings.push(
            "backpressure.disk_full_policy = \"drop-oldest\" has no effect: \
             storage.max_total_bytes is unset (0 = unlimited), so no produce is ever over-cap"
                .to_string(),
        );
    }

    verdict
}

/// A flat map of `section.key` -> the raw string value the FILE layer extracted from the TOML
/// document, the neutral handoff between the (IO-bound, CLI-side) TOML reader and the
/// (pure, here) strict typed validation. The CLI flattens the parsed TOML into this map, then
/// calls [`validate_known_keys`] to reject any unknown key BEFORE consulting the values.
pub type RawKeyMap = BTreeMap<String, String>;

/// A single unknown-key rejection, with the closest known key as a did-you-mean (if any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// The rejected fully-qualified dotted key.
    pub key: String,
    /// The closest known key, if one is a plausible typo.
    pub suggestion: Option<&'static str>,
}

impl fmt::Display for UnknownKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.suggestion {
            Some(s) => write!(
                f,
                "unknown config key `{}`; did you mean `{}`?",
                self.key, s
            ),
            None => write!(f, "unknown config key `{}`", self.key),
        }
    }
}

/// Strictly checks every dotted key in `keys` against [`KEY_TABLE`], returning the unknown
/// keys (each with a did-you-mean). A key whose top-level section is a RESERVED section
/// ([`is_reserved_section`]) is tolerated (it belongs to another issue's wired keys), so it is
/// NOT returned as unknown. PURE: it consults only the compiled-in table. The CALLER decides
/// the policy: by default an unknown key is FATAL; with `--allow-unknown-config` it is
/// downgraded to a warning.
#[must_use]
pub fn validate_known_keys(keys: &RawKeyMap) -> Vec<UnknownKey> {
    let mut unknown = Vec::new();
    for key in keys.keys() {
        if lookup_key(key).is_some() {
            continue;
        }
        // Tolerate any key under a reserved-but-unwired section (its top-level segment).
        if let Some((section, _)) = key.split_once('.') {
            if is_reserved_section(section) {
                continue;
            }
        }
        unknown.push(UnknownKey {
            key: key.clone(),
            suggestion: did_you_mean(key),
        });
    }
    unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the literal grammar: durations ----

    #[test]
    fn duration_units_parse_to_milliseconds() {
        assert_eq!(parse_duration_ms("100ms"), Ok(100));
        assert_eq!(parse_duration_ms("5s"), Ok(5_000));
        assert_eq!(parse_duration_ms("2m"), Ok(120_000));
        assert_eq!(parse_duration_ms("1h"), Ok(3_600_000));
        assert_eq!(parse_duration_ms("1d"), Ok(86_400_000));
        // Surrounding whitespace is tolerated on the whole token.
        assert_eq!(parse_duration_ms("  30s  "), Ok(30_000));
    }

    #[test]
    fn a_unitless_duration_is_rejected() {
        // The grammar is unit-REQUIRED: a bare number is NOT seconds-or-ms by guess.
        assert!(matches!(
            parse_duration_ms("100"),
            Err(LiteralError::MissingUnit { .. })
        ));
    }

    #[test]
    fn a_decimal_or_signed_duration_is_rejected() {
        assert!(matches!(
            parse_duration_ms("1.5s"),
            Err(LiteralError::NotAnInteger { .. })
        ));
        assert!(matches!(
            parse_duration_ms("-5s"),
            Err(LiteralError::NotAnInteger { .. })
        ));
        assert!(matches!(
            parse_duration_ms("ms"),
            Err(LiteralError::NotAnInteger { .. })
        ));
    }

    #[test]
    fn an_unknown_duration_unit_is_rejected() {
        // `sec` is not `s`; `min` is not `m`.
        assert!(matches!(
            parse_duration_ms("100sec"),
            Err(LiteralError::UnknownUnit { .. })
        ));
    }

    #[test]
    fn a_duration_overflow_is_rejected_not_wrapped() {
        // Days * 86_400_000 overflows u64 well before u128, so it is a clean error.
        assert!(matches!(
            parse_duration_ms("999999999999999999d"),
            Err(LiteralError::Overflow { .. })
        ));
    }

    // ---- the literal grammar: binary byte sizes ----

    #[test]
    fn binary_byte_units_parse_to_bytes() {
        assert_eq!(parse_byte_size("4096B"), Ok(4096));
        assert_eq!(parse_byte_size("1KiB"), Ok(1024));
        assert_eq!(parse_byte_size("64MiB"), Ok(64 * 1024 * 1024));
        assert_eq!(parse_byte_size("1GiB"), Ok(1024 * 1024 * 1024));
        assert_eq!(parse_byte_size("1TiB"), Ok(1024_u64 * 1024 * 1024 * 1024));
    }

    #[test]
    fn a_decimal_si_byte_size_is_rejected() {
        // `MB`/`GB` (decimal SI) are NOT the binary `MiB`/`GiB`: rejected, never coerced.
        assert!(matches!(
            parse_byte_size("5MB"),
            Err(LiteralError::UnknownUnit { .. })
        ));
        assert!(matches!(
            parse_byte_size("5GB"),
            Err(LiteralError::UnknownUnit { .. })
        ));
        // a unitless byte size is also rejected.
        assert!(matches!(
            parse_byte_size("1048576"),
            Err(LiteralError::MissingUnit { .. })
        ));
    }

    #[test]
    fn a_byte_size_overflow_is_rejected_not_wrapped() {
        assert!(matches!(
            parse_byte_size("99999999999999TiB"),
            Err(LiteralError::Overflow { .. })
        ));
    }

    // ---- the typed key table + did-you-mean ----

    #[test]
    fn a_known_key_is_looked_up_with_its_kind() {
        assert_eq!(
            lookup_key("storage.segment_size").map(|s| s.kind),
            Some(KeyKind::ByteSize)
        );
        assert_eq!(
            lookup_key("delivery.visibility_timeout_ms").map(|s| s.kind),
            Some(KeyKind::Duration)
        );
        assert!(lookup_key("storage.no_such_key").is_none());
    }

    #[test]
    fn an_unknown_key_gets_a_did_you_mean_suggestion() {
        // A close typo gets the nearest known key.
        assert_eq!(
            did_you_mean("storage.segment_size"),
            Some("storage.segment_size")
        );
        assert_eq!(
            did_you_mean("storage.segmnet_size"),
            Some("storage.segment_size")
        );
        assert_eq!(
            did_you_mean("durability.flush_interval"),
            Some("durability.flush_interval_ms")
        );
    }

    #[test]
    fn a_wildly_unrelated_key_gets_no_misleading_suggestion() {
        assert_eq!(did_you_mean("zzzzzzzzzzzzzzzzzz"), None);
    }

    #[test]
    fn validate_known_keys_rejects_unknown_and_keeps_reserved_sections() {
        let mut keys = RawKeyMap::new();
        keys.insert("storage.segment_size".to_string(), "64MiB".to_string());
        keys.insert("storage.segmnet_size".to_string(), "32MiB".to_string());
        // A reserved-but-unwired section is tolerated (no rejection), per #139.
        keys.insert("observability.metrics_addr".to_string(), "x".to_string());
        keys.insert("auth.token".to_string(), "y".to_string());
        let unknown = validate_known_keys(&keys);
        assert_eq!(unknown.len(), 1, "{unknown:?}");
        assert_eq!(unknown[0].key, "storage.segmnet_size");
        assert_eq!(unknown[0].suggestion, Some("storage.segment_size"));
    }

    // ---- coupled-set validation ----

    fn base_resolved() -> ResolvedConfig {
        ResolvedConfig {
            segment_bytes: 64 * 1024 * 1024,
            max_record_bytes: 1024 * 1024,
            frame_overhead: 64,
            durability_level: DurabilityLevel::Sync,
            flush_interval_ms: 1000,
            flush_max_bytes: 1024 * 1024,
            async_loss_ack: false,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            retention_requested: false,
            max_total_bytes: 0,
            disk_full_policy_drop_oldest: false,
            // The pure-core unit tests exercise the durability teeth, so the gate is ON here.
            enforce_durability_gate: true,
        }
    }

    #[test]
    fn a_healthy_config_passes_with_no_errors() {
        assert!(validate_coupled_sets(&base_resolved()).is_ok());
    }

    #[test]
    fn segment_smaller_than_a_max_record_is_rejected() {
        let mut c = base_resolved();
        c.segment_bytes = 1024 * 1024; // == max_record_bytes, cannot hold one + overhead
        let v = validate_coupled_sets(&c);
        assert!(!v.is_ok());
        assert!(
            v.errors[0].0.contains("cannot hold a max-size record"),
            "{:?}",
            v.errors
        );
    }

    #[test]
    fn an_unbounded_loss_level_without_the_ack_is_rejected() {
        let mut c = base_resolved();
        c.durability_level = DurabilityLevel::None;
        let v = validate_coupled_sets(&c);
        assert!(!v.is_ok());
        assert!(v
            .errors
            .iter()
            .any(|e| e.0.contains("async_loss_ack = true")));
        // With the ack it passes.
        c.async_loss_ack = true;
        assert!(validate_coupled_sets(&c).is_ok());
    }

    #[test]
    fn an_interval_level_with_no_trigger_is_rejected() {
        let mut c = base_resolved();
        c.durability_level = DurabilityLevel::Interval;
        c.flush_interval_ms = 0;
        c.flush_max_bytes = 0;
        let v = validate_coupled_sets(&c);
        assert!(!v.is_ok());
        assert!(v
            .errors
            .iter()
            .any(|e| e.0.contains("at least one positive flush trigger")));
    }

    #[test]
    fn retention_requested_but_all_off_is_rejected() {
        let mut c = base_resolved();
        c.retention_requested = true;
        let v = validate_coupled_sets(&c);
        assert!(!v.is_ok());
        assert!(v
            .errors
            .iter()
            .any(|e| e.0.contains("retention requested but every limit is 0")));
    }

    #[test]
    fn drop_oldest_with_no_cap_warns_but_does_not_fail() {
        let mut c = base_resolved();
        c.disk_full_policy_drop_oldest = true;
        c.max_total_bytes = 0;
        let v = validate_coupled_sets(&c);
        assert!(v.is_ok(), "a no-op policy is a warning, not a fatal error");
        assert_eq!(v.warnings.len(), 1);
        assert!(v.warnings[0].contains("has no effect"));
    }
}
