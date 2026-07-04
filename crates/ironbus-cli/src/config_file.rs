// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TOML config-FILE layer (#85, #86, #382): the file IO half of the configuration
//! system, the layer that slots BETWEEN env and default so the precedence becomes
//! `flag > env > FILE > default` (`docs/CONFIG.md` section 2).
//!
//! This module owns the parts that touch a FILE; the PURE grammar and the typed-key /
//! coupled-set validation live in the IO-free [`ironbus_core::config`] core and are
//! shared with the flag/env resolver. The flow is whole-read -> parse -> flatten ->
//! strict-validate -> build the per-key override layer:
//!
//! 1. read the whole file (a missing/unreadable file is a typed config error),
//! 2. parse it with the pure-Rust `toml` crate (a broken file fails fatally with the
//!    PATH and the line/column the parser reports),
//! 3. FLATTEN the nested `[section]` tables into dotted `section.key` -> raw-value pairs,
//! 4. strictly validate the KEY SET against [`ironbus_core::config::KEY_TABLE`]: an
//!    unknown key is REJECTED with a did-you-mean (or, under `--allow-unknown-config`,
//!    downgraded to a warning), and a reserved-but-unwired section is tolerated,
//! 5. expose the known keys as a [`FileLayer`] the resolver consults via the SAME
//!    `IRONBUS_<FLAG>` env-name mapping the env layer uses, so the existing
//!    `flag > env > default` resolvers gain the file layer with NO change to their
//!    relative order (env still beats file, file still beats default).
//!
//! With NO `--config`, none of this runs and the broker resolves exactly as today
//! (flag > env > default), so the default behavior is byte-for-byte unchanged.

use std::collections::BTreeMap;

use ironbus_core::config::{
    self, parse_byte_size, parse_duration_ms, KeyKind, RawKeyMap, UnknownKey,
};

/// A failure loading or parsing the `--config` file, carrying enough context for a clean
/// usage/config exit (never a panic). The caller maps each onto the usage exit code and the
/// message names the PATH (and, for a parse error, the line/column the `toml` parser reports).
#[derive(Debug)]
pub enum ConfigFileError {
    /// The file could not be read (absent, a directory, unreadable): names the path and the
    /// underlying IO error.
    Read {
        /// The `--config` path as given.
        path: String,
        /// The underlying IO error message.
        source: String,
    },
    /// The file is not valid TOML: names the path and the parser's line/column message.
    Parse {
        /// The `--config` path as given.
        path: String,
        /// The `toml` parser's message (already includes "line N, column M").
        message: String,
    },
    /// A known key carried the wrong TOML type (a string where an integer was expected, etc.):
    /// names the key and what was expected.
    Type {
        /// The fully-qualified dotted key.
        key: String,
        /// The mismatch description.
        message: String,
    },
    /// A duration/size LITERAL under a known key did not parse (a missing unit, a decimal-SI
    /// size, an overflow): names the key and the literal-grammar error.
    Literal {
        /// The fully-qualified dotted key.
        key: String,
        /// The literal-grammar error message.
        message: String,
    },
    /// One or more UNKNOWN keys, rejected (the default strict policy). Carries every rejected
    /// key with its did-you-mean so the operator sees them all at once.
    UnknownKeys(Vec<UnknownKey>),
}

impl std::fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigFileError::Read { path, source } => {
                write!(f, "cannot read config file `{path}`: {source}")
            }
            ConfigFileError::Parse { path, message } => {
                write!(f, "config file `{path}` is not valid TOML: {message}")
            }
            // A wrong-type and a bad-literal both name the key then the mismatch/grammar message.
            ConfigFileError::Type { key, message } | ConfigFileError::Literal { key, message } => {
                write!(f, "config key `{key}`: {message}")
            }
            ConfigFileError::UnknownKeys(keys) => {
                write!(f, "config file rejected: ")?;
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{k}")?;
                }
                Ok(())
            }
        }
    }
}

/// The resolved FILE layer: the known config keys mapped to the `IRONBUS_<FLAG>` env-name the
/// resolver looks up, so the existing `flag > env > default` resolvers consult the file by
/// reading this layer AFTER env and BEFORE the default. Built by [`load_config_file`]; consumed
/// through [`FileLayer::lookup_env_name`] inside a combined env-then-file closure.
#[derive(Debug, Default, Clone)]
pub struct FileLayer {
    /// `IRONBUS_<FLAG>` env-var name -> the already-normalized value string the resolver parses
    /// (durations/sizes as decimal-integer strings, bools as `true`/`false`, lists comma-joined,
    /// plain strings as-is), so the file value flows through the same parse path as an env value.
    by_env_name: BTreeMap<String, String>,
    /// Non-fatal warnings to surface (unknown keys downgraded by `--allow-unknown-config`, and
    /// reserved-but-unwired sections whose keys are accepted-but-ignored per #898).
    warnings: Vec<String>,
    /// True when the file explicitly set ANY retention key (drives the coupled-set
    /// "retention requested but all off" check, which fires only on an explicit request).
    retention_requested: bool,
}

impl FileLayer {
    /// Looks the FILE value up by its `IRONBUS_<FLAG>` env-name, the same name the resolver
    /// passes the env seam. Returns `None` when the file did not set that key, so the resolver
    /// falls through to the default. This is the read used by the combined env-then-file closure.
    #[must_use]
    pub fn lookup_env_name(&self, env_name: &str) -> Option<String> {
        self.by_env_name.get(env_name).cloned()
    }

    /// The non-fatal warnings the loader accumulated (downgraded unknown keys, etc.), for the
    /// caller to print to the log stream.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// True when the file explicitly set any retention key, so the coupled-set validator runs the
    /// "retention requested but every limit is 0" check only when the operator asked for retention.
    #[must_use]
    pub fn retention_requested(&self) -> bool {
        self.retention_requested
    }
}

/// Maps a dotted config key (`storage.segment_size`) onto the `IRONBUS_<FLAG>` env-var name the
/// resolver uses for the same knob (`IRONBUS_MAX_SEGMENT_BYTES`), so the file value flows through
/// the identical parse path as an env value and the precedence stays a single mechanism. Returns
/// `None` for a key that has no flag/env knob (none today, but additive-safe). The mapping is the
/// inverse of `docs/CONFIG.md` section 3's flag column.
fn key_to_env_name(key: &str) -> Option<&'static str> {
    let env = match key {
        "profile" => "IRONBUS_PROFILE",
        "storage.segment_size" => "IRONBUS_MAX_SEGMENT_BYTES",
        "storage.data_dir" => "IRONBUS_DATA_DIR",
        "storage.max_total_bytes" => "IRONBUS_MAX_TOTAL_BYTES",
        "storage.io_mode" => "IRONBUS_IO_MODE",
        "durability.level" => "IRONBUS_DURABILITY_LEVEL",
        "durability.flush_interval_ms" => "IRONBUS_FLUSH_INTERVAL_MS",
        "durability.flush_max_bytes" => "IRONBUS_FLUSH_MAX_BYTES",
        "durability.async_loss_ack" => "IRONBUS_ASYNC_LOSS_ACK",
        "retention.max_retained_bytes" => "IRONBUS_MAX_RETAINED_BYTES",
        "retention.max_age_ms" => "IRONBUS_MAX_AGE_MS",
        "retention.max_messages" => "IRONBUS_MAX_MESSAGES",
        "backpressure.disk_full_policy" => "IRONBUS_DISK_FULL_POLICY",
        "backpressure.consumer_credit" => "IRONBUS_CONSUMER_CREDIT",
        "backpressure.consumer_credit_bytes" => "IRONBUS_CONSUMER_CREDIT_BYTES",
        "backpressure.max_in_flight" => "IRONBUS_MAX_IN_FLIGHT",
        "backpressure.max_connections" => "IRONBUS_MAX_CONNECTIONS",
        "backpressure.max_groups" => "IRONBUS_MAX_GROUPS",
        "backpressure.group_idle_evict_ms" => "IRONBUS_GROUP_IDLE_EVICT_MS",
        "backpressure.ram_ceiling_bytes" => "IRONBUS_RAM_CEILING_BYTES",
        "backpressure.codel_target_ms" => "IRONBUS_CODEL_TARGET_MS",
        "backpressure.codel_interval_ms" => "IRONBUS_CODEL_INTERVAL_MS",
        "backpressure.retry_budget_ratio_per_million" => "IRONBUS_RETRY_BUDGET_RATIO_PPM",
        "backpressure.retry_budget_window_ms" => "IRONBUS_RETRY_BUDGET_WINDOW_MS",
        "backpressure.fire_and_forget_msg_rate" => "IRONBUS_FIRE_AND_FORGET_MSG_RATE",
        "backpressure.fire_and_forget_byte_rate" => "IRONBUS_FIRE_AND_FORGET_BYTE_RATE",
        "backpressure.fire_and_forget_refill_ms" => "IRONBUS_FIRE_AND_FORGET_REFILL_MS",
        "backpressure.egress_limit" => "IRONBUS_EGRESS_LIMIT",
        "delivery.max_deliver" => "IRONBUS_MAX_DELIVER",
        "delivery.allow_unlimited_deliver" => "IRONBUS_ALLOW_UNLIMITED_DELIVER",
        "delivery.backoff_ms" => "IRONBUS_BACKOFF_MS",
        "delivery.visibility_timeout_ms" => "IRONBUS_VISIBILITY_TIMEOUT_MS",
        "delivery.checkpoint_interval" => "IRONBUS_CHECKPOINT_INTERVAL",
        "delivery.dedup_max_ids" => "IRONBUS_DEDUP_MAX_IDS",
        "delivery.dedup_window_ms" => "IRONBUS_DEDUP_WINDOW_MS",
        "delivery.dedup_max_producers" => "IRONBUS_DEDUP_MAX_PRODUCERS",
        "delivery.max_prepared" => "IRONBUS_MAX_PREPARED",
        "delivery.max_prepared_bytes" => "IRONBUS_MAX_PREPARED_BYTES",
        "network.listen" => "IRONBUS_ADDR",
        "network.health_addr" => "IRONBUS_HEALTH_ADDR",
        "network.health_allow_public" => "IRONBUS_HEALTH_ALLOW_PUBLIC",
        "network.health_liveness_window_ms" => "IRONBUS_HEALTH_LIVENESS_WINDOW_MS",
        "network.enable_admin" => "IRONBUS_ENABLE_ADMIN",
        _ => return None,
    };
    Some(env)
}

/// Reads, parses, and validates the `--config` file at `path`, producing a [`FileLayer`].
///
/// This is the whole-read -> parse -> flatten -> strict-validate pipeline. `allow_unknown`
/// (from `--allow-unknown-config`) downgrades an unknown key from a fatal error to a warning;
/// by default an unknown key is fatal (with a did-you-mean), so a typo that would silently
/// disable durability or retention is caught. A broken file fails with the PATH + line/column.
///
/// `read` is the whole-file reader seam: production passes a `std::fs::read_to_string` closure,
/// tests pass an in-memory map, so this function (and every test of the precedence and the
/// strict validation) is deterministic and IO-injectable.
///
/// # Errors
/// [`ConfigFileError`] for an unreadable file, a TOML parse error (with line/column), a typed
/// key with the wrong TOML type, a bad duration/size literal, or (strict mode) unknown keys.
pub fn load_config_file(
    path: &str,
    allow_unknown: bool,
    read: &dyn Fn(&str) -> Result<String, String>,
) -> Result<FileLayer, ConfigFileError> {
    let text = read(path).map_err(|source| ConfigFileError::Read {
        path: path.to_string(),
        source,
    })?;
    // Parse the WHOLE document to a typed `toml::Value`. The `toml` Display already carries
    // "line N column M"; keep it verbatim so the operator gets the exact location, and prefix the
    // path so a multi-file setup is clear.
    let value: toml::Value =
        toml::from_str(&text).map_err(|e: toml::de::Error| ConfigFileError::Parse {
            path: path.to_string(),
            message: e.to_string(),
        })?;
    // A valid TOML document is always a table at the top level; `from_str` rejects a non-table root.
    let table = value.as_table().ok_or_else(|| ConfigFileError::Parse {
        path: path.to_string(),
        message: "the top-level TOML value is not a table".to_string(),
    })?;

    // FLATTEN the nested tables into dotted `section.key` -> Value. A non-table top-level value
    // (the bare `profile` key) is kept as a top-level dotted key with no section prefix.
    let mut flat: BTreeMap<String, toml::Value> = BTreeMap::new();
    flatten_table("", table, &mut flat);

    // The raw key SET for the strict unknown-key check (the values are not consulted yet).
    let key_set: RawKeyMap = flat.keys().map(|k| (k.clone(), String::new())).collect();
    let unknown = config::validate_known_keys(&key_set);
    let mut warnings = Vec::new();
    if !unknown.is_empty() {
        if allow_unknown {
            // Downgraded: keep going, but surface every unknown key as a loud warning so an
            // operator who opted into the escape hatch still sees the typo.
            for u in &unknown {
                warnings.push(format!("ignoring {u} (--allow-unknown-config)"));
            }
        } else {
            return Err(ConfigFileError::UnknownKeys(unknown));
        }
    }
    // A reserved-but-unwired section (`[auth]`/`[observability]`/`[compression]`) parses clean but
    // silently swallows every key (#898). Surface each such section as a non-fatal WARN so a
    // misplaced security/codec setting is not believed-applied while being dead. This is
    // independent of `--allow-unknown-config`: the section is tolerated by design, but its
    // accepted-but-ignored keys still warrant a loud warning.
    warnings.extend(config::reserved_section_warnings(&key_set));

    // Build the env-name override layer from the KNOWN keys only (an unknown key, if it reached
    // here, was downgraded and is ignored, never wired into a knob).
    let mut by_env_name = BTreeMap::new();
    let mut retention_requested = false;
    for (key, value) in &flat {
        let Some(spec) = config::lookup_key(key) else {
            continue; // unknown-but-allowed, or a reserved-section key: not a wired knob.
        };
        let normalized = normalize_value(key, spec.kind, value)?;
        if key.starts_with("retention.") {
            retention_requested = true;
        }
        if let Some(env_name) = key_to_env_name(key) {
            by_env_name.insert(env_name.to_string(), normalized);
        }
    }

    Ok(FileLayer {
        by_env_name,
        warnings,
        retention_requested,
    })
}

/// Recursively flattens a TOML table into dotted `section.key` -> leaf-value pairs. A nested
/// table extends the prefix; a leaf (scalar or array) is recorded under the accumulated dotted
/// key. Only ONE level of nesting is expected today (`[network.tls]` is the deepest), but the
/// recursion is general so a future nested section flattens without a special case.
fn flatten_table(
    prefix: &str,
    table: &toml::value::Table,
    out: &mut BTreeMap<String, toml::Value>,
) {
    for (key, value) in table {
        let dotted = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::Table(inner) => flatten_table(&dotted, inner, out),
            other => {
                out.insert(dotted, other.clone());
            }
        }
    }
}

/// Normalizes one typed TOML value into the string form the existing resolver parses, enforcing
/// the key's [`KeyKind`]: a duration/size literal STRING is parsed by the shared literal grammar
/// and re-emitted as a decimal-integer string (so the resolver's numeric parse sees a plain
/// integer); a plain integer is emitted as-is; a bool as `true`/`false`; an int list as a
/// comma-separated string; a free string as-is. A TOML type that does not match the key's kind is
/// a typed [`ConfigFileError::Type`] naming the key.
fn normalize_value(
    key: &str,
    kind: KeyKind,
    value: &toml::Value,
) -> Result<String, ConfigFileError> {
    match kind {
        KeyKind::Duration => {
            let raw = as_literal_str(key, value, "a duration string like \"30s\"")?;
            let ms = parse_duration_ms(&raw).map_err(|e| ConfigFileError::Literal {
                key: key.to_string(),
                message: e.to_string(),
            })?;
            Ok(ms.to_string())
        }
        KeyKind::ByteSize => {
            // A byte size may be a literal string (`"64MiB"`) OR a plain integer (raw bytes), so
            // an operator can write either; an integer is taken as a byte count verbatim.
            if let Some(i) = value.as_integer() {
                return non_negative(key, i);
            }
            let raw = as_literal_str(key, value, "a byte-size string like \"64MiB\"")?;
            let bytes = parse_byte_size(&raw).map_err(|e| ConfigFileError::Literal {
                key: key.to_string(),
                message: e.to_string(),
            })?;
            Ok(bytes.to_string())
        }
        KeyKind::Integer => {
            let i = value.as_integer().ok_or_else(|| ConfigFileError::Type {
                key: key.to_string(),
                message: format!("expected an integer, got a {}", value.type_str()),
            })?;
            non_negative(key, i)
        }
        KeyKind::Bool => {
            let b = value.as_bool().ok_or_else(|| ConfigFileError::Type {
                key: key.to_string(),
                message: format!("expected a boolean, got a {}", value.type_str()),
            })?;
            Ok(if b {
                "true".to_string()
            } else {
                "false".to_string()
            })
        }
        KeyKind::Str => {
            let s = value.as_str().ok_or_else(|| ConfigFileError::Type {
                key: key.to_string(),
                message: format!("expected a string, got a {}", value.type_str()),
            })?;
            Ok(s.to_string())
        }
        KeyKind::IntList => {
            let arr = value.as_array().ok_or_else(|| ConfigFileError::Type {
                key: key.to_string(),
                message: format!("expected a list of integers, got a {}", value.type_str()),
            })?;
            let mut parts = Vec::with_capacity(arr.len());
            for item in arr {
                let i = item.as_integer().ok_or_else(|| ConfigFileError::Type {
                    key: key.to_string(),
                    message: format!(
                        "expected a list of integers, found a {} element",
                        item.type_str()
                    ),
                })?;
                parts.push(non_negative(key, i)?);
            }
            if parts.is_empty() {
                return Err(ConfigFileError::Type {
                    key: key.to_string(),
                    message: "expected a non-empty list of integers".to_string(),
                });
            }
            Ok(parts.join(","))
        }
    }
}

/// Extracts a literal STRING value for a duration/size key, or a typed type error naming the key.
fn as_literal_str(key: &str, value: &toml::Value, want: &str) -> Result<String, ConfigFileError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| ConfigFileError::Type {
            key: key.to_string(),
            message: format!("expected {want}, got a {}", value.type_str()),
        })
}

/// Rejects a negative TOML integer (every knob is a non-negative count/size), returning the
/// non-negative value as a decimal string.
fn non_negative(key: &str, i: i64) -> Result<String, ConfigFileError> {
    if i < 0 {
        return Err(ConfigFileError::Type {
            key: key.to_string(),
            message: format!("expected a non-negative integer, got {i}"),
        });
    }
    Ok(i.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whole-file reader seam over a fixed in-memory document, so the loader is deterministic.
    fn reader(doc: &'static str) -> impl Fn(&str) -> Result<String, String> {
        move |_path: &str| Ok(doc.to_string())
    }

    #[test]
    fn a_file_value_is_exposed_under_its_env_name() {
        let doc = "[storage]\nsegment_size = \"32MiB\"\n";
        let layer = load_config_file("/x.toml", false, &reader(doc)).unwrap();
        assert_eq!(
            layer.lookup_env_name("IRONBUS_MAX_SEGMENT_BYTES"),
            Some((32 * 1024 * 1024).to_string())
        );
    }

    #[test]
    fn a_duration_literal_is_normalized_to_milliseconds() {
        let doc = "[delivery]\nvisibility_timeout_ms = \"45s\"\n";
        let layer = load_config_file("/x.toml", false, &reader(doc)).unwrap();
        assert_eq!(
            layer.lookup_env_name("IRONBUS_VISIBILITY_TIMEOUT_MS"),
            Some("45000".to_string())
        );
    }

    #[test]
    fn a_byte_size_may_be_a_literal_or_a_plain_integer() {
        let doc = "[storage]\nmax_total_bytes = 1048576\n";
        let layer = load_config_file("/x.toml", false, &reader(doc)).unwrap();
        assert_eq!(
            layer.lookup_env_name("IRONBUS_MAX_TOTAL_BYTES"),
            Some("1048576".to_string())
        );
    }

    #[test]
    fn a_bool_and_a_list_normalize() {
        let doc = "[delivery]\nallow_unlimited_deliver = true\nbackoff_ms = [100, 500, 2000]\n";
        let layer = load_config_file("/x.toml", false, &reader(doc)).unwrap();
        assert_eq!(
            layer.lookup_env_name("IRONBUS_ALLOW_UNLIMITED_DELIVER"),
            Some("true".to_string())
        );
        assert_eq!(
            layer.lookup_env_name("IRONBUS_BACKOFF_MS"),
            Some("100,500,2000".to_string())
        );
    }

    #[test]
    fn an_unknown_key_is_rejected_with_a_suggestion() {
        let doc = "[storage]\nsegmnet_size = \"32MiB\"\n";
        let err = load_config_file("/x.toml", false, &reader(doc)).unwrap_err();
        match err {
            ConfigFileError::UnknownKeys(keys) => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].suggestion, Some("storage.segment_size"));
            }
            other => panic!("expected UnknownKeys, got {other}"),
        }
    }

    #[test]
    fn an_unknown_key_is_a_warning_under_allow_unknown() {
        let doc = "[storage]\nsegmnet_size = \"32MiB\"\n";
        let layer = load_config_file("/x.toml", true, &reader(doc)).unwrap();
        assert_eq!(layer.warnings().len(), 1);
        assert!(layer.warnings()[0].contains("segmnet_size"));
        // The unknown key is NOT wired into any knob.
        assert!(layer.lookup_env_name("IRONBUS_MAX_SEGMENT_BYTES").is_none());
    }

    #[test]
    fn a_reserved_section_key_is_tolerated_but_warned() {
        let doc = "[observability]\nmetrics_addr = \"127.0.0.1:9000\"\n[auth]\ntoken = \"x\"\n";
        let layer = load_config_file("/x.toml", false, &reader(doc)).unwrap();
        // NOT rejected (the frozen-section contract still starts the broker), but #898 requires a
        // loud non-fatal WARN so the accepted-but-ignored keys are not silently swallowed.
        let warnings = layer.warnings();
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings.iter().all(|w| w.contains("IGNORED")));
        assert!(warnings.iter().any(|w| w.contains("[auth]")
            && w.contains("auth.token")
            && w.contains("--auth-config")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("[observability]") && w.contains("observability.metrics_addr")));
        // The reserved keys are still NOT wired into any knob.
        assert!(layer.lookup_env_name("IRONBUS_METRICS_ADDR").is_none());
    }

    #[test]
    fn a_unitless_duration_in_the_file_is_rejected() {
        let doc = "[delivery]\nvisibility_timeout_ms = \"45\"\n";
        let err = load_config_file("/x.toml", false, &reader(doc)).unwrap_err();
        assert!(matches!(err, ConfigFileError::Literal { .. }), "{err}");
    }

    #[test]
    fn a_decimal_si_size_in_the_file_is_rejected() {
        let doc = "[storage]\nsegment_size = \"32MB\"\n";
        let err = load_config_file("/x.toml", false, &reader(doc)).unwrap_err();
        assert!(matches!(err, ConfigFileError::Literal { .. }), "{err}");
    }

    #[test]
    fn a_wrong_type_is_a_typed_error() {
        // consumer_credit is an integer; a string is a type error naming the key.
        let doc = "[backpressure]\nconsumer_credit = \"lots\"\n";
        let err = load_config_file("/x.toml", false, &reader(doc)).unwrap_err();
        match err {
            ConfigFileError::Type { key, .. } => {
                assert_eq!(key, "backpressure.consumer_credit");
            }
            other => panic!("expected Type, got {other}"),
        }
    }

    #[test]
    fn a_broken_file_reports_the_path_and_a_location() {
        let doc = "[storage\nsegment_size = \"32MiB\"\n";
        let err = load_config_file("/etc/ironbus.toml", false, &reader(doc)).unwrap_err();
        match err {
            ConfigFileError::Parse { path, message } => {
                assert_eq!(path, "/etc/ironbus.toml");
                assert!(message.contains("line"), "{message}");
            }
            other => panic!("expected Parse, got {other}"),
        }
    }

    #[test]
    fn an_unreadable_file_is_a_typed_read_error() {
        let read = |_p: &str| Err("No such file or directory".to_string());
        let err = load_config_file("/nope.toml", false, &read).unwrap_err();
        assert!(matches!(err, ConfigFileError::Read { .. }), "{err}");
    }

    #[test]
    fn setting_a_retention_key_marks_retention_requested() {
        let doc = "[retention]\nmax_retained_bytes = \"1GiB\"\n";
        let layer = load_config_file("/x.toml", false, &reader(doc)).unwrap();
        assert!(layer.retention_requested());
    }
}
