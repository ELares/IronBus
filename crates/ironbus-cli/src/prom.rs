// SPDX-License-Identifier: MIT OR Apache-2.0
//! A tiny, dependency-free reader for the Prometheus text exposition format (V2-M6, #589), confined
//! to the shapes the broker's `/metrics` endpoint emits: bare `name value` samples, labeled
//! `name{label="v",..} value` samples, and the `# HELP`/`# TYPE` comment lines (ignored). It is
//! deliberately small and tolerant of sample order, matching the hand-rolled `/admin` JSON
//! extractors in [`crate::admin`] — the workspace keeps no serde / no prometheus-parser on the
//! shipped rendering path, so the `report` views are driven by parsing these samples ALONE.
//!
//! It does NOT validate the exposition format as a whole; it pulls exactly the series the `report`
//! verb renders. An absent series reads as absent (the caller substitutes a clean default), so a
//! broker that does not emit a given counter never makes the report panic.

use std::collections::BTreeMap;

/// One parsed sample: its `value` (kept as the raw token so an integer counter and a float gauge
/// both round-trip without precision loss) and its label set (empty for a bare sample). Labels are
/// a `BTreeMap` so a lookup is order-independent and a render is deterministic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sample {
    /// The metric value, as the raw text token (e.g. `42`, `-1`, `3.5`, `1.2e3`). The caller parses
    /// it to the numeric type it needs.
    pub value: String,
    /// The label set: `{group="orders"}` → `{"group": "orders"}`. Empty for a bare `name value`.
    pub labels: BTreeMap<String, String>,
}

impl Sample {
    /// Parses the value as a `u64`, returning `None` if it is not a bare unsigned integer (a `-1`
    /// sentinel or a float thus reads as absent for an unsigned consumer).
    pub fn as_u64(&self) -> Option<u64> {
        self.value.parse::<u64>().ok()
    }

    /// Parses the value as an `i64` (for the `-1` sentinels such as `last_dead_lettered_offset` and
    /// `ironbus_disk_free_bytes` on an in-memory broker).
    pub fn as_i64(&self) -> Option<i64> {
        self.value.parse::<i64>().ok()
    }

    /// Returns the value of label `key`, if present.
    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(String::as_str)
    }
}

/// A parsed `/metrics` document: every sample, keyed by metric name. A metric name maps to ALL of
/// its samples (one for a bare gauge/counter; many for a labeled family, one per label set). The
/// caller asks for a metric by name and reads the bare value or walks the labeled family.
#[derive(Clone, Debug, Default)]
pub(crate) struct Metrics {
    by_name: BTreeMap<String, Vec<Sample>>,
}

impl Metrics {
    /// Parses a Prometheus text-exposition body. `# HELP`/`# TYPE`/blank lines are skipped; every
    /// other line is parsed as `name[{labels}] value` and indexed by name. A line that does not
    /// match the sample grammar is skipped (the parser is tolerant: it pulls the series the report
    /// needs and ignores anything it does not understand), so a future series can never break it.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        let mut by_name: BTreeMap<String, Vec<Sample>> = BTreeMap::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((name, sample)) = parse_sample_line(line) {
                by_name.entry(name).or_default().push(sample);
            }
        }
        Self { by_name }
    }

    /// Returns the single BARE sample for `name` (no labels), or `None` if the metric is absent or
    /// every sample of it is labeled. Used for the scalar gauges/counters
    /// (`ironbus_disk_free_bytes`, `ironbus_segment_count`, ...).
    pub fn scalar(&self, name: &str) -> Option<&Sample> {
        self.by_name.get(name)?.iter().find(|s| s.labels.is_empty())
    }

    /// Reads the bare scalar value of `name` as a `u64`, or `0` if the metric is absent (a broker
    /// that never produced a given counter reports a clean zero, not a parse failure).
    pub fn u64_or_zero(&self, name: &str) -> u64 {
        self.scalar(name).and_then(Sample::as_u64).unwrap_or(0)
    }

    /// Reads the bare scalar value of `name` as an `i64`, or `default` if absent (for the `-1`
    /// sentinels: an in-memory broker reports `ironbus_disk_free_bytes -1`).
    pub fn i64_or(&self, name: &str, default: i64) -> i64 {
        self.scalar(name)
            .and_then(Sample::as_i64)
            .unwrap_or(default)
    }

    /// Returns every sample of the labeled family `name` (one per label set), or an empty slice if
    /// the family is absent. Used for the per-group / per-stream / per-state series.
    pub fn family(&self, name: &str) -> &[Sample] {
        self.by_name.get(name).map_or(&[], Vec::as_slice)
    }

    /// Looks up one sample of family `name` whose label `key` equals `value` (e.g. the
    /// `ironbus_connections_total{state="accepted"}` sample), returning its value as a `u64` or `0`
    /// if that label combination is absent.
    pub fn labeled_u64(&self, name: &str, key: &str, value: &str) -> u64 {
        self.family(name)
            .iter()
            .find(|s| s.label(key) == Some(value))
            .and_then(Sample::as_u64)
            .unwrap_or(0)
    }
}

/// Parses one sample line `name[{labels}] value` into `(name, Sample)`. Returns `None` if the line
/// does not fit the grammar (so the tolerant parser skips it). The value is the LAST
/// whitespace-delimited token (Prometheus permits an optional trailing timestamp, which the broker
/// never emits, but taking the token immediately after the metric identifier keeps us correct for
/// the shapes we do parse).
fn parse_sample_line(line: &str) -> Option<(String, Sample)> {
    let bytes = line.as_bytes();
    // The metric name runs up to the first `{` (labeled) or whitespace (bare).
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b'{' && !bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let name = line[..i].to_string();
    let labels = if i < bytes.len() && bytes[i] == b'{' {
        // A labeled sample: parse to the matching `}`.
        let close = line[i..].find('}')? + i;
        let parsed = parse_labels(&line[i + 1..close]);
        i = close + 1;
        parsed
    } else {
        BTreeMap::new()
    };
    // The remainder is `<ws> value [<ws> timestamp]`; the value is the first token after the name /
    // label block.
    let rest = line[i..].trim_start();
    let value = rest.split_whitespace().next()?.to_string();
    if value.is_empty() {
        return None;
    }
    Some((name, Sample { value, labels }))
}

/// Parses the inside of a `{...}` label block: `key="value",key2="value2"`. Tolerant of spaces
/// around commas and `=`. Undoes the two structural escapes the exporter emits inside a label
/// value (`\"` and `\\`), matching the server's `escape_label`.
fn parse_labels(inner: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let bytes = inner.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip separators / whitespace.
        while i < bytes.len() && (bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        // Read the key up to `=`.
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = inner[key_start..i].trim().to_string();
        i += 1; // past '='
                // The value must be a quoted string.
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'"' {
            break;
        }
        i += 1; // past opening quote
        let mut value = String::new();
        while i < bytes.len() {
            let c = bytes[i];
            if c == b'\\' {
                i += 1;
                match bytes.get(i) {
                    Some(b'"') => value.push('"'),
                    Some(b'\\') => value.push('\\'),
                    Some(b'n') => value.push('\n'),
                    Some(other) => value.push(*other as char),
                    None => break,
                }
            } else if c == b'"' {
                i += 1; // past closing quote
                break;
            } else {
                value.push(c as char);
            }
            i += 1;
        }
        if !key.is_empty() {
            labels.insert(key, value);
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# HELP ironbus_segment_count Open plus sealed segments.
# TYPE ironbus_segment_count gauge
ironbus_segment_count 4
# HELP ironbus_disk_free_bytes Free bytes.
# TYPE ironbus_disk_free_bytes gauge
ironbus_disk_free_bytes -1
# TYPE ironbus_connections_total counter
ironbus_connections_total{state=\"accepted\"} 10
ironbus_connections_total{state=\"closed\"} 3
# TYPE ironbus_group_consumer_lag gauge
ironbus_group_consumer_lag{group=\"\"} 7
ironbus_group_consumer_lag{group=\"orders\"} 2
";

    #[test]
    fn parses_bare_and_labeled_samples() {
        let m = Metrics::parse(SAMPLE);
        assert_eq!(m.u64_or_zero("ironbus_segment_count"), 4);
        assert_eq!(m.i64_or("ironbus_disk_free_bytes", 0), -1);
        assert_eq!(
            m.labeled_u64("ironbus_connections_total", "state", "accepted"),
            10
        );
        assert_eq!(
            m.labeled_u64("ironbus_connections_total", "state", "closed"),
            3
        );
        let groups = m.family("ironbus_group_consumer_lag");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].label("group"), Some(""));
        assert_eq!(groups[0].as_u64(), Some(7));
        assert_eq!(groups[1].label("group"), Some("orders"));
        assert_eq!(groups[1].as_u64(), Some(2));
    }

    #[test]
    fn an_absent_metric_reads_as_a_clean_zero_or_default() {
        let m = Metrics::parse(SAMPLE);
        assert_eq!(m.u64_or_zero("ironbus_not_present"), 0);
        assert_eq!(m.i64_or("ironbus_not_present", -1), -1);
        assert!(m.family("ironbus_not_present").is_empty());
        assert_eq!(m.labeled_u64("ironbus_not_present", "x", "y"), 0);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let m = Metrics::parse("\n# HELP x y\n\n# TYPE x gauge\n");
        assert!(m.scalar("x").is_none());
    }

    #[test]
    fn a_label_value_with_escapes_round_trips() {
        let m = Metrics::parse("ironbus_group_consumer_lag{group=\"a\\\"b\\\\c\"} 5\n");
        let f = m.family("ironbus_group_consumer_lag");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].label("group"), Some("a\"b\\c"));
        assert_eq!(f[0].as_u64(), Some(5));
    }

    #[test]
    fn a_float_value_does_not_parse_as_u64_but_round_trips_as_text() {
        let m = Metrics::parse("ironbus_retry_ratio 0.25\n");
        let s = m.scalar("ironbus_retry_ratio").unwrap();
        assert_eq!(s.as_u64(), None);
        assert_eq!(s.value, "0.25");
    }

    #[test]
    fn the_overflow_label_bucket_is_just_another_label_value() {
        let m = Metrics::parse("ironbus_stream_produced_total{stream=\"__overflow__\"} 99\n");
        let f = m.family("ironbus_stream_produced_total");
        assert_eq!(f[0].label("stream"), Some("__overflow__"));
        assert_eq!(f[0].as_u64(), Some(99));
    }

    #[test]
    fn a_histogram_count_line_parses_as_a_bare_sample() {
        // The report reads `ironbus_append_duration_seconds_count` as a throughput proxy; it must
        // parse like any other bare counter even though it is part of a histogram family.
        let m = Metrics::parse("ironbus_append_duration_seconds_count 1234\n");
        assert_eq!(m.u64_or_zero("ironbus_append_duration_seconds_count"), 1234);
    }
}
