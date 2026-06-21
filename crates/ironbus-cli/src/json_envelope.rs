// SPDX-License-Identifier: MIT OR Apache-2.0
//! The uniform `--json` envelope and the frozen exit-code contract (V2-M6, #579).
//!
//! Every command, run with the global `--json` flag, emits ONE machine-readable envelope on
//! stdout with a STABLE, FROZEN shape. A command's normal human output is captured and carried
//! verbatim inside the envelope, so a script keys off the envelope (never the wording) and EVERY
//! verb — present and future — honors `--json` uniformly without a per-verb rewrite. The frozen
//! envelope shape and the frozen exit-code table are pinned by snapshot/contract tests in
//! [`crate::tests`] so neither can silently change.
//!
//! # The frozen envelope (`ironbus.cli.v1`)
//! On SUCCESS:
//! ```json
//! {"schema":"ironbus.cli.v1","ok":true,"exit_code":0,"data":{"stdout":"<verbatim>","lines":[...]}}
//! ```
//! On FAILURE:
//! ```json
//! {"schema":"ironbus.cli.v1","ok":false,"exit_code":N,
//!  "error":{"kind":"usage|not_found|handled_corruption|corrupt|unreachable|internal",
//!           "message":"<text>"}}
//! ```
//! The keys are emitted in a FIXED order (`schema`, `ok`, `exit_code`, then `data` XOR `error`) so
//! the byte output is deterministic for a snapshot test. `data.stdout` is the command's full human
//! output (the bytes it would have written without `--json`); `data.lines` is the same output split
//! on `\n` with the trailing empty element dropped, for line-oriented consumers. The envelope NEVER
//! carries an `error` on success nor a `data` on failure (the two are mutually exclusive), so `ok`
//! alone disambiguates which key is present.
//!
//! # Back-compat
//! WITHOUT the global `--json` flag the dispatch and output are byte-identical to before this module
//! existed: the flag is detected and stripped only when present, and the per-command legacy `--json`
//! surfaces (e.g. `ironbus.cli.scrub.v1`) are untouched — they still render inside `data.stdout`
//! when both flags are passed, so no existing schema regresses.

use crate::CliError;
use std::fmt::Write as _;

/// The frozen schema tag for the uniform CLI envelope. Bumping this is a BREAKING contract change
/// and fails the envelope snapshot test (`json_envelope_success_shape_is_frozen`).
pub(crate) const ENVELOPE_SCHEMA: &str = "ironbus.cli.v1";

/// The stable string `kind` for each [`CliError`] variant, frozen alongside the exit-code table.
/// A consumer switches on this WITHOUT parsing the human message. The mapping is pinned by
/// `json_envelope_error_kinds_are_frozen`.
pub(crate) fn error_kind(err: &CliError) -> &'static str {
    match err {
        CliError::Usage(_) => "usage",
        CliError::NotFound(_) => "not_found",
        CliError::HandledCorruption(_) => "handled_corruption",
        CliError::Corrupt(_) => "corrupt",
        CliError::Unreachable(_) => "unreachable",
        CliError::Internal(_) => "internal",
    }
}

/// Escapes `value` for embedding in a JSON string literal: backslash, double-quote, and the
/// control characters the format requires. Cross-platform (unlike the `#[cfg(unix)]` `escape_json`
/// in `main.rs`), because the envelope is emitted on EVERY target the CLI builds for.
pub(crate) fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // A write into a String never fails; the Result is intentionally discarded.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Renders the frozen SUCCESS envelope, carrying the command's captured human output `stdout`
/// verbatim. The output is split into `lines` (on `\n`, trailing empty element dropped) for
/// line-oriented consumers. Keys are emitted in the fixed frozen order.
pub(crate) fn success_envelope(stdout: &str) -> String {
    let mut s = String::with_capacity(stdout.len() + 96);
    let _ = write!(
        s,
        "{{\"schema\":\"{ENVELOPE_SCHEMA}\",\"ok\":true,\"exit_code\":0,\"data\":{{\"stdout\":\"{}\",\"lines\":[",
        escape(stdout)
    );
    for (i, line) in split_lines(stdout).iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"{}\"", escape(line));
    }
    s.push_str("]}}");
    s
}

/// Renders the frozen FAILURE envelope from a [`CliError`]: the stable `kind`, the `exit_code` it
/// maps to, and the human `message`. Keys are emitted in the fixed frozen order.
pub(crate) fn error_envelope(err: &CliError) -> String {
    let mut s = String::with_capacity(128);
    let _ = write!(
        s,
        "{{\"schema\":\"{ENVELOPE_SCHEMA}\",\"ok\":false,\"exit_code\":{},\"error\":{{\"kind\":\"{}\",\"message\":\"{}\"}}}}",
        err.exit_code(),
        error_kind(err),
        escape(&err.to_string()),
    );
    s
}

/// Splits captured output into JSON `lines`: split on `\n`, dropping a single trailing empty
/// element so a normal `writeln!`-terminated output does not produce a spurious empty last line.
fn split_lines(stdout: &str) -> Vec<&str> {
    let mut lines: Vec<&str> = stdout.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines
}

/// Detects and STRIPS a leading-or-anywhere global `--json` from `args`, returning the
/// remaining args and whether `--json` was present. Only the global occurrence is consumed:
/// because every position is scanned, a per-command `--json` (e.g. `peek --json`) is ALSO
/// removed here so the inner command never double-handles it; the inner command therefore runs
/// in its plain (human) mode and its output is captured into the envelope. A `--` terminator is
/// respected: tokens after the first bare `--` are positional and never treated as the flag, so a
/// literal `--json` payload (e.g. `pub -- --json`) is preserved.
pub(crate) fn strip_global_json(args: &[String]) -> (Vec<String>, bool) {
    let mut json = false;
    let mut rest = Vec::with_capacity(args.len());
    let mut after_terminator = false;
    for a in args {
        if after_terminator {
            rest.push(a.clone());
            continue;
        }
        if a == "--" {
            after_terminator = true;
            rest.push(a.clone());
            continue;
        }
        if a == "--json" {
            json = true;
            continue;
        }
        rest.push(a.clone());
    }
    (rest, json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_handles_quotes_backslashes_and_controls() {
        assert_eq!(escape("a\"b\\c\n\t\r"), "a\\\"b\\\\c\\n\\t\\r");
        assert_eq!(escape("\u{0001}"), "\\u0001");
        assert_eq!(escape("plain"), "plain");
    }

    #[test]
    fn split_lines_drops_one_trailing_empty() {
        assert_eq!(split_lines("a\nb\n"), vec!["a", "b"]);
        assert_eq!(split_lines("a\nb"), vec!["a", "b"]);
        assert_eq!(split_lines(""), Vec::<&str>::new());
        assert_eq!(split_lines("a\n\n"), vec!["a", ""]);
    }

    #[test]
    fn strip_global_json_removes_the_flag_anywhere() {
        let args: Vec<String> = ["peek", "--json", "--data-dir", "/x"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (rest, json) = strip_global_json(&args);
        assert!(json);
        assert_eq!(rest, vec!["peek", "--data-dir", "/x"]);
    }

    #[test]
    fn strip_global_json_absent_is_unchanged() {
        let args: Vec<String> = ["peek", "--data-dir", "/x"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (rest, json) = strip_global_json(&args);
        assert!(!json);
        assert_eq!(rest, args);
    }

    #[test]
    fn strip_global_json_respects_the_terminator() {
        // A literal `--json` payload after `--` is preserved, never consumed as the flag.
        let args: Vec<String> = ["pub", "--", "--json"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let (rest, json) = strip_global_json(&args);
        assert!(!json);
        assert_eq!(rest, vec!["pub", "--", "--json"]);
    }
}
