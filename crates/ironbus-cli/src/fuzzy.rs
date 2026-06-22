// SPDX-License-Identifier: MIT OR Apache-2.0
//! Interactive fuzzy stream/group selection (V2-M6, #583): when a verb needs a stream or group and
//! none is given ON AN INTERACTIVE TERMINAL, offer a minimal fuzzy picker over the live names. It is
//! SCRIPTABLE-SAFE by construction: a non-TTY stdin/stdout, the global `--json` envelope, or an
//! explicit name on the command line all SKIP the picker, so a pipeline behaves exactly as before.
//!
//! NO heavyweight TUI dependency: the matcher is a tiny pure function (case-insensitive substring
//! AND subsequence filter), and the prompt is a plain `stdin().read_line` loop — so the picker pulls
//! ZERO new crates (MSRV-1.78-safe) and the cargo-deny allow-list is untouched. The interactive loop
//! is Unix-gated in tests (`#[cfg(all(test, unix))]`) because it reads a terminal; the matcher
//! itself is pure and tested on every platform.

use crate::CliError;
use std::io::{BufRead, IsTerminal, Write};

/// Returns whether the matcher considers `query` a fuzzy match for `candidate`. The rule (matching
/// the common `fzf`-style intuition, but minimal): case-insensitive, and EITHER a contiguous
/// substring OR an in-order subsequence of the candidate's characters. An EMPTY query matches every
/// candidate (the picker shows the full list before the operator types). The comparison is over
/// Unicode scalar values lower-cased with `to_lowercase`, so an ASCII group/stream name (the
/// common case) and a non-ASCII one both filter predictably.
#[must_use]
pub(crate) fn is_match(query: &str, candidate: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let q: Vec<char> = query.chars().flat_map(char::to_lowercase).collect();
    let c: Vec<char> = candidate.chars().flat_map(char::to_lowercase).collect();
    is_subsequence(&q, &c)
}

/// Whether `needle` is an in-order subsequence of `haystack` (every char of `needle` appears in
/// `haystack`, in order, not necessarily contiguous). A contiguous substring is a special case, so
/// this single test covers both the substring and the subsequence intuition.
fn is_subsequence(needle: &[char], haystack: &[char]) -> bool {
    let mut ni = 0;
    for &h in haystack {
        if ni == needle.len() {
            break;
        }
        if needle[ni] == h {
            ni += 1;
        }
    }
    ni == needle.len()
}

/// Filters `candidates` to those matching `query`, preserving the input order (the caller sorts the
/// list once, so the filtered view stays deterministic).
#[must_use]
pub(crate) fn filter<'a>(query: &str, candidates: &'a [String]) -> Vec<&'a str> {
    candidates
        .iter()
        .map(String::as_str)
        .filter(|c| is_match(query, c))
        .collect()
}

/// Whether the interactive picker is eligible: it requires BOTH stdin AND stdout to be a terminal
/// (so a redirected/piped stream never triggers a prompt), and the caller must NOT have requested
/// the `--json` envelope or passed an explicit name. The global `--json` is detected by the
/// dispatch (the captured-output path is non-interactive), so this guard plus the dispatch's stdout
/// capture means `--json` can never reach an interactive prompt.
#[must_use]
pub(crate) fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Runs the interactive picker over `candidates` (the `noun`, e.g. "group" or "stream", labels the
/// prompt), reading the operator's filter/selection from `input` and writing the prompt UI to
/// `prompt_out` (kept as parameters so the loop is unit-testable without a real terminal). Returns
/// the chosen name, or [`CliError::Usage`] if the operator gives up (EOF / empty list / an invalid
/// selection), so a verb that REQUIRES a name fails cleanly rather than proceeding with none.
///
/// The protocol per round: print the numbered filtered list, then read one line. A line that is a
/// number in range selects that entry; any other non-empty line becomes the new filter query; an
/// empty line with exactly one match selects it (a fast path). EOF aborts.
///
/// # Errors
/// [`CliError::Usage`] when the list is empty, the input ends without a selection, or the operator
/// cannot narrow to a choice.
pub(crate) fn pick(
    noun: &str,
    candidates: &[String],
    input: &mut impl BufRead,
    prompt_out: &mut impl Write,
) -> Result<String, CliError> {
    if candidates.is_empty() {
        return Err(CliError::Usage(format!(
            "no {noun}s available to choose from; pass one explicitly"
        )));
    }
    let mut query = String::new();
    loop {
        let matches = filter(&query, candidates);
        render_choices(noun, &query, &matches, prompt_out)?;
        let mut line = String::new();
        let n = input.read_line(&mut line)?;
        if n == 0 {
            // EOF: the operator aborted without choosing.
            return Err(CliError::Usage(format!("no {noun} selected (input ended)")));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            // An empty line selects the sole match, else re-prompts (shows the list again).
            if matches.len() == 1 {
                return Ok(matches[0].to_string());
            }
            continue;
        }
        // A numeric line selects by index (1-based) when in range.
        if let Ok(idx) = trimmed.parse::<usize>() {
            if idx >= 1 && idx <= matches.len() {
                return Ok(matches[idx - 1].to_string());
            }
            writeln!(prompt_out, "  (no such choice: {idx})")?;
            continue;
        }
        // Otherwise the line is a new filter query.
        query = trimmed.to_string();
    }
}

/// Renders one round of the picker UI: the current filter and the numbered, fuzzy-filtered choices.
/// The default group/stream (the empty name) renders as `(default)` so it is selectable and visible.
fn render_choices(
    noun: &str,
    query: &str,
    matches: &[&str],
    out: &mut impl Write,
) -> Result<(), CliError> {
    if query.is_empty() {
        writeln!(
            out,
            "select a {noun} (type to filter, or a number to choose):"
        )?;
    } else {
        writeln!(
            out,
            "select a {noun} matching \"{query}\" (type to refine, or a number to choose):"
        )?;
    }
    if matches.is_empty() {
        writeln!(out, "  (no matches; type a different filter)")?;
    } else {
        for (i, name) in matches.iter().enumerate() {
            let shown = if name.is_empty() { "(default)" } else { name };
            writeln!(out, "  {}: {shown}", i + 1)?;
        }
    }
    write!(out, "> ")?;
    out.flush().map_err(CliError::from)?;
    Ok(())
}

/// Resolves a name for `noun`: if `explicit` is given, returns it unchanged (the scriptable path);
/// otherwise, if the session is interactive, runs the picker over `candidates` reading the real
/// stdin and writing the prompt to stderr (so the picker UI never pollutes stdout, which a `--json`
/// or piped consumer reads). When NOT interactive and no explicit name is given, returns a usage
/// error naming the missing argument — exactly the pre-picker behavior for a scripted run.
///
/// # Errors
/// [`CliError::Usage`] when no name is given and the session is non-interactive, or the picker is
/// aborted.
pub(crate) fn resolve_or_pick(
    noun: &str,
    explicit: Option<&str>,
    candidates: &[String],
) -> Result<String, CliError> {
    if let Some(name) = explicit {
        return Ok(name.to_string());
    }
    if !is_interactive() {
        return Err(CliError::Usage(format!(
            "no {noun} given; pass one explicitly (a {noun} is required for a non-interactive run)"
        )));
    }
    let stdin = std::io::stdin();
    let mut locked = stdin.lock();
    let stderr = std::io::stderr();
    let mut prompt = stderr.lock();
    pick(noun, candidates, &mut locked, &mut prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_query_matches_everything() {
        assert!(is_match("", "anything"));
        assert!(is_match("", ""));
    }

    #[test]
    fn substring_matches_case_insensitively() {
        assert!(is_match("ord", "orders"));
        assert!(is_match("ORD", "orders"));
        assert!(is_match("ders", "orders"));
        assert!(!is_match("xyz", "orders"));
    }

    #[test]
    fn subsequence_matches_non_contiguous_in_order() {
        // o..d..s appear in order in "orders" though not contiguous.
        assert!(is_match("ods", "orders"));
        assert!(is_match("evt", "events"));
        // Out of order does NOT match.
        assert!(!is_match("sdo", "orders"));
    }

    #[test]
    fn filter_preserves_input_order() {
        let names = vec![
            "orders".to_string(),
            "audit".to_string(),
            "order-dlq".to_string(),
        ];
        let got = filter("ord", &names);
        assert_eq!(got, vec!["orders", "order-dlq"]);
    }

    #[test]
    fn pick_selects_by_number() {
        let names = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut input = std::io::Cursor::new(b"2\n".to_vec());
        let mut ui = Vec::new();
        let chosen = pick("group", &names, &mut input, &mut ui).unwrap();
        assert_eq!(chosen, "b");
    }

    #[test]
    fn pick_filters_then_selects() {
        let names = vec![
            "orders".to_string(),
            "audit".to_string(),
            "order-dlq".to_string(),
        ];
        // First line "ord" filters to [orders, order-dlq]; "1" then selects orders.
        let mut input = std::io::Cursor::new(b"ord\n1\n".to_vec());
        let mut ui = Vec::new();
        let chosen = pick("stream", &names, &mut input, &mut ui).unwrap();
        assert_eq!(chosen, "orders");
        // The UI prompt mentions the noun and the refine instruction.
        let ui = String::from_utf8(ui).unwrap();
        assert!(ui.contains("select a stream"), "{ui}");
    }

    #[test]
    fn pick_empty_line_selects_the_sole_match() {
        let names = vec!["orders".to_string(), "audit".to_string()];
        // "aud" filters to exactly [audit]; an empty line then selects the lone match.
        let mut input = std::io::Cursor::new(b"aud\n\n".to_vec());
        let mut ui = Vec::new();
        let chosen = pick("group", &names, &mut input, &mut ui).unwrap();
        assert_eq!(chosen, "audit");
    }

    #[test]
    fn pick_aborts_cleanly_on_eof() {
        let names = vec!["a".to_string()];
        let mut input = std::io::Cursor::new(Vec::new()); // immediate EOF
        let mut ui = Vec::new();
        let e = pick("group", &names, &mut input, &mut ui).unwrap_err();
        assert_eq!(e.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn pick_on_an_empty_candidate_list_is_a_usage_error() {
        let names: Vec<String> = Vec::new();
        let mut input = std::io::Cursor::new(b"1\n".to_vec());
        let mut ui = Vec::new();
        let e = pick("stream", &names, &mut input, &mut ui).unwrap_err();
        assert_eq!(e.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn pick_rejects_out_of_range_then_accepts_a_valid_choice() {
        let names = vec!["a".to_string(), "b".to_string()];
        // "9" is out of range (re-prompts), then "1" selects "a".
        let mut input = std::io::Cursor::new(b"9\n1\n".to_vec());
        let mut ui = Vec::new();
        let chosen = pick("group", &names, &mut input, &mut ui).unwrap();
        assert_eq!(chosen, "a");
        let ui = String::from_utf8(ui).unwrap();
        assert!(ui.contains("no such choice: 9"), "{ui}");
    }

    #[test]
    fn resolve_or_pick_returns_an_explicit_name_unchanged_without_prompting() {
        // The scriptable path: an explicit name is returned verbatim, no TTY needed.
        let names = vec!["a".to_string()];
        let got = resolve_or_pick("group", Some("explicit"), &names).unwrap();
        assert_eq!(got, "explicit");
    }

    #[test]
    fn the_default_empty_name_renders_as_default_in_the_ui() {
        let names = vec![String::new(), "orders".to_string()];
        let mut input = std::io::Cursor::new(b"1\n".to_vec());
        let mut ui = Vec::new();
        let chosen = pick("group", &names, &mut input, &mut ui).unwrap();
        assert_eq!(chosen, ""); // the default group is selectable
        let ui = String::from_utf8(ui).unwrap();
        assert!(ui.contains("(default)"), "{ui}");
    }
}
