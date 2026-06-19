// SPDX-License-Identifier: MIT OR Apache-2.0
//! Conformance + property tests for the subject grammar (#567, V2-M2).
//!
//! Two layers, mirroring the repo's conformance discipline:
//!
//! 1. A checked-in GOLDEN vector table (`CONFORMANCE`) pins the exact verdict — accept,
//!    or which typed [`SubjectError`] — for a representative input in every grammar
//!    class, for BOTH the literal (publish) and pattern (subscribe/bind) parsers, plus a
//!    second table pinning the match semantics. These vectors are the human-readable
//!    spec: a grammar change that shifts any verdict fails here loudly.
//!
//! 2. A PROPTEST suite proves the structural invariants over generated input: valid
//!    subjects round-trip and re-validate; the rune/depth/wildcard rejection classes hold
//!    for arbitrary tokens; and the `*`/`>` match semantics (including `>`-not-last
//!    rejection and the depth cap) hold for generated patterns and subjects.

use ironbus_core::subject::{Subject, SubjectError, SubjectPattern, MAX_SUBJECT_DEPTH};

/// The verdict a parser is expected to return for a vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Parses successfully with this token depth.
    Ok(usize),
    /// Rejected with this specific typed error.
    Err(SubjectError),
}

/// One golden conformance vector for the parsers: an input, its literal verdict, and its
/// pattern verdict. Keeping both verdicts side by side makes the literal-vs-pattern
/// divergence (wildcards) explicit and impossible to drift apart silently.
struct Vec3 {
    input: &'static str,
    literal: Verdict,
    pattern: Verdict,
}

/// The frozen parser conformance corpus. Each row is a deliberate grammar case.
const CONFORMANCE: &[Vec3] = &[
    // --- ordinary literals: identical verdict on both sides ---
    Vec3 {
        input: "a",
        literal: Verdict::Ok(1),
        pattern: Verdict::Ok(1),
    },
    Vec3 {
        input: "a.b.c",
        literal: Verdict::Ok(3),
        pattern: Verdict::Ok(3),
    },
    // UTF-8 is fine; only control/NUL runes are fail-closed.
    Vec3 {
        input: "café.metric",
        literal: Verdict::Ok(2),
        pattern: Verdict::Ok(2),
    },
    // --- empties ---
    Vec3 {
        input: "",
        literal: Verdict::Err(SubjectError::Empty),
        pattern: Verdict::Err(SubjectError::Empty),
    },
    Vec3 {
        input: ".a",
        literal: Verdict::Err(SubjectError::EmptyToken { index: 0 }),
        pattern: Verdict::Err(SubjectError::EmptyToken { index: 0 }),
    },
    Vec3 {
        input: "a.",
        literal: Verdict::Err(SubjectError::EmptyToken { index: 1 }),
        pattern: Verdict::Err(SubjectError::EmptyToken { index: 1 }),
    },
    Vec3 {
        input: "a..b",
        literal: Verdict::Err(SubjectError::EmptyToken { index: 1 }),
        pattern: Verdict::Err(SubjectError::EmptyToken { index: 1 }),
    },
    // --- wildcards: legal on the pattern side, rejected on the literal side ---
    Vec3 {
        input: "*",
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '*', index: 0 }),
        pattern: Verdict::Ok(1),
    },
    Vec3 {
        input: "a.*.c",
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '*', index: 1 }),
        pattern: Verdict::Ok(3),
    },
    Vec3 {
        input: ">",
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '>', index: 0 }),
        pattern: Verdict::Ok(1),
    },
    Vec3 {
        input: "a.>",
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '>', index: 1 }),
        pattern: Verdict::Ok(2),
    },
    // --- partial wildcards: illegal char on BOTH sides (the wildcards are structural) ---
    Vec3 {
        input: "a*",
        literal: Verdict::Err(SubjectError::IllegalChar { ch: '*', index: 0 }),
        pattern: Verdict::Err(SubjectError::IllegalChar { ch: '*', index: 0 }),
    },
    Vec3 {
        input: "a.b>c",
        literal: Verdict::Err(SubjectError::IllegalChar { ch: '>', index: 1 }),
        pattern: Verdict::Err(SubjectError::IllegalChar { ch: '>', index: 1 }),
    },
    // --- fail-closed runes: control + NUL rejected anywhere, on both sides ---
    Vec3 {
        input: "a\u{0}b",
        literal: Verdict::Err(SubjectError::ControlChar {
            ch: '\u{0}',
            index: 0,
        }),
        pattern: Verdict::Err(SubjectError::ControlChar {
            ch: '\u{0}',
            index: 0,
        }),
    },
    Vec3 {
        input: "a.b\tc",
        literal: Verdict::Err(SubjectError::ControlChar { ch: '\t', index: 1 }),
        pattern: Verdict::Err(SubjectError::ControlChar { ch: '\t', index: 1 }),
    },
    Vec3 {
        input: "x\u{7f}",
        literal: Verdict::Err(SubjectError::ControlChar {
            ch: '\u{7f}',
            index: 0,
        }),
        pattern: Verdict::Err(SubjectError::ControlChar {
            ch: '\u{7f}',
            index: 0,
        }),
    },
    // --- `>` placement: legal only as the final pattern token ---
    Vec3 {
        input: "a.>.b",
        // literal rejects the `>` as a disallowed wildcard before placement is judged.
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '>', index: 1 }),
        pattern: Verdict::Err(SubjectError::TailWildcardNotLast { index: 1 }),
    },
    Vec3 {
        input: ">.a",
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '>', index: 0 }),
        pattern: Verdict::Err(SubjectError::TailWildcardNotLast { index: 0 }),
    },
    Vec3 {
        input: "a.>.>",
        literal: Verdict::Err(SubjectError::WildcardNotAllowed { ch: '>', index: 1 }),
        pattern: Verdict::Err(SubjectError::TailWildcardNotLast { index: 1 }),
    },
];

#[test]
fn conformance_corpus_pins_every_verdict() {
    for v in CONFORMANCE {
        let lit = match Subject::parse_literal(v.input) {
            Ok(s) => Verdict::Ok(s.depth()),
            Err(e) => Verdict::Err(e),
        };
        assert_eq!(lit, v.literal, "literal verdict for {:?}", v.input);

        let pat = match SubjectPattern::parse(v.input) {
            Ok(p) => Verdict::Ok(p.depth()),
            Err(e) => Verdict::Err(e),
        };
        assert_eq!(pat, v.pattern, "pattern verdict for {:?}", v.input);
    }
}

/// One golden match vector: does `pattern` match `subject`?
struct MatchVec {
    pattern: &'static str,
    subject: &'static str,
    matches: bool,
}

/// The frozen match-semantics corpus, covering literal equality, single-token `*`, and
/// trailing `>` (one-or-more), alone and mixed.
const MATCHES: &[MatchVec] = &[
    MatchVec {
        pattern: "a.b.c",
        subject: "a.b.c",
        matches: true,
    },
    MatchVec {
        pattern: "a.b.c",
        subject: "a.b",
        matches: false,
    },
    MatchVec {
        pattern: "a.b.c",
        subject: "a.b.c.d",
        matches: false,
    },
    MatchVec {
        pattern: "a.*.c",
        subject: "a.b.c",
        matches: true,
    },
    MatchVec {
        pattern: "a.*.c",
        subject: "a.b.b.c",
        matches: false,
    },
    MatchVec {
        pattern: "a.*.c",
        subject: "a.c",
        matches: false,
    },
    MatchVec {
        pattern: "*",
        subject: "anything",
        matches: true,
    },
    MatchVec {
        pattern: "*",
        subject: "a.b",
        matches: false,
    },
    MatchVec {
        pattern: "a.>",
        subject: "a.b",
        matches: true,
    },
    MatchVec {
        pattern: "a.>",
        subject: "a.b.c.d",
        matches: true,
    },
    MatchVec {
        pattern: "a.>",
        subject: "a",
        matches: false,
    },
    MatchVec {
        pattern: "a.>",
        subject: "b.c",
        matches: false,
    },
    MatchVec {
        pattern: ">",
        subject: "a",
        matches: true,
    },
    MatchVec {
        pattern: ">",
        subject: "a.b.c",
        matches: true,
    },
    MatchVec {
        pattern: "a.*.>",
        subject: "a.b.c",
        matches: true,
    },
    MatchVec {
        pattern: "a.*.>",
        subject: "a.b.c.d.e",
        matches: true,
    },
    MatchVec {
        pattern: "a.*.>",
        subject: "a.b",
        matches: false,
    },
];

#[test]
fn conformance_corpus_pins_match_semantics() {
    for m in MATCHES {
        let p = SubjectPattern::parse(m.pattern).expect("valid pattern vector");
        let s = Subject::parse_literal(m.subject).expect("valid subject vector");
        assert_eq!(
            p.matches(&s),
            m.matches,
            "{:?} matches {:?}",
            m.pattern,
            m.subject
        );
    }
}

#[test]
fn error_display_is_human_readable() {
    // Each variant renders a distinct, non-empty message (it is surfaced to operators).
    let errs = [
        SubjectError::Empty,
        SubjectError::EmptyToken { index: 1 },
        SubjectError::IllegalChar { ch: '*', index: 0 },
        SubjectError::ControlChar {
            ch: '\u{0}',
            index: 0,
        },
        SubjectError::WildcardNotAllowed { ch: '>', index: 2 },
        SubjectError::TailWildcardNotLast { index: 1 },
        SubjectError::TooDeep {
            depth: MAX_SUBJECT_DEPTH + 1,
        },
    ];
    for e in errs {
        assert!(!e.to_string().is_empty());
    }
}

use proptest::prelude::*;

/// A regex strategy for a single legal LITERAL token: 1..=8 chars drawn from the
/// non-wildcard, non-separator, non-control alphabet. A `&str` regex is itself a
/// `Strategy<Value = String>` in proptest, and the character class keeps every
/// generated token provably inside the legal set (no `.`/`*`/`>`/control).
const LEGAL_TOKEN: &str = "[a-zA-Z0-9_-]{1,8}";

proptest! {
    /// A subject built only from legal tokens, within the depth cap, always parses as
    /// both a literal and a pattern, round-trips its text, and reports the right depth.
    #[test]
    fn valid_subjects_round_trip(
        tokens in proptest::collection::vec(LEGAL_TOKEN, 1..=MAX_SUBJECT_DEPTH),
    ) {
        let s = tokens.join(".");
        let subj = Subject::parse_literal(&s).expect("legal subject parses");
        prop_assert_eq!(subj.as_str(), s.as_str());
        prop_assert_eq!(subj.depth(), tokens.len());
        let got: Vec<&str> = subj.tokens().collect();
        prop_assert_eq!(got, tokens.iter().map(String::as_str).collect::<Vec<_>>());

        // A wildcard-free pattern is also valid and matches exactly its own subject.
        let pat = SubjectPattern::parse(&s).expect("legal pattern parses");
        prop_assert!(!pat.has_tail_wildcard());
        prop_assert!(pat.matches(&subj));
    }

    /// Any subject deeper than the cap is rejected as `TooDeep` by both parsers.
    #[test]
    fn over_depth_is_rejected(extra in 1usize..16) {
        let tokens = vec!["a"; MAX_SUBJECT_DEPTH + extra];
        let s = tokens.join(".");
        prop_assert_eq!(
            Subject::parse_literal(&s),
            Err(SubjectError::TooDeep { depth: MAX_SUBJECT_DEPTH + 1 })
        );
        prop_assert_eq!(
            SubjectPattern::parse(&s),
            Err(SubjectError::TooDeep { depth: MAX_SUBJECT_DEPTH + 1 })
        );
    }

    /// A literal subject containing any wildcard token is always rejected (never a panic,
    /// never a silent accept).
    #[test]
    fn literal_never_accepts_a_wildcard(
        prefix in proptest::collection::vec(LEGAL_TOKEN, 0..4),
        wc in prop_oneof![Just("*"), Just(">")],
        suffix in proptest::collection::vec(LEGAL_TOKEN, 0..4),
    ) {
        let mut tokens = prefix.clone();
        tokens.push(wc.to_string());
        tokens.extend(suffix.iter().cloned());
        let s = tokens.join(".");
        // Within the cap, so the only reason to reject is the wildcard.
        prop_assume!(tokens.len() <= MAX_SUBJECT_DEPTH);
        let res = Subject::parse_literal(&s);
        prop_assert!(res.is_err(), "literal accepted a wildcard: {:?}", s);
    }

    /// A control byte anywhere makes both parsers reject with `ControlChar`.
    #[test]
    fn control_runes_are_fail_closed(
        before in proptest::collection::vec(LEGAL_TOKEN, 0..3),
        // The whole ASCII control range `0x00..=0x1F`; none of these is the separator
        // `.` (0x2E), so an embedded control rune is the only reason the parse fails.
        ctrl in 0u32..0x20,
        after in proptest::collection::vec(LEGAL_TOKEN, 0..3),
    ) {
        let ctrl_ch = char::from_u32(ctrl).expect("control scalar");
        let mut tokens = before.clone();
        tokens.push(format!("z{ctrl_ch}z"));
        tokens.extend(after.iter().cloned());
        prop_assume!(tokens.len() <= MAX_SUBJECT_DEPTH);
        let s = tokens.join(".");
        let literal_is_control =
            matches!(Subject::parse_literal(&s), Err(SubjectError::ControlChar { .. }));
        let pattern_is_control =
            matches!(SubjectPattern::parse(&s), Err(SubjectError::ControlChar { .. }));
        prop_assert!(literal_is_control, "literal admitted a control rune: {:?}", s);
        prop_assert!(pattern_is_control, "pattern admitted a control rune: {:?}", s);
    }

    /// `>` as a non-final pattern token is always `TailWildcardNotLast`.
    #[test]
    fn non_final_tail_wildcard_rejected(
        prefix in proptest::collection::vec(LEGAL_TOKEN, 0..4),
        suffix in proptest::collection::vec(LEGAL_TOKEN, 1..4),
    ) {
        let mut tokens = prefix.clone();
        let gt_index = tokens.len();
        tokens.push(">".to_string());
        tokens.extend(suffix.iter().cloned()); // at least one token AFTER `>`
        prop_assume!(tokens.len() <= MAX_SUBJECT_DEPTH);
        let s = tokens.join(".");
        prop_assert_eq!(
            SubjectPattern::parse(&s),
            Err(SubjectError::TailWildcardNotLast { index: gt_index })
        );
    }

    /// `a.>` matches a subject iff it shares the literal prefix and has at least one more
    /// token; `>` alone matches every non-empty subject.
    #[test]
    fn tail_wildcard_match_semantics(
        prefix in proptest::collection::vec(LEGAL_TOKEN, 1..4),
        tail in proptest::collection::vec(LEGAL_TOKEN, 0..4),
    ) {
        prop_assume!(prefix.len() < MAX_SUBJECT_DEPTH);
        let pattern_str = format!("{}.>", prefix.join("."));
        let pat = SubjectPattern::parse(&pattern_str).expect("valid pattern");

        let mut subject_tokens = prefix.clone();
        subject_tokens.extend(tail.iter().cloned());
        prop_assume!(subject_tokens.len() <= MAX_SUBJECT_DEPTH);
        let subject_str = subject_tokens.join(".");
        let subj = Subject::parse_literal(&subject_str).expect("valid subject");

        // `>` requires at least one trailing token beyond the prefix.
        let expected = !tail.is_empty();
        prop_assert_eq!(
            pat.matches(&subj),
            expected,
            "{:?} vs {:?}",
            pattern_str,
            subject_str
        );
    }

    /// `*` matches exactly one token: a single-`*` pattern matches a single-token subject
    /// and rejects any multi-token subject.
    #[test]
    fn single_wildcard_matches_exactly_one(
        tokens in proptest::collection::vec(LEGAL_TOKEN, 1..=MAX_SUBJECT_DEPTH),
    ) {
        let star = SubjectPattern::parse("*").expect("valid");
        let s = tokens.join(".");
        let subj = Subject::parse_literal(&s).expect("valid");
        prop_assert_eq!(star.matches(&subj), tokens.len() == 1);
    }
}
