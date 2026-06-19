// SPDX-License-Identifier: MIT OR Apache-2.0
//! The subject grammar: a bounded, fail-closed parser and matcher (#567, V2-M2).
//!
//! A *subject* is the routing key a record is published on; a *pattern* is what a
//! subscription or stream binding matches against. The grammar is intentionally close to
//! the NATS mental model so it is familiar, but it is **fail-closed and bounded** where
//! NATS is permissive:
//!
//! ```text
//! subject := token ('.' token)*
//! token   := <one or more bytes, none of which is '.', '*', or '>'>
//! ```
//!
//! Wildcards live ONLY on the pattern (subscribe / bind) side, never in a published
//! subject:
//!
//! * `*` matches exactly one whole token.
//! * `>` matches one-or-more trailing tokens and is legal ONLY as the final token.
//!
//! # Why bounded and fail-closed (the first-principles reason)
//!
//! An unbounded subject space is an unbounded routing-state and metric-cardinality
//! hazard: the routing trie (#568) gains a node per token per depth, and per-subject
//! metrics fan out without limit. So we cap depth ([`MAX_SUBJECT_DEPTH`]) and validate
//! every rune **at ingest**, rejecting a bad subject before it can enter the trie or a
//! durable stream. This is the opposite of NATS's posture: NATS's public
//! `IsValidSubject` validates with `checkRunes=false`, so a subject carrying invalid
//! UTF-8 or a NUL byte passes; and the `>`-must-be-last rule is spread across three
//! separate code paths. IronBus has ONE parser, checks runes by default, and enforces a
//! single hard depth cap.
//!
//! # Allocation
//!
//! Parsing is borrowing and zero-allocation: [`Subject`] and [`SubjectPattern`] hold a
//! `&str` into the caller's input and validate by walking it once. Iterating tokens
//! ([`Subject::tokens`] / [`SubjectPattern::tokens`]) yields borrowed `&str` slices, so
//! the routing trie can consume a subject without ever building a `Vec`. The validation
//! walk itself uses no heap and only `MAX_SUBJECT_DEPTH` worth of bounded state.
//!
//! # IO-free
//!
//! This module is pure compute: it touches no filesystem, network, clock, or allocator
//! beyond what `&str`/`char` inspection needs. It stays inside `ironbus-core`'s IO-free
//! invariant (enforced by `tools/io-free-check`).

use core::fmt;

/// The maximum number of tokens (the dotted depth) any subject or pattern may have.
///
/// NATS has **no** such constant — its subject depth is bounded only by the maximum
/// message/protocol-line size — so a single subscription can mint an arbitrarily deep
/// path in the routing tree. IronBus caps depth at the source for two reasons:
///
/// 1. **Bounded routing state.** Each token becomes (at most) one level of the routing
///    trie (#568); a hard cap makes the worst-case trie depth — and therefore the
///    per-lookup work and the per-subject metric cardinality — provably bounded.
/// 2. **A bounded, zero-alloc fast path.** 32 mirrors the small on-stack token buffer
///    NATS itself uses for the common case (`tsa[32]` in its splitter); choosing the
///    same number lets a consumer keep a fixed-size on-stack scratch array for the
///    overwhelmingly common shallow subject without a heap allocation, while anything
///    deeper is a typed rejection rather than an unbounded fallback.
///
/// 32 levels is far beyond any real routing scheme (`tenant.site.device.metric.field`
/// is five) yet small enough to bound state. It is part of the validated grammar: a
/// subject with more tokens is [`SubjectError::TooDeep`], not silently truncated.
pub const MAX_SUBJECT_DEPTH: usize = 32;

/// The token separator.
const SEP: char = '.';
/// The single-token wildcard (pattern side only).
const WILDCARD_ONE: char = '*';
/// The trailing multi-token wildcard (pattern side only, final token only).
const WILDCARD_TAIL: char = '>';

/// Why a subject or pattern was rejected.
///
/// Every rejection is a distinct, typed variant so a caller (and a test) can assert the
/// *reason* a string was refused, never just that it was. The grammar is fail-closed:
/// anything not provably valid maps to one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubjectError {
    /// The whole subject was empty (`""`).
    Empty,
    /// A token was empty: a leading, trailing, or doubled separator (`""`, `.a`, `a.`,
    /// `a..b`). `index` is the 0-based token position of the empty token.
    EmptyToken {
        /// The 0-based position of the empty token.
        index: usize,
    },
    /// A token contained a character that is not allowed inside a token. The wildcards
    /// `*` and `>` are *structural* tokens, never characters *within* a token, so a
    /// token like `a*` or `a>b` is illegal in both subjects and patterns. `ch` is the
    /// offending character; `index` is the 0-based token position.
    IllegalChar {
        /// The offending character.
        ch: char,
        /// The 0-based position of the token that held it.
        index: usize,
    },
    /// A control or NUL character appeared anywhere in the input. Fail-closed rune
    /// posture: ASCII control bytes (`0x00..=0x1F` and `0x7F`) are rejected at ingest
    /// rather than silently admitted, the way NATS's default `checkRunes=false` admits
    /// them. `ch` is the offending character; `index` is the 0-based token position.
    ControlChar {
        /// The offending control character.
        ch: char,
        /// The 0-based position of the token that held it.
        index: usize,
    },
    /// A wildcard appeared where it is not allowed. For a *literal* subject
    /// ([`Subject::parse_literal`]) ANY `*` or `>` is illegal. `ch` is the wildcard;
    /// `index` is the 0-based token position.
    WildcardNotAllowed {
        /// The wildcard character (`*` or `>`).
        ch: char,
        /// The 0-based position of the offending token.
        index: usize,
    },
    /// The multi-token wildcard `>` appeared as a token that is not the final token.
    /// `>` is legal only as the last token of a pattern. `index` is the 0-based position
    /// of the misplaced `>`.
    TailWildcardNotLast {
        /// The 0-based position of the misplaced `>`.
        index: usize,
    },
    /// The subject or pattern exceeded [`MAX_SUBJECT_DEPTH`] tokens. `depth` is the token
    /// count that tripped the cap (it may be reported as `MAX_SUBJECT_DEPTH + 1`, the
    /// first count over the limit, since parsing stops as soon as the cap is exceeded).
    TooDeep {
        /// The token count that exceeded the cap.
        depth: usize,
    },
}

impl fmt::Display for SubjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubjectError::Empty => write!(f, "subject is empty"),
            SubjectError::EmptyToken { index } => {
                write!(
                    f,
                    "subject token {index} is empty (leading, trailing, or doubled '.')"
                )
            }
            SubjectError::IllegalChar { ch, index } => {
                write!(f, "subject token {index} contains illegal character {ch:?}")
            }
            SubjectError::ControlChar { ch, index } => write!(
                f,
                "subject token {index} contains a control character {ch:?}"
            ),
            SubjectError::WildcardNotAllowed { ch, index } => write!(
                f,
                "wildcard {ch:?} is not allowed in a literal subject (token {index})"
            ),
            SubjectError::TailWildcardNotLast { index } => write!(
                f,
                "tail wildcard '>' must be the final token (it was token {index})"
            ),
            SubjectError::TooDeep { depth } => write!(
                f,
                "subject has {depth} tokens, exceeding the maximum depth of {MAX_SUBJECT_DEPTH}"
            ),
        }
    }
}

impl std::error::Error for SubjectError {}

/// Returns `true` if `ch` is an ASCII control character (`0x00..=0x1F` or `0x7F`).
///
/// These are rejected anywhere in a subject. We deliberately scope the rune check to
/// ASCII control + NUL (the bytes that break logging, shells, and on-disk names) rather
/// than a broader Unicode category, so a legitimately UTF-8 subject (`café.metric`) is
/// accepted while the genuinely dangerous bytes NATS's default admits are not.
#[inline]
const fn is_control(ch: char) -> bool {
    (ch as u32) < 0x20 || ch as u32 == 0x7F
}

/// Classifies one token in isolation, given its 0-based `index` and whether wildcards are
/// permitted. Returns the token's wildcard role on success.
///
/// This is the single place the per-token rules live, shared by the literal and pattern
/// parsers so the two can never drift. It walks the token's characters once and is
/// allocation-free.
fn classify_token(
    token: &str,
    index: usize,
    allow_wildcards: bool,
) -> Result<TokenKind, SubjectError> {
    if token.is_empty() {
        return Err(SubjectError::EmptyToken { index });
    }

    // A LONE `*` or `>` is the wildcard token; anything else containing `*`/`>` (e.g.
    // `a*`, `>x`) is an illegal-char token, because the wildcards are structural tokens,
    // never partial characters. `*`/`>` are single-byte ASCII, so a one-byte token whose
    // sole byte is the wildcard is the only wildcard form (no allocation needed).
    if token.len() == 1 {
        let only = token.as_bytes()[0];
        if only == WILDCARD_ONE as u8 {
            return wildcard_or_reject(
                TokenKind::SingleWildcard,
                WILDCARD_ONE,
                index,
                allow_wildcards,
            );
        }
        if only == WILDCARD_TAIL as u8 {
            return wildcard_or_reject(
                TokenKind::TailWildcard,
                WILDCARD_TAIL,
                index,
                allow_wildcards,
            );
        }
    }

    // A non-wildcard (literal) token: every character must be legal. A `*`/`>` here is an
    // illegal character (a partial wildcard), and a control/NUL is a control rejection.
    for ch in token.chars() {
        if is_control(ch) {
            return Err(SubjectError::ControlChar { ch, index });
        }
        if ch == SEP {
            // The splitter never hands a separator inside a token; this is a guard so the
            // invariant is local and total.
            return Err(SubjectError::IllegalChar { ch, index });
        }
        if ch == WILDCARD_ONE || ch == WILDCARD_TAIL {
            return Err(SubjectError::IllegalChar { ch, index });
        }
    }
    Ok(TokenKind::Literal)
}

/// Helper: a wildcard token is the given `kind` when wildcards are allowed, else a typed
/// `WildcardNotAllowed` rejection. Centralizing this keeps the literal/pattern split in
/// exactly one place.
#[inline]
fn wildcard_or_reject(
    kind: TokenKind,
    ch: char,
    index: usize,
    allow_wildcards: bool,
) -> Result<TokenKind, SubjectError> {
    if allow_wildcards {
        Ok(kind)
    } else {
        Err(SubjectError::WildcardNotAllowed { ch, index })
    }
}

/// The role a single token plays in a pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenKind {
    /// An ordinary literal token (matches itself).
    Literal,
    /// The `*` single-token wildcard.
    SingleWildcard,
    /// The `>` trailing multi-token wildcard.
    TailWildcard,
}

/// Validates `input` as a sequence of tokens, applying the per-token rules and the
/// structural rules (`>` last only, depth cap). Returns the validated token count.
///
/// `allow_wildcards` distinguishes a literal subject (false) from a pattern (true). This
/// is the shared core both public parsers call; it allocates nothing and walks the input
/// exactly once.
fn validate(input: &str, allow_wildcards: bool) -> Result<usize, SubjectError> {
    if input.is_empty() {
        return Err(SubjectError::Empty);
    }

    let mut count = 0usize;
    let mut tail_seen_at: Option<usize> = None;

    for token in input.split(SEP) {
        // A `>` is legal only as the FINAL token, so reaching another iteration after one
        // was seen means that earlier `>` was not last. Checking at the top of the loop
        // (before classifying this token) catches every follower uniformly — a literal, a
        // `*`, OR a second `>` — and always reports the FIRST `>`'s position.
        if let Some(at) = tail_seen_at {
            return Err(SubjectError::TailWildcardNotLast { index: at });
        }
        // Enforce the cap as we go so a pathological input cannot make us walk an
        // unbounded number of tokens before rejecting.
        if count == MAX_SUBJECT_DEPTH {
            return Err(SubjectError::TooDeep { depth: count + 1 });
        }
        let kind = classify_token(token, count, allow_wildcards)?;
        if kind == TokenKind::TailWildcard {
            tail_seen_at = Some(count);
        }
        count += 1;
    }

    // A `>` as the final token never enters a further iteration, so the loop's top-of-loop
    // guard never fires for it: reaching here means any `>` was genuinely last.
    Ok(count)
}

/// A validated literal subject: a publish-side routing key with NO wildcards.
///
/// Construct one with [`Subject::parse_literal`]; the borrow is into the caller's input,
/// so a `Subject` is a zero-allocation, validated view. It guarantees: non-empty, no
/// empty tokens, no control/NUL runes, no `*`/`>` anywhere, and at most
/// [`MAX_SUBJECT_DEPTH`] tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Subject<'a> {
    raw: &'a str,
    depth: usize,
}

impl<'a> Subject<'a> {
    /// Parses and validates `input` as a literal subject (the publish side).
    ///
    /// Rejects ANY wildcard (`*` or `>`) along with every other grammar violation.
    ///
    /// # Errors
    ///
    /// Returns the specific [`SubjectError`] for the first violation found.
    pub fn parse_literal(input: &'a str) -> Result<Subject<'a>, SubjectError> {
        let depth = validate(input, false)?;
        Ok(Subject { raw: input, depth })
    }

    /// The subject's text, exactly as parsed (parsing is non-normalizing, so this
    /// round-trips: `Subject::parse_literal(s).unwrap().as_str() == s`).
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.raw
    }

    /// The number of tokens (the dotted depth), in `1..=MAX_SUBJECT_DEPTH`.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// An allocation-free iterator over the subject's tokens, in order.
    ///
    /// The routing trie consumes a subject through this iterator, so it never needs to
    /// build a `Vec` of tokens.
    #[must_use]
    pub fn tokens(&self) -> Tokens<'a> {
        Tokens {
            inner: self.raw.split(SEP),
        }
    }
}

impl fmt::Display for Subject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.raw)
    }
}

/// A validated subscription/bind pattern: a routing key that MAY carry wildcards.
///
/// Construct one with [`SubjectPattern::parse`]. It guarantees the same rune and depth
/// rules as [`Subject`], plus: `*` is allowed as a whole token, `>` is allowed ONLY as
/// the final token, and a partial wildcard (`a*`, `>b`) is still an illegal-char
/// rejection. A pattern with no wildcards is also valid — it matches exactly one literal
/// subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubjectPattern<'a> {
    raw: &'a str,
    depth: usize,
}

impl<'a> SubjectPattern<'a> {
    /// Parses and validates `input` as a pattern (the subscribe / bind side).
    ///
    /// Allows `*` (one token) and a final `>` (one-or-more trailing tokens); rejects a
    /// non-final or duplicate `>`, a partial wildcard, and every other grammar violation.
    ///
    /// # Errors
    ///
    /// Returns the specific [`SubjectError`] for the first violation found.
    pub fn parse(input: &'a str) -> Result<SubjectPattern<'a>, SubjectError> {
        let depth = validate(input, true)?;
        Ok(SubjectPattern { raw: input, depth })
    }

    /// The pattern's text, exactly as parsed (round-trips like [`Subject::as_str`]).
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.raw
    }

    /// The number of tokens (the dotted depth), in `1..=MAX_SUBJECT_DEPTH`.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// `true` if the final token is the `>` trailing wildcard.
    #[must_use]
    pub fn has_tail_wildcard(&self) -> bool {
        self.raw.rsplit(SEP).next() == Some(">")
    }

    /// An allocation-free iterator over the pattern's tokens, in order.
    #[must_use]
    pub fn tokens(&self) -> Tokens<'a> {
        Tokens {
            inner: self.raw.split(SEP),
        }
    }

    /// Returns `true` if this pattern matches the literal `subject`.
    ///
    /// Matching is token-aligned, exactly like the NATS mental model:
    ///
    /// * a literal token matches the identical subject token,
    /// * `*` matches any one subject token,
    /// * a final `>` matches one-or-more remaining subject tokens (so `a.>` matches
    ///   `a.b` and `a.b.c` but NOT `a` — `>` requires at least one trailing token),
    /// * with no `>`, the token counts must be equal.
    ///
    /// This is the primitive the routing trie (#568) and the subject→stream binding
    /// (#585) build on; keeping it here, beside the grammar it depends on, means the
    /// match semantics and the grammar can never disagree.
    #[must_use]
    pub fn matches(&self, subject: &Subject<'_>) -> bool {
        let mut pat = self.tokens();
        let mut sub = subject.tokens();

        loop {
            match pat.next() {
                Some(">") => {
                    // `>` is the final pattern token (the grammar guarantees it). It
                    // matches one-or-more remaining subject tokens, so there must be at
                    // least one subject token left.
                    return sub.next().is_some();
                }
                Some(p) => match sub.next() {
                    // `*` matches any single subject token; a literal must be identical.
                    Some(_) if p == "*" => {}
                    Some(s) if p == s => {}
                    _ => return false,
                },
                None => {
                    // Pattern exhausted: it matches iff the subject is also exhausted
                    // (equal token counts, since there was no trailing `>`).
                    return sub.next().is_none();
                }
            }
        }
    }
}

impl fmt::Display for SubjectPattern<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.raw)
    }
}

/// An allocation-free iterator over a subject's or pattern's tokens, in order.
///
/// Created by [`Subject::tokens`] / [`SubjectPattern::tokens`]. It borrows the validated
/// string, so every yielded token is a non-empty, rule-checked `&str`.
#[derive(Clone, Debug)]
pub struct Tokens<'a> {
    inner: core::str::Split<'a, char>,
}

impl<'a> Iterator for Tokens<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        self.inner.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- valid literal subjects ----

    #[test]
    fn literal_accepts_simple_subjects() {
        for s in [
            "a",
            "a.b",
            "a.b.c",
            "tenant.site.device.metric",
            "café.metric",
        ] {
            let subj = Subject::parse_literal(s).unwrap_or_else(|e| panic!("{s:?} rejected: {e}"));
            assert_eq!(subj.as_str(), s, "non-normalizing round-trip");
        }
    }

    #[test]
    fn literal_depth_counts_tokens() {
        assert_eq!(Subject::parse_literal("a").unwrap().depth(), 1);
        assert_eq!(Subject::parse_literal("a.b.c").unwrap().depth(), 3);
    }

    #[test]
    fn tokens_iterate_in_order_without_alloc() {
        let subj = Subject::parse_literal("a.b.c").unwrap();
        let got: Vec<&str> = subj.tokens().collect();
        assert_eq!(got, ["a", "b", "c"]);
    }

    // ---- every literal rejection class ----

    #[test]
    fn literal_rejects_empty() {
        assert_eq!(Subject::parse_literal(""), Err(SubjectError::Empty));
    }

    #[test]
    fn literal_rejects_empty_tokens() {
        assert_eq!(
            Subject::parse_literal(".a"),
            Err(SubjectError::EmptyToken { index: 0 })
        );
        assert_eq!(
            Subject::parse_literal("a."),
            Err(SubjectError::EmptyToken { index: 1 })
        );
        assert_eq!(
            Subject::parse_literal("a..b"),
            Err(SubjectError::EmptyToken { index: 1 })
        );
    }

    #[test]
    fn literal_rejects_any_wildcard() {
        assert_eq!(
            Subject::parse_literal("a.*.b"),
            Err(SubjectError::WildcardNotAllowed { ch: '*', index: 1 })
        );
        assert_eq!(
            Subject::parse_literal("a.>"),
            Err(SubjectError::WildcardNotAllowed { ch: '>', index: 1 })
        );
        assert_eq!(
            Subject::parse_literal("*"),
            Err(SubjectError::WildcardNotAllowed { ch: '*', index: 0 })
        );
    }

    #[test]
    fn literal_rejects_partial_wildcard_as_illegal_char() {
        // `a*` is NOT a wildcard token; the `*` is an illegal character inside a token.
        assert_eq!(
            Subject::parse_literal("a*"),
            Err(SubjectError::IllegalChar { ch: '*', index: 0 })
        );
        assert_eq!(
            Subject::parse_literal("a.b>c"),
            Err(SubjectError::IllegalChar { ch: '>', index: 1 })
        );
    }

    #[test]
    fn literal_rejects_control_and_nul() {
        assert_eq!(
            Subject::parse_literal("a\u{0}b"),
            Err(SubjectError::ControlChar {
                ch: '\u{0}',
                index: 0
            })
        );
        assert_eq!(
            Subject::parse_literal("a.b\tc"),
            Err(SubjectError::ControlChar { ch: '\t', index: 1 })
        );
        assert_eq!(
            Subject::parse_literal("a\u{7f}"),
            Err(SubjectError::ControlChar {
                ch: '\u{7f}',
                index: 0
            })
        );
    }

    // ---- pattern parsing ----

    #[test]
    fn pattern_accepts_wildcards() {
        for p in ["a.*.c", "*", "a.>", ">", "*.>", "a.*.b.>"] {
            SubjectPattern::parse(p).unwrap_or_else(|e| panic!("{p:?} rejected: {e}"));
        }
    }

    #[test]
    fn pattern_accepts_a_literal_with_no_wildcards() {
        let p = SubjectPattern::parse("a.b.c").unwrap();
        assert!(!p.has_tail_wildcard());
        assert_eq!(p.depth(), 3);
    }

    #[test]
    fn pattern_has_tail_wildcard_detects_final_gt() {
        assert!(SubjectPattern::parse("a.>").unwrap().has_tail_wildcard());
        assert!(SubjectPattern::parse(">").unwrap().has_tail_wildcard());
        assert!(!SubjectPattern::parse("a.*").unwrap().has_tail_wildcard());
    }

    #[test]
    fn pattern_rejects_non_final_tail_wildcard() {
        assert_eq!(
            SubjectPattern::parse("a.>.b"),
            Err(SubjectError::TailWildcardNotLast { index: 1 })
        );
        assert_eq!(
            SubjectPattern::parse(">.a"),
            Err(SubjectError::TailWildcardNotLast { index: 0 })
        );
    }

    #[test]
    fn pattern_rejects_multiple_tail_wildcards() {
        // Two `>`: the first is non-final, so it is reported at its position.
        assert_eq!(
            SubjectPattern::parse("a.>.>"),
            Err(SubjectError::TailWildcardNotLast { index: 1 })
        );
        assert_eq!(
            SubjectPattern::parse(">.>"),
            Err(SubjectError::TailWildcardNotLast { index: 0 })
        );
    }

    #[test]
    fn pattern_rejects_partial_and_control_runes() {
        assert_eq!(
            SubjectPattern::parse("a.b*"),
            Err(SubjectError::IllegalChar { ch: '*', index: 1 })
        );
        assert_eq!(
            SubjectPattern::parse("a.\u{0}"),
            Err(SubjectError::ControlChar {
                ch: '\u{0}',
                index: 1
            })
        );
        assert_eq!(SubjectPattern::parse(""), Err(SubjectError::Empty));
        assert_eq!(
            SubjectPattern::parse("a..b"),
            Err(SubjectError::EmptyToken { index: 1 })
        );
    }

    // ---- depth cap ----

    #[test]
    fn depth_cap_accepts_exactly_max_and_rejects_over() {
        let at_cap = vec!["a"; MAX_SUBJECT_DEPTH].join(".");
        assert_eq!(
            Subject::parse_literal(&at_cap).unwrap().depth(),
            MAX_SUBJECT_DEPTH
        );
        SubjectPattern::parse(&at_cap).unwrap();

        let over = vec!["a"; MAX_SUBJECT_DEPTH + 1].join(".");
        assert_eq!(
            Subject::parse_literal(&over),
            Err(SubjectError::TooDeep {
                depth: MAX_SUBJECT_DEPTH + 1
            })
        );
        assert_eq!(
            SubjectPattern::parse(&over),
            Err(SubjectError::TooDeep {
                depth: MAX_SUBJECT_DEPTH + 1
            })
        );
    }

    // ---- match semantics ----

    fn matches(pattern: &str, subject: &str) -> bool {
        let p = SubjectPattern::parse(pattern).expect("valid pattern");
        let s = Subject::parse_literal(subject).expect("valid subject");
        p.matches(&s)
    }

    #[test]
    fn literal_pattern_matches_only_itself() {
        assert!(matches("a.b.c", "a.b.c"));
        assert!(!matches("a.b.c", "a.b"));
        assert!(!matches("a.b.c", "a.b.c.d"));
        assert!(!matches("a.b.c", "a.b.d"));
    }

    #[test]
    fn single_wildcard_matches_exactly_one_token() {
        assert!(matches("a.*.c", "a.b.c"));
        assert!(matches("a.*.c", "a.zzz.c"));
        assert!(!matches("a.*.c", "a.b.b.c")); // `*` is exactly one token
        assert!(!matches("a.*.c", "a.c")); // `*` requires a token to be present
        assert!(matches("*", "anything"));
        assert!(!matches("*", "two.tokens"));
    }

    #[test]
    fn tail_wildcard_matches_one_or_more_trailing() {
        assert!(matches("a.>", "a.b"));
        assert!(matches("a.>", "a.b.c.d"));
        assert!(!matches("a.>", "a")); // `>` needs at least one trailing token
        assert!(!matches("a.>", "b.c")); // the literal prefix must still match
        assert!(matches(">", "a"));
        assert!(matches(">", "a.b.c"));
    }

    #[test]
    fn mixed_wildcards_match() {
        assert!(matches("a.*.>", "a.b.c"));
        assert!(matches("a.*.>", "a.b.c.d.e"));
        assert!(!matches("a.*.>", "a.b")); // `>` after `*` still needs a trailing token
        assert!(matches("*.>", "x.y"));
    }
}
