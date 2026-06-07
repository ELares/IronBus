// SPDX-License-Identifier: MIT OR Apache-2.0
//! Structural IO-free checker for `ironbus-core`.
//!
//! `ironbus-core` must perform no input or output: no filesystem, no network, no
//! process spawning, no async runtime, no raw OS handles. This crate enforces that
//! invariant by parsing every source file with [`syn`] (a real Rust parser) and
//! walking the resulting syntax tree, rather than grepping the source text.
//!
//! Why an AST walk and not a regex: a line-oriented regex can be evaded by import
//! grouping (`use std::{fs, net::TcpStream}`), aliasing (`use std::fs as f`), globs
//! (`use std::net::*`), odd whitespace, or a comment that looks like code. The walker
//! sees the parsed program, so grouped/aliased/glob `use` trees are expanded to their
//! real paths, comments never appear in the tree, and whitespace is irrelevant.
//!
//! This source walk is one half of the structural guarantee. The other half is the
//! `cargo tree` dependency check in CI: AST walking only sees this crate's own source,
//! so IO that arrives by RE-EXPORT from a dependency (a crate that itself touches the
//! filesystem and re-exports it) is invisible here and is caught by the dep-tree step.
//! Together (AST source walk + dep-tree) they form the structural invariant. A full
//! compiler-level lint (a custom `dylint`/driver that resolves every path against the
//! real name resolver) would be strictly stronger and is a possible future hardening.
//!
//! Known residual gap: IO written as `std::*` INSIDE a local `macro_rules!` body is
//! caught by neither half. `syn` exposes a macro body as opaque tokens, so the walk
//! does not see `std::fs::read(...)` hidden in a macro definition, and `std::*` needs
//! no dependency so the dep-tree check shows nothing either. Only a name-resolving
//! `dylint` would catch it. `ironbus-core` has no such macro today (the baseline is
//! clean), so this one contrived case relies on code review rather than the gate.

use std::collections::BTreeSet;
use std::fmt;

use syn::spanned::Spanned;
use syn::visit::Visit;

/// A single forbidden reference found in a source file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    /// The forbidden path or construct, e.g. `std::fs` or `extern block`.
    pub what: String,
    /// 1-based line where the offending token starts.
    pub line: usize,
    /// 1-based column where the offending token starts.
    pub column: usize,
    /// A short human-readable reason.
    pub reason: &'static str,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: forbidden `{}` ({})",
            self.line, self.column, self.what, self.reason
        )
    }
}

/// Forbidden `std`/`core` submodule prefixes. A path whose leading segments match one
/// of these (after an optional leading `::` or `crate`/`self`/`super`) is a violation.
///
/// `std::io` is the byte IO module and is forbidden; `std::fmt` and `core::fmt` are
/// formatting only (no IO) and are explicitly allowed, so they are NOT listed here.
const FORBIDDEN_STD_MODULES: &[&str] = &[
    "fs",      // filesystem
    "net",     // sockets
    "process", // process spawning / exit
    "os",      // raw OS handles, unix/windows extension traits
    "io",      // byte input/output (Read/Write/stdin/stdout)
];

/// Forbidden crate roots: async runtimes and the low-level event/syscall crates they
/// build on. A path or `use` rooted at one of these is a violation.
const FORBIDDEN_CRATES: &[&str] = &["tokio", "async_std", "smol", "mio"];

/// Walk a single parsed file's syntax tree and collect every forbidden reference.
///
/// `src` is the file's full text; it is parsed with [`syn::parse_file`], so it must be a
/// complete, syntactically valid Rust file (every file under `ironbus-core/src` is).
///
/// # Errors
///
/// Returns the [`syn::Error`] if `src` does not parse as a Rust file.
pub fn check_source(src: &str) -> Result<Vec<Violation>, syn::Error> {
    let file = syn::parse_file(src)?;
    let mut visitor = IoVisitor::default();
    visitor.visit_file(&file);
    // Deterministic, de-duplicated output (a path can be hit by several visit methods).
    let unique: BTreeSet<Violation> = visitor.violations.into_iter().collect();
    Ok(unique.into_iter().collect())
}

#[derive(Default)]
struct IoVisitor {
    violations: Vec<Violation>,
}

impl IoVisitor {
    /// Classify a sequence of leading path segments (already stripped of a leading
    /// `::`/`crate`/`self`/`super`) and record a violation if it names forbidden IO.
    /// Returns `true` if a violation was recorded.
    fn classify(&mut self, segments: &[String], span_line: usize, span_col: usize) -> bool {
        let Some(first) = segments.first() else {
            return false;
        };

        // `std::<mod>` / `core::<mod>` / `alloc::<mod>` then a forbidden submodule.
        if matches!(first.as_str(), "std" | "core" | "alloc") {
            if let Some(second) = segments.get(1) {
                if FORBIDDEN_STD_MODULES.contains(&second.as_str()) {
                    self.violations.push(Violation {
                        what: format!("{first}::{second}"),
                        line: span_line,
                        column: span_col,
                        reason: "std IO module (filesystem, network, process, os, or io)",
                    });
                    return true;
                }
            }
            return false;
        }

        // A bare forbidden crate root, e.g. `tokio::spawn` or `use mio::Poll`.
        if FORBIDDEN_CRATES.contains(&first.as_str()) {
            self.violations.push(Violation {
                what: first.clone(),
                line: span_line,
                column: span_col,
                reason: "async runtime or low-level event/syscall crate",
            });
            return true;
        }
        false
    }

    /// Recursively expand a `use` tree, threading the accumulated path prefix so a
    /// grouped/aliased/glob import is classified by its real, fully-expanded path.
    ///
    /// Once a branch's prefix matches a forbidden prefix it is reported ONCE and not
    /// descended further: every deeper segment shares that same forbidden prefix, so
    /// re-classifying them would only duplicate the single real violation.
    fn walk_use_tree(&mut self, tree: &syn::UseTree, prefix: &mut Vec<String>) {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                let (l, c) = line_col(p.ident.span());
                if !self.classify(prefix, l, c) {
                    self.walk_use_tree(&p.tree, prefix);
                }
                prefix.pop();
            }
            syn::UseTree::Name(n) => {
                prefix.push(n.ident.to_string());
                let (l, c) = line_col(n.ident.span());
                self.classify(prefix, l, c);
                prefix.pop();
            }
            syn::UseTree::Rename(r) => {
                // `use std::fs as f` -> classify on the ORIGINAL name, not the alias.
                prefix.push(r.ident.to_string());
                let (l, c) = line_col(r.ident.span());
                self.classify(prefix, l, c);
                prefix.pop();
            }
            syn::UseTree::Glob(g) => {
                // `use std::fs::*` -> the prefix itself is the import; classify it.
                let (l, c) = line_col(g.star_token.span());
                self.classify(prefix, l, c);
            }
            syn::UseTree::Group(group) => {
                // `use std::{fs, net::TcpStream}` -> recurse into each branch with the
                // SAME shared prefix, so every branch is expanded to its real path.
                for item in &group.items {
                    self.walk_use_tree(item, prefix);
                }
            }
        }
    }
}

/// Strip a leading `::`/`crate`/`self`/`super` qualifier so `::std::fs` and `crate`-
/// relative noise do not hide a forbidden prefix. Returns the meaningful segments.
fn meaningful_segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .skip_while(|s| matches!(s.as_str(), "crate" | "self" | "super"))
        .collect()
}

fn line_col(span: proc_macro2::Span) -> (usize, usize) {
    let start = span.start();
    // `column` is 0-based in proc-macro2; present it 1-based to match editor/grep output.
    (start.line, start.column + 1)
}

impl<'ast> Visit<'ast> for IoVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments = meaningful_segments(path);
        if let Some(first) = path.segments.first() {
            let (l, c) = line_col(first.ident.span());
            self.classify(&segments, l, c);
        }
        // Keep descending: generic arguments can carry more paths, e.g.
        // `Vec<std::fs::File>` or `Foo<tokio::net::TcpStream>`.
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut prefix = Vec::new();
        self.walk_use_tree(&item.tree, &mut prefix);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        // An `extern "C" { ... }` block is a raw FFI escape hatch: it declares foreign
        // functions that can do arbitrary IO/syscalls outside Rust's view. ironbus-core
        // is pure Rust with no FFI, so any foreign module is a violation.
        let (l, c) = line_col(item.abi.extern_token.span());
        self.violations.push(Violation {
            what: "extern block".to_string(),
            line: l,
            column: c,
            reason: "foreign-function (FFI) block can perform IO outside Rust",
        });
        syn::visit::visit_item_foreign_mod(self, item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whats(src: &str) -> Vec<String> {
        check_source(src)
            .expect("snippet must parse")
            .into_iter()
            .map(|v| v.what)
            .collect()
    }

    #[test]
    fn clean_source_passes() {
        let src = r#"
            // SPDX-License-Identifier: MIT OR Apache-2.0
            use core::fmt;
            use std::fmt::Debug;
            use std::collections::BTreeMap;

            /// std::fs in a doc comment must NOT trip the checker.
            pub fn add(a: u64, b: u64) -> u64 {
                // tokio::spawn here is only a comment
                let _ = "std::net::TcpStream in a string literal";
                a.wrapping_add(b)
            }
        "#;
        assert!(
            whats(src).is_empty(),
            "clean source flagged: {:?}",
            whats(src)
        );
    }

    #[test]
    fn plain_fully_qualified_path_is_caught() {
        // `std::fs::read(...)` with no `use` at all (the macro/creative-pathing evasion).
        let src = "fn f() { let _ = std::fs::read(\"x\"); }";
        assert_eq!(whats(src), vec!["std::fs"]);
    }

    #[test]
    fn simple_use_is_caught() {
        assert_eq!(whats("use std::net::TcpStream;"), vec!["std::net"]);
    }

    #[test]
    fn grouped_use_is_caught() {
        // A single line a naive `use std::\{...\}` regex can still miss the second arm.
        let src = "use std::{fmt, fs, net::TcpStream};";
        let mut got = whats(src);
        got.sort();
        got.dedup();
        assert_eq!(got, vec!["std::fs", "std::net"]);
    }

    #[test]
    fn aliased_use_is_caught() {
        // `as f` must not launder the forbidden original name.
        assert_eq!(whats("use std::fs as f;"), vec!["std::fs"]);
    }

    #[test]
    fn glob_use_is_caught() {
        assert_eq!(whats("use std::process::*;"), vec!["std::process"]);
    }

    #[test]
    fn leading_colon_colon_is_caught() {
        assert_eq!(whats("fn f() { ::std::io::stdout(); }"), vec!["std::io"]);
    }

    #[test]
    fn nested_group_is_caught() {
        // Deep grouping: `use std::os::{unix::{io::AsRawFd}}` plus a clean sibling.
        let src = "use std::{fmt::Debug, os::unix::io::AsRawFd};";
        assert_eq!(whats(src), vec!["std::os"]);
    }

    #[test]
    fn async_runtime_use_and_path_are_caught() {
        assert_eq!(whats("use tokio::net::TcpStream;"), vec!["tokio"]);
        assert_eq!(whats("fn f() { mio::Poll::new(); }"), vec!["mio"]);
        assert_eq!(whats("use async_std::task;"), vec!["async_std"]);
        assert_eq!(whats("use smol::block_on;"), vec!["smol"]);
    }

    #[test]
    fn path_in_generic_argument_is_caught() {
        let src = "fn f() -> Vec<std::net::TcpStream> { unimplemented!() }";
        assert_eq!(whats(src), vec!["std::net"]);
    }

    #[test]
    fn extern_block_is_caught() {
        let src = "extern \"C\" { fn write(fd: i32, buf: *const u8, n: usize) -> isize; }";
        assert_eq!(whats(src), vec!["extern block"]);
    }

    #[test]
    fn std_fmt_is_allowed() {
        // The allow-list boundary: fmt is fine, io is not.
        assert!(whats("use std::fmt::Write;").is_empty());
        assert_eq!(whats("use std::io::Write;"), vec!["std::io"]);
    }

    #[test]
    fn violation_carries_a_span() {
        let v = &check_source("\n\nuse std::fs;").expect("parses")[0];
        assert_eq!(v.what, "std::fs");
        assert_eq!(v.line, 3);
        assert!(v.column >= 1);
    }
}
