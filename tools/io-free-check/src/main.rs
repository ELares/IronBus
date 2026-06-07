// SPDX-License-Identifier: MIT OR Apache-2.0
//! CLI entry point for the structural IO-free check.
//!
//! Usage: `io-free-check [<src-dir>]` (default: `crates/ironbus-core/src`). It parses
//! every `*.rs` file under the directory with `syn` and walks the AST for forbidden IO
//! references; see the crate docs in `lib.rs` for the rationale (AST walk, not regex)
//! and for why the `cargo tree` dependency check in CI is the necessary second half.
//!
//! Exit code 0 = clean, 1 = at least one violation (or an IO/parse error reading a
//! source file). On a violation it prints a GitHub-Actions `::error::` annotation so the
//! offending file, path, and span surface inline in the CI log.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use io_free_check::check_source;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let root: PathBuf = args
        .next()
        .map_or_else(|| PathBuf::from("crates/ironbus-core/src"), PathBuf::from);

    let mut rs_files = Vec::new();
    if let Err(e) = collect_rs_files(&root, &mut rs_files) {
        eprintln!(
            "::error::io-free-check could not read {}: {e}",
            root.display()
        );
        return ExitCode::FAILURE;
    }
    rs_files.sort();

    if rs_files.is_empty() {
        eprintln!(
            "::error::io-free-check found no .rs files under {}",
            root.display()
        );
        return ExitCode::FAILURE;
    }

    let mut total = 0usize;
    for file in &rs_files {
        let src = match std::fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "::error::io-free-check could not read {}: {e}",
                    file.display()
                );
                return ExitCode::FAILURE;
            }
        };
        match check_source(&src) {
            Ok(violations) => {
                for v in &violations {
                    // `file::line::col` form so the annotation links to the source.
                    println!("::error file={}::{}", file.display(), v);
                    eprintln!("{}:{}", file.display(), v);
                    total += 1;
                }
            }
            Err(e) => {
                eprintln!(
                    "::error::io-free-check failed to parse {}: {e}",
                    file.display()
                );
                return ExitCode::FAILURE;
            }
        }
    }

    if total > 0 {
        eprintln!(
            "::error::ironbus-core must stay IO-free: {total} forbidden reference(s) in {} (filesystem, network, process, os, io, async runtime, or FFI)",
            root.display(),
        );
        return ExitCode::FAILURE;
    }

    println!(
        "ok: {} source file(s) under {} are structurally IO-free (AST walk)",
        rs_files.len(),
        root.display(),
    );
    ExitCode::SUCCESS
}

/// Recursively collect every `*.rs` file under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}
