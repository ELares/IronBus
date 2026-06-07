# Contributing to IronBus

Thanks for your interest in IronBus. This is a documentation-first project that
is now being built one small, reviewed, CI-gated pull request at a time. The
backlog of design issues is the specification; the [vision EPIC (#1)](https://github.com/ELares/IronBus/issues/1)
is the index of everything. Before writing code, read the relevant design issue
so your change matches a decision that has already been vetted.

## How we work

- **Small, single-purpose PRs.** One concern per PR. A reviewer should be able
  to hold the whole change in their head. Split unrelated work into separate
  PRs.
- **Link the owning issue.** Use `refs #N` when a PR makes partial progress on
  an issue, and `Closes #N` only when the PR fully resolves it. A `Closes #N`
  closes the entire issue, so prefer `refs #N` for partial work.
- **Discuss before you build.** Every design decision states the alternative it
  rejected and why, so disagreement is easy to ground. Challenge a decision on
  its issue before sending code that contradicts it.

## The merge bar

Every pull request needs two things before it can merge:

1. **Green CI.** The merge-blocking checks defined in
   `.github/workflows/ci.yml` must all pass:
   - `rustfmt`: `cargo fmt --all --check`.
   - `clippy`: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
     (the workspace lints set `clippy::all` and `clippy::pedantic` to warn, and
     `-D warnings` promotes every warning to an error).
   - `test`: `cargo test --workspace --all-features --locked` on Linux, macOS,
     and Windows.
   - `msrv (1.78)`: the workspace builds on Rust 1.78.0.
   - `ironbus-core is IO-free`: `ironbus-core` sources and dependency tree carry
     no filesystem, network, process, or async-runtime usage.
   - `cargo-deny`: the supply-chain policy in `deny.toml` (licenses, bans,
     advisories, sources) holds.
   - `SPDX headers`: every Rust source starts with
     `// SPDX-License-Identifier: MIT OR Apache-2.0`.
   - `musl build`: the static `ironbus` binary cross-builds and is statically
     linked for `x86_64`, `aarch64`, and `armv7` musl triples.
   - `parser tests (32-bit)`: `ironbus-core`'s tests pass on
     `i686-unknown-linux-gnu`.
   - `cargo-auditable SBOM`: the musl binary embeds an SBOM that lists the
     workspace crates.
   - `actionlint`: every workflow passes schema, expression, and shell linting.
2. **An independent review.** Green CI is necessary but not sufficient. A
   maintainer other than the author must review and approve before merge. CI
   being green is never on its own a reason to merge.

## The engineering bar

- **Edition 2021, MSRV Rust 1.78.** Do not use language or standard-library
  features newer than the MSRV. The MSRV may rise only in a minor release.
- **Formatting and lints.** Run `cargo fmt` and
  `cargo clippy -- -W clippy::pedantic -D warnings` locally before you push.
  CI runs the same gates and will reject anything that does not pass.
- **No panics in library paths.** Do not use `unwrap`, `expect`, or `panic!` in
  library code. Return a typed error instead. The release profile builds with
  `panic = "abort"`, so a stray panic is a crash, not a recoverable error.
- **Typed errors.** Surface failures as typed error enums, never as stringly
  typed or swallowed errors.
- **`ironbus-core` stays IO-free.** The core crate holds pure types and logic
  only: no filesystem, network, process, or async-runtime use, in its sources or
  its dependency tree. CI enforces this.

## Keep a Changelog

Every PR updates `CHANGELOG.md`. Add a terse bullet under the appropriate
heading (`Added`, `Changed`, `Fixed`, `Security`) in the `## [Unreleased]`
section, and reference the owning issue (`refs #N` or `#N`). The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Keep entries factual
and concise.

## Prose style

Do not use em dashes or en dashes anywhere in prose, code comments, or commit
messages. Use commas, periods, or a rephrase instead.

## Developer Certificate of Origin

IronBus uses the Developer Certificate of Origin (DCO) rather than a contributor
license agreement. By signing off on a commit you certify that you wrote the
change or otherwise have the right to submit it under the project's
`MIT OR Apache-2.0` license, per the
[Developer Certificate of Origin](https://developercertificate.org).

Add a sign-off trailer to every commit:

```
Signed-off-by: Your Name <you@example.com>
```

The simplest way is to pass `-s` (or `--signoff`) to `git commit`:

```sh
git commit -s -m "your message"
```

The name and email in the trailer must match the commit author. Copyright is
held collectively by "The IronBus Authors".

## License

By contributing, you agree that your contributions are dual-licensed under your
choice of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), matching the rest
of the workspace.
