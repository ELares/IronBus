# Architecture Decision Records

This directory holds IronBus Architecture Decision Records (ADRs): short,
numbered, in-tree notes that record a design decision and the reasoning behind
it.

## What an ADR is

An ADR captures one architecturally significant decision: the context that
forced a choice, the choice itself, and the consequences that follow. It is a
historical record, not a living spec. Once written, an ADR is not edited to
change the decision; a later ADR supersedes it.

## What stays canonical

ADRs do not own the decisions. The frozen design decisions live on their owning
GitHub issues (the 22 subsystem issues, #3 through #22, plus the meta issues),
and the headline decisions are summarized in the top-level `README.md` under
"Key decisions already committed". Those remain the source of truth. An ADR just
records a decision in-tree, next to the code, with a pointer back to the issue,
so a reader of the repository can find the rationale without leaving the tree.
If an ADR and its owning issue ever disagree, the issue (and the README) win,
and the ADR is corrected or superseded.

The flat catalog of every resolved decision (the numbered ADRs plus the frozen
decisions that do not yet have a numbered file) lives in [`INDEX.md`](INDEX.md). The
ADR index issue (#130) owns it, under the governance process (#22).

## Numbering

ADRs are numbered sequentially with a zero-padded four-digit prefix and a short
kebab-case slug, for example `0001-log-is-wal.md`. A number, once assigned, is
never reused, even if the ADR is later superseded. The next ADR takes the next
free number.

## Status lifecycle

Every ADR carries one status:

- **Proposed**: the decision is written down but not yet ratified.
- **Accepted**: the decision is in force. It is reflected in the owning issue,
  the README, or the code.
- **Superseded**: a later decision replaced this one. A superseded ADR names the
  ADR that replaces it, and stays in the tree as history.

Because the IronBus decisions in this directory were already resolved on their
issues before being recorded here, the ADRs committed so far open directly at
**Accepted**.

## Adding an ADR

Copy `template.md` to `NNNN-slug.md`, take the next free number, fill in the
sections, and cite the owning issue. Keep it short: one screen is the target.
