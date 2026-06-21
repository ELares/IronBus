# Governance

IronBus is maintainer-led. A small group of maintainers stewards the project,
reviews and merges pull requests, and is responsible for keeping the design
coherent. Every change still follows the contribution process: green CI plus an
independent review before merge.

## Independence (org-agnostic)

IronBus is an **independent, org-agnostic open-source project**. It is owned by no
single company, employer, or organization; copyright is held collectively by "The
IronBus Authors" and the project is licensed under
[MIT](LICENSE-MIT) **OR** [Apache-2.0](LICENSE-APACHE) at the user's option.

Because of that, the source and all tracked files must stay **org-neutral**: no
references that couple IronBus to a specific company, employer, internal
deployment, or private infrastructure may ever be committed — no org names, hosts,
account handles, ticket trackers, or vendor-internal jargon. This is not merely a
style preference; it is a project invariant:

- The general rule — *no org-specific reference of any kind* — is upheld in review.
- The concrete, known-risk subset is **CI-enforced**: the
  [`org-agnostic hygiene`](.github/workflows/org-agnostic.yml) gate greps every
  tracked file for each term in
  [`.github/forbidden-org-terms.txt`](.github/forbidden-org-terms.txt) and **fails
  the build** if any is found, so an org-specific reference can never land on
  `main`. Add terms to that list as the project's contributor base grows.

A contribution that would tie IronBus to one organization is out of scope by
construction, regardless of who contributes it.

## How decisions are made

- **Decisions are recorded on their owning GitHub issues.** Each subsystem has a
  design issue, and the rationale for a decision, including the alternative it
  rejected, lives as a comment or update on that issue. The issues are the
  authoritative design record.
- **The README is the canonical vision.** The
  [README](README.md) states the product's tenets, scope, and committed
  non-goals. When in doubt about direction, the README is the reference.
- **Frozen design decisions win over stale text.** When a recorded, frozen
  decision conflicts with prose somewhere in the repository, the frozen decision
  is authoritative and the stale text is corrected to match it. A decision is
  changed by reopening it on its issue, not by quietly editing downstream text.

## Maintainers

Maintainers carry the merge bit and the responsibility that comes with it.
Becoming a maintainer follows from a sustained record of well-reviewed
contributions and is decided by the existing maintainers. Copyright in the
project is held collectively by "The IronBus Authors".
