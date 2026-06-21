// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cross-cluster DOMAIN namespace / cluster-id (V2-C7-I2, #624) — address a stream across a cluster
//! boundary by a STABLE `<domain>/<stream>` name, not only a raw `host:port` address.
//!
//! This is the NAMESPACE the cross-cluster primitives build on: the geo mirror/source plane (#623,
//! [`geo`](super::geo)) today addresses a remote ORIGIN by a raw `host:port` address, which is brittle —
//! a topology that names "the `east` cluster's `orders` stream" must hard-code `east`'s current node
//! address, and re-wire every reference when that address changes. This module gives each cluster a
//! stable, configured **domain** (a.k.a. cluster-id) and a small RESOLUTION table that maps a remote
//! domain to its configured geo-pull endpoint, so a reference can be the stable `<domain>/<stream>` that
//! survives an address change. The edge leaf-spoke topology (#625) and gateway federation (#626) are
//! SEPARATE issues built ON this namespace; they are NOT pulled in here, but the [`Domain`] type and the
//! [`DomainResolver`] resolution API are the clean primitive they reuse.
//!
//! ## The [`Domain`] grammar (restricted, validated, fail-closed)
//!
//! A domain is a DNS-label-like restricted id: `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, 1..=[`MAX_DOMAIN_LEN`]
//! (63) bytes. Concretely:
//!
//! * lowercase ASCII letters, ASCII digits, and the hyphen `-`;
//! * it must NOT be empty and must NOT exceed 63 bytes;
//! * it must NOT start or end with a hyphen (so a domain is never confusable with a flag/option, and the
//!   `<domain>/<stream>` split is unambiguous).
//!
//! The charset is restricted on PURPOSE: a domain is an identity that appears in config, logs, and (later)
//! a federation wire, so it is held to a small, case-stable, path-safe, shell-safe alphabet. A malformed
//! domain is REJECTED with a typed [`DomainError`] — fail-closed, never silently lower-cased / truncated /
//! guessed at.
//!
//! ## Local vs remote is UNAMBIGUOUS (no cross-domain collision)
//!
//! A LOCAL stream `s` and a REMOTE `east/s` are DISTINCT: the remote one is always domain-QUALIFIED, so
//! the domain prefix disambiguates and a cross-domain name collision is IMPOSSIBLE. A reference that names
//! THIS cluster's OWN domain ([`DomainResolver::own`]) is a SELF-reference; [`DomainResolver::resolve`]
//! returns a typed [`DomainError::SelfReference`] for it (a cross-cluster mirror/source of your own
//! cluster is not a meaningful topology — use the local stream directly), so a self-domain reference can
//! never silently turn into a remote dial.
//!
//! ## No silent cross-domain leakage (the security non-negotiable)
//!
//! [`DomainResolver::resolve`] resolves a remote domain ONLY through the EXPLICITLY-configured link table
//! (`--cluster-link <domain>=<addr>`): an UNCONFIGURED domain is a typed [`DomainError::UnknownDomain`],
//! never an auto-discovered / guessed address. There is NO discovery path — a domain reference can only
//! ever resolve to an endpoint the operator wrote down. This is the [`geo`](super::geo) plane's
//! "connect only to a configured endpoint" guarantee, lifted to the namespace.
//!
//! ## Opt-in + zero-cost when unused (back-compat)
//!
//! Nothing here constructs unless a `--cluster-domain` / `--cluster-link` / a `@domain/stream` reference is
//! configured. The raw-address geo path (#623/#728) is UNCHANGED: an origin given as a raw `host:port`
//! address never touches this module, and a broker with no geo config at all has no [`Domain`], no
//! resolver, and the byte-for-byte single-node behavior. The namespace is a CONFIG-TIME resolution layer:
//! a `@domain/stream` reference resolves to the very same [`GeoOrigin`](super::geo::GeoOrigin) `{ addr,
//! stream }` a raw reference produces, so the entire downstream pull plane (link, applier, cursor) is
//! untouched.

use std::collections::BTreeMap;

/// The hard maximum length, in bytes, of a [`Domain`]. 63 mirrors the DNS label limit: a domain is a
/// stable, restricted, path-/shell-safe identity, so it is held to the same small ceiling. A longer id is
/// rejected fail-closed before any allocation.
pub const MAX_DOMAIN_LEN: usize = 63;

/// A typed DOMAIN error. Every malformed-domain and every resolution failure is one of these — the layer
/// NEVER panics, NEVER lower-cases / truncates / guesses a malformed id, and NEVER resolves a domain to an
/// unconfigured address. Fail-closed on every bad input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainError {
    /// The domain id was empty (`--cluster-domain ` with no value, or an empty `<domain>` in a reference).
    Empty,
    /// The domain id exceeded [`MAX_DOMAIN_LEN`] bytes.
    TooLong {
        /// The byte length seen.
        len: usize,
    },
    /// The domain id carried a byte outside the restricted grammar `[a-z0-9-]` (e.g. an uppercase letter,
    /// a dot, a slash, whitespace, or any non-ASCII byte).
    BadChar {
        /// The offending byte.
        byte: u8,
    },
    /// The domain id started or ended with a hyphen (`-east` / `east-`), which the grammar forbids so a
    /// domain is never confusable with a flag and the `<domain>/<stream>` split is unambiguous.
    HyphenEdge,
    /// A `@<domain>/<stream>` reference named THIS cluster's OWN domain — a self-reference, which is not a
    /// meaningful cross-cluster topology (use the local stream directly). Carries the self domain.
    SelfReference {
        /// The cluster's own domain that was self-referenced.
        domain: String,
    },
    /// A `@<domain>/<stream>` reference named a domain with NO configured `--cluster-link` endpoint. Resolved
    /// fail-closed (never auto-discovered) so a domain reference can only reach an explicitly-configured
    /// remote. Carries the unknown domain.
    UnknownDomain {
        /// The domain that had no configured link.
        domain: String,
    },
}

impl core::fmt::Display for DomainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DomainError::Empty => write!(f, "domain id is empty"),
            DomainError::TooLong { len } => {
                write!(f, "domain id is {len} bytes, over the {MAX_DOMAIN_LEN}-byte cap")
            }
            DomainError::BadChar { byte } => write!(
                f,
                "domain id has an illegal byte {byte:#04x}; the grammar is [a-z0-9-] \
                 (lowercase ASCII letters, digits, hyphen)"
            ),
            DomainError::HyphenEdge => {
                write!(f, "domain id must not start or end with a hyphen")
            }
            DomainError::SelfReference { domain } => write!(
                f,
                "domain reference names this cluster's OWN domain `{domain}`; a cross-cluster \
                 mirror/source of your own cluster is not a valid topology (use the local stream)"
            ),
            DomainError::UnknownDomain { domain } => write!(
                f,
                "domain `{domain}` has no configured `--cluster-link <domain>=<addr>` endpoint; a \
                 domain reference resolves only to an explicitly-configured remote (never auto-discovered)"
            ),
        }
    }
}

impl std::error::Error for DomainError {}

/// A VALIDATED cross-cluster domain (a.k.a. cluster-id): a stable, restricted-charset identity for a
/// cluster within a cross-cluster topology. The ONLY constructor ([`Domain::parse`]) enforces the grammar,
/// so an existing `Domain` is ALWAYS well-formed — a typed proof that the id is one of `[a-z0-9-]`,
/// 1..=[`MAX_DOMAIN_LEN`] bytes, no hyphen edge. This is the clean primitive the geo namespace, the edge
/// leaf-spoke (#625), and the federation (#626) all address streams by.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Domain(String);

impl Domain {
    /// Parse + VALIDATE a domain id against the grammar, fail-closed.
    ///
    /// The grammar is `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, 1..=[`MAX_DOMAIN_LEN`] (63) bytes: lowercase ASCII
    /// letters / digits / hyphen, non-empty, no leading or trailing hyphen. A single character `a`–`z` /
    /// `0`–`9` is the minimal valid domain.
    ///
    /// # Errors
    /// [`DomainError::Empty`] for an empty id, [`DomainError::TooLong`] over the cap,
    /// [`DomainError::BadChar`] for any byte outside `[a-z0-9-]`, [`DomainError::HyphenEdge`] for a leading
    /// or trailing hyphen — never a silent normalization.
    pub fn parse(id: &str) -> Result<Domain, DomainError> {
        if id.is_empty() {
            return Err(DomainError::Empty);
        }
        if id.len() > MAX_DOMAIN_LEN {
            return Err(DomainError::TooLong { len: id.len() });
        }
        // Validate the bytes directly: the grammar is ASCII-only, so a byte scan is exact (a multi-byte
        // UTF-8 sequence's lead/continuation bytes are all > 0x7f, caught by the charset check below).
        for &b in id.as_bytes() {
            let ok = b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
            if !ok {
                return Err(DomainError::BadChar { byte: b });
            }
        }
        // No hyphen edge (checked on the raw bytes; ASCII so byte == char here).
        if id.starts_with('-') || id.ends_with('-') {
            return Err(DomainError::HyphenEdge);
        }
        Ok(Domain(id.to_string()))
    }

    /// The validated domain id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Domain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed `@<domain>/<stream>` domain-QUALIFIED reference: the validated remote domain plus the origin
/// stream name within it. This is the cross-cluster, NAMESPACE twin of a raw `<addr>/<stream>` origin — it
/// names the remote by a STABLE domain, not a node address. Resolved to a concrete
/// [`GeoOrigin`](super::geo::GeoOrigin) by a [`DomainResolver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainRef {
    /// The validated remote domain (the cluster the stream lives in).
    pub domain: Domain,
    /// The origin stream name within that domain (empty = the remote's default stream).
    pub stream: String,
}

/// The on-wire / on-CLI SIGIL that marks a domain-QUALIFIED origin reference (`@east/orders`), so it is
/// UNAMBIGUOUSLY distinguished from a raw `host:port` origin address (`10.0.0.1:7500/orders`). A raw
/// address always carries a `host:port`; a domain reference always leads with `@`. The two grammars cannot
/// overlap (a raw `host:port` never starts with `@`, and a domain `[a-z0-9-]` never contains a `:` or a
/// `.`-bearing host), so a reference is classified by its first byte with zero guesswork.
pub const DOMAIN_REF_SIGIL: char = '@';

impl DomainRef {
    /// Parse a `@<domain>/<stream>` reference. Returns `Ok(None)` if `spec` is NOT a domain reference (it
    /// does not lead with [`DOMAIN_REF_SIGIL`]) — the caller then treats it as a raw `<addr>/<stream>`
    /// origin (the back-compat path). Returns `Ok(Some(_))` for a well-formed reference, or a typed error
    /// for a malformed one.
    ///
    /// The split is at the FIRST `/` after the sigil, so the stream remainder may itself be empty (the
    /// remote's default stream); the domain segment is validated by [`Domain::parse`].
    ///
    /// # Errors
    /// [`DomainError`] (via [`Domain::parse`]) if the domain segment is malformed, or [`DomainError::Empty`]
    /// if the reference is just `@` / `@/stream` (an empty domain). A missing `/` is treated as the whole
    /// remainder being the domain and an empty stream (the default stream).
    pub fn parse(spec: &str) -> Result<Option<DomainRef>, DomainError> {
        let Some(rest) = spec.strip_prefix(DOMAIN_REF_SIGIL) else {
            return Ok(None); // not a domain reference; the caller uses the raw-address path
        };
        // Split at the FIRST `/`: `@east/orders` -> ("east", "orders"); `@east` -> ("east", "") (the
        // remote's default stream). A domain never contains a `/` (the grammar forbids it), so the first
        // `/` is unambiguously the domain/stream boundary.
        let (domain_part, stream) = match rest.split_once('/') {
            Some((d, s)) => (d, s),
            None => (rest, ""),
        };
        let domain = Domain::parse(domain_part)?;
        Ok(Some(DomainRef {
            domain,
            stream: stream.to_string(),
        }))
    }
}

/// The cross-cluster DOMAIN RESOLVER: this cluster's OWN domain (optional) plus the explicit
/// `domain -> geo-pull endpoint address` link table, the ONLY way a `@<domain>/<stream>` reference becomes
/// a concrete dial address. Built from `--cluster-domain` + the repeatable `--cluster-link
/// <domain>=<addr>` flags.
///
/// EMPTY (no own domain, no links) is the default: nothing constructs and no reference can resolve (a
/// `@domain/stream` reference with an empty resolver is an [`DomainError::UnknownDomain`]) — the namespace
/// is opt-in. The resolver is the reusable resolution API the edge leaf-spoke (#625) and federation (#626)
/// build on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DomainResolver {
    /// This cluster's OWN domain, if `--cluster-domain` was set. A `@<own>/...` reference resolves to a
    /// typed [`DomainError::SelfReference`] (a self-mirror is not a valid topology).
    own: Option<Domain>,
    /// The explicit `remote-domain -> geo-pull endpoint address` table (`--cluster-link <domain>=<addr>`).
    /// Sorted (a `BTreeMap`) for a deterministic surface. The ONLY source of a remote address; an
    /// unconfigured domain never resolves (no auto-discovery).
    links: BTreeMap<Domain, String>,
}

impl DomainResolver {
    /// A fresh resolver with an optional own-domain and NO links. Links are added with [`add_link`].
    #[must_use]
    pub fn new(own: Option<Domain>) -> DomainResolver {
        DomainResolver {
            own,
            links: BTreeMap::new(),
        }
    }

    /// This cluster's own domain, if configured.
    #[must_use]
    pub fn own(&self) -> Option<&Domain> {
        self.own.as_ref()
    }

    /// True if NOTHING is configured (no own domain, no links) — the opt-in default; no reference can
    /// resolve.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.own.is_none() && self.links.is_empty()
    }

    /// Add (or replace) the `domain -> addr` link for a remote domain. A later add for the same domain
    /// replaces the earlier address (last-writer-wins), so a repeated `--cluster-link` is well-defined.
    pub fn add_link(&mut self, domain: Domain, addr: String) {
        self.links.insert(domain, addr);
    }

    /// The configured geo-pull endpoint address for `domain`, or `None` if no link is configured.
    #[must_use]
    pub fn link(&self, domain: &Domain) -> Option<&str> {
        self.links.get(domain).map(String::as_str)
    }

    /// Resolve a `@<domain>/<stream>` reference to a concrete `(addr, stream)` — the EXACT shape a raw
    /// `<addr>/<stream>` origin produces, so the resolved reference flows into the very same
    /// [`GeoOrigin`](super::geo::GeoOrigin) and the downstream pull plane is unchanged.
    ///
    /// Resolution is fail-closed and EXPLICIT-ONLY:
    /// * a reference to THIS cluster's own domain is a typed [`DomainError::SelfReference`];
    /// * a reference to a domain with NO configured `--cluster-link` is a typed
    ///   [`DomainError::UnknownDomain`] — never an auto-discovered address (no silent cross-domain leakage);
    /// * otherwise the configured link address + the reference's stream are returned.
    ///
    /// # Errors
    /// [`DomainError::SelfReference`] or [`DomainError::UnknownDomain`] per the above.
    pub fn resolve(&self, reference: &DomainRef) -> Result<(String, String), DomainError> {
        if self.own.as_ref() == Some(&reference.domain) {
            return Err(DomainError::SelfReference {
                domain: reference.domain.as_str().to_string(),
            });
        }
        match self.links.get(&reference.domain) {
            Some(addr) => Ok((addr.clone(), reference.stream.clone())),
            None => Err(DomainError::UnknownDomain {
                domain: reference.domain.as_str().to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_domains_parse() {
        for id in [
            "east",
            "west-2",
            "a",
            "0",
            "cluster-id-99",
            "x".repeat(MAX_DOMAIN_LEN).as_str(),
        ] {
            let d = Domain::parse(id).unwrap_or_else(|e| panic!("`{id}` should parse: {e}"));
            assert_eq!(d.as_str(), id);
        }
    }

    #[test]
    fn empty_domain_is_rejected() {
        assert_eq!(Domain::parse(""), Err(DomainError::Empty));
    }

    #[test]
    fn over_long_domain_is_rejected() {
        let id = "a".repeat(MAX_DOMAIN_LEN + 1);
        assert_eq!(
            Domain::parse(&id),
            Err(DomainError::TooLong {
                len: MAX_DOMAIN_LEN + 1
            })
        );
    }

    #[test]
    fn bad_chars_are_rejected_fail_closed() {
        // Uppercase, dot, slash, space, colon, underscore, and a non-ASCII byte are all outside [a-z0-9-].
        for (id, byte) in [
            ("East", b'E'),
            ("ea.st", b'.'),
            ("ea/st", b'/'),
            ("ea st", b' '),
            ("ea:st", b':'),
            ("ea_st", b'_'),
        ] {
            assert_eq!(
                Domain::parse(id),
                Err(DomainError::BadChar { byte }),
                "`{id}` should be rejected at byte {byte:#x}"
            );
        }
        // A non-ASCII byte (the first byte of a multi-byte UTF-8 char) is rejected by the charset scan.
        match Domain::parse("éast") {
            Err(DomainError::BadChar { .. }) => {}
            other => panic!("non-ASCII domain should be a BadChar, got {other:?}"),
        }
    }

    #[test]
    fn hyphen_edges_are_rejected() {
        assert_eq!(Domain::parse("-east"), Err(DomainError::HyphenEdge));
        assert_eq!(Domain::parse("east-"), Err(DomainError::HyphenEdge));
        // A lone hyphen is a hyphen edge (both ends), rejected.
        assert_eq!(Domain::parse("-"), Err(DomainError::HyphenEdge));
        // An interior hyphen is fine.
        assert!(Domain::parse("ea-st").is_ok());
    }

    #[test]
    fn a_raw_address_is_not_a_domain_reference() {
        // No `@` sigil => not a domain ref; the caller uses the raw-address path (back-compat).
        assert_eq!(DomainRef::parse("10.0.0.1:7500/orders").unwrap(), None);
        assert_eq!(DomainRef::parse("orders").unwrap(), None);
    }

    #[test]
    fn a_domain_reference_parses() {
        let r = DomainRef::parse("@east/orders").unwrap().unwrap();
        assert_eq!(r.domain.as_str(), "east");
        assert_eq!(r.stream, "orders");
        // `@east` with no `/` => the remote's default stream (empty).
        let r = DomainRef::parse("@east").unwrap().unwrap();
        assert_eq!(r.domain.as_str(), "east");
        assert_eq!(r.stream, "");
        // `@east/` => an explicit empty stream too.
        let r = DomainRef::parse("@east/").unwrap().unwrap();
        assert_eq!(r.stream, "");
    }

    #[test]
    fn a_malformed_domain_reference_is_rejected() {
        // Just the sigil => empty domain.
        assert_eq!(DomainRef::parse("@"), Err(DomainError::Empty));
        assert_eq!(DomainRef::parse("@/orders"), Err(DomainError::Empty));
        // A bad domain char in a reference is surfaced.
        assert!(matches!(
            DomainRef::parse("@East/orders"),
            Err(DomainError::BadChar { .. })
        ));
    }

    #[test]
    fn resolve_uses_only_the_configured_link_no_leakage() {
        let mut r = DomainResolver::new(Some(Domain::parse("home").unwrap()));
        r.add_link(Domain::parse("east").unwrap(), "10.0.0.1:7500".to_string());

        // A configured remote resolves to its explicit address + the reference's stream.
        let reference = DomainRef::parse("@east/orders").unwrap().unwrap();
        assert_eq!(
            r.resolve(&reference).unwrap(),
            ("10.0.0.1:7500".to_string(), "orders".to_string())
        );

        // An UNCONFIGURED domain never resolves (no auto-discovery / no leakage).
        let reference = DomainRef::parse("@west/orders").unwrap().unwrap();
        assert_eq!(
            r.resolve(&reference),
            Err(DomainError::UnknownDomain {
                domain: "west".to_string()
            })
        );
    }

    #[test]
    fn a_self_domain_reference_is_a_typed_error() {
        let r = DomainResolver::new(Some(Domain::parse("home").unwrap()));
        let reference = DomainRef::parse("@home/orders").unwrap().unwrap();
        assert_eq!(
            r.resolve(&reference),
            Err(DomainError::SelfReference {
                domain: "home".to_string()
            })
        );
    }

    #[test]
    fn local_stream_and_remote_domain_stream_are_distinct() {
        // The NAMESPACE collision guarantee: a local stream `s` and a remote `east/s` never collide,
        // because the remote is always domain-QUALIFIED (the `@east/` prefix). A raw `s` is not a domain
        // reference at all; `@east/s` is, and it resolves to a DIFFERENT (remote) endpoint.
        let mut r = DomainResolver::new(Some(Domain::parse("home").unwrap()));
        r.add_link(Domain::parse("east").unwrap(), "10.0.0.1:7500".to_string());

        assert_eq!(
            DomainRef::parse("s").unwrap(),
            None,
            "a bare local name is not a domain ref"
        );
        let remote = DomainRef::parse("@east/s").unwrap().unwrap();
        let (addr, stream) = r.resolve(&remote).unwrap();
        assert_eq!((addr.as_str(), stream.as_str()), ("10.0.0.1:7500", "s"));
        // The remote's stream name `s` is the SAME string as a hypothetical local `s`, yet they address
        // different things: local `s` is this broker's log; `@east/s` dials east. No collision.
    }

    #[test]
    fn last_writer_wins_for_a_repeated_link() {
        let mut r = DomainResolver::new(None);
        r.add_link(Domain::parse("east").unwrap(), "a:1".to_string());
        r.add_link(Domain::parse("east").unwrap(), "b:2".to_string());
        assert_eq!(r.link(&Domain::parse("east").unwrap()), Some("b:2"));
    }

    #[test]
    fn an_empty_resolver_resolves_nothing() {
        let r = DomainResolver::default();
        assert!(r.is_empty());
        let reference = DomainRef::parse("@east/orders").unwrap().unwrap();
        assert_eq!(
            r.resolve(&reference),
            Err(DomainError::UnknownDomain {
                domain: "east".to_string()
            })
        );
    }
}
