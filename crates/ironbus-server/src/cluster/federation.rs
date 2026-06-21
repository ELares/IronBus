// SPDX-License-Identifier: MIT OR Apache-2.0
//! Gateway / supercluster FEDERATION — SYMMETRIC cluster-to-cluster interconnect (V2-C7-I4, #626).
//!
//! This is the NATS-gateway / supercluster-class topology, and the LAST geo topology, built ON the geo
//! plane (#623, [`geo`](super::geo)) and the domain namespace (#624, [`domain`](super::domain)). Where the
//! edge leaf-spoke (#625, [`leaf`](super::leaf)) is ASYMMETRIC — one HUB plus many lightweight LEAF nodes
//! that dial UP to it — federation is SYMMETRIC: a set of PEER CLUSTERS, each a full, independent cluster
//! with a GATEWAY, interconnected so a producer in cluster `west` and a consumer in cluster `east` exchange
//! messages across the supercluster. Each cluster is a peer of equal standing; there is no hub.
//!
//! ## Federation is a SYMMETRIC composition of the geo mirror PULL — no new wire frame
//!
//! The cross-cluster data-movement primitive is the geo mirror PULL ([`geo::MirrorPullRequest`], wire tag
//! 40), REUSED VERBATIM — federation introduces NO new frame tag (40 = `MirrorPull`, 41 = `LeafPush` stay
//! the whole geo wire). What is new is the SYMMETRY and the LOOP-SAFETY discipline:
//!
//! * **Each gateway SERVES its own federated streams to peers** — exactly the geo
//!   [`OriginServer`](super::geo::OriginServer): a peer's gateway dials in and PULLS a federated stream's
//!   CRC-framed sealed bytes. A gateway only ever serves streams that ORIGINATE in its own cluster (its own
//!   domain); it NEVER re-serves a stream it itself mirrored from a peer (the no-loop core, below).
//! * **Each gateway PULLS peer-originated federated streams into a read-only local MIRROR** — exactly the
//!   geo [`MirrorApplier`](super::geo::MirrorApplier) + durable [`OriginCursorStore`](super::geo): it dials
//!   the peer gateway, PULLS the peer-origin stream's bytes, RE-VALIDATES every CRC frame, applies in order
//!   to a local read-only mirror, and durably advances a per-origin resume cursor. Byte-faithful, in-order,
//!   gap-free, resumable across a peer disconnect — the whole #728 discipline, REUSED.
//!
//! So a federated stream `orders` originating in `west` is SERVED by `west`'s gateway and MIRRORED into
//! `east` as a read-only local stream `@west/orders`; symmetrically a stream originating in `east` is
//! served by `east` and mirrored into `west`. Each cluster is a peer; the interconnect is symmetric.
//!
//! ## NO routing loops: a record crosses each link EXACTLY once (the non-negotiable)
//!
//! Federation could in principle ECHO — `west` serves `orders` to `east`, `east` re-serves it to `west`,
//! `west` re-serves it to `east`, forever, amplifying without bound. It CANNOT here, by CONSTRUCTION, via
//! the ORIGIN-DOMAIN discipline:
//!
//! * Every federated stream carries its ORIGIN DOMAIN ([`FederatedStream::origin`]): the domain of the
//!   cluster the stream's records originate in. A gateway computes what it SERVES to peers as exactly the
//!   federated streams whose origin domain is its OWN domain ([`FederationConfig::served_streams`]). A
//!   stream it MIRRORS from a peer has a DIFFERENT origin domain, so it is NEVER in the served set — a
//!   gateway never re-forwards a peer-originated record back out. The set of links a record traverses is
//!   therefore a TREE rooted at its origin (origin serves → every peer mirrors once), not a cycle.
//! * The mirror local stream is READ-ONLY (its only writer is the geo apply path), so a mirrored-in record
//!   is never a local produce that could be re-served as this cluster's own origin. A record lives on
//!   exactly one cluster as an ORIGIN and on every other as a read-only MIRROR; it travels each federation
//!   link in exactly one direction, once.
//! * The geo durable cursor + the [`NonContiguous`](super::geo::GeoError::NonContiguous) guard de-dup a
//!   re-pull: a reconnecting peer resumes from its cursor and a replayed span is a recognized no-op, so even
//!   a flapping link never re-applies or amplifies.
//!
//! [`FederationConfig::validate`] additionally REJECTS a config that would let a stream be both served and
//! mirrored under the same local name, or that names this cluster's own domain as a remote peer — the only
//! config-level ways the origin-domain invariant could be subverted.
//!
//! A 2- or 3-cluster RING (`west -> east -> south -> west`, each peering the next) is the worst case for a
//! loop; the [`live_federation_tests`] prove a record produced in one ring member is delivered to every
//! other member EXACTLY ONCE — the total delivered count is bounded by (members - 1), never growing across
//! repeated drain rounds.
//!
//! ## A gateway is NOT a Raft voter in the PEER cluster (each cluster stays independent)
//!
//! Federation does NOT merge the peers' metadata-Raft groups. NOTHING in this module touches the metadata
//! Raft group ([`metadata_group`](super::metadata_group)), the membership API
//! ([`membership`](super::membership)), or the [`ClusterRuntime`](super::runtime). Each cluster keeps its
//! OWN quorum / consensus / leadership; a gateway is a DATA-PLANE bridge between clusters, not a consensus
//! participant in any peer. A gateway connecting/disconnecting is invisible to every peer's metadata group:
//! there is no gateway entry in any peer's `ConfState`, no gateway peer-id, and a peer's quorum math is
//! computed entirely over ITS OWN Raft voters, which a gateway is not. This is the leaf's not-a-voter
//! guarantee (#625) made SYMMETRIC: a gateway is not a voter in ANY peer, and no peer is a voter in it.
//!
//! ## Interest-scoped (no firehose): only configured streams federate
//!
//! A gateway federates ONLY the streams explicitly declared ([`FederatedStream`] per `--federate`); it
//! NEVER blindly mirrors a peer's whole cluster. Cross-cluster interest is the EXPLICIT per-stream config;
//! richer subject-interest gossip / dynamic propagation is a FLAGGED follow-on (see the scope note). The
//! federated set is bounded, so the cross-cluster traffic is bounded.
//!
//! ## Resilient + async / ~0-idle (the #726 lesson, REUSED)
//!
//! Each peer link is the geo pull loop ([`geo::pull_loop`](super::geo)): pull a bounded batch, BLOCK on the
//! response up to a poll window, BACK OFF (interruptible sleep) when caught up. An idle peer link does ~0
//! work (blocks/backs off, never busy-spins). A peer disconnect/reconnect resumes cleanly from the durable
//! cursor (no gap/dup). A DOWN peer's puller backs off and retries on its OWN thread; it does NOT block
//! local produce/consume, the gateway's serving to OTHER peers, or those peers' pulls. One cluster's
//! failure does not cascade — each peer link is independent.
//!
//! ## Single-node / non-federated = byte-identical (the critical guarantee)
//!
//! NOTHING here constructs unless a `--gateway`/`--federate` is configured. With no federation config the
//! local produce/consume/storage hot path is byte-for-byte today's broker: no served-stream
//! [`OriginServer`], no peer [`MirrorApplier`], no cursor file, no extra frame ever decoded. The federation
//! plane is gated entirely on a non-empty [`FederationConfig`] in the CLI serve hook, exactly like the geo
//! (#728) and leaf (#732) planes — ZERO diff to engine/session/actor/storage/core.
//!
//! ## SCOPE / deferred (honest)
//!
//! * **Single default stream per federated link.** A federated stream bridges ONE peer-origin stream <-> ONE
//!   local mirror's default partition (like geo/leaf). Multi-partition is FLAGGED to #693.
//! * **Cross-cluster gateway AUTH/TLS** is minimal (loopback / trusted transport, plaintext — the same as
//!   the intra-cluster peer link, the geo link, and the leaf link). mTLS / token auth on the gateway link
//!   is a FLAGGED follow-on (#629/#631).
//! * **Explicit per-stream interest only.** Cross-cluster interest is the declared [`FederatedStream`] set;
//!   dynamic subject-interest GOSSIP / propagation across the supercluster is a FLAGGED follow-on.
//! * **Gateway-accept BROKER serve-path wiring is deferred EXACTLY as #728/#732 left it.** The puller /
//!   connector side (and the served-stream `OriginServer` answering pulls) are PROVEN in the integration
//!   tests over real loopback sockets; hooking the gateway-accept loop into the broker's main serve listener
//!   is the consistent follow-on the geo/leaf planes also deferred. The federation LOGIC (symmetric peering,
//!   loop-safety, not-a-voter, resilience) is proven by the [`live_federation_tests`].

use crate::cluster::domain::{Domain, DomainError, DomainResolver};
use crate::cluster::geo::{GeoMode, GeoOrigin};

/// A typed FEDERATION error. Every config-level failure mode of the symmetric gateway federation is one of
/// these — the layer NEVER panics and FAILS CLOSED on any malformed / loop-inviting / self-referential
/// config. The cross-cluster DATA path reuses the geo [`GeoError`](super::geo::GeoError) (it IS a geo pull),
/// so this type covers only the federation-config validation; the domain-resolution faults surface as the
/// wrapped [`DomainError`].
#[derive(Debug)]
pub enum FederationError {
    /// A federation config was invalid (e.g. a federated stream named no origin domain, a peer named this
    /// cluster's OWN domain, or the same local mirror name was used by two peer-origin streams).
    Config {
        /// A human description of the config fault.
        what: String,
    },
    /// A domain id / reference in the config was malformed, or a peer domain had no configured `--gateway`
    /// endpoint (resolved fail-closed through the same explicit link table the geo plane uses).
    Domain(DomainError),
}

impl core::fmt::Display for FederationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FederationError::Config { what } => write!(f, "invalid federation config: {what}"),
            FederationError::Domain(e) => write!(f, "federation domain error: {e}"),
        }
    }
}

impl std::error::Error for FederationError {}

impl From<DomainError> for FederationError {
    fn from(e: DomainError) -> Self {
        FederationError::Domain(e)
    }
}

/// One configured FEDERATED stream of a gateway (#626): a stream that crosses the cluster boundary, named
/// by its ORIGIN domain (the cluster its records originate in) + the stream name within that origin, plus
/// the LOCAL stream this cluster materializes it as.
///
/// The ORIGIN DOMAIN is the loop-safety anchor: a gateway SERVES (to peers) exactly the federated streams
/// whose origin is its OWN domain, and MIRRORS (from peers) exactly the federated streams whose origin is a
/// PEER's domain. A stream is therefore an ORIGIN on exactly one cluster and a read-only MIRROR on every
/// other — a record crosses each federation link once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederatedStream {
    /// The ORIGIN domain: the cluster whose local produces are the source of this stream's records. If this
    /// equals THIS cluster's own domain, the gateway SERVES it to peers (it is locally originated); if it is
    /// a PEER's domain, the gateway MIRRORS it FROM that peer (read-only).
    pub origin: Domain,
    /// The stream name within the origin cluster (empty = the origin's default stream). When served, this is
    /// the origin stream the peer pulls; when mirrored, this is the peer-origin stream this gateway pulls.
    pub origin_stream: String,
    /// The LOCAL stream name in THIS cluster. For a peer-originated stream this is the read-only mirror this
    /// gateway materializes (its only writer is the geo apply path). For a self-originated (served) stream
    /// this is the local origin stream whose sealed bytes the gateway serves to peers.
    pub local_stream: String,
}

/// The whole GATEWAY FEDERATION configuration (#626): this cluster's OWN domain, the symmetric PEER gateway
/// endpoints (`domain -> gateway addr`, from `--gateway <domain>=<addr>`), and the declared federated
/// streams (from `--federate`). EMPTY (no own domain, no peers, no streams — the default) means NO
/// federation plane: the byte-identical non-federated path (nothing constructs).
///
/// The peer table is the EXPLICIT, fail-closed source of every peer address — a peer domain with no
/// `--gateway` entry never resolves (no auto-discovery), exactly the domain namespace's no-leakage rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FederationConfig {
    /// This cluster's OWN domain (its identity in the supercluster). `None` with no streams = the
    /// non-federated default. A federated stream whose origin equals this is SERVED; one whose origin is a
    /// peer is MIRRORED.
    pub own: Option<Domain>,
    /// The symmetric PEER gateway endpoints: `peer-domain -> gateway dial address`. The ONLY source of a
    /// peer's address (no auto-discovery). Sorted for a deterministic surface.
    pub peers: std::collections::BTreeMap<Domain, String>,
    /// The declared federated streams (one per `--federate`). Each is either served (origin == own) or
    /// mirrored (origin == a peer).
    pub streams: Vec<FederatedStream>,
}

/// A peer-originated stream this gateway MIRRORS: the geo origin (the peer gateway address + the
/// peer-origin stream) and the local read-only mirror stream it applies into. The connector side builds a
/// geo [`MirrorApplier`](super::geo::MirrorApplier) + [`pull_loop`](super::geo::pull_loop) from this, exactly
/// like a `--mirror`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirroredStream {
    /// The LOCAL read-only mirror stream this gateway materializes.
    pub local_stream: String,
    /// The geo origin to pull from: the PEER gateway's dial address + the peer-origin stream name.
    pub origin: GeoOrigin,
}

/// A self-originated stream this gateway SERVES to peers: the LOCAL origin stream whose sealed CRC-framed
/// bytes the gateway answers peer pulls from (via the geo [`OriginServer`](super::geo::OriginServer)), and
/// the origin stream NAME peers address it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedStream {
    /// The LOCAL origin stream whose sealed bytes are served to peers (a locally-produced stream).
    pub local_stream: String,
    /// The origin stream NAME a peer names in its pull request (the `origin_stream` of the
    /// [`FederatedStream`]).
    pub origin_stream: String,
}

impl FederationConfig {
    /// True if NO federation is configured — the byte-identical non-federated path (nothing constructs).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.own.is_none() && self.peers.is_empty() && self.streams.is_empty()
    }

    /// The LOCAL stream names that are READ-ONLY (the peer-originated mirror locals) — the streams a client
    /// produce must be rejected on, exactly the geo / leaf read-only set. A SELF-originated (served) stream
    /// is NOT read-only (it is this cluster's own locally-produced stream).
    #[must_use]
    pub fn read_only_streams(&self) -> Vec<String> {
        self.mirrored_streams()
            .into_iter()
            .map(|m| m.local_stream)
            .collect()
    }

    /// The peer-originated streams this gateway MIRRORS (origin domain is a PEER, not this cluster's own).
    /// Each resolves to a geo origin over the peer's `--gateway` address; the connector side drives them
    /// with the geo applier + pull loop, exactly like a `--mirror`. A stream whose origin is THIS cluster's
    /// own domain is NOT here (it is served, not mirrored) — the loop-safety core: a gateway never mirrors
    /// (or re-serves) its own origin.
    #[must_use]
    pub fn mirrored_streams(&self) -> Vec<MirroredStream> {
        self.streams
            .iter()
            .filter(|s| self.own.as_ref() != Some(&s.origin))
            .filter_map(|s| {
                self.peers.get(&s.origin).map(|addr| MirroredStream {
                    local_stream: s.local_stream.clone(),
                    origin: GeoOrigin {
                        addr: addr.clone(),
                        stream: s.origin_stream.clone(),
                    },
                })
            })
            .collect()
    }

    /// The self-originated streams this gateway SERVES to peers (origin domain == this cluster's own).
    /// EXACTLY the streams a record can leave this cluster ON; a peer-originated (mirrored) stream is NEVER
    /// here, so a record federated INTO this cluster is never re-served OUT — the no-loop guarantee. Empty
    /// when this cluster has no own domain (it can serve nothing it can call its own).
    #[must_use]
    pub fn served_streams(&self) -> Vec<ServedStream> {
        let Some(own) = self.own.as_ref() else {
            return Vec::new();
        };
        self.streams
            .iter()
            .filter(|s| &s.origin == own)
            .map(|s| ServedStream {
                local_stream: s.local_stream.clone(),
                origin_stream: s.origin_stream.clone(),
            })
            .collect()
    }

    /// The mirrored streams as geo [`GeoMode::Mirror`] modes over their peer gateway addresses — so the
    /// connector side is driven by the geo plane VERBATIM (a federation mirror IS a geo mirror of a peer's
    /// origin). Each returns `(local_stream, GeoMode)` ready for the geo applier/puller, the SAME shape a
    /// `--mirror` produces.
    #[must_use]
    pub fn mirror_geo_modes(&self) -> Vec<(String, GeoMode)> {
        self.mirrored_streams()
            .into_iter()
            .map(|m| (m.local_stream, GeoMode::Mirror(m.origin)))
            .collect()
    }

    /// Validate the federation config fail-closed. A non-empty config MUST be internally consistent:
    ///
    /// * every PEER named by a mirrored (peer-origin) stream MUST have a configured `--gateway` endpoint
    ///   (resolved fail-closed, never auto-discovered);
    /// * NO peer table entry may name this cluster's OWN domain (a cluster does not federate WITH itself);
    /// * NO two federated streams may share a LOCAL name (a local stream cannot be both two mirrors, or a
    ///   mirror and a served origin — the only config ways the origin-domain invariant could be subverted
    ///   into a loop);
    /// * a served (self-origin) stream requires this cluster to HAVE an own domain.
    ///
    /// # Errors
    /// [`FederationError::Config`] describing the first violation found, or [`FederationError::Domain`] if a
    /// peer-origin stream's domain has no configured gateway endpoint.
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.is_empty() {
            return Ok(());
        }
        // A peer must never be this cluster itself.
        if let Some(own) = self.own.as_ref() {
            if self.peers.contains_key(own) {
                return Err(FederationError::Config {
                    what: format!(
                        "peer table names this cluster's OWN domain `{own}`; a cluster does not \
                         federate with itself (remove the `--gateway {own}=...` self-entry)"
                    ),
                });
            }
        }
        // No two federated streams share a LOCAL name (would conflate two cross-cluster logs / let a mirror
        // and a served origin share one log — the config path to a loop).
        let mut seen_local: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for s in &self.streams {
            if !seen_local.insert(s.local_stream.as_str()) {
                return Err(FederationError::Config {
                    what: format!(
                        "local stream `{}` is declared by more than one `--federate`; each federated \
                         local stream name must be unique (a local log is either ONE peer's mirror or \
                         this cluster's own served origin, never both)",
                        s.local_stream
                    ),
                });
            }
        }
        for s in &self.streams {
            let is_self_origin = self.own.as_ref() == Some(&s.origin);
            if is_self_origin {
                // A served stream needs an own domain (guaranteed by is_self_origin, but be explicit).
                if self.own.is_none() {
                    return Err(FederationError::Config {
                        what: "a self-originated federated stream requires `--gateway-domain`"
                            .to_string(),
                    });
                }
            } else {
                // A peer-origin (mirrored) stream MUST have a configured peer gateway endpoint (fail-closed,
                // never auto-discovered) — the same no-leakage rule as the domain namespace.
                if !self.peers.contains_key(&s.origin) {
                    return Err(FederationError::Domain(DomainError::UnknownDomain {
                        domain: s.origin.as_str().to_string(),
                    }));
                }
            }
        }
        Ok(())
    }
}

/// Resolve a `--gateway <domain>=<addr>` peer endpoint spec into `(Domain, addr)` through the SAME
/// validation the domain namespace uses, fail-closed. The domain is parsed by [`Domain::parse`]; the
/// address is used verbatim (a raw `host:port`, like a geo origin address).
///
/// # Errors
/// [`FederationError::Domain`] if the domain segment is malformed, or [`FederationError::Config`] if the
/// address is empty.
pub fn parse_gateway_peer(domain: &str, addr: &str) -> Result<(Domain, String), FederationError> {
    let domain = Domain::parse(domain)?;
    if addr.is_empty() {
        return Err(FederationError::Config {
            what: format!(
                "`--gateway {domain}=` has an empty address; name the peer gateway `host:port`"
            ),
        });
    }
    Ok((domain, addr.to_string()))
}

/// Resolve a peer domain to its configured gateway address through a [`DomainResolver`] (so the federation
/// plane shares the geo plane's explicit `--cluster-link`/`--gateway` resolution surface). Returns the
/// resolved address. A self-domain or an unconfigured domain is a fail-closed typed error — never an
/// auto-discovered address.
///
/// This is offered for the CLI to resolve a `@domain`-style peer reference through the unified resolver; the
/// [`FederationConfig`] itself stores already-resolved addresses in its `peers` table.
///
/// # Errors
/// [`FederationError::Domain`] for a self-reference or an unknown domain.
pub fn resolve_peer_addr(
    resolver: &DomainResolver,
    domain: &Domain,
) -> Result<String, FederationError> {
    match resolver.link(domain) {
        Some(addr) => Ok(addr.to_string()),
        None => Err(FederationError::Domain(DomainError::UnknownDomain {
            domain: domain.as_str().to_string(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::geo::GeoMode;

    fn dom(s: &str) -> Domain {
        Domain::parse(s).unwrap()
    }

    fn cfg_west_east() -> FederationConfig {
        // `west` is THIS cluster; it peers `east`. `orders` originates in `west` (served); `events`
        // originates in `east` (mirrored).
        let mut peers = std::collections::BTreeMap::new();
        peers.insert(dom("east"), "10.0.0.2:7600".to_string());
        FederationConfig {
            own: Some(dom("west")),
            peers,
            streams: vec![
                FederatedStream {
                    origin: dom("west"),
                    origin_stream: "orders".to_string(),
                    local_stream: "orders".to_string(),
                },
                FederatedStream {
                    origin: dom("east"),
                    origin_stream: "events".to_string(),
                    local_stream: "east-events".to_string(),
                },
            ],
        }
    }

    #[test]
    fn empty_config_is_the_non_federated_default() {
        let cfg = FederationConfig::default();
        assert!(cfg.is_empty());
        assert!(cfg.read_only_streams().is_empty());
        assert!(cfg.mirrored_streams().is_empty());
        assert!(cfg.served_streams().is_empty());
        assert!(cfg.mirror_geo_modes().is_empty());
        cfg.validate().unwrap();
    }

    #[test]
    fn served_streams_are_self_origin_only_no_loop_core() {
        let cfg = cfg_west_east();
        // SERVED = only the self-originated `orders` (origin == own `west`). The peer-originated
        // `east-events` is NEVER served — a record federated IN is never re-served OUT (the no-loop core).
        let served = cfg.served_streams();
        assert_eq!(served.len(), 1);
        assert_eq!(served[0].local_stream, "orders");
        assert_eq!(served[0].origin_stream, "orders");
    }

    #[test]
    fn mirrored_streams_are_peer_origin_only() {
        let cfg = cfg_west_east();
        // MIRRORED = only the peer-originated `east-events` (origin == peer `east`), over east's gateway.
        let mirrored = cfg.mirrored_streams();
        assert_eq!(mirrored.len(), 1);
        assert_eq!(mirrored[0].local_stream, "east-events");
        assert_eq!(
            mirrored[0].origin,
            GeoOrigin {
                addr: "10.0.0.2:7600".to_string(),
                stream: "events".to_string()
            }
        );
        // The self-originated `orders` is NOT mirrored (it is served) — a gateway never mirrors its own.
        assert!(mirrored.iter().all(|m| m.local_stream != "orders"));
    }

    #[test]
    fn read_only_set_is_exactly_the_peer_mirrors() {
        let cfg = cfg_west_east();
        // Only the peer-origin mirror is read-only; the self-origin served stream is locally produced.
        assert_eq!(cfg.read_only_streams(), vec!["east-events".to_string()]);
    }

    #[test]
    fn mirror_geo_modes_drive_the_connector_like_a_geo_mirror() {
        let cfg = cfg_west_east();
        let modes = cfg.mirror_geo_modes();
        assert_eq!(modes.len(), 1);
        assert_eq!(modes[0].0, "east-events");
        assert_eq!(
            modes[0].1,
            GeoMode::Mirror(GeoOrigin {
                addr: "10.0.0.2:7600".to_string(),
                stream: "events".to_string()
            })
        );
    }

    #[test]
    fn config_rejects_a_peer_naming_this_clusters_own_domain() {
        let mut cfg = cfg_west_east();
        cfg.peers.insert(dom("west"), "self:1".to_string());
        assert!(matches!(
            cfg.validate(),
            Err(FederationError::Config { .. })
        ));
    }

    #[test]
    fn config_rejects_a_peer_origin_stream_with_no_gateway() {
        // `south` originates a federated stream but is NOT in the peer table -> fail-closed UnknownDomain.
        let cfg = FederationConfig {
            own: Some(dom("west")),
            peers: std::collections::BTreeMap::new(),
            streams: vec![FederatedStream {
                origin: dom("south"),
                origin_stream: "s".to_string(),
                local_stream: "south-s".to_string(),
            }],
        };
        assert!(matches!(
            cfg.validate(),
            Err(FederationError::Domain(DomainError::UnknownDomain { .. }))
        ));
    }

    #[test]
    fn config_rejects_two_federated_streams_sharing_a_local_name() {
        let mut peers = std::collections::BTreeMap::new();
        peers.insert(dom("east"), "e:1".to_string());
        peers.insert(dom("south"), "s:1".to_string());
        let cfg = FederationConfig {
            own: Some(dom("west")),
            peers,
            streams: vec![
                FederatedStream {
                    origin: dom("east"),
                    origin_stream: "a".to_string(),
                    local_stream: "shared".to_string(),
                },
                FederatedStream {
                    origin: dom("south"),
                    origin_stream: "b".to_string(),
                    local_stream: "shared".to_string(),
                },
            ],
        };
        assert!(matches!(
            cfg.validate(),
            Err(FederationError::Config { .. })
        ));
    }

    #[test]
    fn a_valid_symmetric_config_validates() {
        cfg_west_east().validate().unwrap();
    }

    #[test]
    fn parse_gateway_peer_validates_domain_and_addr() {
        let (d, a) = parse_gateway_peer("east", "10.0.0.2:7600").unwrap();
        assert_eq!(d.as_str(), "east");
        assert_eq!(a, "10.0.0.2:7600");
        // Empty addr fails closed.
        assert!(matches!(
            parse_gateway_peer("east", ""),
            Err(FederationError::Config { .. })
        ));
        // Bad domain fails closed.
        assert!(matches!(
            parse_gateway_peer("East", "a:1"),
            Err(FederationError::Domain(DomainError::BadChar { .. }))
        ));
    }

    #[test]
    fn no_own_domain_serves_nothing() {
        // A config with peers + mirrors but NO own domain mirrors peer streams but serves nothing.
        let mut peers = std::collections::BTreeMap::new();
        peers.insert(dom("east"), "e:1".to_string());
        let cfg = FederationConfig {
            own: None,
            peers,
            streams: vec![FederatedStream {
                origin: dom("east"),
                origin_stream: "events".to_string(),
                local_stream: "east-events".to_string(),
            }],
        };
        assert!(cfg.served_streams().is_empty());
        assert_eq!(cfg.mirrored_streams().len(), 1);
        cfg.validate().unwrap();
    }
}
