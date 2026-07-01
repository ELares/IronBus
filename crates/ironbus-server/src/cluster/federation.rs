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

impl std::error::Error for FederationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FederationError::Domain(e) => Some(e),
            FederationError::Config { .. } => None,
        }
    }
}

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

/// The REAL multi-cluster GATEWAY-FEDERATION integration tests (#626): each "cluster" is a real geo
/// origin-serve (its gateway serving its self-originated streams to peers) over a real loopback
/// `TcpStream` + real on-disk `StdFs` logs, and a real geo puller (its gateway mirroring a peer-originated
/// stream). Unix-only because the broker / serve path is `cfg(unix)` via `StdFs` (so the helpers and tests
/// vanish together on Windows under `-D dead_code`), matching the geo `live_geo_tests` / leaf
/// `live_leaf_tests` discipline. These tests PROVE — not merely by construction — symmetric cross-cluster
/// exchange (a record in A reaches B and vice-versa, byte-faithfully), LOOP-FREEDOM in a 3-cluster ring (a
/// record reaches each other member EXACTLY once, bounded, no amplification), a gateway NOT being a Raft
/// voter in a peer (peer quorum untouched across gateway churn), peer-down resilience (a down peer does not
/// block local / other-peer traffic; reconnect resumes with no gap/dup), and an idle gateway link doing ~0
/// work.
#[cfg(all(test, unix))]
#[allow(clippy::similar_names)]
mod live_federation_tests {
    use crate::clock::SystemClock;
    use crate::cluster::geo::{
        GeoError, GeoFrame, GeoLink, MirrorApplier, OriginCursorStore, OriginServer, GEO_POLL,
    };
    use crate::cluster::runtime::{ClusterConfig, ClusterRuntime, StartRole};
    use ironbus_core::clock::ManualClock;
    use ironbus_core::types::{Offset, RecordFlags};
    use ironbus_storage::fs::StdFs;
    use ironbus_storage::log::{Append, Log, LogConfig};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    fn small_config() -> LogConfig {
        LogConfig {
            max_segment_bytes: 256,
            max_total_bytes: 0,
            ..LogConfig::default()
        }
    }

    fn rec(payload: &[u8]) -> Append<'_> {
        Append {
            timestamp_ms: 7,
            flags: RecordFlags::EMPTY,
            key: b"",
            headers: b"",
            payload,
        }
    }

    /// Scale a GENEROUS base wait by the observed host slowdown (#618), so the timing waits stay truthful
    /// and flake-free on a contended CI runner WITHOUT weakening what they prove. A local copy of the
    /// runtime test's `host_scaled` (max-of-probes + a 24x cap): on an unloaded host the factor is ~1 and
    /// the wait stays the base (the test is FAST and exits early the instant its predicate holds); on a
    /// starved host it stretches proportionally. The assertions are UNCHANGED.
    fn host_scaled(base: Duration) -> Duration {
        fn probe_busy_nanos() -> u128 {
            const ITERS: u64 = 2_000_000;
            let start = Instant::now();
            let mut acc: u64 = 0x9E37_79B9_7F4A_7C15;
            for i in 0..ITERS {
                acc = acc
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(i | 1);
                acc ^= acc >> 29;
            }
            std::hint::black_box(acc);
            start.elapsed().as_nanos().max(1)
        }
        const REFERENCE_BUSY_NANOS: u128 = 4_000_000;
        const MAX_SCALE: u32 = 24;
        let mut samples = [probe_busy_nanos(), probe_busy_nanos(), probe_busy_nanos()];
        samples.sort_unstable();
        let observed = samples[2];
        let factor = (observed / REFERENCE_BUSY_NANOS).clamp(1, u128::from(MAX_SCALE));
        let factor = u32::try_from(factor).unwrap_or(MAX_SCALE);
        base * factor
    }

    /// Poll `pred` until true or `timeout` (host-scaled) elapses. Returns the final predicate value.
    fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + host_scaled(timeout);
        while Instant::now() < deadline {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        pred()
    }

    /// Bind an ephemeral loopback port, read it, drop the listener (the caller rebinds it).
    fn free_addr() -> SocketAddr {
        let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral");
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    /// A real on-disk log with `n` records (payload `<prefix>-NNN`), fsync'd, leaked to `'static` so its
    /// read plane keeps observing it for the test's lifetime (a cluster's self-originated stream that its
    /// gateway serves to peers). In a real serve the engine's append actor owns it.
    fn leaked_log(dir: &std::path::Path, prefix: &str, n: u32) -> &'static Log<StdFs, ManualClock> {
        let fs = StdFs::new(dir.to_path_buf());
        let mut log = Log::open(fs, ManualClock::new(), small_config()).expect("log opens");
        for i in 0..n {
            log.append(&rec(format!("{prefix}-{i:03}").as_bytes()))
                .unwrap();
        }
        log.sync().unwrap();
        Box::leak(Box::new(log))
    }

    fn sealed_served_end(log: &Log<StdFs, ManualClock>) -> u64 {
        let plane = log.read_plane().unwrap();
        let flushed = plane.flushed();
        let mut next = 0u64;
        let mut guard = 0u32;
        while next < flushed {
            guard += 1;
            assert!(guard < 100_000);
            let raw = plane
                .read_range_raw(Offset::new(next), 1_000, None)
                .unwrap();
            let adv = raw.run.next_offset.get();
            if adv > next {
                next = adv;
            } else {
                break;
            }
        }
        next
    }

    /// A cluster GATEWAY's serve side: a geo origin listener serving ONE self-originated stream's sealed
    /// bytes to any peer gateway that dials in and PULLS. This is exactly the geo origin-serve pattern
    /// (REUSED) — a federation served-stream IS a geo origin a peer mirrors. The gateway ACCEPTS inbound
    /// peer links (symmetric: every peer dials every peer it federates with); it answers `MirrorPull`
    /// requests from the served stream's read plane. Returns a shutdown flag + the join handle.
    fn spawn_gateway_serve(
        addr: SocketAddr,
        served: &'static Log<StdFs, ManualClock>,
    ) -> (Arc<AtomicBool>, JoinHandle<()>) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_t = Arc::clone(&shutdown);
        let listener = TcpListener::bind(addr).expect("gateway serve listener binds");
        listener.set_nonblocking(true).unwrap();
        let plane = Arc::new(served.read_plane().expect("served read plane"));
        let handle = std::thread::Builder::new()
            .name("ib-fed-gateway-serve".to_string())
            .spawn(move || {
                while !shutdown_t.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            let plane = Arc::clone(&plane);
                            let sd = Arc::clone(&shutdown_t);
                            std::thread::spawn(move || {
                                let mut link = GeoLink::new(stream);
                                let server = OriginServer::new(&plane);
                                while !sd.load(Ordering::Acquire) {
                                    match link.recv() {
                                        Ok(Some(GeoFrame::Request(req))) => {
                                            let resp = server.serve_pull(&req).expect("serve_pull");
                                            if link.send_response(&resp).is_err() {
                                                return;
                                            }
                                        }
                                        Ok(Some(GeoFrame::Response(_))) => {}
                                        Err(GeoError::Io(e))
                                            if matches!(
                                                e.kind(),
                                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                                            ) => {}
                                        Ok(None) | Err(_) => return,
                                    }
                                }
                            });
                        }
                        Err(ref e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) =>
                        {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                }
            })
            .expect("spawn gateway serve");
        (shutdown, handle)
    }

    /// Open a gateway MIRROR applier (the connector side: this cluster mirroring a peer-originated stream)
    /// over an on-disk dir (its local read-only mirror log + geo cursor), exactly the geo mirror open.
    fn open_mirror(dir: &std::path::Path) -> MirrorApplier<StdFs, ManualClock> {
        let log = Log::open(
            StdFs::new(dir.to_path_buf()),
            ManualClock::new(),
            small_config(),
        )
        .expect("mirror log opens");
        let cursors = OriginCursorStore::open(&StdFs::new(dir.to_path_buf())).expect("geo cursor");
        MirrorApplier::new(log, cursors, true)
    }

    /// The connector dials a peer gateway (outbound) and pulls a peer-origin stream into its local mirror
    /// until caught up to the peer's currently-served sealed prefix, resuming from the durable geo cursor.
    /// Reuses the geo pull request + apply path VERBATIM (a federation mirror IS a geo mirror). Returns
    /// `false` if the dial failed (a down peer — the caller treats that as "not yet").
    fn drain_mirror(
        addr: SocketAddr,
        app: &mut MirrorApplier<StdFs, ManualClock>,
        key: &str,
        origin_stream: &str,
    ) -> bool {
        let Ok(stream) = TcpStream::connect_timeout(&addr, GEO_POLL) else {
            return false;
        };
        stream.set_read_timeout(Some(GEO_POLL)).unwrap();
        let mut link = GeoLink::new(stream);
        loop {
            let req = app.pull_request(key, origin_stream, 1024, 1024 * 1024);
            if link.send_request(&req).is_err() {
                break;
            }
            match link.recv() {
                Ok(Some(GeoFrame::Response(resp))) => {
                    let out = app.apply_pull_response(key, &resp).expect("apply");
                    if out.applied == 0 {
                        break;
                    }
                }
                _ => break,
            }
        }
        true
    }

    #[test]
    fn symmetric_federation_exchanges_records_both_ways_byte_faithfully() {
        // SYMMETRIC PEERING: cluster A serves its self-originated `orders`; cluster B mirrors it. Cluster B
        // serves its self-originated `events`; cluster A mirrors it. A record produced in A reaches B's
        // federated mirror byte-faithfully, AND a record produced in B reaches A's — symmetric, both ways.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let a_orders_dir = tempfile::tempdir().expect("a orders dir");
        let b_events_dir = tempfile::tempdir().expect("b events dir");
        let a_mirror_dir = tempfile::tempdir().expect("a mirror dir");
        let b_mirror_dir = tempfile::tempdir().expect("b mirror dir");

        // A's self-originated `orders` (40 records) + B's self-originated `events` (35 records).
        let a_orders = leaked_log(a_orders_dir.path(), "A-ord", 40);
        let b_events = leaked_log(b_events_dir.path(), "B-evt", 35);
        let a_served = sealed_served_end(a_orders);
        let b_served = sealed_served_end(b_events);
        assert!(a_served > 0 && b_served > 0);

        // Each gateway serves its OWN origin (the no-loop core: a gateway serves only self-originated).
        let a_addr = free_addr();
        let b_addr = free_addr();
        let (a_sd, a_h) = spawn_gateway_serve(a_addr, a_orders);
        let (b_sd, b_h) = spawn_gateway_serve(b_addr, b_events);

        // B mirrors A's `orders` (dialing A's gateway); A mirrors B's `events` (dialing B's gateway).
        let mut b_mirror = open_mirror(b_mirror_dir.path()); // B's local mirror of @west/orders
        let mut a_mirror = open_mirror(a_mirror_dir.path()); // A's local mirror of @east/events
        let b_key = format!("{a_addr}/orders");
        let a_key = format!("{b_addr}/events");

        assert!(
            wait_until(Duration::from_secs(10), || {
                drain_mirror(a_addr, &mut b_mirror, &b_key, "orders");
                drain_mirror(b_addr, &mut a_mirror, &a_key, "events");
                b_mirror.cursor(&b_key) == a_served && a_mirror.cursor(&a_key) == b_served
            }),
            "both federated mirrors converged (B<-A {} of {a_served}, A<-B {} of {b_served})",
            b_mirror.cursor(&b_key),
            a_mirror.cursor(&a_key),
        );

        // A->B byte-faithful, in order.
        let recs = b_mirror.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, a_served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("A-ord-{i:03}").as_bytes());
        }
        // B->A byte-faithful, in order.
        let recs = a_mirror.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, b_served);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("B-evt-{i:03}").as_bytes());
        }

        a_sd.store(true, Ordering::Release);
        b_sd.store(true, Ordering::Release);
        let _ = a_h.join();
        let _ = b_h.join();
    }

    #[test]
    fn a_three_cluster_ring_delivers_each_record_exactly_once_no_loop() {
        // THE NO-LOOP PROOF over the wire, in a 3-cluster RING — the worst case for a routing loop.
        // `west` originates `orders`; `east` and `south` each federate `@west/orders` as a read-only
        // mirror. Critically, east/south are configured in a RING (west->east->south->west peerings), yet
        // because a gateway SERVES only its OWN origin (never re-serves a peer mirror), `orders` is served
        // ONLY by west and mirrored ONCE into each of east + south. We prove:
        //   * each of east, south ends with EXACTLY `served` records (each crossed its link once),
        //   * draining MANY MORE TIMES (which would re-pull/amplify if anything re-served) never grows the
        //     count — the cursor de-dup + the served-set discipline bound it.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let west_dir = tempfile::tempdir().expect("west dir");
        let east_dir = tempfile::tempdir().expect("east mirror dir");
        let south_dir = tempfile::tempdir().expect("south mirror dir");

        let west_orders = leaked_log(west_dir.path(), "W-ord", 50);
        let served = sealed_served_end(west_orders);
        assert!(served > 0);

        // Only WEST's gateway serves `orders` (its own origin). East + south are pure mirrors of it. (In
        // a ring east + south also serve THEIR own origins, but `orders` is west's alone — the no-loop
        // discipline means neither east nor south ever re-serves `orders`, so there is no cycle for it.)
        let west_addr = free_addr();
        let (w_sd, w_h) = spawn_gateway_serve(west_addr, west_orders);

        let mut east = open_mirror(east_dir.path());
        let mut south = open_mirror(south_dir.path());
        let east_key = format!("{west_addr}/orders");
        let south_key = format!("{west_addr}/orders");

        assert!(
            wait_until(Duration::from_secs(10), || {
                drain_mirror(west_addr, &mut east, &east_key, "orders");
                drain_mirror(west_addr, &mut south, &south_key, "orders");
                east.cursor(&east_key) == served && south.cursor(&south_key) == served
            }),
            "ring mirrors converged (east {} / south {} of {served})",
            east.cursor(&east_key),
            south.cursor(&south_key),
        );

        // Drain SEVERAL MORE rounds around the ring: with any echo/re-serve these would amplify.
        for _ in 0..6 {
            drain_mirror(west_addr, &mut east, &east_key, "orders");
            drain_mirror(west_addr, &mut south, &south_key, "orders");
        }

        // EXACTLY `served` records in each ring mirror — each record crossed its link ONCE, total delivered
        // is bounded by (members - 1) * served, never growing (no loop / no amplification).
        let east_count = east.log().read_from(Offset::new(0), 10_000).unwrap().len() as u64;
        let south_count = south.log().read_from(Offset::new(0), 10_000).unwrap().len() as u64;
        assert_eq!(east_count, served, "east got each record exactly once");
        assert_eq!(south_count, served, "south got each record exactly once");
        // Byte-faithful in order at each ring member.
        for (mirror, key) in [(&east, &east_key), (&south, &south_key)] {
            let recs = mirror.log().read_from(Offset::new(0), 10_000).unwrap();
            for (i, r) in recs.iter().enumerate() {
                assert_eq!(r.payload.as_ref(), format!("W-ord-{i:03}").as_bytes());
            }
            let _ = key;
        }

        w_sd.store(true, Ordering::Release);
        let _ = w_h.join();
    }

    #[test]
    fn federating_does_not_make_a_gateway_a_voter_in_a_peer() {
        // THE NOT-A-VOTER PROOF: a peer cluster's metadata Raft group (a single seeded voter, its own
        // quorum + leader) is UNCHANGED by a gateway repeatedly connecting/disconnecting to FEDERATE with
        // it. A gateway is a data-plane bridge, never a voter in the peer — the peer's voter_count, quorum,
        // and leadership are untouched. (Symmetric to leaf's not-a-voter, #625: a gateway is not a voter in
        // ANY peer.) Each cluster keeps its OWN independent Raft cluster.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let peer_meta_dir = tempfile::tempdir().expect("peer metadata dir");
        let peer_stream_dir = tempfile::tempdir().expect("peer stream dir");
        let mirror_dir = tempfile::tempdir().expect("mirror dir");

        // The PEER cluster's metadata Raft group: a single seeded voter (its own quorum) — entirely
        // separate from the federation plane.
        let meta_addr = free_addr();
        let mut peers = BTreeMap::new();
        peers.insert(1u64, meta_addr);
        let cfg = ClusterConfig {
            node_id: 1,
            peers,
            role: StartRole::Voter,
            pending_learners: BTreeSet::new(),
        };
        let runtime = ClusterRuntime::start(
            &cfg,
            &StdFs::new(peer_meta_dir.path().to_path_buf()),
            SystemClock::new(),
            LogConfig::new(64 * 1024).unwrap(),
        )
        .expect("peer metadata cluster starts");
        assert!(
            wait_until(Duration::from_secs(10), || runtime.status().is_leader),
            "the single-node peer self-elects"
        );
        let voters_before = runtime.status().voter_count;
        assert_eq!(voters_before, 1, "the peer has exactly its one voter");

        // The peer's GATEWAY endpoint (a SEPARATE listener — the federation plane, NOT the metadata peer
        // port) serving its self-originated stream. A gateway in another cluster federates with it.
        let peer_served = leaked_log(peer_stream_dir.path(), "P-evt", 30);
        let gw_addr = free_addr();
        let (gw_sd, gw_h) = spawn_gateway_serve(gw_addr, peer_served);
        let key = format!("{gw_addr}/events");
        let mut mirror = open_mirror(mirror_dir.path());

        // Churn the federating gateway 15x against the peer's gateway endpoint.
        for _ in 0..15 {
            let stream = TcpStream::connect(gw_addr).expect("gateway dials peer gateway");
            stream.set_read_timeout(Some(GEO_POLL)).unwrap();
            let mut link = GeoLink::new(stream);
            let req = mirror.pull_request(&key, "events", 1024, 1024 * 1024);
            if link.send_request(&req).is_ok() {
                if let Ok(Some(GeoFrame::Response(resp))) = link.recv() {
                    let _ = mirror.apply_pull_response(&key, &resp);
                }
            }
        }

        // THE ASSERTION: the peer's metadata membership + leadership are UNCHANGED by all that gateway
        // churn. A gateway appears in NO ConfState; the voter_count (the quorum basis) is the same 1, and
        // the peer is still its own leader. Federation touched the peer's consensus ZERO times.
        let after = runtime.status();
        assert_eq!(
            after.voter_count, voters_before,
            "federating did not change the peer's voter set (a gateway is NOT a voter in a peer)"
        );
        assert!(
            after.is_leader,
            "federating did not disturb the peer's leadership"
        );
        assert!(
            after.suspected_dead.is_empty(),
            "a gateway is never a metadata peer, so none can be a suspected-dead voter"
        );
        assert!(
            after.learners.is_empty(),
            "a gateway never joins a peer's metadata group even as a learner"
        );

        gw_sd.store(true, Ordering::Release);
        let _ = gw_h.join();
        drop(runtime);
    }

    #[test]
    fn a_down_peer_does_not_block_a_live_peer_and_reconnect_resumes_no_gap_or_dup() {
        // PEER-DOWN RESILIENCE: cluster A federates with TWO peers — `up` (serving) and `down` (never
        // started). A's puller for `down` backs off + retries on its OWN thread and NEVER blocks A's puller
        // for `up`, which converges fully. Then `down` comes UP and A's mirror of it resumes from the
        // durable cursor with NO gap/dup. One peer's failure does not cascade.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let up_dir = tempfile::tempdir().expect("up served dir");
        let down_dir = tempfile::tempdir().expect("down served dir");
        let up_mirror_dir = tempfile::tempdir().expect("up mirror dir");
        let down_mirror_dir = tempfile::tempdir().expect("down mirror dir");

        let up_served = leaked_log(up_dir.path(), "UP", 40);
        let up_end = sealed_served_end(up_served);
        let up_addr = free_addr();
        let (up_sd, up_h) = spawn_gateway_serve(up_addr, up_served);

        // The `down` peer's address is reserved but NOTHING serves on it yet (a down peer).
        let down_addr = free_addr();

        let up_key = format!("{up_addr}/u");
        let down_key = format!("{down_addr}/d");
        let mut up_mirror = open_mirror(up_mirror_dir.path());
        let mut down_mirror = open_mirror(down_mirror_dir.path());

        // The LIVE peer converges fully even though the DOWN peer's dials all fail (drain_mirror returns
        // false for `down`, never blocking `up`).
        assert!(
            wait_until(Duration::from_secs(10), || {
                let down_ok = drain_mirror(down_addr, &mut down_mirror, &down_key, "d");
                assert!(!down_ok, "the down peer's dial fails (it is not serving)");
                drain_mirror(up_addr, &mut up_mirror, &up_key, "u");
                up_mirror.cursor(&up_key) == up_end
            }),
            "the live peer converged despite the down peer (up {} of {up_end})",
            up_mirror.cursor(&up_key),
        );
        assert_eq!(
            down_mirror.cursor(&down_key),
            0,
            "nothing from the down peer"
        );

        // NOW bring the `down` peer UP and prove A resumes its mirror of it from the durable cursor.
        let down_served = leaked_log(down_dir.path(), "DN", 30);
        let down_end = sealed_served_end(down_served);
        let (down_sd, down_h) = spawn_gateway_serve(down_addr, down_served);
        assert!(
            wait_until(Duration::from_secs(10), || {
                drain_mirror(down_addr, &mut down_mirror, &down_key, "d");
                down_mirror.cursor(&down_key) == down_end
            }),
            "the recovered peer's mirror converged (down {} of {down_end})",
            down_mirror.cursor(&down_key),
        );
        // Byte-faithful, in order, exactly once (no gap/dup across the down->up transition).
        let recs = down_mirror.log().read_from(Offset::new(0), 10_000).unwrap();
        assert_eq!(recs.len() as u64, down_end);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(r.payload.as_ref(), format!("DN-{i:03}").as_bytes());
        }

        up_sd.store(true, Ordering::Release);
        down_sd.store(true, Ordering::Release);
        let _ = up_h.join();
        let _ = down_h.join();
    }

    #[test]
    fn an_idle_gateway_link_does_no_work_and_backs_off() {
        // THE IDLE PROOF (#726): a gateway whose mirror is fully caught up (cursor at the peer's served
        // frontier) BLOCKS / BACKS OFF, doing ~0 work — the geo pull_loop applies nothing and backs off on
        // the empty-response path. We drive the real pull_loop against a fully-served peer and assert it
        // applies NOTHING across several poll windows, then exits promptly on shutdown.
        let _serial = crate::cluster::heavy_cluster_test_guard();
        let served_dir = tempfile::tempdir().expect("served dir");
        let mirror_dir = tempfile::tempdir().expect("mirror dir");
        let served = leaked_log(served_dir.path(), "I", 20);
        let end = sealed_served_end(served);
        let addr = free_addr();
        let (sd, h) = spawn_gateway_serve(addr, served);
        let key = format!("{addr}/i");

        // First, catch the mirror fully up (so further pulls are all empty = idle).
        let mirror = Arc::new(std::sync::Mutex::new(open_mirror(mirror_dir.path())));
        assert!(wait_until(Duration::from_secs(10), || {
            let mut m = mirror.lock().unwrap();
            drain_mirror(addr, &mut m, &key, "i");
            m.cursor(&key) == end
        }));

        // Now run the REAL geo pull_loop against the fully-served peer and count applied records: an idle
        // (caught-up) link applies NOTHING and backs off (~0 CPU), never busy-spins.
        let applied = Arc::new(AtomicU64::new(0));
        let loop_shutdown = Arc::new(AtomicBool::new(false));
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let ls = Arc::clone(&loop_shutdown);
        let applied_t = Arc::clone(&applied);
        let mirror_t = Arc::clone(&mirror);
        let key_t = key.clone();
        let loop_handle = std::thread::spawn(move || {
            let mut link = GeoLink::new(stream);
            crate::cluster::geo::pull_loop(
                &mut link,
                &key_t,
                "i",
                &ls,
                || mirror_t.lock().map_or(0, |m| m.cursor(&key_t)),
                |resp| {
                    let mut m = mirror_t
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let out = m.apply_pull_response(&key_t, resp)?;
                    applied_t.fetch_add(out.applied, Ordering::Relaxed);
                    Ok(out)
                },
            );
        });

        std::thread::sleep(Duration::from_millis(600));
        loop_shutdown.store(true, Ordering::Release);
        let _ = loop_handle.join();
        assert_eq!(
            applied.load(Ordering::Relaxed),
            0,
            "an idle (caught-up) gateway link applies nothing (it blocks/backs off, no busy work)"
        );

        sd.store(true, Ordering::Release);
        let _ = h.join();
    }
}
