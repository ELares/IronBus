// SPDX-License-Identifier: MIT OR Apache-2.0
//! Connection-signal ("connz") metrics (#572): the broker's CONNECTION-LEVEL observability, shared
//! across the wire-server accept loop, the per-connection handler threads, and the `/metrics`
//! scrape via an `Arc<ConnectionMetrics>`.
//!
//! These signals live OUTSIDE the engine (connections are accepted, closed, refused, and
//! authenticated entirely off the append actor's single-writer lock), so the metric is a set of
//! plain lock-free atomics, NOT engine state. The hot path (accept / close / refuse / authed-flip)
//! is a single relaxed atomic add — no lock, no allocation — so leaving the connz metrics on costs
//! nothing measurable even under a connection flood, and the scrape reads a consistent-enough
//! snapshot off-lock.
//!
//! # Cardinality
//!
//! Connz is a FIXED set of scalar gauges/counters (total accepted, total closed, total refused,
//! currently-open, total authenticated) plus ONE labeled counter family,
//! `ironbus_connections_rejected_total{reason}` (#633): the pre-auth `DoS` rejections, with a `reason`
//! label drawn from a FIXED, four-value enum ([`RejectReason`]). There is NO per-connection-id,
//! per-peer, or per-address label — a connection id (or a source IP) is exactly the kind of
//! unbounded, per-connection label the #576 cardinality firewall forbids; the `reason` label is a
//! closed enum, so the surface is bounded BY CONSTRUCTION regardless of how many connections the
//! broker has ever served or how many distinct attackers it has rejected.

use std::sync::atomic::{AtomicU64, Ordering};

/// The bounded reason an UNAUTHENTICATED connection was rejected by a pre-auth `DoS` defense (#633),
/// the `reason` label on `ironbus_connections_rejected_total`. It is a CLOSED four-value enum so the
/// labeled family is low-cardinality by construction (the #576 firewall's `reason` key is already
/// allowlisted): a per-IP or per-connection label here would be the unbounded footgun the firewall
/// forbids, so the SOURCE of the rejection is never a label — only its bounded class is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The per-source-IP new-connection token bucket was empty: this source connected faster than its
    /// configured sustained rate. `reason="rate_limited"`.
    RateLimited,
    /// The global half-open (accepted-but-not-yet-authenticated) connection cap was full: too many
    /// connections are mid-handshake, so a new one is refused before it can consume handshake work.
    /// `reason="half_open_cap"`.
    HalfOpenCap,
    /// The source IP is in its failed-auth lockout cooldown: it exceeded the failed-auth threshold
    /// within the window, so new connections from it are refused until the cooldown lapses.
    /// `reason="locked_out"`.
    LockedOut,
    /// An authentication attempt FAILED (a bad/unmatched credential, an unknown mechanism, or a
    /// missing credential on an auth-required broker). Counted at the failure, distinct from the
    /// pre-connection refusals above. `reason="auth_failed"`.
    AuthFailed,
}

impl RejectReason {
    /// The fixed, lowercase wire/label value. A closed set, so the `reason` label stays bounded.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::RateLimited => "rate_limited",
            RejectReason::HalfOpenCap => "half_open_cap",
            RejectReason::LockedOut => "locked_out",
            RejectReason::AuthFailed => "auth_failed",
        }
    }
}

/// The shared, lock-free connection-signal counters (#572). Created ONCE at broker bootstrap and
/// shared (via `Arc`) between the wire-server accept loop / handler threads (which RECORD) and the
/// health server (which READS a snapshot for `/metrics`). Every record is a single relaxed atomic
/// add, so it never locks, never allocates, and never touches the engine.
///
/// All counters are MONOTONIC totals except `currently_open`, a live gauge maintained as
/// `accepted - closed` incrementally (bumped on accept, decremented on close) so the scrape need not
/// recompute it. A close is recorded exactly once per accepted connection (the handler's RAII guard),
/// so `currently_open` never underflows in practice; the decrement saturates at zero defensively.
#[derive(Debug, Default)]
pub struct ConnectionMetrics {
    /// `ironbus_connections_accepted_total`: connections accepted into a handler over the broker's
    /// life (the connection became live and got its own handler thread). Monotonic.
    accepted: AtomicU64,
    /// `ironbus_connections_closed_total`: accepted connections that have since closed (the handler
    /// returned or unwound). Monotonic. `accepted - closed == currently_open`.
    closed: AtomicU64,
    /// `ironbus_connections_refused_total`: connections REFUSED before becoming a live handler (the
    /// connection cap was full, or a transient accept error). Monotonic. A refused connection never
    /// counts toward `accepted`/`closed`/`currently_open`.
    refused: AtomicU64,
    /// `ironbus_connections_open`: connections currently live (a gauge), maintained incrementally as
    /// accept-minus-close so the scrape reads it directly. Saturating at zero on the decrement.
    currently_open: AtomicU64,
    /// `ironbus_connections_authenticated_total`: connections whose `Connect` handshake successfully
    /// AUTHENTICATED against the configured identity table (#631). Monotonic. Zero on a no-auth
    /// (zero-config loopback-dev) broker, which authenticates nothing.
    authenticated: AtomicU64,
    /// `ironbus_connections_rejected_total{reason="rate_limited"}` (#633): connections refused because
    /// the per-source-IP new-connection token bucket was empty. Monotonic. Zero when no per-IP rate
    /// limit is configured. A separate atomic per reason keeps the record path a single relaxed add
    /// with NO map and NO label allocation (the label is materialized only at scrape time).
    rejected_rate_limited: AtomicU64,
    /// `ironbus_connections_rejected_total{reason="half_open_cap"}` (#633): connections refused
    /// because the global half-open (accepted-but-not-yet-authed) cap was full. Monotonic.
    rejected_half_open_cap: AtomicU64,
    /// `ironbus_connections_rejected_total{reason="locked_out"}` (#633): connections refused because
    /// the source IP was in its failed-auth lockout cooldown. Monotonic.
    rejected_locked_out: AtomicU64,
    /// `ironbus_connections_rejected_total{reason="auth_failed"}` (#633): authentication attempts that
    /// FAILED (bad/unmatched/missing credential, or unknown mechanism). Monotonic. Zero on a no-auth
    /// broker, which authenticates nothing and so fails nothing.
    rejected_auth_failed: AtomicU64,
}

impl ConnectionMetrics {
    /// Constructs an all-zero connection-metrics set.
    #[must_use]
    pub fn new() -> ConnectionMetrics {
        ConnectionMetrics::default()
    }

    /// Records one connection ACCEPTED (it became live and got a handler): bump the accepted total
    /// and the live gauge. Lock-free; called from the accept loop, off the engine lock.
    pub fn record_accept(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        self.currently_open.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one accepted connection CLOSED (the handler returned or unwound): bump the closed
    /// total and decrement the live gauge (saturating at zero, so a double-close can never underflow
    /// the gauge). Lock-free; called from the handler's RAII drop guard, off the engine lock.
    pub fn record_close(&self) {
        self.closed.fetch_add(1, Ordering::Relaxed);
        // Saturating decrement: load-then-CAS-down, but a simple fetch_update keeps it lock-free and
        // never wraps below zero even under a (defended-against) double close.
        let _ = self
            .currently_open
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    /// Records one connection REFUSED before it became a live handler (the connection cap was full,
    /// or a transient accept error): bump the refused total only (it never entered the live gauge).
    /// Lock-free; called from the accept loop, off the engine lock.
    pub fn record_refused(&self) {
        self.refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one connection AUTHENTICATED (its `Connect` handshake resolved a valid credential):
    /// bump the authenticated total. Lock-free; called from the handler thread at the authed-flip,
    /// off the engine lock.
    pub fn record_authenticated(&self) {
        self.authenticated.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one PRE-AUTH `DoS` rejection (#633) by its bounded [`RejectReason`]: bump the per-reason
    /// total. Lock-free (a single relaxed atomic add into one of four fixed atomics, NO map, NO label
    /// allocation), so an unauthenticated connection FLOOD costs one atomic per rejection and never
    /// touches the engine. The `reason` label is materialized only at scrape time, so the record path
    /// stays O(1) and the metric stays bounded (a closed four-value enum, never a per-IP label).
    pub fn record_rejected(&self, reason: RejectReason) {
        let counter = match reason {
            RejectReason::RateLimited => &self.rejected_rate_limited,
            RejectReason::HalfOpenCap => &self.rejected_half_open_cap,
            RejectReason::LockedOut => &self.rejected_locked_out,
            RejectReason::AuthFailed => &self.rejected_auth_failed,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Reads a consistent-enough snapshot of every counter for the `/metrics` scrape. Each load is
    /// relaxed and independent (no global lock), so the five values may be from infinitesimally
    /// different instants under concurrent connection churn — acceptable for a monitoring scrape, and
    /// the alternative (a lock) would put the scrape on the connection hot path.
    #[must_use]
    pub fn snapshot(&self) -> ConnectionMetricsSnapshot {
        ConnectionMetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            currently_open: self.currently_open.load(Ordering::Relaxed),
            authenticated: self.authenticated.load(Ordering::Relaxed),
            rejected_rate_limited: self.rejected_rate_limited.load(Ordering::Relaxed),
            rejected_half_open_cap: self.rejected_half_open_cap.load(Ordering::Relaxed),
            rejected_locked_out: self.rejected_locked_out.load(Ordering::Relaxed),
            rejected_auth_failed: self.rejected_auth_failed.load(Ordering::Relaxed),
        }
    }
}

/// An off-lock snapshot of the connection-signal counters (#572), read once per `/metrics` scrape and
/// rendered by [`crate::health`]. A plain `Copy` value object so it crosses into the renderer without
/// holding the shared atomics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectionMetricsSnapshot {
    /// Connections accepted over the broker's life (`ironbus_connections_accepted_total`).
    pub accepted: u64,
    /// Accepted connections that have since closed (`ironbus_connections_closed_total`).
    pub closed: u64,
    /// Connections refused before becoming a live handler (`ironbus_connections_refused_total`).
    pub refused: u64,
    /// Connections currently live (`ironbus_connections_open`).
    pub currently_open: u64,
    /// Connections that authenticated (`ironbus_connections_authenticated_total`).
    pub authenticated: u64,
    /// Pre-auth rejections for an empty per-IP rate-limit bucket (#633),
    /// `ironbus_connections_rejected_total{reason="rate_limited"}`.
    pub rejected_rate_limited: u64,
    /// Pre-auth rejections for a full half-open cap (#633),
    /// `ironbus_connections_rejected_total{reason="half_open_cap"}`.
    pub rejected_half_open_cap: u64,
    /// Pre-auth rejections for a locked-out source IP (#633),
    /// `ironbus_connections_rejected_total{reason="locked_out"}`.
    pub rejected_locked_out: u64,
    /// Failed authentication attempts (#633),
    /// `ironbus_connections_rejected_total{reason="auth_failed"}`.
    pub rejected_auth_failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn accept_close_refuse_auth_account_independently() {
        let m = ConnectionMetrics::new();
        // Three accepts, one close, two refuses, two auths.
        m.record_accept();
        m.record_accept();
        m.record_accept();
        m.record_close();
        m.record_refused();
        m.record_refused();
        m.record_authenticated();
        m.record_authenticated();
        let s = m.snapshot();
        assert_eq!(s.accepted, 3);
        assert_eq!(s.closed, 1);
        assert_eq!(s.refused, 2);
        assert_eq!(s.currently_open, 2, "open == accepted - closed");
        assert_eq!(s.authenticated, 2);
    }

    #[test]
    fn rejected_total_accounts_each_reason_independently_and_is_bounded() {
        // #633: each pre-auth `DoS` reason is its own monotonic counter; the `reason` label is a closed
        // four-value enum (never a per-IP label), so the family is bounded by construction.
        let m = ConnectionMetrics::new();
        m.record_rejected(RejectReason::RateLimited);
        m.record_rejected(RejectReason::RateLimited);
        m.record_rejected(RejectReason::HalfOpenCap);
        m.record_rejected(RejectReason::LockedOut);
        m.record_rejected(RejectReason::LockedOut);
        m.record_rejected(RejectReason::LockedOut);
        m.record_rejected(RejectReason::AuthFailed);
        let s = m.snapshot();
        assert_eq!(s.rejected_rate_limited, 2);
        assert_eq!(s.rejected_half_open_cap, 1);
        assert_eq!(s.rejected_locked_out, 3);
        assert_eq!(s.rejected_auth_failed, 1);
        // The reasons do NOT cross-contaminate the lifecycle counters.
        assert_eq!(s.accepted, 0);
        assert_eq!(s.refused, 0);
        // The label set is exactly four bounded values.
        let labels: Vec<&str> = [
            RejectReason::RateLimited,
            RejectReason::HalfOpenCap,
            RejectReason::LockedOut,
            RejectReason::AuthFailed,
        ]
        .iter()
        .map(|r| r.as_str())
        .collect();
        assert_eq!(
            labels,
            ["rate_limited", "half_open_cap", "locked_out", "auth_failed"]
        );
    }

    #[test]
    fn the_open_gauge_saturates_at_zero_on_an_unmatched_close() {
        // A defensive double-close can never drive the live gauge negative (it would wrap a u64).
        let m = ConnectionMetrics::new();
        m.record_accept();
        m.record_close();
        m.record_close(); // unmatched
        assert_eq!(m.snapshot().currently_open, 0);
        // The closed TOTAL still counts both close events (it is a monotonic total, not the gauge).
        assert_eq!(m.snapshot().closed, 2);
    }

    #[test]
    fn the_record_path_is_lock_free_and_shareable_across_threads() {
        // The metric is an Arc of atomics, so two threads can record concurrently with no lock; the
        // monotonic totals are exact under contention (relaxed adds are still atomic).
        let m = Arc::new(ConnectionMetrics::new());
        let mut handles = Vec::new();
        for _ in 0..4 {
            let m = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_accept();
                    m.record_close();
                    m.record_authenticated();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let s = m.snapshot();
        assert_eq!(s.accepted, 4000);
        assert_eq!(s.closed, 4000);
        assert_eq!(s.authenticated, 4000);
        assert_eq!(s.currently_open, 0, "every accept was matched by a close");
    }
}
