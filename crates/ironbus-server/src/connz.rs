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
//! Connz is a FIXED, UNLABELED set of scalar gauges/counters: total accepted, total closed, total
//! refused, currently-open, and total authenticated. There is NO per-connection-id, per-peer, or
//! per-address label — a connection id is exactly the kind of unbounded, per-connection label the
//! #576 cardinality firewall forbids — so the connz surface is bounded BY CONSTRUCTION regardless of
//! how many connections the broker has ever served.

use std::sync::atomic::{AtomicU64, Ordering};

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
