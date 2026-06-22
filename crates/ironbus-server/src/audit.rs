// SPDX-License-Identifier: MIT OR Apache-2.0
//! The structured security AUDIT-EVENT stream (#635, V2-M7, `docs/SECRETS.md` "The event set").
//!
//! This is the implementation of the audit-event schema `docs/SECRETS.md` froze: every connect-time
//! authentication outcome, every scope (authz) denial, every secret-permission boot refusal, and every
//! configuration change emits ONE structured, **secret-free** record. The load-bearing safety property
//! is in the emitter's TYPE, not in caller discipline: an [`AuditEvent`] carries the identity NAME (a
//! safe handle) and never a credential — there is no field, and no constructor argument, that can carry
//! a token, a password, a key, a hash, or a payload. A reviewer cannot leak a secret through this path
//! because the path has nowhere to put one. This mirrors the redacting newtype in [`crate::auth`]: the
//! `Secret` type renders `<redacted>`, and this emitter simply never takes one.
//!
//! ## The common envelope (sequence + wall-clock)
//! Every event carries a per-process MONOTONIC SEQUENCE number (an atomic `u64` that increments by one
//! per emitted event and never decreases) PLUS a wall-clock millis-since-epoch timestamp. The sequence
//! is the authoritative ordering: it survives a wall-clock jump (NTP step, suspend/resume) that would
//! reorder or collide timestamps, mirroring the I6 "ordering never consults the wall clock" discipline.
//! When the two disagree, the sequence wins and the disagreement is itself the evidence of a clock jump.
//!
//! ## The sink is operator-selectable and ZERO-COST when off
//! The transport is a structured LOG stream to an operator-selected sink: stderr, a file, or nothing.
//! With NO sink configured ([`AuditSink::Null`]) emission is a single relaxed atomic increment of the
//! sequence and an early return — no formatting, no allocation, no IO — so a broker that did not opt in
//! pays no hot-path cost and is byte-for-byte unchanged. (The auth handshake is not a per-message hot
//! path in any case, but the gate keeps the no-sink path provably free.) We deliberately do NOT add a
//! `/metrics` counter family here, so the frozen metric taxonomy (#576) is untouched; a counter family
//! is the documented alternative transport (`docs/SECRETS.md`) and can be added later additively.

use ironbus_core::clock::Clock;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Which authentication mechanism an [`AuditEvent::AuthOutcome`] concerns (#635). The lowercase wire/log
/// spelling, never a secret. `Unknown` covers a malformed or unrecognized mechanism selector so a probe
/// that sends garbage still produces a well-formed, bounded-cardinality event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// Bearer-token (`bearer`).
    Bearer,
    /// Username + password (`password`).
    Password,
    /// mutual TLS (`mtls`).
    Mtls,
    /// A malformed / unrecognized mechanism selector (`unknown`).
    Unknown,
}

impl Mechanism {
    /// The fixed lowercase log spelling. Low-cardinality (four values), never a secret.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Bearer => "bearer",
            Mechanism::Password => "password",
            Mechanism::Mtls => "mtls",
            Mechanism::Unknown => "unknown",
        }
    }
}

/// The outcome of an authentication attempt (#635): `success` or `failure`. Low-cardinality, never a
/// secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The credential verified and an identity was resolved.
    Success,
    /// The credential did not resolve to any identity (bad/unknown credential, no credential, or a
    /// malformed/unknown mechanism). On the wire this is the single uniform Authorization Violation
    /// (no oracle); the audit event, on the trusted side, records the mechanism and the failure.
    Failure,
}

impl Outcome {
    /// The fixed lowercase log spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        }
    }
}

/// The literal subject for a failed authentication whose identity could not be resolved (#635,
/// `docs/SECRETS.md`): the event records `<unknown>` rather than echoing attacker-supplied bytes (an
/// unknown-username probe must not be reflected into the audit log).
pub const UNKNOWN_IDENTITY: &str = "<unknown>";

/// One structured, secret-free security audit event (#635, `docs/SECRETS.md` "The event set"). The set
/// is frozen; a test pins it. EVERY variant's identity field is a NAME (or a non-secret handle such as
/// a source IP or a file path), NEVER a credential. There is no variant, and no field, that can carry a
/// token / password / key / hash / payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    /// A connect-time authentication attempt resolved (#635). `identity` is the resolved name on
    /// success, or [`UNKNOWN_IDENTITY`] on a failed lookup.
    AuthOutcome {
        /// The resolved identity name (success) or `<unknown>` (failure). Never a credential.
        identity: String,
        /// Which mechanism the client selected.
        mechanism: Mechanism,
        /// `success` or `failure`.
        outcome: Outcome,
    },
    /// A connection authenticated but lacked the scope for the verb it attempted (#635). The wire saw
    /// the uniform Authorization Violation (no oracle); this trusted-side event distinguishes the
    /// denial for the operator.
    AuthzDenial {
        /// The authenticated identity name. Never a credential.
        identity: String,
        /// The scope the verb required (`publish` / `subscribe` / `admin`).
        scope: &'static str,
        /// The verb that was attempted (a fixed frame-type name, low-cardinality).
        verb: &'static str,
    },
    /// The fail-closed `StrictModes` secret-file permission check refused to start (#635). Emitted
    /// before the broker exits so a fail-closed boot is observable. The file PATH is safe to log; the
    /// file contents are never read.
    SecretPermissionRefusal {
        /// The offending secret-bearing file path (safe handle).
        path: String,
        /// The failing condition (`group_world_readable` / `wrong_owner` / `missing` / `unreadable`).
        condition: &'static str,
    },
    /// The broker configuration changed (#635): startup config materialization or a live config
    /// reload. The summary is a count/shape, never a credential. (The identity-table reload variant of
    /// the spec maps onto this same secret-free change-summary form.)
    ConfigChange {
        /// What changed, as a non-secret summary (e.g. `"startup"`, `"reload: 2 key(s) applied"`).
        summary: String,
    },
}

impl AuditEvent {
    /// The event-type tag, a fixed low-cardinality string used as the structured `event=` field.
    #[must_use]
    pub fn type_tag(&self) -> &'static str {
        match self {
            AuditEvent::AuthOutcome { .. } => "authn_outcome",
            AuditEvent::AuthzDenial { .. } => "authz_denial",
            AuditEvent::SecretPermissionRefusal { .. } => "secret_permission_refusal",
            AuditEvent::ConfigChange { .. } => "config_change",
        }
    }

    /// Renders this event's type-specific fields into the structured line builder (the common envelope
    /// — `seq` and `ts_ms` — is prepended by [`AuditEmitter::emit`]). Field VALUES are escaped so an
    /// identity name a client influenced (it never reaches here as a secret, but a name is operator
    /// data) cannot inject a newline or a quote that breaks the structured line or forges a field.
    fn render_fields(&self, out: &mut String) {
        match self {
            AuditEvent::AuthOutcome {
                identity,
                mechanism,
                outcome,
            } => {
                push_field(out, "identity", identity);
                push_static(out, "mechanism", mechanism.as_str());
                push_static(out, "outcome", outcome.as_str());
            }
            AuditEvent::AuthzDenial {
                identity,
                scope,
                verb,
            } => {
                push_field(out, "identity", identity);
                push_static(out, "scope", scope);
                push_static(out, "verb", verb);
            }
            AuditEvent::SecretPermissionRefusal { path, condition } => {
                push_field(out, "path", path);
                push_static(out, "condition", condition);
            }
            AuditEvent::ConfigChange { summary } => {
                push_field(out, "summary", summary);
            }
        }
    }
}

/// Appends ` key="value"` with the value escaped (quote, backslash, newline, CR), so a structured line
/// is unambiguous and a value cannot forge a field or break the line.
fn push_field(out: &mut String, key: &str, value: &str) {
    out.push(' ');
    out.push_str(key);
    out.push_str("=\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends ` key=value` for a fixed, known-safe static value (a mechanism / outcome / scope / verb /
/// condition tag) that needs no escaping. Kept distinct from [`push_field`] so the low-cardinality
/// enum values render bare (no quotes) and stay grep-friendly.
fn push_static(out: &mut String, key: &str, value: &str) {
    out.push(' ');
    out.push_str(key);
    out.push('=');
    out.push_str(value);
}

/// The operator-selected destination for the audit stream (#635). A dedicated stream so the audit log
/// is separable from the broker's diagnostic log. `Null` is the zero-cost default; the writer sink is a
/// shared, mutex-guarded `Write` (stderr or an opened file), so events from concurrent connection
/// threads never interleave mid-line.
#[derive(Clone)]
pub enum AuditSink {
    /// No sink: emission is a sequence bump and an early return (no formatting, no IO). The
    /// byte-for-byte-unchanged default.
    Null,
    /// A shared `Write` sink (stderr or an opened append file). Guarded by a `Mutex` so a whole event
    /// line is written atomically with respect to other emitters.
    Writer(Arc<Mutex<Box<dyn Write + Send>>>),
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditSink::Null => f.write_str("AuditSink::Null"),
            AuditSink::Writer(_) => f.write_str("AuditSink::Writer(..)"),
        }
    }
}

impl AuditSink {
    /// A writer sink over any `Write + Send` (stderr in production, a `Vec<u8>` in a test).
    #[must_use]
    pub fn writer(w: Box<dyn Write + Send>) -> AuditSink {
        AuditSink::Writer(Arc::new(Mutex::new(w)))
    }

    /// Whether this sink actually writes (so a caller can skip building an event when nothing will
    /// consume it — the no-sink zero-cost gate).
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, AuditSink::Writer(_))
    }
}

/// The single security-event emitter (#635, `docs/SECRETS.md` "One security-event emitter takes the
/// name, never the credential"). It owns the per-process monotonic sequence counter and a clock for the
/// wall-clock stamp, and routes every event to the configured [`AuditSink`]. It is `Clone` (a cheap
/// `Arc` bump of the shared counter + sink), so every connection thread shares ONE sequence space and
/// ONE sink. Cloning preserves the shared counter, which is what makes the sequence monotonic across
/// threads.
#[derive(Clone)]
pub struct AuditEmitter {
    seq: Arc<AtomicU64>,
    sink: AuditSink,
    clock: Arc<dyn Clock>,
}

impl AuditEmitter {
    /// Builds an emitter over a sink and a clock. The sequence starts at 0 and the first emitted event
    /// is sequence 0 (the per-process count of events emitted before it).
    #[must_use]
    pub fn new(sink: AuditSink, clock: Arc<dyn Clock>) -> AuditEmitter {
        AuditEmitter {
            seq: Arc::new(AtomicU64::new(0)),
            sink,
            clock,
        }
    }

    /// A no-op emitter (the zero-cost default): a [`AuditSink::Null`] over the given clock. Used by the
    /// no-audit serve path and by tests that do not assert on the stream.
    #[must_use]
    pub fn disabled(clock: Arc<dyn Clock>) -> AuditEmitter {
        AuditEmitter::new(AuditSink::Null, clock)
    }

    /// Emits one structured audit event (#635). With [`AuditSink::Null`] this still bumps the sequence
    /// (so a later active sink continues the count) but does NO formatting and NO IO — the zero-cost
    /// no-sink path. With a writer sink it renders ONE line `event=<type> seq=<n> ts_ms=<ms> <fields>`
    /// under the sink's mutex (so concurrent emitters never interleave) and returns the sequence used.
    ///
    /// The sequence is sourced from the atomic counter, NOT the clock (it survives a wall-clock jump);
    /// the `ts_ms` wall-clock stamp is recorded for SIEM correlation but is explicitly not trusted for
    /// ordering.
    pub fn emit(&self, event: &AuditEvent) -> u64 {
        // The sequence is ALWAYS advanced, even for the Null sink, so enabling a sink later does not
        // reset or collide the count. A single relaxed fetch_add: the only cost on the no-sink path.
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let AuditSink::Writer(writer) = &self.sink else {
            return seq; // Null sink: no formatting, no IO.
        };
        let ts_ms = self.clock.now_unix_millis();
        let mut line = String::with_capacity(96);
        line.push_str("event=");
        line.push_str(event.type_tag());
        push_static(&mut line, "seq", &seq.to_string());
        push_static(&mut line, "ts_ms", &ts_ms.to_string());
        event.render_fields(&mut line);
        line.push('\n');
        // A poisoned mutex (an emitter thread panicked mid-write) must not crash the broker on a later
        // audit write; recover the guard and continue (the audit stream is best-effort observability,
        // never a correctness barrier). An IO error to the sink is likewise swallowed: a full disk on
        // the audit file must not take the broker down.
        if let Ok(mut w) = writer.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        } else if let Ok(mut w) = writer.clear_poison_lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
        seq
    }
}

/// A tiny extension so the poisoned-mutex recovery reads clearly without depending on the unstable
/// `Mutex::clear_poison` API surface (MSRV 1.78): on a poisoned lock, take the inner guard anyway.
trait ClearPoisonLock<T> {
    fn clear_poison_lock(&self) -> Result<std::sync::MutexGuard<'_, T>, ()>;
}

impl<T> ClearPoisonLock<T> for Mutex<T> {
    fn clear_poison_lock(&self) -> Result<std::sync::MutexGuard<'_, T>, ()> {
        match self.lock() {
            Ok(g) => Ok(g),
            Err(poisoned) => Ok(poisoned.into_inner()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::clock::ManualClock;

    /// A writer sink over a shared `Vec<u8>` so a test can read back exactly what was written.
    fn capturing() -> (AuditEmitter, Arc<Mutex<Vec<u8>>>) {
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let buf_clone = Arc::clone(&buf);
        // A Write impl over the shared buffer.
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let clock = Arc::new(ManualClock::at_unix_millis(1_700_000_000_000)) as Arc<dyn Clock>;
        let emitter = AuditEmitter::new(
            AuditSink::writer(Box::new(SharedBuf(buf_clone))),
            clock,
        );
        (emitter, buf)
    }

    fn rendered(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(buf.lock().unwrap().clone()).unwrap()
    }

    #[test]
    fn each_event_type_renders_its_fields_and_the_common_envelope() {
        let (emitter, buf) = capturing();
        emitter.emit(&AuditEvent::AuthOutcome {
            identity: "producer".to_string(),
            mechanism: Mechanism::Bearer,
            outcome: Outcome::Success,
        });
        emitter.emit(&AuditEvent::AuthOutcome {
            identity: UNKNOWN_IDENTITY.to_string(),
            mechanism: Mechanism::Password,
            outcome: Outcome::Failure,
        });
        emitter.emit(&AuditEvent::AuthzDenial {
            identity: "consumer".to_string(),
            scope: "admin",
            verb: "StreamDeclare",
        });
        emitter.emit(&AuditEvent::SecretPermissionRefusal {
            path: "/etc/ironbus/auth.toml".to_string(),
            condition: "group_world_readable",
        });
        emitter.emit(&AuditEvent::ConfigChange {
            summary: "startup".to_string(),
        });
        let text = rendered(&buf);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5, "one line per event: {text}");

        // The common envelope is present on every line, and the sequence is monotonic 0..5.
        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(&format!("seq={i}")), "seq on line {i}: {line}");
            assert!(line.contains("ts_ms=1700000000000"), "wall clock: {line}");
        }
        assert!(lines[0].starts_with("event=authn_outcome"));
        assert!(lines[0].contains("identity=\"producer\""));
        assert!(lines[0].contains("mechanism=bearer"));
        assert!(lines[0].contains("outcome=success"));
        assert!(lines[1].contains("identity=\"<unknown>\""));
        assert!(lines[1].contains("mechanism=password"));
        assert!(lines[1].contains("outcome=failure"));
        assert!(lines[2].starts_with("event=authz_denial"));
        assert!(lines[2].contains("identity=\"consumer\""));
        assert!(lines[2].contains("scope=admin"));
        assert!(lines[2].contains("verb=StreamDeclare"));
        assert!(lines[3].starts_with("event=secret_permission_refusal"));
        assert!(lines[3].contains("path=\"/etc/ironbus/auth.toml\""));
        assert!(lines[3].contains("condition=group_world_readable"));
        assert!(lines[4].starts_with("event=config_change"));
        assert!(lines[4].contains("summary=\"startup\""));
    }

    #[test]
    fn no_event_can_carry_a_secret_and_a_malicious_name_cannot_inject_a_line() {
        // The load-bearing #635 property: the emitter has no field for a credential, so a sentinel
        // "secret" can only ever enter via a NAME field — and even then it is escaped, never a second
        // forged line, never a bare credential. (There is no API to pass a token/password/hash here:
        // that is the type-level guarantee. This test proves the escaping half.)
        let (emitter, buf) = capturing();
        emitter.emit(&AuditEvent::AuthOutcome {
            // A hostile "identity" that tries to inject a newline + a forged success line.
            identity: "evil\"\nevent=authn_outcome seq=999 outcome=success identity=\"admin"
                .to_string(),
            mechanism: Mechanism::Password,
            outcome: Outcome::Failure,
        });
        let text = rendered(&buf);
        // Exactly ONE physical line: the injected newline was escaped to `\n`, not a real newline.
        assert_eq!(text.lines().count(), 1, "no injected second line: {text}");
        assert!(text.contains("\\n"), "newline escaped: {text}");
        assert!(text.contains("\\\""), "quote escaped: {text}");
        // The forged `seq=999 outcome=success` did not become a real, trusted envelope: the only
        // un-escaped envelope on the line is the real one (seq=0, outcome=failure).
        assert!(text.contains("seq=0"));
        assert!(text.contains("outcome=failure"));
    }

    #[test]
    fn null_sink_writes_nothing_but_still_advances_the_sequence() {
        // The zero-cost no-sink path: with the Null sink, emit() does no IO but still bumps the
        // sequence, so enabling a sink later continues the count rather than colliding at 0.
        let clock = Arc::new(ManualClock::at_unix_millis(1)) as Arc<dyn Clock>;
        let emitter = AuditEmitter::disabled(clock);
        assert!(!emitter.sink.is_active());
        assert_eq!(
            emitter.emit(&AuditEvent::ConfigChange {
                summary: "x".to_string()
            }),
            0
        );
        assert_eq!(
            emitter.emit(&AuditEvent::ConfigChange {
                summary: "y".to_string()
            }),
            1
        );
    }

    #[test]
    fn the_event_set_is_frozen() {
        // Pins the complete set of audit event-type tags (#635, `docs/SECRETS.md` "The set is frozen").
        // Adding, removing, or renaming an event without updating this set fails here, so the audit
        // schema cannot silently drift — modeled on the frozen wire-tag and metric-taxonomy tests.
        let all = [
            AuditEvent::AuthOutcome {
                identity: String::new(),
                mechanism: Mechanism::Bearer,
                outcome: Outcome::Success,
            }
            .type_tag(),
            AuditEvent::AuthzDenial {
                identity: String::new(),
                scope: "publish",
                verb: "Pub",
            }
            .type_tag(),
            AuditEvent::SecretPermissionRefusal {
                path: String::new(),
                condition: "missing",
            }
            .type_tag(),
            AuditEvent::ConfigChange {
                summary: String::new(),
            }
            .type_tag(),
        ];
        let got: std::collections::BTreeSet<&str> = all.into_iter().collect();
        let expected: std::collections::BTreeSet<&str> = [
            "authn_outcome",
            "authz_denial",
            "secret_permission_refusal",
            "config_change",
        ]
        .into_iter()
        .collect();
        assert_eq!(got, expected, "the frozen audit event set drifted");
    }
}
