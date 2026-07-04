// SPDX-License-Identifier: MIT OR Apache-2.0
//! The immutable effective-config + atomic RELOAD engine (#380, #382, the no-auth part).
//!
//! `docs/CONFIG.md` section 4 requires that the effective configuration be resolved into
//! ONE immutable value, read on the path that needs it via a single atomic pointer load
//! (never re-parsed per message), and that a RELOAD re-read the WHOLE config, validate it
//! fully, reject a COLD-key change ATOMICALLY, and swap the pointer in ONE store ONLY on
//! full success (a broken reload leaves the running config exactly unchanged).
//!
//! This module implements that engine, AUTH-FREE: the [`ConfigHandle`] holds the immutable
//! [`EffectiveConfig`] behind a single swap point, and [`ConfigHandle::reload_from`] is the
//! safe re-read entry point (the reload path #380 names). SIGHUP drives it at runtime (the #380
//! trigger): `cmd_serve`'s signal thread re-reads `--config` on SIGHUP and applies the
//! live-reloadable subset to the running engine; it also runs once at startup as a validate-whole
//! self-check when `--config` is set. The MUTATING wire `CONFIG SET` verbs that change runtime
//! state need the connection-scoped AUTH of #106 and are NOT in scope here, so this module exposes
//! only a READ of the current config and the file re-read reload, never an unauthenticated remote
//! mutation.
//!
//! The swap is a safe-Rust `RwLock<Arc<EffectiveConfig>>`: a READ takes a read lock and clones
//! the `Arc` (a single refcount bump, no parse, no allocation of the config itself), so the
//! hot path observes a consistent immutable snapshot; a RELOAD takes the write lock, validates
//! the candidate fully, and replaces the `Arc` ONLY if validation AND the cold-key check pass.
//! The no-unsafe invariant rules out a raw `AtomicPtr` swap, so this is the idiomatic safe
//! equivalent: the lock is held only for the pointer move, never across IO or a parse.

use std::sync::{Arc, RwLock};

use ironbus_core::config::{validate_coupled_sets, ConfigVerdict, ResolvedConfig};

/// The reload CLASS of a configuration key (`docs/CONFIG.md` section 3): COLD keys are
/// layout-affecting or open-time-immutable and MAY NOT change across a live reload (changing
/// them live could strand segments), HOT keys may. A reload that changes a COLD key is rejected
/// atomically (the running config is left unchanged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadClass {
    /// Safe to change at runtime; a reload applies it.
    Hot,
    /// Requires a restart; a reload that changes it is REJECTED atomically.
    Cold,
}

/// The COLD configuration keys (`docs/CONFIG.md` section 3): the layout-affecting / open-time-
/// immutable keys a live reload must reject if changed. The reload engine compares exactly these
/// against the candidate; classifying them here, with their [`ReloadClass`], keeps the cold/hot
/// distinction the design names in one auditable place. `storage.segment_size` and
/// `storage.data_dir` are COLD because changing them live could strand segments or move the store.
/// `storage.io_mode` is COLD because the open segment fds carry the io strategy (buffered vs the
/// `O_DIRECT` direct-write file); switching it live cannot re-open them, so a change requires a restart.
pub const COLD_KEYS: &[(&str, ReloadClass)] = &[
    ("storage.segment_size", ReloadClass::Cold),
    ("storage.data_dir", ReloadClass::Cold),
    ("storage.io_mode", ReloadClass::Cold),
];

/// The reload class of `key`: [`ReloadClass::Cold`] if it is in the classified [`COLD_KEYS`] set,
/// else [`ReloadClass::Hot`] (the default: a key not pinned COLD is safe to change at runtime). The
/// single classifier the engine consults so the hot/cold distinction `docs/CONFIG.md` names lives in
/// one place.
#[must_use]
pub fn class_of(key: &str) -> ReloadClass {
    COLD_KEYS
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(ReloadClass::Hot, |(_, class)| *class)
}

/// True when `key` is a COLD key (a change across a reload is rejected). Consulted when a snapshot
/// is built so the engine knows which keys to compare; a hot key never blocks a reload.
#[must_use]
pub fn is_cold(key: &str) -> bool {
    class_of(key) == ReloadClass::Cold
}

/// The immutable EFFECTIVE config snapshot the broker runs against, the value a single atomic
/// pointer load returns. It carries the COLD keys (so a reload can prove none changed) and the
/// resolved [`ResolvedConfig`] view (so a reload can re-validate the whole config as a unit).
/// It is `Arc`-shared and never mutated in place: a reload builds a NEW one and swaps it.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    /// The COLD keys, by dotted name, as their resolved string value. A reload compares these
    /// to the candidate's and rejects ANY change (the cold-key-immutable rule). Kept as strings
    /// so the comparison is exact and value-kind-agnostic.
    pub cold_keys: Vec<(&'static str, String)>,
    /// The resolved cross-key view the coupled-set validator checks. A reload re-validates this
    /// for the candidate before swapping, so a broken reload never installs.
    pub resolved: ResolvedConfig,
}

impl EffectiveConfig {
    /// The value of a named COLD key in this snapshot, for the cold-key-change comparison.
    fn cold_value(&self, key: &str) -> Option<&str> {
        self.cold_keys
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// The outcome of a [`ConfigHandle::reload_from`] attempt. A reload is ALL-OR-NOTHING: either
/// the new config is installed (`Applied`) or the running config is left exactly unchanged
/// (`Rejected`, with the reason). The hot path never sees a half-applied config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The candidate validated and swapped in. Carries any non-fatal warnings to surface.
    Applied {
        /// Non-fatal coupled-set warnings from the candidate (a no-op setting).
        warnings: Vec<String>,
    },
    /// The candidate was rejected; the OLD config is kept. Carries the reason(s).
    Rejected {
        /// The fatal reasons (a coupled-set violation, or a cold-key change), every one collected.
        reasons: Vec<String>,
    },
}

impl ReloadOutcome {
    /// True when the candidate was installed.
    #[must_use]
    pub fn applied(&self) -> bool {
        matches!(self, ReloadOutcome::Applied { .. })
    }
}

/// The single atomic swap point for the immutable effective config. A READ
/// ([`ConfigHandle::current`]) returns the current immutable snapshot via one refcount bump (no
/// parse); a RELOAD ([`ConfigHandle::reload_from`]) validates a candidate and swaps ONLY on full
/// success. Cheap to clone (the inner `Arc<RwLock<...>>` is shared), so the handle is handed to
/// every reader and the reload trigger alike.
#[derive(Clone)]
pub struct ConfigHandle {
    inner: Arc<RwLock<Arc<EffectiveConfig>>>,
}

impl ConfigHandle {
    /// Creates the handle around the INITIAL effective config (the startup-resolved one, already
    /// validated by the `serve` startup path before it reaches here).
    #[must_use]
    pub fn new(initial: EffectiveConfig) -> ConfigHandle {
        ConfigHandle {
            inner: Arc::new(RwLock::new(Arc::new(initial))),
        }
    }

    /// The CURRENT immutable config snapshot, via a single read-lock + `Arc` clone (one refcount
    /// bump, no parse). This is the read the hot path uses; it never blocks on a reload longer than
    /// the pointer move (the write lock is held only for the swap, never across IO).
    ///
    /// # Panics
    /// Never in practice: the lock is only ever poisoned if a holder panicked while holding it, and
    /// no code path here panics under the lock. A poisoned lock is recovered (the inner `Arc` is
    /// always a fully-initialized value), so a reader still gets a consistent snapshot.
    #[must_use]
    pub fn current(&self) -> Arc<EffectiveConfig> {
        match self.inner.read() {
            Ok(guard) => Arc::clone(&guard),
            // Recover from a poisoned lock: the protected value is always a valid `Arc`, so the
            // snapshot is consistent; recovering keeps the no-panic bar (an `unwrap` would panic).
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Attempts a RELOAD to `candidate`: re-validate the whole config as a unit, reject any COLD-key
    /// change, and swap the immutable snapshot in ONE store ONLY on full success. On ANY failure the
    /// running config is left EXACTLY unchanged ([`ReloadOutcome::Rejected`]). This is the safe,
    /// auth-free reload (the local re-read path SIGHUP invokes at runtime, #380): it mutates only
    /// the in-process config pointer, on a locally-read candidate, never on an unauthenticated
    /// remote request.
    ///
    /// The validation order is: (1) the coupled-set / range checks on the candidate (a broken
    /// candidate is rejected before anything is touched), then (2) the cold-key comparison against
    /// the CURRENT snapshot (a changed cold key is rejected). Only if BOTH pass is the pointer
    /// swapped, so the swap is the last, all-or-nothing step.
    pub fn reload_from(&self, candidate: EffectiveConfig) -> ReloadOutcome {
        // (1) Re-validate the candidate fully. A fatal coupled-set violation rejects, keeping old.
        let verdict: ConfigVerdict = validate_coupled_sets(&candidate.resolved);
        if !verdict.is_ok() {
            return ReloadOutcome::Rejected {
                reasons: verdict.errors.into_iter().map(|e| e.0).collect(),
            };
        }
        // (2) Reject a COLD-key change atomically: compare every cold key against the current
        // snapshot. A single differing cold key fails the whole reload (no partial apply).
        let current = self.current();
        let mut reasons = Vec::new();
        for (key, new_value) in &candidate.cold_keys {
            // Defensive: only a COLD key blocks a reload. The snapshot only ever lists cold keys
            // (built from `COLD_KEYS`), so this is a belt-and-braces guard that a future hot key
            // accidentally added to a snapshot's `cold_keys` never wedges a reload.
            if !is_cold(key) {
                continue;
            }
            let old_value = current.cold_value(key);
            if old_value != Some(new_value.as_str()) {
                reasons.push(format!(
                    "cold-key `{key}` changed from `{}` to `{new_value}`; it requires a restart \
                     and cannot be changed by a live reload (the reload is rejected; the running \
                     config is unchanged)",
                    old_value.unwrap_or("<unset>"),
                ));
            }
        }
        if !reasons.is_empty() {
            return ReloadOutcome::Rejected { reasons };
        }
        // Both checks passed: SWAP in one store. The write lock is held only for this pointer move.
        let warnings = verdict.warnings;
        match self.inner.write() {
            Ok(mut guard) => *guard = Arc::new(candidate),
            // A poisoned lock still holds a valid `Arc`; recover and swap rather than panic.
            Err(poisoned) => *poisoned.into_inner() = Arc::new(candidate),
        }
        ReloadOutcome::Applied { warnings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::config::DurabilityLevel;

    fn resolved(segment_bytes: u64, max_total: u64) -> ResolvedConfig {
        ResolvedConfig {
            segment_bytes,
            max_record_bytes: 1024 * 1024,
            frame_overhead: 64,
            durability_level: DurabilityLevel::Sync,
            flush_interval_ms: 1000,
            flush_max_bytes: 1024 * 1024,
            async_loss_ack: false,
            max_retained_bytes: 0,
            max_age_ms: 0,
            max_messages: 0,
            retention_requested: false,
            max_total_bytes: max_total,
            disk_full_policy_drop_oldest: false,
            enforce_durability_gate: false,
        }
    }

    fn effective(segment_bytes: u64, max_total: u64) -> EffectiveConfig {
        EffectiveConfig {
            // segment_size is a COLD key; max_total_bytes is HOT (not in cold_keys).
            cold_keys: vec![("storage.segment_size", segment_bytes.to_string())],
            resolved: resolved(segment_bytes, max_total),
        }
    }

    #[test]
    fn the_cold_key_set_is_classified_cold() {
        assert!(is_cold("storage.segment_size"));
        assert!(is_cold("storage.data_dir"));
        // A hot key is not in the cold set.
        assert!(!is_cold("storage.max_total_bytes"));
        // Every entry in COLD_KEYS is classified Cold.
        assert!(COLD_KEYS.iter().all(|(_, c)| *c == ReloadClass::Cold));
    }

    #[test]
    fn a_read_returns_the_current_snapshot() {
        let handle = ConfigHandle::new(effective(64 * 1024 * 1024, 0));
        assert_eq!(handle.current().resolved.segment_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn a_valid_hot_reload_swaps_atomically() {
        let handle = ConfigHandle::new(effective(64 * 1024 * 1024, 0));
        // Change only a HOT key (max_total_bytes), keeping the cold segment size identical.
        let candidate = effective(64 * 1024 * 1024, 8 * 1024 * 1024);
        let outcome = handle.reload_from(candidate);
        assert!(outcome.applied(), "{outcome:?}");
        assert_eq!(handle.current().resolved.max_total_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn a_broken_reload_keeps_the_old_config() {
        let handle = ConfigHandle::new(effective(64 * 1024 * 1024, 0));
        // A candidate whose segment cannot hold a max record is INVALID; the reload must reject and
        // KEEP the old config exactly (no partial apply).
        let mut bad = effective(512 * 1024, 0); // 512 KiB < 1 MiB max record
                                                // Keep the cold key identical so the FAILURE is the coupled-set check, not the cold-key check.
        bad.cold_keys = vec![("storage.segment_size", (64 * 1024 * 1024).to_string())];
        let outcome = handle.reload_from(bad);
        assert!(!outcome.applied(), "{outcome:?}");
        // The running config is unchanged.
        assert_eq!(handle.current().resolved.segment_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn a_cold_key_change_is_rejected_atomically() {
        let handle = ConfigHandle::new(effective(64 * 1024 * 1024, 0));
        // Change the COLD segment size: even though the candidate is itself VALID, a cold-key change
        // is rejected, and the running config is left unchanged.
        let candidate = effective(32 * 1024 * 1024, 0);
        let outcome = handle.reload_from(candidate);
        match outcome {
            ReloadOutcome::Rejected { reasons } => {
                assert!(
                    reasons.iter().any(|r| r.contains("cold-key")),
                    "{reasons:?}"
                );
            }
            ReloadOutcome::Applied { .. } => {
                panic!("a cold-key change must be Rejected, not Applied")
            }
        }
        // Unchanged.
        assert_eq!(handle.current().resolved.segment_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn the_handle_is_shareable_and_sees_the_swap_from_a_clone() {
        let handle = ConfigHandle::new(effective(64 * 1024 * 1024, 0));
        let reader = handle.clone();
        assert!(handle
            .reload_from(effective(64 * 1024 * 1024, 4 * 1024 * 1024))
            .applied());
        // The clone observes the swap (one shared swap point).
        assert_eq!(reader.current().resolved.max_total_bytes, 4 * 1024 * 1024);
    }
}
