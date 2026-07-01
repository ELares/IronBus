// SPDX-License-Identifier: MIT OR Apache-2.0
//! The IO-free compute half of the trained-dictionary lifecycle (#357,
//! `docs/DICTIONARY_LIFECYCLE.md`): `ZDICT` training over a per-type sample corpus and the
//! content-addressed `dict_id` derivation. Compiled ONLY on the OPT-IN `zstd` feature.
//!
//! What lives HERE (pure compute, no IO): the `ZDICT_trainFromBuffer` call (via the `zstd` crate),
//! the corpus floors (min/target sample counts and a de-duplicated-record-bytes floor), the
//! `dict_id = truncate_u32(BLAKE3-256(dict_bytes))` derivation, and the dict_id `0`-sentinel
//! refusal. What lives ABOVE this (in `ironbus-storage`/`ironbus-cli`, NOT here): the sidecar file
//! IO (`dicts/<dict_id>.zstd`), the embedded active set, the resolver. Keeping the IO out preserves
//! the IO-free invariant of `ironbus-core` even under the feature.
//!
//! The zstd FFI is entirely inside the `zstd` crate, so this module adds no `unsafe`
//! (`ironbus-core` is `#![forbid(unsafe_code)]`).

use crate::compress::DICT_ID_NONE;

/// The minimum number of samples the trainer accepts by default (`docs/DICTIONARY_LIFECYCLE.md`
/// §1): `ZDICT_trainFromBuffer` needs roughly a few thousand samples to produce a useful
/// dictionary. Below this the trainer REFUSES rather than emit a weak dictionary. Tunable by the
/// caller (the CLI exposes `--min-samples`).
pub const MIN_SAMPLES: usize = 1000;

/// The recommended corpus size the operator flow aims for (advisory; surfaced as a warning below
/// it by the caller, not a hard floor here).
pub const TARGET_SAMPLES: usize = 10_000;

/// The minimum total bytes across the corpus's DE-DUPLICATED records: identical records are
/// collapsed and the byte LENGTHS of the surviving unique records are summed, and that sum must
/// reach this floor. This is a coarse proxy for redundancy — it stops N copies of a single record
/// from passing the count floor (they collapse to one record's length) — NOT a byte-level or
/// entropy measure of diversity (it never inspects which byte VALUES occur, only unique-record
/// lengths). A floor on de-duplicated corpus size, not a size cap.
pub const MIN_DISTINCT_BYTES: usize = 8 * 1024;

/// The default requested dictionary size in bytes (110 KiB, zstd's own `ZDICT` default).
pub const DEFAULT_TARGET_DICT_BYTES: usize = 112_640;

/// A trained dictionary and its derived content-addressed id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrainedDictionary {
    /// The content-addressed id: `truncate_u32(BLAKE3-256(bytes))`. Never [`DICT_ID_NONE`].
    pub dict_id: u32,
    /// The opaque trained dictionary blob (the bytes that land in `dicts/<dict_id>.zstd`).
    pub bytes: Vec<u8>,
}

/// Why training a dictionary failed. Typed, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrainError {
    /// The corpus has fewer than `min_samples` records (the count floor).
    TooFewSamples {
        /// How many samples were supplied.
        have: usize,
        /// The required minimum.
        need: usize,
    },
    /// The corpus's de-duplicated records sum to fewer than [`MIN_DISTINCT_BYTES`] bytes (the
    /// de-duplicated-record-bytes floor): after collapsing identical records, too little unique
    /// material remains for zstd to learn any redundancy. (The name is historical; the check sums
    /// unique-record lengths, it does not measure byte-level diversity.)
    TooLittleDiversity {
        /// The summed byte length of the corpus's de-duplicated (unique) records.
        have: usize,
        /// The required minimum de-duplicated-record byte total.
        need: usize,
    },
    /// The `ZDICT_trainFromBuffer` C call returned an error (for example the corpus was too small
    /// or too uniform for zstd to extract a dictionary at the requested size).
    ZdictFailed,
    /// The derived `dict_id` truncated to `0`, the permanent no-dictionary sentinel. A ~1-in-2^32
    /// event; the documented recovery is to re-train with a trivially different corpus
    /// (`docs/DICTIONARY_LIFECYCLE.md` §2). Fail-closed: a trained dictionary may never claim the
    /// no-dictionary id.
    DerivedZeroDictId,
}

impl core::fmt::Display for TrainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TrainError::TooFewSamples { have, need } => write!(
                f,
                "too few samples to train a dictionary: have {have}, need at least {need}"
            ),
            TrainError::TooLittleDiversity { have, need } => write!(
                f,
                "corpus has too few de-duplicated record bytes: {have}, need at least {need}"
            ),
            TrainError::ZdictFailed => {
                write!(f, "ZDICT training failed (corpus too small or too uniform)")
            }
            TrainError::DerivedZeroDictId => write!(
                f,
                "the trained dictionary hashed to dict_id 0 (the no-dictionary sentinel); re-train \
                 with a trivially different corpus"
            ),
        }
    }
}

impl std::error::Error for TrainError {}

/// Derives the content-addressed `dict_id` for a dictionary blob:
/// `truncate_u32(BLAKE3-256(bytes))`, taking the first 4 bytes of the 32-byte BLAKE3 digest as a
/// little-endian `u32` (`docs/DICTIONARY_LIFECYCLE.md` §2).
///
/// The id is a 32-bit TRUNCATION of BLAKE3, so BLAKE3's collision and second-preimage resistance
/// (which hold for the full 256-bit output) do NOT carry over to the id: a birthday collision
/// between two blobs costs ~2^16 trials and a chosen-target second-preimage (forging a blob that
/// hashes to a specific id) costs ~2^32 hashes — both cheap on commodity hardware. So the `dict_id`
/// is a compact content-addressed IDENTIFIER, NOT a tamper-proof integrity or immutability
/// guarantee; do not treat "same `dict_id`" as proof of "same bytes" against an adversary. That is
/// acceptable here because minting and installing dictionaries is an operator/filesystem-trusted
/// flow (`docs/DICTIONARY_LIFECYCLE.md` §3-§4), not an untrusted-input path: the id only needs to
/// disambiguate honestly-produced dictionaries and give a stable registry-free name. If integrity
/// against a motivated adversary is ever required, the resolver must verify the FULL BLAKE3 digest
/// (store/compare all 32 bytes), not this 32-bit id.
///
/// This is a pure function of the bytes alone, so the same dictionary always derives the same id
/// everywhere with no coordination (the registry-free, never-reuse property). It can legitimately
/// return [`DICT_ID_NONE`] (0); callers that mint a NEW dictionary must refuse that (see
/// [`train_dictionary`]), but a reader re-deriving the id of an existing blob uses this directly.
#[must_use]
pub fn derive_dict_id(bytes: &[u8]) -> u32 {
    let digest = blake3::hash(bytes);
    let b = digest.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Trains a zstd dictionary from a per-type `samples` corpus (each element one raw, uncompressed
/// record of one message type), targeting `target_dict_bytes`, using the default sample-count and
/// distinct-record-bytes floors.
///
/// # Errors
/// Returns a [`TrainError`] if the corpus fails the count or distinct-record-bytes floors, the `ZDICT` call
/// fails, or the derived `dict_id` is the `0` sentinel. Never panics.
pub fn train_dictionary(
    samples: &[Vec<u8>],
    target_dict_bytes: usize,
) -> Result<TrainedDictionary, TrainError> {
    train_dictionary_with_floors(samples, target_dict_bytes, MIN_SAMPLES, MIN_DISTINCT_BYTES)
}

/// Like [`train_dictionary`] but with explicit count and distinct-record-bytes floors, for an operator who
/// knowingly accepts a smaller corpus (the CLI `--min-samples`).
///
/// # Errors
/// As [`train_dictionary`].
pub fn train_dictionary_with_floors(
    samples: &[Vec<u8>],
    target_dict_bytes: usize,
    min_samples: usize,
    min_distinct_bytes: usize,
) -> Result<TrainedDictionary, TrainError> {
    if samples.len() < min_samples {
        return Err(TrainError::TooFewSamples {
            have: samples.len(),
            need: min_samples,
        });
    }

    // De-duplicated-record-bytes floor: collapse identical records to a set, then sum the byte
    // LENGTHS of the surviving unique records (this measures unique-record volume, not byte-level
    // diversity), so 1000 copies of one record cannot pass on count alone.
    let unique_records: std::collections::BTreeSet<&[u8]> =
        samples.iter().map(Vec::as_slice).collect();
    let unique_record_bytes: usize = unique_records.iter().map(|s| s.len()).sum();
    if unique_record_bytes < min_distinct_bytes {
        return Err(TrainError::TooLittleDiversity {
            have: unique_record_bytes,
            need: min_distinct_bytes,
        });
    }

    // The ZDICT_trainFromBuffer call (via the zstd crate's `from_samples`, gated by the
    // `zdict_builder` feature). It concatenates the samples, records their sizes, and trains a
    // dictionary of at most `target_dict_bytes`. A failure (corpus too small/uniform for the
    // requested size) is a typed error, never a panic.
    let bytes = zstd::dict::from_samples(samples, target_dict_bytes)
        .map_err(|_| TrainError::ZdictFailed)?;
    if bytes.is_empty() {
        return Err(TrainError::ZdictFailed);
    }

    let dict_id = derive_dict_id(&bytes);
    if dict_id == DICT_ID_NONE {
        // The trained blob hashed to the no-dictionary sentinel; refuse it fail-closed.
        return Err(TrainError::DerivedZeroDictId);
    }

    Ok(TrainedDictionary { dict_id, bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_for(i: u32) -> Vec<u8> {
        format!(
            "{{\"type\":\"sensor.telemetry.v1\",\"device\":\"hive-{:04}\",\"temp\":{}.{},\"unit\":\"C\",\"rssi\":-{},\"seq\":{}}}",
            i % 64,
            18 + (i % 12),
            i % 10,
            40 + (i % 50),
            i
        )
        .into_bytes()
    }

    fn corpus(n: u32) -> Vec<Vec<u8>> {
        (0..n).map(record_for).collect()
    }

    #[test]
    fn derive_dict_id_is_deterministic_and_content_addressed() {
        // Same bytes -> same id, everywhere, with no coordination.
        let a = b"a trained dictionary blob";
        assert_eq!(derive_dict_id(a), derive_dict_id(a));
        // Different bytes -> (almost certainly) a different id.
        assert_ne!(derive_dict_id(a), derive_dict_id(b"a different blob"));
        // It is the LE-u32 truncation of the BLAKE3 digest.
        let digest = blake3::hash(a);
        let want = u32::from_le_bytes([
            digest.as_bytes()[0],
            digest.as_bytes()[1],
            digest.as_bytes()[2],
            digest.as_bytes()[3],
        ]);
        assert_eq!(derive_dict_id(a), want);
    }

    #[test]
    fn training_over_a_representative_corpus_succeeds_and_never_yields_the_sentinel() {
        let dict = train_dictionary(&corpus(2000), 4096).expect("trains");
        assert!(!dict.bytes.is_empty());
        assert_ne!(dict.dict_id, DICT_ID_NONE);
        // The id is re-derivable from the blob (the content-name integrity check the sidecar uses).
        assert_eq!(derive_dict_id(&dict.bytes), dict.dict_id);
    }

    #[test]
    fn too_few_samples_is_a_typed_error_not_a_weak_dictionary() {
        let err = train_dictionary(&corpus(10), 4096).unwrap_err();
        assert!(matches!(
            err,
            TrainError::TooFewSamples {
                have: 10,
                need: 1000
            }
        ));
    }

    #[test]
    fn an_undiverse_corpus_is_refused() {
        // 2000 identical records pass the count floor but carry no diversity.
        let same = vec![record_for(7); 2000];
        let err =
            train_dictionary_with_floors(&same, 4096, MIN_SAMPLES, MIN_DISTINCT_BYTES).unwrap_err();
        assert!(matches!(err, TrainError::TooLittleDiversity { .. }));
    }

    #[test]
    fn a_lowered_floor_lets_a_smaller_corpus_through() {
        // With an operator-lowered floor, a smaller but diverse corpus trains.
        let dict = train_dictionary_with_floors(&corpus(300), 4096, 100, 1024).expect("trains");
        assert_ne!(dict.dict_id, DICT_ID_NONE);
    }
}
