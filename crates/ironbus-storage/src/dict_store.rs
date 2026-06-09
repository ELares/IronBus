// SPDX-License-Identifier: MIT OR Apache-2.0
//! The on-disk trained-dictionary sidecar store and resolver (#357,
//! `docs/DICTIONARY_LIFECYCLE.md` §3-§4), behind the OPT-IN `zstd` feature.
//!
//! A trained dictionary is REQUIRED to decompress a zstd record that references it, so a missing
//! dictionary is permanently undecodable data. This store keeps a dictionary travelling WITH the
//! data it serves by writing it as a content-named sidecar in a `dicts/` subdirectory of the data
//! directory, exactly parallel to `quarantine/`:
//!
//! ```text
//! <data_dir>/
//!   seg-0000000000000000.log
//!   dicts/
//!     <dict_id>.zstd          # the dictionary blob, content-named (the file NAME is the integrity check)
//! ```
//!
//! - The sidecar lives in the `dicts/` SUBDIRECTORY, so the flat live-log walk (which lists only
//!   `seg-*.log`) never sees it: a `dicts/` blob can never be mistaken for a segment.
//! - The sidecar is content-named `<dict_id>.zstd`, so the file name IS the integrity check: a
//!   reader re-derives the BLAKE3-truncated content hash of the bytes and confirms it equals the
//!   id before trusting them. A corrupt or wrong blob fails the check and is treated as ABSENT,
//!   never silently misused.
//! - The blob is written ONCE per data directory (content-addressed, so the same dictionary is the
//!   same file) and durably (fsync the blob, then dir-sync `dicts/`) BEFORE the referencing segment
//!   is acked, so a referenced dictionary is always on disk before the data that needs it.
//!
//! This module is the IO half; the training and the `dict_id` derivation are the IO-free compute in
//! `ironbus_core::dict`. The whole module is `#[cfg(feature = "zstd")]`, absent from the default
//! build (which is pure Rust and has no dictionaries).

use crate::fs::Filesystem;
use crate::io::RandomAccessFile;
use ironbus_core::compress::{DictResolver, DICT_ID_NONE};
use ironbus_core::dict::derive_dict_id;
use std::collections::BTreeMap;
use std::io;

/// The subdirectory of the data directory that holds the dictionary sidecar blobs. Parallel to
/// [`crate::quarantine::QUARANTINE_SUBDIR`] and, like it, invisible to the live `seg-*.log` walk.
pub const DICTS_SUBDIR: &str = "dicts";

/// The suffix of a content-named dictionary sidecar file (`<dict_id>.zstd`).
pub const DICT_SUFFIX: &str = ".zstd";

/// A cap on a single dictionary blob's size when loading it from disk (zstd's `ZDICT` default is
/// 110 KiB; 16 MiB is a generous ceiling that bounds the read of a hostile oversized sidecar).
pub const MAX_DICT_BYTES: u64 = 16 * 1024 * 1024;

/// The content-named sidecar file for `dict_id` (`<dict_id>.zstd`). The id is rendered in decimal
/// so the name round-trips through [`parse_dict_id_from_name`].
#[must_use]
pub fn dict_file_name(dict_id: u32) -> String {
    format!("{dict_id}{DICT_SUFFIX}")
}

/// Parses the `dict_id` out of a `<dict_id>.zstd` sidecar file name, or `None` if the name does not
/// have that shape.
#[must_use]
pub fn parse_dict_id_from_name(name: &str) -> Option<u32> {
    name.strip_suffix(DICT_SUFFIX)?.parse::<u32>().ok()
}

/// Errors writing a dictionary sidecar.
#[derive(Debug)]
#[non_exhaustive]
pub enum SidecarError {
    /// The bytes do not hash to `dict_id`: the caller passed a mismatched (id, bytes) pair. The
    /// store never writes a blob whose content hash disagrees with its name (the integrity
    /// invariant the reader relies on).
    ContentHashMismatch {
        /// The id the caller claimed.
        claimed: u32,
        /// The id the bytes actually hash to.
        derived: u32,
    },
    /// `dict_id` is the no-dictionary sentinel `0`, which never names a stored dictionary.
    ZeroDictId,
    /// An underlying IO error writing or syncing the blob.
    Io(io::Error),
}

impl std::fmt::Display for SidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SidecarError::ContentHashMismatch { claimed, derived } => write!(
                f,
                "dictionary bytes hash to dict_id {derived}, not the claimed {claimed}"
            ),
            SidecarError::ZeroDictId => {
                write!(
                    f,
                    "dict_id 0 is the no-dictionary sentinel and is never stored"
                )
            }
            SidecarError::Io(e) => write!(f, "dictionary sidecar IO error: {e}"),
        }
    }
}

impl std::error::Error for SidecarError {}

impl From<io::Error> for SidecarError {
    fn from(e: io::Error) -> SidecarError {
        SidecarError::Io(e)
    }
}

/// The on-disk dictionary sidecar store rooted at the `dicts/` subdirectory of a data directory.
///
/// Writes are content-addressed and write-once: storing a dictionary already on disk is a no-op
/// (the same id is the same bytes). Reads re-derive the content hash and treat a mismatched or
/// absent blob as unresolved (the caller then falls through to the embedded set, then to the
/// `UnresolvedDictId` poison path).
pub struct DictSidecarStore<F: Filesystem> {
    fs: F,
}

impl<F: Filesystem> DictSidecarStore<F> {
    /// Opens (creating on demand) the sidecar store at the `dicts/` subdirectory of `parent_fs`.
    ///
    /// # Errors
    /// Propagates an IO error creating or opening the subdirectory.
    pub fn open(parent_fs: &F) -> io::Result<DictSidecarStore<F>> {
        let fs = parent_fs.subdir(DICTS_SUBDIR)?;
        Ok(DictSidecarStore { fs })
    }

    /// Borrows the underlying sidecar filesystem (for inspection and tests).
    #[must_use]
    pub fn filesystem(&self) -> &F {
        &self.fs
    }

    /// Persists a trained dictionary as a content-named sidecar, durably: write the blob, fsync it,
    /// then dir-sync `dicts/`, so a referenced dictionary is on disk before the referencing segment
    /// is acked (`docs/DICTIONARY_LIFECYCLE.md` §3a). Content-addressed and WRITE-ONCE: if the
    /// sidecar already exists this is a no-op (the same id names the same bytes). The (id, bytes)
    /// pair is validated against the content hash so a mismatched blob is never written.
    ///
    /// # Errors
    /// Returns [`SidecarError::ZeroDictId`] for the sentinel id, [`SidecarError::ContentHashMismatch`]
    /// if the bytes do not hash to `dict_id`, or [`SidecarError::Io`] on an IO failure.
    pub fn store(&self, dict_id: u32, bytes: &[u8]) -> Result<(), SidecarError> {
        if dict_id == DICT_ID_NONE {
            return Err(SidecarError::ZeroDictId);
        }
        let derived = derive_dict_id(bytes);
        if derived != dict_id {
            return Err(SidecarError::ContentHashMismatch {
                claimed: dict_id,
                derived,
            });
        }
        let name = dict_file_name(dict_id);
        // Write-once: an existing sidecar is the same content (content-addressed), so a present
        // file means this is a no-op. `exists` then `create_new` keeps the no-op race-free enough
        // for the single-writer store (a concurrent create loses the create_new and is treated as
        // already-present below).
        if self.fs.exists(&name)? {
            return Ok(());
        }
        let file = match self.fs.create_new(&name) {
            Ok(f) => f,
            // Another path created it first: content-addressed, so it is the same bytes; no-op.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(e) => return Err(SidecarError::Io(e)),
        };
        // Durability ordering: the blob's bytes (fsync), then the directory entry (dir-sync), so a
        // power loss right after this leaves either no sidecar or a complete, fsynced one.
        if let Err(e) = file
            .write_all_at(bytes, 0)
            .and_then(|()| file.sync_all())
            .and_then(|()| self.fs.sync_dir())
        {
            // Roll back a partial blob so a half-written sidecar is never read as a valid (it would
            // fail the content-hash check anyway, but leaving it is sloppy). Best-effort remove.
            let _ = self.fs.remove(&name);
            return Err(SidecarError::Io(e));
        }
        Ok(())
    }

    /// Loads and content-validates the dictionary `dict_id` from its sidecar, or `None` if the
    /// sidecar is absent, oversized, unreadable, or its bytes do not re-derive to `dict_id` (a
    /// corrupt or wrong blob is treated as ABSENT, never trusted). Best-effort: an IO error reads
    /// as absent so a resolution failure is never a crash.
    #[must_use]
    pub fn load(&self, dict_id: u32) -> Option<Vec<u8>> {
        if dict_id == DICT_ID_NONE {
            return None;
        }
        let name = dict_file_name(dict_id);
        let file = self.fs.open(&name).ok()?;
        let len = file.len().ok()?;
        if len == 0 || len > MAX_DICT_BYTES {
            return None;
        }
        let len = usize::try_from(len).ok()?;
        let mut bytes = vec![0u8; len];
        file.read_exact_at(&mut bytes, 0).ok()?;
        // The file NAME is the integrity check: re-derive the content hash and confirm it equals
        // the id. A corrupt or wrong blob fails here and is treated as absent.
        if derive_dict_id(&bytes) != dict_id {
            return None;
        }
        Some(bytes)
    }

    /// Lists the `dict_id`s currently held as sidecars (those whose name has the `<id>.zstd`
    /// shape), in the filesystem's sorted order. Best-effort: a list failure yields an empty set.
    #[must_use]
    pub fn list_ids(&self) -> Vec<u32> {
        let Ok(names) = self.fs.list() else {
            return Vec::new();
        };
        names
            .iter()
            .filter_map(|n| parse_dict_id_from_name(n))
            .collect()
    }
}

/// A [`DictResolver`] that resolves a `dict_id` sidecar-first then from an embedded active set,
/// caching the resolved bytes so the borrow `DictResolver::resolve` returns is `&self`-owned.
///
/// The resolution ORDER is the §4 contract: on-disk sidecar FIRST (the copy that travels with the
/// data, so it survives a binary downgrade), then the embedded build-time active set. A `dict_id`
/// in neither is left unresolved (the caller's decompress then returns `PoisonUnresolvedDict`,
/// surfaced as `ReasonCode::UnresolvedDictId`).
///
/// Build it by preloading the set of `dict_id`s a read pass will reference (recovery knows them
/// from the descriptors it scans), so `resolve` is a pure map lookup with no IO on the hot path and
/// no interior mutability. An embedded active set can be supplied for the build-time copy.
#[derive(Debug, Default)]
pub struct CachingDictResolver {
    resolved: BTreeMap<u32, Vec<u8>>,
}

impl CachingDictResolver {
    /// An empty resolver (every non-zero `dict_id` is unresolved). Equivalent to
    /// `ironbus_core::compress::NoDictionaries` but owning, so dictionaries can be added.
    #[must_use]
    pub fn new() -> CachingDictResolver {
        CachingDictResolver {
            resolved: BTreeMap::new(),
        }
    }

    /// Adds an embedded active-set dictionary (the build-time copy, §3b), validating its content
    /// hash. A sidecar loaded later for the same id takes precedence (sidecar-first, §4) only if
    /// added after; in practice the embedded set seeds the resolver and sidecars override per-id
    /// via [`CachingDictResolver::preload_from_store`], which inserts the sidecar copy.
    ///
    /// # Errors
    /// Returns [`SidecarError::ContentHashMismatch`] if `bytes` do not hash to `dict_id`, or
    /// [`SidecarError::ZeroDictId`].
    pub fn add_embedded(&mut self, dict_id: u32, bytes: Vec<u8>) -> Result<(), SidecarError> {
        if dict_id == DICT_ID_NONE {
            return Err(SidecarError::ZeroDictId);
        }
        let derived = derive_dict_id(&bytes);
        if derived != dict_id {
            return Err(SidecarError::ContentHashMismatch {
                claimed: dict_id,
                derived,
            });
        }
        self.resolved.entry(dict_id).or_insert(bytes);
        Ok(())
    }

    /// Loads every `dict_id` in `wanted` from the sidecar store, OVERRIDING any embedded copy
    /// already present (sidecar-first, §4: the on-disk copy that travels with the data wins). A
    /// `dict_id` whose sidecar is absent or fails its content hash is left as-is (so an embedded
    /// copy, if present, still serves it), or unresolved.
    pub fn preload_from_store<F: Filesystem>(
        &mut self,
        store: &DictSidecarStore<F>,
        wanted: impl IntoIterator<Item = u32>,
    ) {
        for dict_id in wanted {
            if dict_id == DICT_ID_NONE {
                continue;
            }
            if let Some(bytes) = store.load(dict_id) {
                self.resolved.insert(dict_id, bytes);
            }
        }
    }

    /// How many dictionaries are resolvable.
    #[must_use]
    pub fn len(&self) -> usize {
        self.resolved.len()
    }

    /// Whether the resolver holds no dictionaries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resolved.is_empty()
    }
}

impl DictResolver for CachingDictResolver {
    fn resolve(&self, dict_id: u32) -> Option<&[u8]> {
        self.resolved.get(&dict_id).map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::InMemoryFs;
    use ironbus_core::dict::train_dictionary;

    fn record_for(i: u32) -> Vec<u8> {
        format!(
            "{{\"type\":\"sensor.telemetry.v1\",\"device\":\"hive-{:04}\",\"temp\":{}.{},\"seq\":{}}}",
            i % 64,
            18 + (i % 12),
            i % 10,
            i
        )
        .into_bytes()
    }

    fn a_trained_dict() -> ironbus_core::dict::TrainedDictionary {
        let corpus: Vec<Vec<u8>> = (0..2000u32).map(record_for).collect();
        train_dictionary(&corpus, 4096).expect("trains")
    }

    #[test]
    fn name_round_trips() {
        assert_eq!(dict_file_name(42), "42.zstd");
        assert_eq!(parse_dict_id_from_name("42.zstd"), Some(42));
        assert_eq!(parse_dict_id_from_name("seg-0.log"), None);
        assert_eq!(parse_dict_id_from_name("notanumber.zstd"), None);
    }

    #[test]
    fn store_then_load_round_trips_and_validates_the_content_hash() {
        let root = InMemoryFs::new();
        let store = DictSidecarStore::open(&root).unwrap();
        let dict = a_trained_dict();
        store.store(dict.dict_id, &dict.bytes).unwrap();
        // It lands in the dicts/ subdir under its content name.
        assert_eq!(store.list_ids(), vec![dict.dict_id]);
        let loaded = store.load(dict.dict_id).expect("loads");
        assert_eq!(loaded, dict.bytes);
    }

    #[test]
    fn store_refuses_a_mismatched_id_and_the_zero_sentinel() {
        let root = InMemoryFs::new();
        let store = DictSidecarStore::open(&root).unwrap();
        let dict = a_trained_dict();
        // A claimed id that does not match the bytes is refused.
        let wrong = dict.dict_id.wrapping_add(1);
        let err = store.store(wrong, &dict.bytes).unwrap_err();
        assert!(matches!(err, SidecarError::ContentHashMismatch { .. }));
        // The zero sentinel is never stored.
        assert!(matches!(
            store.store(DICT_ID_NONE, &dict.bytes).unwrap_err(),
            SidecarError::ZeroDictId
        ));
    }

    #[test]
    fn a_corrupt_sidecar_reads_as_absent() {
        let root = InMemoryFs::new();
        let store = DictSidecarStore::open(&root).unwrap();
        let dict = a_trained_dict();
        store.store(dict.dict_id, &dict.bytes).unwrap();
        // Corrupt the on-disk blob by writing a different file under the same content name. We do
        // this through the subdir fs directly: open the sidecar and flip a byte.
        let sub = store.filesystem();
        let name = dict_file_name(dict.dict_id);
        let f = sub.open(&name).unwrap();
        f.write_all_at(&[0xFF, 0xFF, 0xFF, 0xFF], 0).unwrap();
        f.sync_all().unwrap();
        // The content hash no longer matches the name, so load() treats it as ABSENT.
        assert_eq!(store.load(dict.dict_id), None);
    }

    #[test]
    fn store_is_write_once_and_idempotent() {
        let root = InMemoryFs::new();
        let store = DictSidecarStore::open(&root).unwrap();
        let dict = a_trained_dict();
        store.store(dict.dict_id, &dict.bytes).unwrap();
        // Storing the same content again is a no-op (content-addressed), not an error.
        store.store(dict.dict_id, &dict.bytes).unwrap();
        assert_eq!(store.list_ids().len(), 1);
    }

    #[test]
    fn resolver_resolves_sidecar_first_then_unresolved() {
        let root = InMemoryFs::new();
        let store = DictSidecarStore::open(&root).unwrap();
        let dict = a_trained_dict();
        store.store(dict.dict_id, &dict.bytes).unwrap();

        let mut resolver = CachingDictResolver::new();
        assert!(resolver.is_empty());
        // Before preloading, the id is unresolved.
        assert_eq!(resolver.resolve(dict.dict_id), None);
        resolver.preload_from_store(&store, [dict.dict_id, 0xDEAD_BEEF]);
        // The stored id resolves to its bytes; an unknown id stays unresolved (poison upstream).
        assert_eq!(resolver.resolve(dict.dict_id), Some(dict.bytes.as_slice()));
        assert_eq!(resolver.resolve(0xDEAD_BEEF), None);
        assert_eq!(resolver.len(), 1);
    }

    #[test]
    fn embedded_set_serves_when_no_sidecar_then_sidecar_overrides() {
        let root = InMemoryFs::new();
        let store = DictSidecarStore::open(&root).unwrap();
        let dict = a_trained_dict();

        // An embedded copy serves the id with no sidecar on disk (§3b, §4 step 2).
        let mut resolver = CachingDictResolver::new();
        resolver
            .add_embedded(dict.dict_id, dict.bytes.clone())
            .unwrap();
        assert_eq!(resolver.resolve(dict.dict_id), Some(dict.bytes.as_slice()));

        // Now write the sidecar and preload: sidecar-first means the on-disk copy is loaded (same
        // bytes here, content-addressed), confirming the §4 order does not strand the embedded id.
        store.store(dict.dict_id, &dict.bytes).unwrap();
        resolver.preload_from_store(&store, [dict.dict_id]);
        assert_eq!(resolver.resolve(dict.dict_id), Some(dict.bytes.as_slice()));
    }
}
