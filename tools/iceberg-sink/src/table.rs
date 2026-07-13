// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Iceberg v2 table writer: create/open, append a batch as a new snapshot, and expose the
//! durable resume watermark.
//!
//! ## Why the `iceberg` crate's spec writers, not hand-rolled Avro
//!
//! A minimal Iceberg table is Parquet data files plus an Avro manifest chain (manifest -> manifest
//! list -> `metadata.json`). The Avro manifest schemas carry ~30 fields each keyed by exact Iceberg
//! field-ids, and one wrong id silently produces a table an engine refuses to read. Rather than
//! hand-encode that (high risk for the "must be queryable" acceptance bar), this uses the `iceberg`
//! crate's own `spec` writers (`ManifestWriter`, `ManifestListWriter`, `TableMetadataBuilder`), which
//! are spec-correct by construction, while we keep full control of the two things a catalog would
//! otherwise own — the file LAYOUT and the durable CURRENT-metadata pointer — so the sink is
//! resumable and the table is readable by the plain Hadoop/`version-hint.text` convention that
//! DuckDB, Spark and Trino understand. Parquet data files are written directly with the Arrow writer
//! (sync); only the manifest/manifest-list writes are async (opendal `FileIO`), driven by one small
//! tokio runtime per table.
//!
//! ## Atomic commit + resume/dedup
//!
//! A batch commit writes, in order: the Parquet data file, the manifest, the manifest list, the new
//! `v{N}.metadata.json`, and finally an ATOMIC rename of `version-hint.text` to `N`. Crash-safety
//! rests on the classic "fsync the file, THEN fsync its parent directory, before writing the pointer
//! that references it" discipline: every file the new metadata transitively references — the Parquet
//! data file, the manifest, the manifest list, and `v{N}.metadata.json` — has both its CONTENTS and
//! its parent DIRECTORY ENTRY fsynced to disk BEFORE the `version-hint.text` rename that publishes
//! them, and the rename itself is then made durable by a final fsync of its directory. So a crash
//! mid-commit leaves the table valid at the previous version (orphaned files are harmless) and can
//! never leave the published pointer chain referencing a file whose dirent a power-loss dropped —
//! the failure that would otherwise cost committed rows the broker cursor has already advanced past.
//! See [`IcebergTable::append`] (data + manifest fsyncs) and [`IcebergTable::commit_metadata`] (the
//! metadata/version-hint publish) for the exact ordering. Each snapshot's summary records
//! `ironbus.next-offset` (the exclusive high offset the table now covers); that is the sink's
//! authoritative resume point AND dedup watermark — [`IcebergTable::append`] drops any record at or
//! below it, so an at-least-once redelivery can never duplicate a row.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use arrow_array::{ArrayRef, BinaryArray, Int32Array, Int64Array, RecordBatch};
use arrow_schema::{DataType, Field as ArrowField, Schema as ArrowSchema};
use iceberg::io::{FileIO, FileIOBuilder, LocalFsStorageFactory};
use iceberg::spec::{
    DataContentType, DataFileBuilder, DataFileFormat, FormatVersion, ManifestFile, ManifestList,
    ManifestListWriter, ManifestWriterBuilder, NestedField, Operation, PartitionSpec,
    PrimitiveType, Schema, Snapshot, SnapshotReference, SnapshotRetention, SortOrder, Struct,
    Summary, TableMetadata, TableMetadataBuilder, Type, MAIN_BRANCH,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use uuid::Uuid;

/// The snapshot-summary property that records the exclusive high offset the table covers: the sink's
/// durable resume point and dedup watermark.
pub const NEXT_OFFSET_PROP: &str = "ironbus.next-offset";
/// The table property that records where a brand-new table began materializing.
pub const START_OFFSET_PROP: &str = "ironbus.start-offset";

/// One consumed bus record, mapped to the table's columns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The bus log offset (the table's ordering key and dedup watermark).
    pub offset: i64,
    /// The producer timestamp, milliseconds since the Unix epoch.
    pub timestamp_ms: i64,
    /// The stored record flags.
    pub flags: i32,
    /// The routing/ordering key (empty if none).
    pub key: Vec<u8>,
    /// The headers blob (empty if none).
    pub headers: Vec<u8>,
    /// The message payload.
    pub payload: Vec<u8>,
}

/// The six table columns and their Iceberg field-ids. The Parquet `PARQUET:field_id` metadata is set
/// from the SAME ids so an engine maps columns by id, not just by name.
const COLUMNS: [(&str, i32); 6] = [
    ("offset", 1),
    ("timestamp_ms", 2),
    ("flags", 3),
    ("key", 4),
    ("headers", 5),
    ("payload", 6),
];

fn iceberg_schema() -> Result<Schema> {
    let fields = vec![
        NestedField::required(1, "offset", Type::Primitive(PrimitiveType::Long)).into(),
        NestedField::required(2, "timestamp_ms", Type::Primitive(PrimitiveType::Long)).into(),
        NestedField::required(3, "flags", Type::Primitive(PrimitiveType::Int)).into(),
        NestedField::required(4, "key", Type::Primitive(PrimitiveType::Binary)).into(),
        NestedField::required(5, "headers", Type::Primitive(PrimitiveType::Binary)).into(),
        NestedField::required(6, "payload", Type::Primitive(PrimitiveType::Binary)).into(),
    ];
    Schema::builder()
        .with_schema_id(0)
        .with_fields(fields)
        .build()
        .context("building the Iceberg table schema")
}

fn arrow_schema() -> Arc<ArrowSchema> {
    let fields = COLUMNS
        .iter()
        .map(|(name, id)| {
            let dt = match *name {
                "offset" | "timestamp_ms" => DataType::Int64,
                "flags" => DataType::Int32,
                _ => DataType::Binary,
            };
            ArrowField::new(*name, dt, false).with_metadata(HashMap::from([(
                "PARQUET:field_id".to_string(),
                id.to_string(),
            )]))
        })
        .collect::<Vec<_>>();
    Arc::new(ArrowSchema::new(fields))
}

/// A write-side Iceberg v2 table backed by a local directory.
pub struct IcebergTable {
    location: String,
    file_io: FileIO,
    rt: tokio::runtime::Runtime,
    metadata: TableMetadata,
    /// The last version persisted to `v{N}.metadata.json` / `version-hint.text`; `0` = none yet.
    version: u64,
    /// The path of the current persisted metadata file (for the metadata-log), if any.
    meta_path: Option<String>,
}

/// What a [`IcebergTable::compact_and_expire`] pass accomplished.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompactionStats {
    /// Manifests the current snapshot referenced BEFORE compaction — what a plain append would have
    /// carried forward wholesale into its next commit.
    pub manifests_before: usize,
    /// Manifests the compacted snapshot references (`1` on a real compaction).
    pub manifests_after: usize,
    /// Snapshots dropped from `metadata.json` by expiry (always keeping the current + retained window).
    pub snapshots_expired: usize,
    /// Stale manifest / manifest-list files physically deleted AFTER the commit was made durable.
    pub files_deleted: usize,
}

/// One live data file carried over into the compacted manifest, with the original provenance a
/// rewrite must preserve (resolved from the manifest-list entry when the manifest stored it
/// unassigned, exactly as a reader inherits it).
struct ExistingFile {
    data_file: iceberg::spec::DataFile,
    snapshot_id: i64,
    sequence_number: i64,
    file_sequence_number: i64,
}

impl IcebergTable {
    /// Opens the table at `location`, or creates a fresh (unmaterialized) one that will begin
    /// consuming at `start_offset`. An existing table's `start_offset` argument is ignored.
    pub fn open_or_create(location: &str, start_offset: i64) -> Result<Self> {
        std::fs::create_dir_all(format!("{location}/data"))
            .with_context(|| format!("creating {location}/data"))?;
        std::fs::create_dir_all(format!("{location}/metadata"))
            .with_context(|| format!("creating {location}/metadata"))?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .context("building the tokio runtime for Iceberg writes")?;
        let file_io: FileIO = FileIOBuilder::new(Arc::new(LocalFsStorageFactory)).build();

        let hint_path = format!("{location}/metadata/version-hint.text");
        if Path::new(&hint_path).exists() {
            let version: u64 = std::fs::read_to_string(&hint_path)
                .context("reading version-hint.text")?
                .trim()
                .parse()
                .context("parsing version-hint.text")?;
            let meta_path = format!("{location}/metadata/v{version}.metadata.json");
            let metadata: TableMetadata = serde_json::from_slice(
                &std::fs::read(&meta_path)
                    .with_context(|| format!("reading current table metadata {meta_path}"))?,
            )
            .context("parsing current table metadata")?;
            Ok(IcebergTable {
                location: location.to_string(),
                file_io,
                rt,
                metadata,
                version,
                meta_path: Some(meta_path),
            })
        } else {
            let mut props = HashMap::new();
            props.insert(START_OFFSET_PROP.to_string(), start_offset.to_string());
            let metadata = TableMetadataBuilder::new(
                iceberg_schema()?,
                PartitionSpec::unpartition_spec(),
                SortOrder::unsorted_order(),
                location.to_string(),
                FormatVersion::V2,
                props,
            )
            .context("initializing table metadata")?
            .build()
            .context("building initial table metadata")?
            .metadata;
            Ok(IcebergTable {
                location: location.to_string(),
                file_io,
                rt,
                metadata,
                version: 0,
                meta_path: None,
            })
        }
    }

    /// The exclusive high offset the table covers: the offset to resume consuming from, and the
    /// dedup watermark. It is the current snapshot's `ironbus.next-offset`, or the table's configured
    /// start offset when nothing has been materialized yet.
    #[must_use]
    pub fn next_offset(&self) -> i64 {
        if let Some(snap) = self.metadata.current_snapshot() {
            if let Some(v) = snap.summary().additional_properties.get(NEXT_OFFSET_PROP) {
                if let Ok(n) = v.parse::<i64>() {
                    return n;
                }
            }
        }
        self.metadata
            .properties()
            .get(START_OFFSET_PROP)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0)
    }

    /// The number of snapshots (append commits) in the table.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.metadata.snapshots().count()
    }

    /// The current persisted version (`0` if nothing has been committed yet).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Appends a batch of records as a new atomic snapshot. Records at or below the current watermark
    /// are dropped (dedup); the remainder MUST be strictly increasing in offset (bus log order).
    /// Returns the new number of records actually written (0 = the whole batch was already
    /// materialized, a no-op).
    #[allow(clippy::too_many_lines)]
    pub fn append(&mut self, records: &[Record]) -> Result<usize> {
        let watermark = self.next_offset();
        // Dedup: never re-materialize an offset the table already covers. This is what makes an
        // at-least-once redelivery (or a crash between this commit and the broker-cursor commit)
        // dup-safe.
        let fresh: Vec<&Record> = records.iter().filter(|r| r.offset >= watermark).collect();
        if fresh.is_empty() {
            return Ok(0);
        }
        for w in fresh.windows(2) {
            if w[1].offset <= w[0].offset {
                bail!(
                    "records are not strictly increasing in offset ({} then {}); refusing to append",
                    w[0].offset,
                    w[1].offset
                );
            }
        }
        let new_next_offset = fresh
            .last()
            .expect("fresh is non-empty")
            .offset
            .checked_add(1)
            .ok_or_else(|| anyhow!("offset overflow"))?;

        let commit_uuid = Uuid::new_v4();
        // Never reuse a snapshot id already in this table (Iceberg requires them unique) and never 0.
        let existing_ids: HashSet<i64> =
            self.metadata.snapshots().map(|s| s.snapshot_id()).collect();
        let snapshot_id = new_snapshot_id(&existing_ids);
        let next_seq = self.metadata.next_sequence_number();
        let schema_ref = self.metadata.current_schema().clone();
        let spec = self.metadata.default_partition_spec().as_ref().clone();

        // 1. Parquet data file. `write_parquet` fsyncs the file's CONTENTS; here we additionally make
        //    its DIRENT durable by fsyncing the data/ directory, BEFORE any pointer (manifest ->
        //    metadata -> the published version-hint) references it. A file-content fsync alone does
        //    not guarantee the parent directory's new entry survives a power loss on every FS; without
        //    this a committed metadata could reference a data file whose dirent was lost, yielding an
        //    unreadable table and rows lost past the already-advanced broker cursor.
        let data_path = format!("{}/data/{commit_uuid}.parquet", self.location);
        let size = write_parquet(&data_path, &fresh).context("writing the Parquet data file")?;
        fsync_dir(&format!("{}/data", self.location)).context("fsyncing the data directory")?;
        let data_file = DataFileBuilder::default()
            .content(DataContentType::Data)
            .file_path(data_path)
            .file_format(DataFileFormat::Parquet)
            .partition(Struct::empty())
            .partition_spec_id(0)
            .record_count(fresh.len() as u64)
            .file_size_in_bytes(size)
            .build()
            .map_err(|e| anyhow!("building the Iceberg DataFile: {e}"))?;

        // 2. Manifest (Avro) for the new data file.
        let manifest_path = format!("{}/metadata/{commit_uuid}-m0.avro", self.location);
        let out = self
            .file_io
            .new_output(&manifest_path)
            .context("opening the manifest output")?;
        let mut mw = ManifestWriterBuilder::new(out, Some(snapshot_id), None, schema_ref, spec)
            .build_v2_data();
        // `-1` = UNASSIGNED sequence number: v2 inherits it from the snapshot at read time.
        mw.add_file(data_file, -1)
            .context("adding the data file to the manifest")?;
        let new_manifest = self
            .rt
            .block_on(mw.write_manifest_file())
            .context("writing the manifest file")?;
        // The async opendal writer returns a path, not a synced handle: fsync the manifest's contents
        // now. Its DIRENT is made durable with the rest of metadata/ at the commit point below.
        fsync_file(&manifest_path).context("fsyncing the manifest file")?;

        // 3. Manifest list (Avro): carry forward every manifest from the parent snapshot, then add
        //    the new one, so the snapshot references the FULL set of live data (the append bug that
        //    otherwise makes only the newest batch visible).
        let mut manifests: Vec<ManifestFile> = Vec::new();
        if let Some(parent) = self.metadata.current_snapshot() {
            let bytes = std::fs::read(parent.manifest_list())
                .context("reading the parent manifest list")?;
            let parent_list = ManifestList::parse_with_version(&bytes, FormatVersion::V2)
                .context("parsing the parent manifest list")?;
            manifests.extend(parent_list.consume_entries());
        }
        manifests.push(new_manifest);
        let ml_path = format!(
            "{}/metadata/snap-{snapshot_id}-0-{commit_uuid}.avro",
            self.location
        );
        let out2 = self
            .file_io
            .new_output(&ml_path)
            .context("opening the manifest-list output")?;
        let mut mlw = ManifestListWriter::v2(
            out2,
            snapshot_id,
            self.metadata.current_snapshot_id(),
            next_seq,
        );
        mlw.add_manifests(manifests.into_iter())
            .context("adding manifests to the manifest list")?;
        self.rt
            .block_on(mlw.close())
            .context("writing the manifest list")?;
        // Fsync the manifest list's contents (same reason as the manifest above).
        fsync_file(&ml_path).context("fsyncing the manifest list")?;

        // 4. Snapshot, recording the durable resume watermark in its summary.
        let mut props = HashMap::new();
        props.insert(NEXT_OFFSET_PROP.to_string(), new_next_offset.to_string());
        props.insert("added-records".to_string(), fresh.len().to_string());
        let summary = Summary {
            operation: Operation::Append,
            additional_properties: props,
        };
        let snapshot = Snapshot::builder()
            .with_snapshot_id(snapshot_id)
            .with_parent_snapshot_id(self.metadata.current_snapshot_id())
            .with_sequence_number(next_seq)
            .with_timestamp_ms(now_ms())
            .with_manifest_list(ml_path)
            .with_summary(summary)
            .with_schema_id(self.metadata.current_schema_id())
            .build();

        // 5. New table metadata pointing at the new snapshot on `main`.
        let new_metadata =
            TableMetadataBuilder::new_from_metadata(self.metadata.clone(), self.meta_path.clone())
                .add_snapshot(snapshot)
                .context("adding the snapshot to table metadata")?
                .set_ref(
                    MAIN_BRANCH,
                    SnapshotReference::new(
                        snapshot_id,
                        SnapshotRetention::branch(None, None, None),
                    ),
                )
                .context("advancing the main branch ref")?
                .build()
                .context("building the new table metadata")?
                .metadata;

        // 6. Atomic commit: persist metadata.json, then swap version-hint.text.
        let new_version = self.version + 1;
        let meta_path = self
            .commit_metadata(new_version, &new_metadata)
            .context("committing table metadata")?;

        self.metadata = new_metadata;
        self.version = new_version;
        self.meta_path = Some(meta_path);
        Ok(fresh.len())
    }

    /// The number of manifest files the CURRENT snapshot references (its manifest list's entry count).
    /// This is exactly the set a plain [`append`](Self::append) carries forward wholesale into the next
    /// commit, so it is what bounds per-commit manifest-list bytes; the sink watches it to decide when
    /// to compact. `0` when nothing has been committed yet.
    pub fn current_manifest_count(&self) -> Result<usize> {
        let Some(snapshot) = self.metadata.current_snapshot() else {
            return Ok(0);
        };
        let bytes =
            std::fs::read(snapshot.manifest_list()).context("reading the current manifest list")?;
        let list = ManifestList::parse_with_version(&bytes, FormatVersion::V2)
            .context("parsing the current manifest list")?;
        Ok(list.entries().len())
    }

    /// Compacts the current snapshot's manifests into ONE and expires snapshots beyond
    /// `snapshot_retention_count`, as a single atomic, crash-safe commit; then deletes the manifest /
    /// manifest-list files that NO retained snapshot references any more (delete-AFTER-commit). This
    /// bounds two forms of unbounded metadata growth on a long-lived table: the O(N) manifest list
    /// every append must otherwise carry forward (hence O(N^2) total manifest-list bytes over N
    /// commits), and the ever-growing snapshot log in `metadata.json`.
    ///
    /// ## Correctness — never drop a live file
    ///
    /// Compaction is a pure metadata REWRITE: the new "replace" snapshot references the exact same set
    /// of live data files as the snapshot it replaces — each carried over with
    /// [`ManifestWriter::add_existing_file`](iceberg::spec::ManifestWriter), preserving its original
    /// snapshot id and data/file sequence numbers (resolved from the manifest-list entry exactly as a
    /// reader inherits them), so a reader sees byte-identical table contents. Expiry only removes
    /// snapshots that are NOT the current one and fall outside the retained window. The
    /// delete-after-commit sweep computes the RETAINED live set = the union of every manifest list,
    /// manifest and data file reachable from EVERY snapshot still in the committed metadata, and
    /// deletes a physical file only if it is in NO retained snapshot's reachable set. So no file any
    /// retained snapshot (current included) needs is ever removed.
    ///
    /// ## Crash-safety — delete strictly after the commit is durable
    ///
    /// The new compacted manifest, manifest list and `metadata.json` are written and fsynced with the
    /// IDENTICAL fail-closed discipline as [`append`](Self::append) (contents fsynced, dirents fsynced
    /// before any pointer references them), and the commit is published atomically by the
    /// `version-hint.text` rename in [`commit_metadata`](Self::commit_metadata). Only AFTER that swap is
    /// durable does this delete the now-unreferenced old files. A crash before the swap leaves the
    /// table valid at the previous version (the compaction simply re-runs later); a crash DURING the
    /// post-commit sweep leaves a few orphan files nothing live references — never a dangling pointer.
    /// The reachable-set computation the sweep trusts is FAIL-CLOSED: if any retained snapshot's
    /// manifest chain cannot be fully read, the sweep deletes nothing (bounded metadata growth is the
    /// goal; a missed reclaim is harmless, a wrong delete is not), and an individual unlink failure is
    /// ignored — it never fails the already-durable commit.
    ///
    /// `snapshot_retention_count` is clamped to at least 1 (the current snapshot is always kept).
    /// Returns a no-op (zeroed stats) when there is nothing to gain: no snapshot yet, or already a
    /// single manifest with no snapshots to expire.
    #[allow(clippy::too_many_lines)]
    pub fn compact_and_expire(
        &mut self,
        snapshot_retention_count: usize,
    ) -> Result<CompactionStats> {
        let retain = snapshot_retention_count.max(1);

        // Snapshot the current manifest-list path, releasing the borrow of self before we mutate.
        let current_ml = match self.metadata.current_snapshot() {
            Some(s) => s.manifest_list().to_string(),
            None => return Ok(CompactionStats::default()),
        };

        // Read the current manifest list -> every LIVE data-file entry across all its manifests, each
        // with its original provenance resolved (inheriting snapshot id + sequence numbers from the
        // manifest-list entry when the manifest stored them unassigned, exactly as a reader would).
        let ml_bytes = std::fs::read(&current_ml).context("reading the current manifest list")?;
        let manifest_list = ManifestList::parse_with_version(&ml_bytes, FormatVersion::V2)
            .context("parsing the current manifest list")?;
        let manifests_before = manifest_list.entries().len();
        let snapshots_now = self.metadata.snapshots().count();

        // Nothing to gain: already a single manifest AND nothing to expire.
        if manifests_before <= 1 && snapshots_now <= retain {
            return Ok(CompactionStats {
                manifests_before,
                manifests_after: manifests_before,
                snapshots_expired: 0,
                files_deleted: 0,
            });
        }

        let mut live: Vec<ExistingFile> = Vec::new();
        for mf in manifest_list.entries() {
            let man_bytes = std::fs::read(&mf.manifest_path)
                .with_context(|| format!("reading manifest {}", mf.manifest_path))?;
            let manifest = iceberg::spec::Manifest::parse_avro(&man_bytes)
                .with_context(|| format!("parsing manifest {}", mf.manifest_path))?;
            for e in manifest.entries() {
                if !e.is_alive() {
                    continue;
                }
                live.push(ExistingFile {
                    data_file: e.data_file().clone(),
                    snapshot_id: e.snapshot_id().unwrap_or(mf.added_snapshot_id),
                    sequence_number: e.sequence_number().unwrap_or(mf.sequence_number),
                    file_sequence_number: e.file_sequence_number.unwrap_or(mf.sequence_number),
                });
            }
        }

        // Preserve the durable resume watermark on the replace snapshot: next_offset() reads it from
        // the CURRENT snapshot summary, so the compacted snapshot MUST carry it or a cold resume would
        // regress to the table's start offset and re-materialize everything.
        let watermark = self.next_offset();

        let existing_ids: HashSet<i64> =
            self.metadata.snapshots().map(|s| s.snapshot_id()).collect();
        let new_sid = new_snapshot_id(&existing_ids);
        let next_seq = self.metadata.next_sequence_number();
        let schema_ref = self.metadata.current_schema().clone();
        let spec = self.metadata.default_partition_spec().as_ref().clone();
        let commit_uuid = Uuid::new_v4();

        // 1. One compacted manifest holding every live data file as an EXISTING entry (status
        //    Existing, original provenance preserved — this is a rewrite, not a re-append).
        let manifest_path = format!("{}/metadata/{commit_uuid}-compact-m0.avro", self.location);
        let out = self
            .file_io
            .new_output(&manifest_path)
            .context("opening the compacted manifest output")?;
        let mut mw =
            ManifestWriterBuilder::new(out, Some(new_sid), None, schema_ref, spec).build_v2_data();
        for e in live {
            mw.add_existing_file(
                e.data_file,
                e.snapshot_id,
                e.sequence_number,
                Some(e.file_sequence_number),
            )
            .context("adding an existing data file to the compacted manifest")?;
        }
        let compacted = self
            .rt
            .block_on(mw.write_manifest_file())
            .context("writing the compacted manifest")?;
        fsync_file(&manifest_path).context("fsyncing the compacted manifest")?;

        // 2. Manifest list referencing only the one compacted manifest.
        let ml_path = format!(
            "{}/metadata/snap-{new_sid}-0-{commit_uuid}.avro",
            self.location
        );
        let out2 = self
            .file_io
            .new_output(&ml_path)
            .context("opening the compacted manifest-list output")?;
        let mut mlw =
            ManifestListWriter::v2(out2, new_sid, self.metadata.current_snapshot_id(), next_seq);
        mlw.add_manifests(std::iter::once(compacted))
            .context("adding the compacted manifest to the manifest list")?;
        self.rt
            .block_on(mlw.close())
            .context("writing the compacted manifest list")?;
        fsync_file(&ml_path).context("fsyncing the compacted manifest list")?;

        // 3. A "replace" snapshot over the same data, carrying the resume watermark forward.
        let mut props = HashMap::new();
        props.insert(NEXT_OFFSET_PROP.to_string(), watermark.to_string());
        props.insert(
            "compacted-manifests".to_string(),
            manifests_before.to_string(),
        );
        let summary = Summary {
            operation: Operation::Replace,
            additional_properties: props,
        };
        let snapshot = Snapshot::builder()
            .with_snapshot_id(new_sid)
            .with_parent_snapshot_id(self.metadata.current_snapshot_id())
            .with_sequence_number(next_seq)
            .with_timestamp_ms(now_ms())
            .with_manifest_list(ml_path)
            .with_summary(summary)
            .with_schema_id(self.metadata.current_schema_id())
            .build();

        // 4. Choose which OLD snapshots to expire: keep the newest `retain - 1` of them plus the new
        //    replace snapshot = `retain` total. The current snapshot always survives (it is never in
        //    the expire set, and after set_ref the main ref points at the new snapshot).
        let mut by_seq: Vec<(i64, i64)> = self
            .metadata
            .snapshots()
            .map(|s| (s.sequence_number(), s.snapshot_id()))
            .collect();
        by_seq.sort_by_key(|(seq, _)| *seq);
        let keep_old = retain.saturating_sub(1);
        let expire_ids: Vec<i64> = if by_seq.len() > keep_old {
            by_seq[..by_seq.len() - keep_old]
                .iter()
                .map(|(_, id)| *id)
                .collect()
        } else {
            Vec::new()
        };

        // 5. New metadata: add the replace snapshot, advance main, expire the old snapshots. The
        //    builder prunes the snapshot log to the retained suffix ending at the current snapshot.
        let new_metadata =
            TableMetadataBuilder::new_from_metadata(self.metadata.clone(), self.meta_path.clone())
                .add_snapshot(snapshot)
                .context("adding the compaction snapshot to table metadata")?
                .set_ref(
                    MAIN_BRANCH,
                    SnapshotReference::new(new_sid, SnapshotRetention::branch(None, None, None)),
                )
                .context("advancing the main branch ref to the compaction snapshot")?
                .remove_snapshots(&expire_ids)
                .build()
                .context("building the compacted table metadata")?
                .metadata;

        // 6. Atomic, crash-safe commit (identical discipline to append).
        let new_version = self.version + 1;
        let meta_path = self
            .commit_metadata(new_version, &new_metadata)
            .context("committing the compacted table metadata")?;
        self.metadata = new_metadata;
        self.version = new_version;
        self.meta_path = Some(meta_path);

        // 7. Delete-AFTER-commit: only now that the new pointer chain (which references NONE of the
        //    old per-commit manifests / manifest lists that fell out of the retained set) is durable
        //    do we reclaim them. Fail-closed + best-effort: an incompletely computed reachable set
        //    deletes nothing, and an individual unlink failure is ignored (a harmless orphan either
        //    way). This NEVER fails the already-durable commit.
        let files_deleted = match self.unreferenced_metadata_files() {
            Ok(paths) => paths
                .iter()
                .filter(|p| std::fs::remove_file(p).is_ok())
                .count(),
            Err(e) => {
                eprintln!(
                    "iceberg-sink: compaction GC skipped (reachable set incomplete, fail-closed): {e:#}"
                );
                0
            }
        };

        Ok(CompactionStats {
            manifests_before,
            manifests_after: 1,
            snapshots_expired: expire_ids.len(),
            files_deleted,
        })
    }

    /// The delete-after-commit reclaim set: the manifest / manifest-list (`*.avro`) files under
    /// `metadata/` that NO snapshot currently in the table references. Computes the RETAINED live set —
    /// the union of every manifest list, manifest, and data file reachable from every snapshot still in
    /// the committed metadata — and returns the `*.avro` files not in it. FAIL-CLOSED: any failure to
    /// fully walk a retained snapshot's manifest chain (or to canonicalize a file it references)
    /// returns `Err`, so the caller deletes nothing rather than risk removing a file a retained
    /// snapshot still needs. Data files ARE included in the reachable set (so a live `.parquet` can
    /// never become a candidate) but are never themselves returned: this append-only sink keeps every
    /// data file live, so the only reclaimable garbage is stale metadata. All paths are canonicalized
    /// so string-form differences (relative vs absolute) cannot cause a false "unreferenced" verdict.
    fn unreferenced_metadata_files(&self) -> Result<Vec<PathBuf>> {
        let mut reachable: HashSet<PathBuf> = HashSet::new();
        for snapshot in self.metadata.snapshots() {
            let ml = snapshot.manifest_list();
            reachable.insert(canonical(ml)?);
            let ml_bytes =
                std::fs::read(ml).with_context(|| format!("reading manifest list {ml}"))?;
            let list = ManifestList::parse_with_version(&ml_bytes, FormatVersion::V2)
                .with_context(|| format!("parsing manifest list {ml}"))?;
            for mf in list.entries() {
                reachable.insert(canonical(&mf.manifest_path)?);
                let man_bytes = std::fs::read(&mf.manifest_path)
                    .with_context(|| format!("reading manifest {}", mf.manifest_path))?;
                let manifest = iceberg::spec::Manifest::parse_avro(&man_bytes)
                    .with_context(|| format!("parsing manifest {}", mf.manifest_path))?;
                for e in manifest.entries() {
                    if e.is_alive() {
                        reachable.insert(canonical(e.data_file().file_path())?);
                    }
                }
            }
        }

        // Candidates: every `*.avro` (manifest / manifest list) under metadata/. metadata.json,
        // version-hint.text and the *.tmp.* staging files are deliberately NOT candidates — the
        // pointer chain / metadata log is governed by the atomic commit, not this sweep.
        let meta_dir = format!("{}/metadata", self.location);
        let mut garbage = Vec::new();
        for entry in std::fs::read_dir(&meta_dir).with_context(|| format!("listing {meta_dir}"))? {
            let path = entry
                .with_context(|| format!("reading a dir entry in {meta_dir}"))?
                .path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("avro") {
                continue;
            }
            let canon = canonical(&path)?;
            if !reachable.contains(&canon) {
                garbage.push(canon);
            }
        }
        Ok(garbage)
    }

    /// Persists `v{version}.metadata.json` and then atomically publishes it by renaming
    /// `version-hint.text` over it — the table's commit point. The ordering is crash-safe and
    /// FAIL-CLOSED:
    ///
    /// 1. write + fsync `v{version}.metadata.json`'s contents;
    /// 2. fsync the `metadata/` directory, so the new metadata.json AND the manifest / manifest-list
    ///    files [`IcebergTable::append`] already wrote there have durable DIRENTS — everything the
    ///    pointer is about to reference now survives a crash;
    /// 3. write + fsync a temp `version-hint.text`, then atomically rename it over the real one;
    /// 4. fsync the `metadata/` directory again, so the rename (the publish) is itself durable.
    ///
    /// A directory fsync that cannot be performed FAILS the commit rather than being silently skipped:
    /// on a data-integrity path a missing dirent-fsync is exactly the durability hole being closed.
    /// Returns the metadata file path.
    fn commit_metadata(&self, version: u64, md: &TableMetadata) -> Result<String> {
        let meta_dir = format!("{}/metadata", self.location);
        let meta_path = format!("{meta_dir}/v{version}.metadata.json");
        let json = serde_json::to_vec_pretty(md).context("serializing table metadata")?;
        write_fsync(&meta_path, &json)?;

        // Make the metadata.json + manifest + manifest-list DIRENTS durable BEFORE publishing the
        // pointer that references them.
        fsync_dir(&meta_dir).context("fsyncing the metadata directory before publish")?;

        let hint = format!("{meta_dir}/version-hint.text");
        let tmp = format!("{hint}.tmp.{}", Uuid::new_v4());
        write_fsync(&tmp, version.to_string().as_bytes())?;
        std::fs::rename(&tmp, &hint).context("atomically swapping version-hint.text")?;
        // Make the rename itself (the commit point) durable.
        fsync_dir(&meta_dir).context("fsyncing the metadata directory after publish")?;
        Ok(meta_path)
    }
}

/// Scans the whole table via its Iceberg metadata graph (version-hint -> metadata.json -> manifest
/// list -> manifests -> Parquet) and returns every `offset` value it contains, in file order. This
/// walks the real Iceberg reference chain, so it proves the metadata is internally consistent and
/// the referenced data is reachable — the structural verification that pairs with the external
/// DuckDB query. Returns an empty vec for a table with no snapshot yet.
pub fn scan_offsets(location: &str) -> Result<Vec<i64>> {
    let hint_path = format!("{location}/metadata/version-hint.text");
    if !Path::new(&hint_path).exists() {
        return Ok(Vec::new());
    }
    let version: u64 = std::fs::read_to_string(&hint_path)
        .context("reading version-hint.text")?
        .trim()
        .parse()
        .context("parsing version-hint.text")?;
    let meta_path = format!("{location}/metadata/v{version}.metadata.json");
    let metadata: TableMetadata = serde_json::from_slice(
        &std::fs::read(&meta_path).context("reading table metadata for scan")?,
    )
    .context("parsing table metadata for scan")?;
    let Some(snapshot) = metadata.current_snapshot() else {
        return Ok(Vec::new());
    };
    let ml_bytes = std::fs::read(snapshot.manifest_list()).context("reading the manifest list")?;
    let manifest_list = ManifestList::parse_with_version(&ml_bytes, FormatVersion::V2)
        .context("parsing the manifest list")?;

    let mut offsets = Vec::new();
    for entry in manifest_list.entries() {
        let man_bytes = std::fs::read(&entry.manifest_path).context("reading a manifest")?;
        let manifest =
            iceberg::spec::Manifest::parse_avro(&man_bytes).context("parsing a manifest")?;
        for e in manifest.entries() {
            if !e.is_alive() {
                continue;
            }
            let path = e.data_file().file_path();
            let file = File::open(path).with_context(|| format!("opening data file {path}"))?;
            let reader = ParquetRecordBatchReaderBuilder::try_new(file)
                .with_context(|| format!("opening Parquet reader for {path}"))?
                .build()
                .context("building the Parquet reader")?;
            for batch in reader {
                let batch = batch.context("reading a Parquet batch")?;
                let col = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or_else(|| anyhow!("offset column is not Int64"))?;
                for i in 0..col.len() {
                    offsets.push(col.value(i));
                }
            }
        }
    }
    Ok(offsets)
}

fn write_fsync(path: &str, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("opening {path}"))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {path}"))?;
    f.sync_all().with_context(|| format!("fsyncing {path}"))?;
    Ok(())
}

/// Fsyncs a directory so a newly created or renamed entry inside it is durable. FAIL-CLOSED: on the
/// data-integrity commit path a directory-fsync failure must fail the commit, never be skipped — a
/// lost dirent for a file the committed metadata references is exactly the power-loss hole this
/// closes. Opening the directory read-only and calling `fsync` on it is the portable POSIX idiom.
fn fsync_dir(path: &str) -> Result<()> {
    let dir = File::open(path).with_context(|| format!("opening directory {path} for fsync"))?;
    dir.sync_all()
        .with_context(|| format!("fsyncing directory {path}"))?;
    Ok(())
}

/// Fsyncs an already-written file's CONTENTS by path. The async manifest / manifest-list writers hand
/// back only a path (not a synced handle) and may not fsync themselves, so the sink fsyncs them here;
/// their dirents are then made durable together with the enclosing directory at the commit point.
fn fsync_file(path: &str) -> Result<()> {
    let f = File::open(path).with_context(|| format!("opening {path} for fsync"))?;
    f.sync_all().with_context(|| format!("fsyncing {path}"))?;
    Ok(())
}

/// Resolves a path to its canonical, absolute form (following the real filesystem). Used by the
/// compaction GC to compare on-disk files against the reachable set by identity rather than by string
/// form; it requires the file to EXIST, so a canonicalize failure on a supposedly-reachable file is a
/// fail-closed signal that aborts the sweep.
fn canonical<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    std::fs::canonicalize(&path)
        .with_context(|| format!("canonicalizing {}", path.as_ref().display()))
}

fn write_parquet(path: &str, records: &[&Record]) -> Result<u64> {
    let schema = arrow_schema();
    let offsets = Int64Array::from(records.iter().map(|r| r.offset).collect::<Vec<_>>());
    let ts = Int64Array::from(records.iter().map(|r| r.timestamp_ms).collect::<Vec<_>>());
    let flags = Int32Array::from(records.iter().map(|r| r.flags).collect::<Vec<_>>());
    let key = BinaryArray::from_iter_values(records.iter().map(|r| r.key.as_slice()));
    let headers = BinaryArray::from_iter_values(records.iter().map(|r| r.headers.as_slice()));
    let payload = BinaryArray::from_iter_values(records.iter().map(|r| r.payload.as_slice()));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(offsets) as ArrayRef,
            Arc::new(ts) as ArrayRef,
            Arc::new(flags) as ArrayRef,
            Arc::new(key) as ArrayRef,
            Arc::new(headers) as ArrayRef,
            Arc::new(payload) as ArrayRef,
        ],
    )
    .context("assembling the Arrow record batch")?;
    let file = File::create(path).with_context(|| format!("creating {path}"))?;
    // A shared handle to fsync after the writer finalizes the footer (close() consumes the writer and
    // returns Parquet metadata, not the file).
    let fsync_handle = file.try_clone().context("cloning the data-file handle")?;
    let mut writer =
        ArrowWriter::try_new(file, schema, None).context("opening the Parquet writer")?;
    writer.write(&batch).context("writing the Parquet batch")?;
    writer.close().context("closing the Parquet writer")?;
    fsync_handle
        .sync_all()
        .context("fsyncing the Parquet data file")?;
    std::fs::metadata(path)
        .map(|m| m.len())
        .with_context(|| format!("sizing {path}"))
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// Generates a fresh snapshot id: 128 bits of UUID entropy folded to a positive 63-bit value. A
/// collision is astronomically unlikely, but the loop turns "unique and non-zero" from a probability
/// into a guarantee — Iceberg requires snapshot ids unique within a table, and `0` is the
/// nil/degenerate id some readers treat as "no snapshot". Re-rolls on `0` or a collision with an
/// existing id.
fn new_snapshot_id(existing: &HashSet<i64>) -> i64 {
    loop {
        let (a, b) = Uuid::new_v4().as_u64_pair();
        let id = ((a ^ b) as i64).saturating_abs();
        if id != 0 && !existing.contains(&id) {
            return id;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(offset: i64) -> Record {
        Record {
            offset,
            timestamp_ms: 1_700_000_000_000 + offset,
            flags: 0,
            key: format!("k{offset}").into_bytes(),
            headers: Vec::new(),
            payload: format!("payload-{offset}").into_bytes(),
        }
    }

    /// The Iceberg schema field-ids must stay 1..=6 after the builder's id reassignment, because the
    /// Parquet `PARQUET:field_id` metadata is written from those same constants; a drift would break
    /// engine column mapping.
    #[test]
    fn schema_field_ids_are_stable() {
        let dir = tempfile::tempdir().unwrap();
        let t = IcebergTable::open_or_create(dir.path().to_str().unwrap(), 0).unwrap();
        let schema = t.metadata.current_schema();
        for (name, id) in COLUMNS {
            let f = schema.field_by_name(name).expect("field present");
            assert_eq!(f.id, id, "field {name} id drifted");
        }
    }

    #[test]
    fn fresh_table_watermark_is_start_offset() {
        let dir = tempfile::tempdir().unwrap();
        let t = IcebergTable::open_or_create(dir.path().to_str().unwrap(), 7).unwrap();
        assert_eq!(t.next_offset(), 7);
        assert_eq!(t.snapshot_count(), 0);
        assert_eq!(t.version(), 0);
    }

    #[test]
    fn append_advances_watermark_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        let batch: Vec<Record> = (0..5).map(mk).collect();
        assert_eq!(t.append(&batch).unwrap(), 5);
        assert_eq!(t.next_offset(), 5);
        assert_eq!(t.version(), 1);
        assert_eq!(t.snapshot_count(), 1);
        // Reopen: the watermark survives via version-hint -> metadata.json.
        let t2 = IcebergTable::open_or_create(loc, 999).unwrap();
        assert_eq!(
            t2.next_offset(),
            5,
            "start_offset ignored on an existing table"
        );
        assert_eq!(t2.version(), 1);
    }

    #[test]
    fn append_is_dup_safe() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        t.append(&(0..5).map(mk).collect::<Vec<_>>()).unwrap();
        // Redeliver [0,5) plus new [5,8): the overlap is dropped, only 5..8 is written.
        let redelivered: Vec<Record> = (0..8).map(mk).collect();
        assert_eq!(t.append(&redelivered).unwrap(), 3);
        assert_eq!(t.next_offset(), 8);
        // A pure redelivery below the watermark is a no-op (no empty snapshot).
        assert_eq!(t.append(&(0..8).map(mk).collect::<Vec<_>>()).unwrap(), 0);
        assert_eq!(t.snapshot_count(), 2);
    }

    #[test]
    fn scan_offsets_reads_contiguous_across_snapshots() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        assert!(
            scan_offsets(loc).unwrap().is_empty(),
            "empty table scans empty"
        );
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        t.append(&(0..5).map(mk).collect::<Vec<_>>()).unwrap();
        t.append(&(5..8).map(mk).collect::<Vec<_>>()).unwrap();
        let mut got = scan_offsets(loc).unwrap();
        got.sort_unstable();
        assert_eq!(got, (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn append_rejects_non_increasing() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        let bad = vec![mk(0), mk(2), mk(2)];
        assert!(t.append(&bad).is_err());
    }

    /// Walks the CURRENT metadata graph (version-hint -> metadata.json -> manifest-list -> manifests)
    /// and returns every live data-file path it references — the files whose dirents FIX 1 makes
    /// durable before the metadata that points at them is published.
    fn referenced_data_files(location: &str) -> Vec<String> {
        let hint =
            std::fs::read_to_string(format!("{location}/metadata/version-hint.text")).unwrap();
        let version: u64 = hint.trim().parse().unwrap();
        let md: TableMetadata = serde_json::from_slice(
            &std::fs::read(format!("{location}/metadata/v{version}.metadata.json")).unwrap(),
        )
        .unwrap();
        let snap = md
            .current_snapshot()
            .expect("a committed table has a current snapshot");
        let ml = ManifestList::parse_with_version(
            &std::fs::read(snap.manifest_list()).unwrap(),
            FormatVersion::V2,
        )
        .unwrap();
        let mut out = Vec::new();
        for entry in ml.entries() {
            let man =
                iceberg::spec::Manifest::parse_avro(&std::fs::read(&entry.manifest_path).unwrap())
                    .unwrap();
            for e in man.entries() {
                if e.is_alive() {
                    out.push(e.data_file().file_path().to_string());
                }
            }
        }
        out
    }

    /// The commit-ordering durability invariant, verified functionally (FIX 1). After commits return
    /// and the writer is DROPPED — so only the durable on-disk state remains — the table opened COLD
    /// through its public Iceberg reference chain reads back EXACTLY the committed rows, and every
    /// data file the metadata references is present on disk. This is precisely what the "fsync the
    /// data/ dirent (and each manifest) before publishing the metadata that points at it" ordering
    /// guarantees: a lost data-file dirent would make the cold scan fail to open the file or drop its
    /// rows. (A syscall-order recording FS is not available across both std::fs and iceberg's async
    /// opendal writer, so this cold read-back + reachability check is the invariant's proof; the exact
    /// fsync ordering is documented on `append`/`commit_metadata`.)
    #[test]
    fn committed_table_reads_back_all_rows_and_referenced_files_exist() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        {
            let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
            t.append(&(0..5).map(mk).collect::<Vec<_>>()).unwrap();
            t.append(&(5..11).map(mk).collect::<Vec<_>>()).unwrap();
        } // writer dropped: nothing in memory, only what was fsynced survives

        let mut got = scan_offsets(loc).unwrap();
        got.sort_unstable();
        assert_eq!(
            got,
            (0..11).collect::<Vec<_>>(),
            "cold read through the metadata chain must return exactly the committed rows"
        );

        let referenced = referenced_data_files(loc);
        assert_eq!(
            referenced.len(),
            2,
            "two appends -> two data files referenced"
        );
        for path in referenced {
            assert!(
                Path::new(&path).exists(),
                "data file {path} referenced by committed metadata must exist on disk"
            );
        }

        // The durable resume watermark also survives a cold reopen.
        let t2 = IcebergTable::open_or_create(loc, 999).unwrap();
        assert_eq!(t2.next_offset(), 11);
        assert_eq!(t2.version(), 2);
    }

    /// FIX 2: `new_snapshot_id` never yields 0 and never collides with an id already in the set.
    #[test]
    fn new_snapshot_id_is_nonzero_and_unique() {
        let mut seen: HashSet<i64> = HashSet::new();
        for _ in 0..20_000 {
            let id = new_snapshot_id(&seen);
            assert!(
                id > 0,
                "snapshot id must be positive and non-zero, got {id}"
            );
            assert!(
                seen.insert(id),
                "new_snapshot_id must not return an id already in the set"
            );
        }
        // The guard must re-roll away from a preloaded id: seed the set with a value and confirm the
        // generator never hands it (or 0) back.
        let mut preset: HashSet<i64> = HashSet::new();
        preset.insert(0);
        let forced = new_snapshot_id(&preset);
        preset.insert(forced);
        for _ in 0..1000 {
            let id = new_snapshot_id(&preset);
            assert_ne!(id, 0);
            assert_ne!(id, forced);
            preset.insert(id);
        }
    }

    /// FIX 2: across many real appends the snapshot ids recorded in metadata stay distinct and
    /// non-zero (the collision/zero guard holds end-to-end, not just in isolation).
    #[test]
    fn snapshot_ids_across_appends_are_distinct_and_nonzero() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        for i in 0..8 {
            let batch: Vec<Record> = (i * 4..i * 4 + 4).map(mk).collect();
            t.append(&batch).unwrap();
        }
        let ids: Vec<i64> = t.metadata.snapshots().map(|s| s.snapshot_id()).collect();
        assert_eq!(ids.len(), 8, "one snapshot per append");
        assert!(ids.iter().all(|&id| id != 0), "no snapshot id may be 0");
        let uniq: HashSet<i64> = ids.iter().copied().collect();
        assert_eq!(uniq.len(), ids.len(), "all snapshot ids must be distinct");
    }

    // ----------------------------------------------------------------------------------------------
    // Bounded manifest compaction + expire-snapshots (#1179)
    // ----------------------------------------------------------------------------------------------

    /// Walks a table's WHOLE metadata graph (every retained snapshot -> its manifest list -> every
    /// manifest -> every live data file) and returns every physical file path any retained snapshot
    /// references. This is the "retained live set" the never-drop-a-live-file property is stated over.
    fn all_referenced_files(t: &IcebergTable) -> Vec<String> {
        let mut files = Vec::new();
        for snap in t.metadata.snapshots() {
            let ml = snap.manifest_list().to_string();
            files.push(ml.clone());
            let bytes = std::fs::read(&ml).unwrap();
            let list = ManifestList::parse_with_version(&bytes, FormatVersion::V2).unwrap();
            for mf in list.entries() {
                files.push(mf.manifest_path.clone());
                let mb = std::fs::read(&mf.manifest_path).unwrap();
                let manifest = iceberg::spec::Manifest::parse_avro(&mb).unwrap();
                for e in manifest.entries() {
                    if e.is_alive() {
                        files.push(e.data_file().file_path().to_string());
                    }
                }
            }
        }
        files
    }

    /// Appends `batches` batches of `per` records each, contiguously from offset 0. Returns the loc.
    fn table_with_batches(loc: &str, batches: i64, per: i64) {
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        for b in 0..batches {
            let recs: Vec<Record> = (b * per..b * per + per).map(mk).collect();
            t.append(&recs).unwrap();
        }
    }

    /// The core proof: after compaction the table reads back EVERY committed row at the exact offsets,
    /// no dups, the watermark is preserved, and a COLD reopen recovers all of it. The manifest set is
    /// collapsed to one, and the snapshot log is trimmed to the retention window.
    #[test]
    fn compaction_preserves_all_rows_watermark_and_reads_cold() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        table_with_batches(loc, 12, 3); // offsets 0..36 across 12 snapshots

        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        assert_eq!(
            t.current_manifest_count().unwrap(),
            12,
            "one manifest per append"
        );
        assert_eq!(t.snapshot_count(), 12);
        assert_eq!(t.next_offset(), 36);

        let stats = t.compact_and_expire(5).unwrap();
        assert_eq!(stats.manifests_before, 12);
        assert_eq!(stats.manifests_after, 1, "compacted to a single manifest");
        assert_eq!(
            stats.snapshots_expired, 8,
            "12 old + 1 new, keep 5 => expire 8"
        );

        // Manifest set collapsed; snapshot log trimmed to the retention window.
        assert_eq!(t.current_manifest_count().unwrap(), 1);
        assert_eq!(t.snapshot_count(), 5);
        // Watermark preserved on the in-memory handle.
        assert_eq!(t.next_offset(), 36);

        // Structural read via the real Iceberg chain: all 36 offsets, contiguous, no dup/drop.
        let mut got = scan_offsets(loc).unwrap();
        got.sort_unstable();
        assert_eq!(
            got,
            (0..36).collect::<Vec<_>>(),
            "every row survives compaction"
        );

        // COLD reopen: watermark + full contents recover from the committed metadata.
        let t2 = IcebergTable::open_or_create(loc, 999).unwrap();
        assert_eq!(
            t2.next_offset(),
            36,
            "cold resume watermark survives compaction"
        );
        assert_eq!(t2.snapshot_count(), 5);
        let mut got2 = scan_offsets(loc).unwrap();
        got2.sort_unstable();
        assert_eq!(got2, (0..36).collect::<Vec<_>>());
    }

    /// THE LOAD-BEARING SAFETY PROPERTY: after compaction (with aggressive expiry AND physical GC),
    /// every file referenced by every RETAINED snapshot still exists on disk. A single missing live
    /// file would be a broken/lossy table.
    #[test]
    fn compaction_never_drops_a_retained_live_file() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        table_with_batches(loc, 10, 4); // offsets 0..40

        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        // retention=1 => keep ONLY the compacted snapshot => maximal expiry + maximal GC.
        let stats = t.compact_and_expire(1).unwrap();
        assert_eq!(t.snapshot_count(), 1);
        assert!(
            stats.files_deleted > 0,
            "aggressive expiry must reclaim stale manifests"
        );

        // Every file the (sole) retained snapshot references must still exist.
        for f in all_referenced_files(&t) {
            assert!(
                Path::new(&f).exists(),
                "a retained-snapshot-referenced file was deleted: {f}"
            );
        }
        // And the table still reads back every row.
        let mut got = scan_offsets(loc).unwrap();
        got.sort_unstable();
        assert_eq!(got, (0..40).collect::<Vec<_>>());
    }

    /// Physical GC deletes ONLY files no retained snapshot references, and is bounded by retention: a
    /// large retention window keeps the old manifests alive (deletes nothing), a retention of 1
    /// reclaims all of them but the compacted one.
    #[test]
    fn gc_deletes_only_unreferenced_files_and_respects_retention() {
        // High retention: every old snapshot is retained, so nothing is unreferenced -> no deletion.
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        table_with_batches(loc, 8, 2);
        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        let avro_before = count_avro(loc);
        let stats = t.compact_and_expire(100).unwrap();
        assert_eq!(stats.snapshots_expired, 0, "retention 100 expires nothing");
        assert_eq!(
            stats.files_deleted, 0,
            "nothing unreferenced -> nothing deleted"
        );
        // The new compacted manifest + list were added, old ones all still referenced.
        assert!(count_avro(loc) > avro_before);
        for f in all_referenced_files(&t) {
            assert!(Path::new(&f).exists(), "referenced file missing: {f}");
        }

        // Low retention on a fresh table: reclaims the now-unreferenced old .avro files.
        let dir2 = tempfile::tempdir().unwrap();
        let loc2 = dir2.path().to_str().unwrap();
        table_with_batches(loc2, 8, 2);
        let mut t2 = IcebergTable::open_or_create(loc2, 0).unwrap();
        let stats2 = t2.compact_and_expire(1).unwrap();
        assert!(stats2.files_deleted > 0);
        // Belt-and-suspenders: the surviving .avro files are exactly the referenced ones.
        let referenced: HashSet<PathBuf> = all_referenced_files(&t2)
            .iter()
            .filter(|f| Path::new(f).extension().and_then(std::ffi::OsStr::to_str) == Some("avro"))
            .map(|f| std::fs::canonicalize(f).unwrap())
            .collect();
        for entry in std::fs::read_dir(format!("{loc2}/metadata")).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().and_then(std::ffi::OsStr::to_str) == Some("avro") {
                assert!(
                    referenced.contains(&std::fs::canonicalize(&p).unwrap()),
                    "an unreferenced .avro survived the GC: {}",
                    p.display()
                );
            }
        }
    }

    fn count_avro(loc: &str) -> usize {
        std::fs::read_dir(format!("{loc}/metadata"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.path().extension().and_then(std::ffi::OsStr::to_str) == Some("avro"))
            .count()
    }

    /// Appends continue correctly AFTER a compaction: dedup still holds (the watermark carried onto the
    /// replace snapshot), and new records extend the table contiguously.
    #[test]
    fn append_after_compaction_dedups_and_extends() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        table_with_batches(loc, 6, 3); // 0..18

        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        t.compact_and_expire(2).unwrap();
        assert_eq!(t.next_offset(), 18);
        assert_eq!(t.current_manifest_count().unwrap(), 1);

        // A redelivery of already-materialized offsets is dropped; only the new tail is written.
        let redelivered: Vec<Record> = (15..24).map(mk).collect();
        assert_eq!(t.append(&redelivered).unwrap(), 6, "only 18..24 are new");
        assert_eq!(t.next_offset(), 24);
        // Post-compaction append carries forward the one compacted manifest + the new one.
        assert_eq!(t.current_manifest_count().unwrap(), 2);

        let mut got = scan_offsets(loc).unwrap();
        got.sort_unstable();
        assert_eq!(
            got,
            (0..24).collect::<Vec<_>>(),
            "no dup/drop across the compaction seam"
        );
    }

    /// Expiry always keeps the CURRENT snapshot and never leaves the main ref dangling, even when
    /// retention is smaller than the number of pre-existing snapshots.
    #[test]
    fn expiry_keeps_current_snapshot_and_valid_main_ref() {
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        table_with_batches(loc, 9, 1);

        let mut t = IcebergTable::open_or_create(loc, 0).unwrap();
        t.compact_and_expire(3).unwrap();
        assert_eq!(t.snapshot_count(), 3);
        let current = t
            .metadata
            .current_snapshot()
            .expect("a current snapshot must survive expiry");
        // The main ref points at a snapshot that still exists (build() validates this, but assert it).
        assert!(
            t.metadata
                .snapshots()
                .any(|s| s.snapshot_id() == current.snapshot_id()),
            "current snapshot must remain in the snapshot set"
        );
        // The compacted current snapshot carries the resume watermark.
        assert_eq!(t.next_offset(), 9);
    }

    /// Compaction is a no-op (no churn, no growth) when there is nothing to gain: an empty table, and a
    /// table already at a single manifest within the retention window.
    #[test]
    fn compaction_is_a_noop_when_nothing_to_gain() {
        // Empty table.
        let dir = tempfile::tempdir().unwrap();
        let loc = dir.path().to_str().unwrap();
        let mut empty = IcebergTable::open_or_create(loc, 0).unwrap();
        let s = empty.compact_and_expire(5).unwrap();
        assert_eq!(s, CompactionStats::default());
        assert_eq!(empty.version(), 0, "no commit on an empty table");

        // Single-manifest table within retention: compacting again must not add a snapshot.
        let dir2 = tempfile::tempdir().unwrap();
        let loc2 = dir2.path().to_str().unwrap();
        table_with_batches(loc2, 4, 2);
        let mut t = IcebergTable::open_or_create(loc2, 0).unwrap();
        t.compact_and_expire(2).unwrap(); // -> 1 manifest, 2 snapshots
        let v = t.version();
        let snaps = t.snapshot_count();
        let s2 = t.compact_and_expire(10).unwrap(); // nothing to gain (1 manifest, within retention)
        assert_eq!(s2.files_deleted, 0);
        assert_eq!(
            t.version(),
            v,
            "no-op compaction must not commit a new version"
        );
        assert_eq!(
            t.snapshot_count(),
            snaps,
            "no-op compaction must not add a snapshot"
        );
    }
}
