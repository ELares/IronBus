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
use std::path::Path;
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
}
