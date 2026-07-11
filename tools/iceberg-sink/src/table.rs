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
//! `v{N}.metadata.json`, and finally an ATOMIC rename of `version-hint.text` to `N`. Everything the
//! new metadata references exists and is fsynced before the pointer flips, so a crash mid-commit
//! leaves the table valid at the previous version (orphaned files are harmless). Each snapshot's
//! summary records `ironbus.next-offset` (the exclusive high offset the table now covers); that is
//! the sink's authoritative resume point AND dedup watermark — [`IcebergTable::append`] drops any
//! record at or below it, so an at-least-once redelivery can never duplicate a row.

use std::collections::HashMap;
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
        let snapshot_id = new_snapshot_id();
        let next_seq = self.metadata.next_sequence_number();
        let schema_ref = self.metadata.current_schema().clone();
        let spec = self.metadata.default_partition_spec().as_ref().clone();

        // 1. Parquet data file.
        let data_path = format!("{}/data/{commit_uuid}.parquet", self.location);
        let size = write_parquet(&data_path, &fresh).context("writing the Parquet data file")?;
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

    /// Writes `v{version}.metadata.json` (fsynced), then atomically renames `version-hint.text` to
    /// point at it (the commit point). Returns the metadata file path.
    fn commit_metadata(&self, version: u64, md: &TableMetadata) -> Result<String> {
        let meta_path = format!("{}/metadata/v{version}.metadata.json", self.location);
        let json = serde_json::to_vec_pretty(md).context("serializing table metadata")?;
        write_fsync(&meta_path, &json)?;

        let hint = format!("{}/metadata/version-hint.text", self.location);
        let tmp = format!("{hint}.tmp.{}", Uuid::new_v4());
        write_fsync(&tmp, version.to_string().as_bytes())?;
        std::fs::rename(&tmp, &hint).context("atomically swapping version-hint.text")?;
        // fsync the metadata directory so the rename + new files are durable.
        if let Ok(dir) = File::open(format!("{}/metadata", self.location)) {
            let _ = dir.sync_all();
        }
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

fn new_snapshot_id() -> i64 {
    let (a, b) = Uuid::new_v4().as_u64_pair();
    let id = (a ^ b) as i64;
    id.saturating_abs()
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
}
