// SPDX-License-Identifier: MIT OR Apache-2.0
//! The OPT-IN `dict` subcommand group (#357, `docs/DICTIONARY_LIFECYCLE.md`): the operator surface
//! for the trained-dictionary lifecycle. Compiled ONLY on a build with the `zstd` feature (Unix
//! only, like the rest of the on-disk store path).
//!
//! - `dict train` runs `ZDICT_trainFromBuffer` over a directory of per-type sample records, derives
//!   the content-addressed `dict_id`, writes `dicts/<dict_id>.zstd` under `--out`, and prints a
//!   `--json` summary including the MEASURED before/after compression ratio on the corpus.
//! - `dict install` copies a trained dictionary blob into a data directory's `dicts/` sidecar store,
//!   so the broker can use it (content-validated, write-once).
//! - `dict ls` lists the dictionary sidecars in a data directory.
//!
//! All IO lives here (reading sample files, writing the blob); the IO-free compute (training, the
//! `dict_id` hash) is in `ironbus_core::dict`, and the durable sidecar store is in
//! `ironbus_storage::dict_store`.

use crate::{escape_json, CliError};
use ironbus_core::compress::{Codec, CompressConfig, DEFAULT_ZSTD_LEVEL, DICT_ID_NONE};
use ironbus_core::dict::{
    train_dictionary_with_floors, DEFAULT_TARGET_DICT_BYTES, MIN_DISTINCT_BYTES, MIN_SAMPLES,
    TARGET_SAMPLES,
};
use ironbus_storage::dict_store::{dict_file_name, DictSidecarStore};
use ironbus_storage::fs::StdFs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The versioned `--json` schema name for `dict train`.
const DICT_TRAIN_SCHEMA_VERSION: u32 = 1;

/// Dispatches `dict <verb>`.
pub fn run_dict(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let (verb, rest) = args.split_first().ok_or_else(|| {
        CliError::Usage("dict needs a subcommand: train | install | ls".to_string())
    })?;
    match verb.as_str() {
        "train" => run_train(rest, out),
        "install" => run_install(rest, out),
        "ls" => run_ls(rest, out),
        other => Err(CliError::Usage(format!(
            "unknown dict subcommand `{other}` (expected train | install | ls)"
        ))),
    }
}

/// Reads the per-type sample corpus from `samples_dir`: one raw, uncompressed record per regular
/// file in the directory (sorted for determinism). A subdirectory is skipped. An empty file is a
/// zero-length sample (kept, so the count is honest).
fn read_sample_corpus(samples_dir: &Path) -> Result<Vec<Vec<u8>>, CliError> {
    let read_dir = std::fs::read_dir(samples_dir).map_err(|e| {
        CliError::Usage(format!(
            "cannot read samples dir {}: {e}",
            samples_dir.display()
        ))
    })?;
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in read_dir {
        let entry =
            entry.map_err(|e| CliError::Internal(format!("reading samples dir entry: {e}")))?;
        let path = entry.path();
        let is_file = entry
            .file_type()
            .map(|t| t.is_file())
            .map_err(|e| CliError::Internal(format!("stat {}: {e}", path.display())))?;
        if is_file {
            paths.push(path);
        }
    }
    paths.sort();
    let mut samples = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = std::fs::read(&path)
            .map_err(|e| CliError::Internal(format!("reading sample {}: {e}", path.display())))?;
        samples.push(bytes);
    }
    Ok(samples)
}

/// Measures the before/after compression ratio of a trained dictionary on its training corpus,
/// per `docs/DICTIONARY_LIFECYCLE.md` §7: both arms compress the SAME records at the SAME zstd
/// level; the only variable is the dictionary. Returns `(raw_bytes, no_dict_bytes, with_dict_bytes)`
/// summed over the corpus.
fn measure_ratio(samples: &[Vec<u8>], dict_id: u32, dict: &[u8]) -> (u64, u64, u64) {
    let no_dict_cfg = CompressConfig {
        codec: Codec::Zstd,
        raw_store_threshold: 1, // measure the codec, not the raw-store fallback
        dict_id: DICT_ID_NONE,
        dict: None,
        zstd_level: DEFAULT_ZSTD_LEVEL,
    };
    let with_dict_cfg = CompressConfig {
        codec: Codec::Zstd,
        raw_store_threshold: 1,
        dict_id,
        dict: Some(dict),
        zstd_level: DEFAULT_ZSTD_LEVEL,
    };
    let mut raw = 0u64;
    let mut no_dict = 0u64;
    let mut with_dict = 0u64;
    for rec in samples {
        raw = raw.saturating_add(rec.len() as u64);
        // Both arms re-build a fresh compressor per record (the per-batch unit); a compress failure
        // on a single record is counted as its raw size so the ratio is never falsely inflated.
        no_dict = no_dict.saturating_add(
            ironbus_core::compress::compress_payload(rec, &no_dict_cfg)
                .map_or(rec.len() as u64, |c| c.stored.len() as u64),
        );
        with_dict = with_dict.saturating_add(
            ironbus_core::compress::compress_payload(rec, &with_dict_cfg)
                .map_or(rec.len() as u64, |c| c.stored.len() as u64),
        );
    }
    (raw, no_dict, with_dict)
}

/// `dict train --type <t> --samples <dir> [--out <dir>] [--target-dict-bytes <n>]
/// [--min-samples <n>] [--json]`.
fn run_train(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut msg_type: Option<String> = None;
    let mut samples_dir: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut target_dict_bytes = DEFAULT_TARGET_DICT_BYTES;
    let mut min_samples = MIN_SAMPLES;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--type" => msg_type = Some(take_value("--type", args, &mut i)?),
            "--samples" => samples_dir = Some(take_value("--samples", args, &mut i)?),
            "--out" => out_dir = Some(take_value("--out", args, &mut i)?),
            "--target-dict-bytes" => {
                target_dict_bytes = take_number("--target-dict-bytes", args, &mut i)?;
            }
            "--min-samples" => min_samples = take_number("--min-samples", args, &mut i)?,
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for dict train"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "dict train takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let msg_type = msg_type.ok_or_else(|| {
        CliError::Usage("dict train requires `--type <message-type>`".to_string())
    })?;
    let samples_dir = samples_dir
        .ok_or_else(|| CliError::Usage("dict train requires `--samples <dir>`".to_string()))?;
    let out_dir = out_dir.unwrap_or_else(|| ".".to_string());

    let samples = read_sample_corpus(Path::new(&samples_dir))?;
    if samples.len() < TARGET_SAMPLES && !json {
        // Advisory warning below the target corpus size (not a hard floor).
        writeln!(
            out,
            "note: corpus has {} samples, below the recommended {TARGET_SAMPLES}; the dictionary \
             may be weaker than ideal",
            samples.len()
        )
        .map_err(io_err)?;
    }

    let trained =
        train_dictionary_with_floors(&samples, target_dict_bytes, min_samples, MIN_DISTINCT_BYTES)
            .map_err(|e| CliError::Usage(format!("dict train: {e}")))?;

    // Write the content-named dictionary to the out dir, via the sidecar store rooted there (it
    // creates a `dicts/` subdir under --out; the operator points the broker at that data dir or
    // installs the blob into one with `dict install`).
    let store = DictSidecarStore::open(&StdFs::new(PathBuf::from(&out_dir)))
        .map_err(|e| CliError::Internal(format!("opening dicts/ under {out_dir}: {e}")))?;
    store
        .store(trained.dict_id, &trained.bytes)
        .map_err(|e| CliError::Internal(format!("writing the dictionary sidecar: {e}")))?;

    let (raw, no_dict, with_dict) = measure_ratio(&samples, trained.dict_id, &trained.bytes);
    let summary = TrainSummary {
        msg_type,
        dict_id: trained.dict_id,
        dict_bytes: trained.bytes.len(),
        sample_count: samples.len(),
        sample_bytes: samples.iter().map(|s| s.len() as u64).sum(),
        blob_path: format!("{out_dir}/dicts/{}", dict_file_name(trained.dict_id)),
        ratio_no_dict: ratio(raw, no_dict),
        ratio_with_dict: ratio(raw, with_dict),
    };
    write_train_summary(&summary, json, out)
}

/// The structured outcome of `dict train`, the source for both the human and `--json` renderings.
struct TrainSummary {
    msg_type: String,
    dict_id: u32,
    dict_bytes: usize,
    sample_count: usize,
    sample_bytes: u64,
    blob_path: String,
    ratio_no_dict: f64,
    ratio_with_dict: f64,
}

/// Writes the `dict train` result: the versioned `ironbus.cli.dict-train.v1` `--json` object or the
/// human summary, both including the MEASURED before/after ratio (`docs/DICTIONARY_LIFECYCLE.md` §7).
fn write_train_summary(s: &TrainSummary, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    let gain = safe_div(s.ratio_with_dict, s.ratio_no_dict);
    if json {
        writeln!(
            out,
            "{{\"schema\":\"ironbus.cli.dict-train.v{DICT_TRAIN_SCHEMA_VERSION}\",\
             \"type\":\"{}\",\"dict_id\":{},\"dict_bytes\":{},\"sample_count\":{},\
             \"sample_bytes\":{},\"path\":\"{}\",\
             \"ratio_no_dict\":{:.4},\"ratio_with_dict\":{:.4},\"ratio_gain\":{gain:.4},\
             \"ok\":true}}",
            escape_json(&s.msg_type),
            s.dict_id,
            s.dict_bytes,
            s.sample_count,
            s.sample_bytes,
            escape_json(&s.blob_path),
            s.ratio_no_dict,
            s.ratio_with_dict,
        )
        .map_err(io_err)?;
    } else {
        let msg_type = &s.msg_type;
        writeln!(
            out,
            "dict train: type {msg_type:?} -> dict_id {} ({} bytes) written to {}",
            s.dict_id, s.dict_bytes, s.blob_path
        )
        .map_err(io_err)?;
        writeln!(
            out,
            "  corpus: {} samples, {} bytes",
            s.sample_count, s.sample_bytes
        )
        .map_err(io_err)?;
        writeln!(
            out,
            "  measured ratio: {:.2}x without dict -> {:.2}x with dict ({gain:.2}x gain)",
            s.ratio_no_dict, s.ratio_with_dict
        )
        .map_err(io_err)?;
    }
    Ok(())
}

/// `dict install --data-dir <dir> --dict <path>`: copy a trained dictionary blob into the data
/// directory's `dicts/` sidecar store (content-validated, write-once).
fn run_install(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut dict_path: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--dict" => dict_path = Some(take_value("--dict", args, &mut i)?),
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for dict install"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "dict install takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir = data_dir
        .ok_or_else(|| CliError::Usage("dict install requires `--data-dir <dir>`".to_string()))?;
    let dict_path = dict_path
        .ok_or_else(|| CliError::Usage("dict install requires `--dict <path>`".to_string()))?;

    let bytes = std::fs::read(&dict_path)
        .map_err(|e| CliError::Usage(format!("cannot read dictionary {dict_path}: {e}")))?;
    // Derive the id from the bytes (content-addressed), so the install never trusts the file name.
    let dict_id = ironbus_core::dict::derive_dict_id(&bytes);
    if dict_id == DICT_ID_NONE {
        return Err(CliError::Usage(
            "the dictionary hashes to dict_id 0 (the no-dictionary sentinel); it is not a valid \
             trained dictionary"
                .to_string(),
        ));
    }
    let store = DictSidecarStore::open(&StdFs::new(PathBuf::from(&data_dir)))
        .map_err(|e| CliError::Internal(format!("opening dicts/ under {data_dir}: {e}")))?;
    store
        .store(dict_id, &bytes)
        .map_err(|e| CliError::Internal(format!("installing the dictionary sidecar: {e}")))?;

    if json {
        writeln!(
            out,
            "{{\"schema\":\"ironbus.cli.dict-install.v1\",\"data_dir\":\"{}\",\"dict_id\":{},\
             \"dict_bytes\":{},\"ok\":true}}",
            escape_json(&data_dir),
            dict_id,
            bytes.len()
        )
        .map_err(io_err)?;
    } else {
        writeln!(
            out,
            "dict install: dict_id {dict_id} ({} bytes) installed into {}/dicts/",
            bytes.len(),
            data_dir
        )
        .map_err(io_err)?;
    }
    Ok(())
}

/// `dict ls --data-dir <dir>`: list the dictionary sidecars in a data directory.
fn run_ls(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for dict ls"
                )));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "dict ls takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir = data_dir
        .ok_or_else(|| CliError::Usage("dict ls requires `--data-dir <dir>`".to_string()))?;
    let store = DictSidecarStore::open(&StdFs::new(PathBuf::from(&data_dir)))
        .map_err(|e| CliError::Internal(format!("opening dicts/ under {data_dir}: {e}")))?;
    let mut ids = store.list_ids();
    ids.sort_unstable();

    if json {
        write!(
            out,
            "{{\"schema\":\"ironbus.cli.dict-ls.v1\",\"dict_ids\":["
        )
        .map_err(io_err)?;
        for (n, id) in ids.iter().enumerate() {
            if n > 0 {
                write!(out, ",").map_err(io_err)?;
            }
            write!(out, "{id}").map_err(io_err)?;
        }
        writeln!(out, "],\"count\":{},\"ok\":true}}", ids.len()).map_err(io_err)?;
    } else if ids.is_empty() {
        writeln!(out, "dict ls: no dictionaries in {data_dir}/dicts/").map_err(io_err)?;
    } else {
        writeln!(
            out,
            "dict ls: {} dictionaries in {data_dir}/dicts/",
            ids.len()
        )
        .map_err(io_err)?;
        for id in ids {
            writeln!(out, "  {id} ({})", dict_file_name(id)).map_err(io_err)?;
        }
    }
    Ok(())
}

/// The compression ratio `raw / compressed`, or `0.0` if `compressed` is `0`.
#[allow(clippy::cast_precision_loss)] // a reported ratio; the byte counts are well within f64
fn ratio(raw: u64, compressed: u64) -> f64 {
    safe_div(raw as f64, compressed as f64)
}

/// `a / b`, or `0.0` if `b` is `0` (so a degenerate measurement never produces NaN/inf).
fn safe_div(a: f64, b: f64) -> f64 {
    if b == 0.0 {
        0.0
    } else {
        a / b
    }
}

/// Maps a write failure to an internal error (stdout broke). Takes the error by value so it can be
/// used directly as a `.map_err(io_err)` adapter (which hands over the owned error).
#[allow(clippy::needless_pass_by_value)]
fn io_err(e: std::io::Error) -> CliError {
    CliError::Internal(format!("writing output: {e}"))
}

/// Returns the value following `flag`, advancing `*i` past both tokens. Local mirror of the
/// main-module helper so this opt-in module is self-contained.
fn take_value(flag: &str, args: &[String], i: &mut usize) -> Result<String, CliError> {
    let value = args
        .get(*i + 1)
        .ok_or_else(|| CliError::Usage(format!("`{flag}` needs a value")))?
        .clone();
    *i += 2;
    Ok(value)
}

/// Like [`take_value`] but parses the value as a number.
fn take_number(flag: &str, args: &[String], i: &mut usize) -> Result<usize, CliError> {
    let raw = take_value(flag, args, i)?;
    raw.parse::<usize>()
        .map_err(|_| CliError::Usage(format!("`{flag}` needs a number, got `{raw}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

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

    /// A unique scratch directory under the system temp dir, removed by [`Scratch`] on drop. Follows
    /// the CLI's no-`tempfile`-dev-dep convention (`std::env::temp_dir()` + a unique suffix).
    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Scratch {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "ironbus-dict-test-{}-{}-{n}",
                std::process::id(),
                tag
            ));
            fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Writes a per-type sample corpus of `n` records, one file per record, into a fresh scratch dir.
    fn write_corpus(n: u32, tag: &str) -> Scratch {
        let dir = Scratch::new(tag);
        for i in 0..n {
            fs::write(dir.path().join(format!("rec-{i:05}.json")), record_for(i)).unwrap();
        }
        dir
    }

    #[test]
    fn train_writes_a_sidecar_and_reports_a_positive_ratio() {
        let samples = write_corpus(2000, "train-samples");
        let out_dir = Scratch::new("train-out");
        let args = vec![
            "--type".to_string(),
            "sensor.telemetry.v1".to_string(),
            "--samples".to_string(),
            samples.path().display().to_string(),
            "--out".to_string(),
            out_dir.path().display().to_string(),
            "--target-dict-bytes".to_string(),
            "8192".to_string(),
            "--json".to_string(),
        ];
        let mut out = Vec::new();
        run_train(&args, &mut out).expect("train succeeds");
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("\"schema\":\"ironbus.cli.dict-train.v1\""),
            "{s}"
        );
        assert!(s.contains("\"ok\":true"), "{s}");
        // A dictionary sidecar landed under <out>/dicts/.
        let dicts = out_dir.path().join("dicts");
        let entries: Vec<_> = fs::read_dir(&dicts).unwrap().collect();
        assert_eq!(
            entries.len(),
            1,
            "exactly one dictionary sidecar was written"
        );
        // The reported with-dict ratio beats the no-dict ratio (the dictionary helps).
        let gain = extract_f64(&s, "\"ratio_gain\":");
        assert!(
            gain > 1.0,
            "the dictionary improves the ratio (gain {gain}): {s}"
        );
    }

    #[test]
    fn train_refuses_too_small_a_corpus() {
        let samples = write_corpus(10, "small-samples");
        let out_dir = Scratch::new("small-out");
        let args = vec![
            "--type".to_string(),
            "t".to_string(),
            "--samples".to_string(),
            samples.path().display().to_string(),
            "--out".to_string(),
            out_dir.path().display().to_string(),
        ];
        let mut out = Vec::new();
        let err = run_train(&args, &mut out).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)), "{err:?}");
    }

    #[test]
    fn install_then_ls_round_trips() {
        // Train into a scratch dir to get a real dictionary blob.
        let samples = write_corpus(2000, "inst-samples");
        let train_out = Scratch::new("inst-train");
        run_train(
            &[
                "--type".to_string(),
                "t".to_string(),
                "--samples".to_string(),
                samples.path().display().to_string(),
                "--out".to_string(),
                train_out.path().display().to_string(),
                "--target-dict-bytes".to_string(),
                "8192".to_string(),
                "--json".to_string(),
            ],
            &mut Vec::new(),
        )
        .unwrap();
        // Find the trained blob.
        let dicts = train_out.path().join("dicts");
        let blob = fs::read_dir(&dicts)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();

        // Install it into a separate data dir.
        let data_dir = Scratch::new("inst-data");
        let mut out = Vec::new();
        run_install(
            &[
                "--data-dir".to_string(),
                data_dir.path().display().to_string(),
                "--dict".to_string(),
                blob.display().to_string(),
                "--json".to_string(),
            ],
            &mut out,
        )
        .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("\"ok\":true"));

        // ls shows exactly one dictionary.
        let mut out = Vec::new();
        run_ls(
            &[
                "--data-dir".to_string(),
                data_dir.path().display().to_string(),
                "--json".to_string(),
            ],
            &mut out,
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("\"count\":1"), "{s}");
    }

    #[test]
    fn unknown_dict_subcommand_is_a_usage_error() {
        let err = run_dict(&["frobnicate".to_string()], &mut Vec::new()).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
        let err = run_dict(&[], &mut Vec::new()).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    fn extract_f64(json: &str, key: &str) -> f64 {
        let start = json.find(key).expect("key present") + key.len();
        let tail = &json[start..];
        let end = tail
            .find(|c: char| c != '.' && c != '-' && !c.is_ascii_digit())
            .unwrap_or(tail.len());
        tail[..end].parse().unwrap()
    }
}
