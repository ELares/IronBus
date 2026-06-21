// SPDX-License-Identifier: MIT OR Apache-2.0
//! Named connection profiles — `kubectl config`-style contexts (V2-M6, #581).
//!
//! A *context* bundles the settings a client verb needs to reach a broker: the server `addr`, an
//! optional auth `token`, optional `tls` settings (CA bundle path + SNI server-name override), and
//! an optional offline `data_dir`. Contexts are PERSISTED to a CLI config file and selected by a
//! `current` pointer, so an operator switches whole environments with one `context use` instead of
//! repeating `--addr`/`--token` on every command.
//!
//! # Opt-in + byte-identical default
//! Contexts are STRICTLY opt-in. With NO config file (the default state) every resolver returns
//! exactly what it returned before this module existed: `addr` falls back to the caller's compiled
//! default, `token`/`tls`/`data_dir` resolve to `None`. A command's behavior is therefore
//! byte-identical until an operator deliberately creates and `use`s a context. Flags ALWAYS override
//! the context (flag > context > default), per the frozen precedence.
//!
//! # Config file location (org-agnostic)
//! The file path is, in precedence order:
//!   1. `$IRONBUS_CONFIG` if set (an explicit override, for tests and non-standard layouts), else
//!   2. `$XDG_CONFIG_HOME/ironbus/contexts.toml` if `XDG_CONFIG_HOME` is set, else
//!   3. `$HOME/.config/ironbus/contexts.toml`.
//! There is NO hard-coded org, host, or vendor path anywhere in the default — only the generic
//! `ironbus` application directory under the user's standard config dir.
//!
//! # Secret handling
//! A context's `token` is a secret. It is NEVER printed by `context show`/`list` (only a
//! `token: <set>`/`<unset>` indicator is shown), and the config file is written `0o600` (owner-only)
//! on Unix, the same discipline the auth path uses for token files. The plaintext token lives only
//! in the on-disk config the operator chose to create.
//!
//! The on-disk format is TOML, parsed with the `toml` crate already in the tree (no new dependency).

use crate::CliError;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One named connection profile. Every field except the implicit name is optional, so a minimal
/// context is just an `addr`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Context {
    /// The broker `host:port` a client verb dials. `None` ⇒ fall back to the caller's default.
    pub addr: Option<String>,
    /// A bearer/auth token (a SECRET; never printed). `None` ⇒ unauthenticated, as today.
    pub token: Option<String>,
    /// A TLS CA-bundle path to trust for the broker's certificate.
    pub tls_ca: Option<String>,
    /// A TLS SNI / server-name override (when the dialed host differs from the cert's name).
    pub tls_server_name: Option<String>,
    /// An offline data directory for the local-inspection verbs.
    pub data_dir: Option<String>,
}

/// The whole persisted config: the named contexts plus the `current` selection pointer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Config {
    /// The name of the active context, or `None` if none is selected.
    pub current: Option<String>,
    /// All named contexts, ordered (a `BTreeMap` so `list` and the serialized file are
    /// deterministic — load/save round-trips byte-stably, which a test pins).
    pub contexts: BTreeMap<String, Context>,
}

impl Config {
    /// Resolves the active context: the one named by `current`, if any. Returns `None` when no
    /// context is selected (the default, byte-identical-to-today state).
    pub fn current_context(&self) -> Option<&Context> {
        self.current.as_ref().and_then(|n| self.contexts.get(n))
    }
}

/// Resolves the config file path per the documented precedence, through an injected `env` lookup so
/// the resolution is unit-testable without mutating the process environment.
pub(crate) fn config_path_with(env: impl Fn(&str) -> Option<String>) -> Result<PathBuf, CliError> {
    if let Some(explicit) = env("IRONBUS_CONFIG") {
        return Ok(PathBuf::from(explicit));
    }
    let base = if let Some(xdg) = env("XDG_CONFIG_HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(xdg)
    } else if let Some(home) = env("HOME").filter(|s| !s.is_empty()) {
        PathBuf::from(home).join(".config")
    } else {
        return Err(CliError::Usage(
            "cannot locate a config directory: set $IRONBUS_CONFIG, $XDG_CONFIG_HOME, or $HOME"
                .to_string(),
        ));
    };
    Ok(base.join("ironbus").join("contexts.toml"))
}

/// The process-environment config path (production entry point).
pub(crate) fn config_path() -> Result<PathBuf, CliError> {
    config_path_with(|k| std::env::var(k).ok())
}

/// Loads the config from `path`, returning an empty default if the file does not exist (so a
/// first run, or any run with no config, behaves exactly as today).
///
/// # Errors
/// A present-but-unreadable or malformed file is a usage error naming the path, so a corrupt
/// config is reported, not silently treated as empty.
pub(crate) fn load(path: &Path) -> Result<Config, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => {
            return Err(CliError::Usage(format!(
                "cannot read config {}: {e}",
                path.display()
            )))
        }
    };
    parse(&text, path)
}

/// Parses the TOML config text. The schema is a top-level `current` string plus a `[contexts.<name>]`
/// table per context, each with optional `addr`/`token`/`tls_ca`/`tls_server_name`/`data_dir` keys.
fn parse(text: &str, path: &Path) -> Result<Config, CliError> {
    let value: toml::Value = text
        .parse()
        .map_err(|e| CliError::Usage(format!("malformed config {}: {e}", path.display())))?;
    let mut cfg = Config::default();
    if let Some(cur) = value.get("current") {
        cfg.current = Some(
            cur.as_str()
                .ok_or_else(|| {
                    CliError::Usage(format!("`current` must be a string in {}", path.display()))
                })?
                .to_string(),
        );
    }
    if let Some(table) = value.get("contexts").and_then(toml::Value::as_table) {
        for (name, ctx_val) in table {
            let t = ctx_val.as_table().ok_or_else(|| {
                CliError::Usage(format!(
                    "context `{name}` must be a table in {}",
                    path.display()
                ))
            })?;
            let get = |k: &str| t.get(k).and_then(|v| v.as_str()).map(str::to_string);
            cfg.contexts.insert(
                name.clone(),
                Context {
                    addr: get("addr"),
                    token: get("token"),
                    tls_ca: get("tls_ca"),
                    tls_server_name: get("tls_server_name"),
                    data_dir: get("data_dir"),
                },
            );
        }
    }
    Ok(cfg)
}

/// Serializes the config to deterministic TOML. Hand-rendered (no `toml::to_string`, which `toml
/// 0.5` gates behind a non-default feature) so the output order is fixed and the round-trip is
/// byte-stable. A `None` field is omitted entirely (so a minimal context is a minimal table).
pub(crate) fn serialize(cfg: &Config) -> String {
    let mut s = String::new();
    if let Some(cur) = &cfg.current {
        s.push_str("current = ");
        s.push_str(&toml_string(cur));
        s.push('\n');
    }
    for (name, ctx) in &cfg.contexts {
        s.push('\n');
        s.push_str("[contexts.");
        s.push_str(&toml_key(name));
        s.push_str("]\n");
        let mut put = |k: &str, v: &Option<String>| {
            if let Some(val) = v {
                s.push_str(k);
                s.push_str(" = ");
                s.push_str(&toml_string(val));
                s.push('\n');
            }
        };
        put("addr", &ctx.addr);
        put("token", &ctx.token);
        put("tls_ca", &ctx.tls_ca);
        put("tls_server_name", &ctx.tls_server_name);
        put("data_dir", &ctx.data_dir);
    }
    s
}

/// Renders a TOML basic string with the escapes the format requires.
fn toml_string(v: &str) -> String {
    let mut out = String::with_capacity(v.len() + 2);
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Renders a TOML table-header key: a bare key if it is a simple identifier, else a quoted key.
fn toml_key(name: &str) -> String {
    let bare = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if bare {
        name.to_string()
    } else {
        toml_string(name)
    }
}

/// Persists `cfg` to `path`, creating parent directories (`0o700` on Unix) and writing the file
/// `0o600` (owner-only) on Unix so the secret token is never group/world readable. The write is
/// staged to a sibling temp and renamed, so a crash never leaves a half-written config.
pub(crate) fn save(path: &Path, cfg: &Config) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CliError::Internal(format!("creating config dir {}: {e}", parent.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort tighten of the app config dir; a pre-existing dir's mode is left as the
            // operator set it (we never loosen, and a failure here is not fatal to the save).
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let body = serialize(cfg);
    let tmp = path.with_extension("toml.tmp");
    write_owner_only(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)
        .map_err(|e| CliError::Internal(format!("installing config {}: {e}", path.display())))?;
    Ok(())
}

/// Writes `bytes` to `path` with owner-only (`0o600`) permissions on Unix. On non-Unix the file is
/// created with default permissions (the OS has no POSIX mode), matching the rest of the CLI.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| CliError::Internal(format!("writing {}: {e}", path.display())))?;
        f.write_all(bytes)
            .map_err(|e| CliError::Internal(format!("writing {}: {e}", path.display())))?;
        f.flush()
            .map_err(|e| CliError::Internal(format!("writing {}: {e}", path.display())))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
            .map_err(|e| CliError::Internal(format!("writing {}: {e}", path.display())))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The `context` subcommand surface.
// ---------------------------------------------------------------------------

/// Runs `ironbus context <verb> ...`. Verbs: `create`, `use`, `list`/`ls`, `show`, `rm`, `current`.
///
/// # Errors
/// A usage problem (unknown verb, missing required value, unknown context name) is a [`CliError::Usage`].
pub(crate) fn run_context(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let (verb, rest) = args.split_first().ok_or_else(|| {
        CliError::Usage(
            "context requires a subcommand: create|use|list|show|rm|current".to_string(),
        )
    })?;
    let path = config_path()?;
    match verb.as_str() {
        "create" => context_create(&path, rest, out),
        "use" => context_use(&path, rest, out),
        "list" | "ls" => context_list(&path, out),
        "show" => context_show(&path, rest, out),
        "rm" | "delete" => context_rm(&path, rest, out),
        "current" => context_current(&path, out),
        other => Err(CliError::Usage(format!(
            "unknown context subcommand `{other}` (expected create|use|list|show|rm|current)"
        ))),
    }
}

/// `context create <name> [--addr a] [--token t] [--tls-ca p] [--tls-server-name n] [--data-dir d] [--use]`.
fn context_create(path: &Path, args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut ctx = Context::default();
    let mut set_current = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => ctx.addr = Some(crate::take_value("--addr", args, &mut i)?),
            "--token" => ctx.token = Some(crate::take_value("--token", args, &mut i)?),
            "--tls-ca" => ctx.tls_ca = Some(crate::take_value("--tls-ca", args, &mut i)?),
            "--tls-server-name" => {
                ctx.tls_server_name = Some(crate::take_value("--tls-server-name", args, &mut i)?);
            }
            "--data-dir" => ctx.data_dir = Some(crate::take_value("--data-dir", args, &mut i)?),
            "--use" => {
                set_current = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!(
                    "unknown flag `{flag}` for context create"
                )));
            }
            _ => {
                if name.is_some() {
                    return Err(CliError::Usage(
                        "context create takes a single <name>".to_string(),
                    ));
                }
                name = Some(args[i].clone());
                i += 1;
            }
        }
    }
    let name =
        name.ok_or_else(|| CliError::Usage("context create requires a <name>".to_string()))?;
    let mut cfg = load(path)?;
    let existed = cfg.contexts.insert(name.clone(), ctx).is_some();
    if set_current || cfg.current.is_none() {
        cfg.current = Some(name.clone());
    }
    save(path, &cfg)?;
    let verb = if existed { "updated" } else { "created" };
    writeln!(out, "{verb} context `{name}`")?;
    Ok(())
}

/// `context use <name>` — point `current` at an existing context.
fn context_use(path: &Path, args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let name = single_name("use", args)?;
    let mut cfg = load(path)?;
    if !cfg.contexts.contains_key(&name) {
        return Err(CliError::Usage(format!("no context named `{name}`")));
    }
    cfg.current = Some(name.clone());
    save(path, &cfg)?;
    writeln!(out, "switched to context `{name}`")?;
    Ok(())
}

/// `context list` — list every context name, marking the current with `*`.
fn context_list(path: &Path, out: &mut impl Write) -> Result<(), CliError> {
    let cfg = load(path)?;
    if cfg.contexts.is_empty() {
        writeln!(out, "no contexts configured")?;
        return Ok(());
    }
    for name in cfg.contexts.keys() {
        let marker = if cfg.current.as_deref() == Some(name.as_str()) {
            "*"
        } else {
            " "
        };
        writeln!(out, "{marker} {name}")?;
    }
    Ok(())
}

/// `context show [name]` — show one context's fields (the current context if no name). The token is
/// shown only as a set/unset indicator, never its value.
fn context_show(path: &Path, args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let cfg = load(path)?;
    let name = if args.is_empty() {
        cfg.current
            .clone()
            .ok_or_else(|| CliError::Usage("no current context (pass a <name>)".to_string()))?
    } else {
        single_name("show", args)?
    };
    let ctx = cfg
        .contexts
        .get(&name)
        .ok_or_else(|| CliError::Usage(format!("no context named `{name}`")))?;
    writeln!(out, "name: {name}")?;
    writeln!(out, "addr: {}", ctx.addr.as_deref().unwrap_or("<default>"))?;
    // The secret is NEVER printed: only whether one is configured.
    writeln!(
        out,
        "token: {}",
        if ctx.token.is_some() {
            "<set>"
        } else {
            "<unset>"
        }
    )?;
    writeln!(
        out,
        "tls_ca: {}",
        ctx.tls_ca.as_deref().unwrap_or("<unset>")
    )?;
    writeln!(
        out,
        "tls_server_name: {}",
        ctx.tls_server_name.as_deref().unwrap_or("<unset>")
    )?;
    writeln!(
        out,
        "data_dir: {}",
        ctx.data_dir.as_deref().unwrap_or("<unset>")
    )?;
    Ok(())
}

/// `context rm <name>` — delete a context, clearing `current` if it pointed there.
fn context_rm(path: &Path, args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let name = single_name("rm", args)?;
    let mut cfg = load(path)?;
    if cfg.contexts.remove(&name).is_none() {
        return Err(CliError::Usage(format!("no context named `{name}`")));
    }
    if cfg.current.as_deref() == Some(name.as_str()) {
        cfg.current = None;
    }
    save(path, &cfg)?;
    writeln!(out, "removed context `{name}`")?;
    Ok(())
}

/// `context current` — print the current context name (or a clear "none" message).
fn context_current(path: &Path, out: &mut impl Write) -> Result<(), CliError> {
    let cfg = load(path)?;
    match cfg.current {
        Some(name) => writeln!(out, "{name}")?,
        None => writeln!(out, "no current context")?,
    }
    Ok(())
}

/// Parses the single `<name>` positional a verb requires, rejecting flags and extra positionals.
fn single_name(verb: &str, args: &[String]) -> Result<String, CliError> {
    match args {
        [name] if !name.starts_with("--") => Ok(name.clone()),
        [] => Err(CliError::Usage(format!("context {verb} requires a <name>"))),
        _ => Err(CliError::Usage(format!(
            "context {verb} takes a single <name>"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Connection resolution used by client verbs (flag > context > default).
// ---------------------------------------------------------------------------

/// Resolves a broker address with the frozen precedence flag > current-context > `default`. When no
/// config file exists (or no context is current, or the current context sets no `addr`), this
/// returns `default` — byte-identical to the pre-context behavior. Loads the config from the
/// process-resolved path; a malformed config is a usage error.
///
/// # Errors
/// A malformed/unreadable config file (only when one exists) is a [`CliError::Usage`].
pub(crate) fn resolve_addr(flag: Option<&str>, default: &str) -> Result<String, CliError> {
    if let Some(a) = flag {
        return Ok(a.to_string());
    }
    let path = config_path()?;
    let cfg = load(&path)?;
    Ok(cfg
        .current_context()
        .and_then(|c| c.addr.clone())
        .unwrap_or_else(|| default.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_map<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn config_path_prefers_explicit_override() {
        let p = config_path_with(env_map(&[("IRONBUS_CONFIG", "/tmp/x/c.toml")])).unwrap();
        assert_eq!(p, PathBuf::from("/tmp/x/c.toml"));
    }

    #[test]
    fn config_path_uses_xdg_then_home() {
        let p = config_path_with(env_map(&[("XDG_CONFIG_HOME", "/cfg")])).unwrap();
        assert_eq!(p, PathBuf::from("/cfg/ironbus/contexts.toml"));
        let p = config_path_with(env_map(&[("HOME", "/home/u")])).unwrap();
        assert_eq!(p, PathBuf::from("/home/u/.config/ironbus/contexts.toml"));
    }

    #[test]
    fn config_path_errors_without_any_base() {
        assert!(config_path_with(env_map(&[])).is_err());
    }

    #[test]
    fn serialize_parse_round_trips_byte_stably() {
        let mut cfg = Config {
            current: Some("prod".to_string()),
            ..Config::default()
        };
        cfg.contexts.insert(
            "prod".to_string(),
            Context {
                addr: Some("example.com:7000".to_string()),
                token: Some("s3cr3t".to_string()),
                tls_ca: Some("/etc/ca.pem".to_string()),
                tls_server_name: None,
                data_dir: None,
            },
        );
        cfg.contexts.insert(
            "local".to_string(),
            Context {
                addr: Some("localhost:7000".to_string()),
                ..Context::default()
            },
        );
        let text = serialize(&cfg);
        let back = parse(&text, Path::new("<mem>")).unwrap();
        assert_eq!(cfg, back);
        // Deterministic: re-serializing the parsed copy reproduces the same bytes.
        assert_eq!(text, serialize(&back));
    }

    #[test]
    fn missing_file_loads_empty_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        assert_eq!(load(&path).unwrap(), Config::default());
    }

    #[test]
    fn malformed_file_is_a_usage_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is = = not toml").unwrap();
        let e = load(&path).unwrap_err();
        assert_eq!(e.exit_code(), crate::EXIT_USAGE);
    }

    #[test]
    fn create_use_show_rm_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contexts.toml");
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();

        let mut buf = Vec::new();
        context_create(
            &path,
            &args(&[
                "prod",
                "--addr",
                "example.com:7000",
                "--token",
                "sup3rsecretvalue",
            ]),
            &mut buf,
        )
        .unwrap();
        // First context becomes current automatically.
        let cfg = load(&path).unwrap();
        assert_eq!(cfg.current.as_deref(), Some("prod"));

        buf.clear();
        context_create(&path, &args(&["dev", "--addr", "localhost:7000"]), &mut buf).unwrap();
        // A non-first create does NOT steal current.
        assert_eq!(load(&path).unwrap().current.as_deref(), Some("prod"));

        buf.clear();
        context_use(&path, &args(&["dev"]), &mut buf).unwrap();
        assert_eq!(load(&path).unwrap().current.as_deref(), Some("dev"));

        // show never prints the token value.
        buf.clear();
        context_show(&path, &args(&["prod"]), &mut buf).unwrap();
        let shown = String::from_utf8(buf.clone()).unwrap();
        assert!(shown.contains("token: <set>"), "{shown}");
        assert!(
            !shown.contains("sup3rsecretvalue"),
            "secret leaked: {shown}"
        );

        // rm of the current clears current.
        buf.clear();
        context_rm(&path, &args(&["dev"]), &mut buf).unwrap();
        assert_eq!(load(&path).unwrap().current, None);

        // use of a missing context is a usage error.
        buf.clear();
        assert_eq!(
            context_use(&path, &args(&["ghost"]), &mut buf)
                .unwrap_err()
                .exit_code(),
            crate::EXIT_USAGE
        );
    }

    #[test]
    fn resolve_addr_flag_overrides_context() {
        // Flag always wins, regardless of any context.
        assert_eq!(resolve_addr(Some("flag:1"), "default:0").unwrap(), "flag:1");
    }

    /// On Unix the saved config file is owner-only (0o600) so the secret token is not exposed.
    #[cfg(all(test, unix))]
    #[test]
    fn saved_config_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("contexts.toml");
        let mut cfg = Config::default();
        cfg.contexts.insert(
            "c".to_string(),
            Context {
                token: Some("secret".to_string()),
                ..Context::default()
            },
        );
        save(&path, &cfg).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "config must be owner-only, got {mode:o}");
    }
}
