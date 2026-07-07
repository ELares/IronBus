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
use ironbus_client::ClientConfig;
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
    /// A TLS CA-bundle path to trust for the broker's certificate. Setting this makes the client verbs
    /// dial the broker over TLS 1.3 (verifying its certificate); leaving it unset keeps the connection
    /// plaintext, exactly as today.
    pub tls_ca: Option<String>,
    /// A TLS SNI / server-name override (when the dialed host differs from the cert's name).
    pub tls_server_name: Option<String>,
    /// A client-certificate PEM path for mTLS — presented at the handshake so a broker configured with
    /// `--tls-client-ca` can authenticate this client by certificate. Requires [`Context::tls_client_key`].
    pub tls_client_cert: Option<String>,
    /// The private-key PEM path paired with [`Context::tls_client_cert`] for mTLS (a SECRET; never
    /// printed). Both cert and key must be set together, or neither.
    pub tls_client_key: Option<String>,
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
                    tls_client_cert: get("tls_client_cert"),
                    tls_client_key: get("tls_client_key"),
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
        put("tls_client_cert", &ctx.tls_client_cert);
        put("tls_client_key", &ctx.tls_client_key);
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

/// `context create <name> [--addr a] [--token-file p | --token t] [--tls-ca p] [--tls-server-name n] [--data-dir d] [--use]`.
///
/// The bearer token is a SECRET: prefer `--token-file <path>` (StrictModes-checked owner-only on unix)
/// or `--token-file -` (stdin) so it never lands on the process argv table; `--token <t>` is kept for
/// back-compat but warns about argv exposure (#885).
fn context_create(path: &Path, args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut name: Option<String> = None;
    let mut ctx = Context::default();
    let mut set_current = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => ctx.addr = Some(crate::take_value("--addr", args, &mut i)?),
            "--token" => {
                let token = crate::take_value("--token", args, &mut i)?;
                // #885: a bearer token is a secret; on argv it is visible to any local user via `ps` /
                // `/proc/<pid>/cmdline` for the lifetime of the invocation and lingers in shell history.
                // Warn (to stderr, never stdout) and steer to the off-argv path, mirroring `passwd`.
                eprintln!(
                    "warning: --token exposes the bearer token in the process table and shell history; \
                     prefer `--token-file <path>` (or `--token-file -` to read from stdin)"
                );
                ctx.token = Some(token);
            }
            "--token-file" => {
                let path = crate::take_value("--token-file", args, &mut i)?;
                ctx.token = Some(read_token_from_file_or_stdin(&path)?);
            }
            "--tls-ca" => ctx.tls_ca = Some(crate::take_value("--tls-ca", args, &mut i)?),
            "--tls-server-name" => {
                ctx.tls_server_name = Some(crate::take_value("--tls-server-name", args, &mut i)?);
            }
            "--tls-client-cert" => {
                ctx.tls_client_cert = Some(crate::take_value("--tls-client-cert", args, &mut i)?);
            }
            "--tls-client-key" => {
                ctx.tls_client_key = Some(crate::take_value("--tls-client-key", args, &mut i)?);
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

/// Read a bearer token from a file (or from stdin when `path` is `-`), so the secret never appears on
/// the process argv table (#885) — mirroring `passwd`'s `--password-file` discipline. On unix the file
/// is StrictModes-checked fail-closed (owner-only) BEFORE it is read, exactly like the auth-config /
/// TLS-key / password file. One trailing newline (and an accompanying CR) is trimmed, the shape a
/// `printf` / `echo` / heredoc produces, so the stored token is the intended value, not `token\n`. The
/// token must be valid UTF-8 (it is sent as a UTF-8 wire credential).
fn read_token_from_file_or_stdin(path: &str) -> Result<String, CliError> {
    use std::io::Read as _;
    let mut bytes = if path == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| CliError::Usage(format!("cannot read --token-file from stdin: {e}")))?;
        buf
    } else {
        // The token file is a secret reference: fail-closed owner-only check on unix (no-op elsewhere,
        // where POSIX mode bits do not apply), then read.
        #[cfg(unix)]
        crate::strict_mode_check_secret_file(path)?;
        std::fs::read(path)
            .map_err(|e| CliError::Usage(format!("cannot read --token-file `{path}`: {e}")))?
    };
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    String::from_utf8(bytes)
        .map_err(|_| CliError::Usage("the token in --token-file is not valid UTF-8".to_string()))
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
        "tls_client_cert: {}",
        ctx.tls_client_cert.as_deref().unwrap_or("<unset>")
    )?;
    // A PATH to the key, not the key itself — shown like the CA/cert paths. The secret is the file's
    // contents, which `context show` never reads or prints.
    writeln!(
        out,
        "tls_client_key: {}",
        ctx.tls_client_key.as_deref().unwrap_or("<unset>")
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

/// Builds the client [`ClientConfig`] a verb dials with, from the ACTIVE context's TLS settings (#957):
/// when the context sets `tls_ca`, the client dials the broker over TLS 1.3 — verifying its certificate
/// against that CA bundle and checking the server name — and optionally presents a client certificate for
/// mTLS. With no TLS configured the config is the plaintext default, byte-identical to today. `addr` is
/// the resolved broker address, used to derive the default TLS server name when the context sets none.
///
/// # Errors
/// A usage error if the context configures TLS on a build without the `tls` feature, if only one of the
/// mTLS cert/key is set (or a client cert is set with no `tls_ca`), or if a configured PEM cannot be read.
pub(crate) fn resolve_client_config(addr: &str) -> Result<ClientConfig, CliError> {
    // A config dir that cannot even be LOCATED (a bare environment with none of $IRONBUS_CONFIG /
    // $XDG_CONFIG_HOME / $HOME — e.g. a Windows runner where only $USERPROFILE is set) means NO context
    // is configured, so this resolves to the plaintext default, byte-identical to the historical
    // `Client::connect`. Every client verb must keep working with no config present; only a config that
    // is locatable AND present-but-malformed surfaces an error (via `load`). This mirrors the historical
    // `connect` path, which never touched the config file at all.
    let Ok(path) = config_path() else {
        return client_config_for_context(None, addr);
    };
    let cfg = load(&path)?;
    client_config_for_context(cfg.current_context(), addr)
}

/// The host portion of a `host:port` (or bare host) broker address, the default TLS server name when the
/// context sets no `tls_server_name`. Handles a bracketed IPv6 literal (`[::1]:7000` → `::1`).
#[cfg(feature = "tls")]
fn host_of(addr: &str) -> &str {
    if addr.starts_with('[') {
        if let Some(end) = addr.find(']') {
            return &addr[1..end];
        }
    }
    addr.rsplit_once(':').map_or(addr, |(host, _port)| host)
}

/// The `--features tls` builder: reads the context's PEM paths and assembles a verifying (optionally
/// mutual) TLS client config. See [`resolve_client_config`].
#[cfg(feature = "tls")]
fn client_config_for_context(ctx: Option<&Context>, addr: &str) -> Result<ClientConfig, CliError> {
    let mut config = ClientConfig::default();
    let Some(ctx) = ctx else {
        return Ok(config);
    };
    // A client certificate with no CA to verify the SERVER against is a misconfiguration: mTLS is still
    // TLS, and there is no accept-any path. Fail closed rather than silently dropping the client cert.
    if ctx.tls_ca.is_none() && (ctx.tls_client_cert.is_some() || ctx.tls_client_key.is_some()) {
        return Err(CliError::Usage(
            "the context sets a TLS client certificate but no tls_ca: mTLS still requires tls_ca to \
             verify the broker (set tls_ca, or clear the client cert/key)"
                .to_string(),
        ));
    }
    let Some(ca_path) = &ctx.tls_ca else {
        return Ok(config);
    };
    let ca = std::fs::read(ca_path)
        .map_err(|e| CliError::Usage(format!("cannot read TLS CA bundle `{ca_path}`: {e}")))?;
    let server_name = ctx
        .tls_server_name
        .clone()
        .unwrap_or_else(|| host_of(addr).to_string());
    let mut tls = ironbus_client::TlsClientConfig::new(ca, server_name);
    match (&ctx.tls_client_cert, &ctx.tls_client_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert = std::fs::read(cert_path).map_err(|e| {
                CliError::Usage(format!("cannot read TLS client cert `{cert_path}`: {e}"))
            })?;
            let key = std::fs::read(key_path).map_err(|e| {
                CliError::Usage(format!("cannot read TLS client key `{key_path}`: {e}"))
            })?;
            tls = tls.with_client_cert(cert, key);
        }
        (None, None) => {}
        _ => {
            return Err(CliError::Usage(
                "mTLS needs BOTH tls_client_cert and tls_client_key on the context (set both, or \
                 neither)"
                    .to_string(),
            ));
        }
    }
    config.tls = Some(tls);
    Ok(config)
}

/// The no-`tls`-feature builder: TLS is not compiled in, so a context that configures ANY TLS setting is
/// refused with an actionable error (mirroring the server side's refusal of `--tls-*` on a non-tls
/// build), never silently ignored. With no TLS configured the plaintext default is returned unchanged.
#[cfg(not(feature = "tls"))]
fn client_config_for_context(ctx: Option<&Context>, _addr: &str) -> Result<ClientConfig, CliError> {
    if let Some(ctx) = ctx {
        if ctx.tls_ca.is_some()
            || ctx.tls_server_name.is_some()
            || ctx.tls_client_cert.is_some()
            || ctx.tls_client_key.is_some()
        {
            return Err(CliError::Usage(
                "the active context configures TLS, but this ironbus build has no TLS support: \
                 rebuild with `--features tls` to dial a TLS broker"
                    .to_string(),
            ));
        }
    }
    Ok(ClientConfig::default())
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
                tls_client_cert: Some("/etc/client.pem".to_string()),
                tls_client_key: Some("/etc/client.key".to_string()),
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
    fn create_reads_the_token_from_a_file_not_argv() {
        // #885: `--token-file` reads the bearer token from a file (off the argv table), trimming one
        // trailing newline, and on unix StrictModes-checks the file owner-only fail-closed first.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("contexts.toml");
        let tok = dir.path().join("token.secret");
        std::fs::write(&tok, "s3cr3t-bearer\n").unwrap(); // a trailing newline, the printf/echo shape
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let mut buf = Vec::new();
        context_create(
            &path,
            &args(&[
                "prod",
                "--addr",
                "example.com:7000",
                "--token-file",
                tok.to_str().unwrap(),
            ]),
            &mut buf,
        )
        .unwrap();
        let cfg = load(&path).unwrap();
        assert_eq!(
            cfg.contexts.get("prod").and_then(|c| c.token.as_deref()),
            Some("s3cr3t-bearer"),
            "the token is read from the file with the trailing newline trimmed"
        );

        // On unix, a group/world-readable token file is refused fail-closed (StrictModes).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut buf2 = Vec::new();
            let e = context_create(
                &path,
                &args(&["staging", "--token-file", tok.to_str().unwrap()]),
                &mut buf2,
            )
            .unwrap_err();
            assert_eq!(
                e.exit_code(),
                crate::EXIT_USAGE,
                "a group/world-readable token file is refused"
            );
        }
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

    // Client-TLS config resolution (#957, increment 4c): the pure context->ClientConfig builder, tested
    // WITHOUT a broker (the CLI test binary is where the known parallel raft deadlock lives, so we do not
    // add a broker-spin here — 4a's library e2e already proves a TlsClientConfig connects+produces).
    #[cfg(feature = "tls")]
    mod tls_client {
        use super::*;

        // A self-signed "localhost" server cert + matching key (the client crate's fixture): usable both
        // as a trust anchor (CA) and, for the mTLS build path, as a client cert+key pair.
        const CERT: &[u8] = b"\
-----BEGIN CERTIFICATE-----
MIIBVzCB/aADAgECAhMjGIxpQAwb+081fMl2nX2WEMQ8MAoGCCqGSM49BAMCMB4x
HDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIwIBcNMjAwMTAxMDAwMDAwWhgP
MjEwMDAxMDEwMDAwMDBaMB4xHDAaBgNVBAMME2lyb25idXMtdGVzdC1zZXJ2ZXIw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+AoxgwFjAU
BgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJ+smDY9Jybx
FoJDOjOor9Cb56IyQQ64ts0roLO5NVx9AiEAnB1pAliacK3UDfG6xKEig12h4tzf
UrjVOalNQ4uwFJg=
-----END CERTIFICATE-----
";
        const KEY: &[u8] = b"\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWd4kisc5NnK6Nv0I
RL0rrbnn9ozoIOti7I4eisF3CHWhRANCAAS4ZuCioex4thlFvAdYg6ER4GlPiFK/
yqG6VNwt0cp7LoCwHmOkcr6JLYLNSa2mar9F2nTFk2cSj49+OzMYbF+A
-----END PRIVATE KEY-----
";

        fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> String {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            p.to_str().unwrap().to_string()
        }

        #[test]
        fn no_tls_ca_yields_the_plaintext_default() {
            let ctx = Context {
                addr: Some("localhost:7000".to_string()),
                ..Context::default()
            };
            let cfg = client_config_for_context(Some(&ctx), "localhost:7000").unwrap();
            assert!(
                cfg.tls.is_none(),
                "no tls_ca => plaintext, byte-identical to today"
            );
        }

        #[test]
        fn tls_ca_builds_a_verifying_config_with_server_name_from_the_addr() {
            let dir = tempfile::tempdir().unwrap();
            let ca = write_temp(dir.path(), "ca.pem", CERT);
            let ctx = Context {
                tls_ca: Some(ca),
                ..Context::default()
            };
            let cfg = client_config_for_context(Some(&ctx), "localhost:7000").unwrap();
            let tls = cfg.tls.expect("tls_ca => a TLS client config");
            assert_eq!(
                tls.server_name(),
                "localhost",
                "the server name derives from the addr host when the context sets none"
            );
            assert!(!tls.has_client_cert());
            tls.build().expect("the CA parses as a valid trust anchor");
        }

        #[test]
        fn tls_server_name_override_wins_over_the_addr_host() {
            let dir = tempfile::tempdir().unwrap();
            let ca = write_temp(dir.path(), "ca.pem", CERT);
            let ctx = Context {
                tls_ca: Some(ca),
                tls_server_name: Some("broker.internal".to_string()),
                ..Context::default()
            };
            let cfg = client_config_for_context(Some(&ctx), "10.0.0.1:7000").unwrap();
            assert_eq!(cfg.tls.unwrap().server_name(), "broker.internal");
        }

        #[test]
        fn a_client_cert_and_key_enable_mtls() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = Context {
                tls_ca: Some(write_temp(dir.path(), "ca.pem", CERT)),
                tls_client_cert: Some(write_temp(dir.path(), "client.pem", CERT)),
                tls_client_key: Some(write_temp(dir.path(), "client.key", KEY)),
                ..Context::default()
            };
            let cfg = client_config_for_context(Some(&ctx), "localhost:7000").unwrap();
            let tls = cfg.tls.expect("tls configured");
            assert!(tls.has_client_cert(), "both cert+key => mTLS");
            tls.build().expect("cert+key build an mTLS client config");
        }

        #[test]
        fn a_client_cert_without_a_key_is_rejected() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = Context {
                tls_ca: Some(write_temp(dir.path(), "ca.pem", CERT)),
                tls_client_cert: Some(write_temp(dir.path(), "client.pem", CERT)),
                ..Context::default()
            };
            assert!(matches!(
                client_config_for_context(Some(&ctx), "localhost:7000"),
                Err(CliError::Usage(_))
            ));
        }

        #[test]
        fn a_client_cert_without_a_ca_is_rejected() {
            let ctx = Context {
                tls_client_cert: Some("/x.pem".to_string()),
                tls_client_key: Some("/x.key".to_string()),
                ..Context::default()
            };
            assert!(matches!(
                client_config_for_context(Some(&ctx), "localhost:7000"),
                Err(CliError::Usage(_))
            ));
        }

        #[test]
        fn a_missing_ca_file_is_a_usage_error() {
            let ctx = Context {
                tls_ca: Some("/does/not/exist.pem".to_string()),
                ..Context::default()
            };
            assert!(matches!(
                client_config_for_context(Some(&ctx), "localhost:7000"),
                Err(CliError::Usage(_))
            ));
        }

        #[test]
        fn a_bracketed_ipv6_host_derives_the_inner_literal_as_the_server_name() {
            let dir = tempfile::tempdir().unwrap();
            let ctx = Context {
                tls_ca: Some(write_temp(dir.path(), "ca.pem", CERT)),
                ..Context::default()
            };
            let cfg = client_config_for_context(Some(&ctx), "[::1]:7000").unwrap();
            assert_eq!(cfg.tls.unwrap().server_name(), "::1");
        }
    }

    // On a build WITHOUT the tls feature, any TLS setting on the active context is refused (never
    // silently ignored), mirroring the server side's refusal of `--tls-*` on a non-tls build.
    #[cfg(not(feature = "tls"))]
    mod tls_client_no_feature {
        use super::*;

        #[test]
        fn a_tls_context_on_a_non_tls_build_is_refused() {
            let ctx = Context {
                tls_ca: Some("/etc/ca.pem".to_string()),
                ..Context::default()
            };
            assert!(matches!(
                client_config_for_context(Some(&ctx), "localhost:7000"),
                Err(CliError::Usage(_))
            ));
        }

        #[test]
        fn a_plaintext_context_still_yields_the_default() {
            let ctx = Context {
                addr: Some("localhost:7000".to_string()),
                ..Context::default()
            };
            // No `tls` field exists on this build; a context with no TLS settings just builds the
            // plaintext default without error.
            client_config_for_context(Some(&ctx), "localhost:7000")
                .expect("a plaintext context builds the default config");
        }
    }
}
