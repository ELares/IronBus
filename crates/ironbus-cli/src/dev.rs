// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus dev`: a one-command local quickstart (#796).
//!
//! `ironbus dev` gives a newcomer a first-five-minutes "wow": one command stands up a working
//! local broker, pre-declares a demo stream + subjects, and prints a copy-paste produce/consume
//! snippet — nothing to hand-assemble.
//!
//! It is PURE SUGAR over capabilities the broker already has: `dev` spawns the SAME `ironbus serve`
//! as a child process (the broker binary and its data plane are byte-for-byte untouched) and only
//! layers orchestration on top:
//!
//! 1. **serve-with-sane-defaults** — a normal broker bound to loopback on friendly, non-privileged
//!    default ports, backed by an EPHEMERAL data dir (a temp dir) that is removed on exit: a clean
//!    exit, a broker that exits on its own, AND Ctrl-C / `SIGINT` / `SIGTERM`.
//! 2. **pre-declared demo topology** — a [`DEMO_STREAM`] named stream plus a couple of [`DEMO_SUBJECTS`]
//!    bound to it, declared over the live admin/declare surface right after the broker is up, so
//!    produce/consume, `top`, and `/admin` have something to show on first launch.
//! 3. **a copy-paste snippet** — the real `ironbus pub` / `ironbus sub` / `ironbus top` / `ironbus
//!    admin` commands pointed at THIS broker's bound address, printed on startup.
//! 4. **optional `--seed N`** — publish N synthetic messages into [`DEMO_STREAM`] so `ironbus top`
//!    and `/admin` show instant activity.
//!
//! Deliberately OUT OF SCOPE (kept an XS quickstart, not a Trojan horse): no embedded console / web
//! UI, no connector / seed pipeline beyond the trivial synthetic `--seed`, no new broker runtime,
//! and no KV / object store (the ephemeral dir is just the bus's normal storage at a temp path).
//!
//! Unix-only in v1, exactly like `serve` itself (the on-disk broker uses positioned IO the Windows
//! path does not yet implement); the non-Unix build compiles a stub that errors cleanly. The
//! argument parser, the help, and the snippet builder are pure and cross-platform so their behavior
//! and unit tests are identical on every target.

use crate::CliError;
use std::io::Write;

/// The demo NAMED stream `ironbus dev` pre-declares on startup. Declaring is idempotent
/// (create-or-ensure), so a re-run never conflicts.
const DEMO_STREAM: &str = "demo";

/// The demo SUBJECT patterns bound to [`DEMO_STREAM`] (wildcards live on the pattern side). The two
/// patterns are DISJOINT, so a literal subject resolves unambiguously to the one demo stream; they
/// exist so the subject router is non-empty out of the box.
const DEMO_SUBJECTS: &[&str] = &["demo.orders.*", "demo.events.*"];

/// The friendly default client-wire port `dev` binds when `--addr` is not given. Non-privileged
/// (> 1024, needs no elevation); if it is already in use `dev` falls back to an OS-assigned free
/// port rather than failing.
const DEFAULT_DEV_WIRE_PORT: u16 = 7777;

/// The friendly default health/admin port (`/admin`, `top --health-addr`) `dev` binds when
/// `--health-addr` is not given; same non-privileged + fallback story as [`DEFAULT_DEV_WIRE_PORT`].
const DEFAULT_DEV_HEALTH_PORT: u16 = 7778;

/// Parsed `ironbus dev` arguments. Cross-platform (the parser and its error text are identical on
/// every target); the Unix-only orchestration reads them, and the non-Unix stub consumes them.
struct DevArgs {
    /// `--seed N`: publish N synthetic messages into [`DEMO_STREAM`]. `0` (the default) seeds
    /// nothing.
    seed: u64,
    /// `--addr <host:port>`: override the client-wire bind (default: the friendly
    /// [`DEFAULT_DEV_WIRE_PORT`] with fallback). Mostly for tests and for an operator who wants a
    /// specific port.
    addr: Option<String>,
    /// `--health-addr <host:port>`: override the health/admin bind (default:
    /// [`DEFAULT_DEV_HEALTH_PORT`] with fallback).
    health_addr: Option<String>,
}

/// Parses the `dev` flags. Cross-platform pure logic (unit-tested on every target).
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag, a missing flag value, or a non-numeric `--seed`.
fn parse_dev_args(args: &[String]) -> Result<DevArgs, CliError> {
    let mut seed = 0u64;
    let mut addr = None;
    let mut health_addr = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => seed = crate::take_number::<u64>("--seed", args, &mut i)?,
            "--addr" => addr = Some(crate::take_value("--addr", args, &mut i)?),
            "--health-addr" => {
                health_addr = Some(crate::take_value("--health-addr", args, &mut i)?);
            }
            other => return Err(CliError::Usage(format!("unknown flag `{other}` for dev"))),
        }
    }
    Ok(DevArgs {
        seed,
        addr,
        health_addr,
    })
}

/// Prints the `dev` help. It formats the demo + default-port constants so they are "used" on EVERY
/// target, keeping the non-Unix `-D warnings` build free of `dead_code` (the #288/#99 footgun: a
/// const read only on the Unix path trips `never used` on the Windows cross-check).
///
/// # Errors
/// Propagates an [`io::Error`](std::io::Error) writing to `out`.
fn print_dev_help(out: &mut impl Write) -> Result<(), CliError> {
    let subjects = DEMO_SUBJECTS.join(", ");
    writeln!(
        out,
        "ironbus dev — one-command local quickstart.\n\
         \n\
         USAGE:\n    ironbus dev [--seed <n>] [--addr <host:port>] [--health-addr <host:port>]\n\
         \n\
         Starts a normal broker on an EPHEMERAL data dir (a temp dir removed on exit — a clean exit\n\
         AND Ctrl-C/SIGINT/SIGTERM), pre-declares the `{DEMO_STREAM}` stream (subjects: {subjects}),\n\
         and prints a copy-paste produce/consume snippet pointed at the live broker.\n\
         \n\
         --seed <n>          publish <n> synthetic messages into `{DEMO_STREAM}` so `ironbus top`\n\
                             and `/admin` show instant activity (default: 0).\n\
         --addr <host:port>  client-wire bind (default: 127.0.0.1:{DEFAULT_DEV_WIRE_PORT}, or an\n\
                             OS-assigned free port when that is busy).\n\
         --health-addr <a>   health/admin bind (default: 127.0.0.1:{DEFAULT_DEV_HEALTH_PORT}, same\n\
                             fallback).\n\
         \n\
         The broker binary and data plane are untouched: `dev` spawns the SAME `ironbus serve` and\n\
         adds only the ephemeral-dir + friendly-defaults + demo-declare + snippet + optional-seed\n\
         orchestration. Unix only in v1 (the broker is Unix-only)."
    )?;
    Ok(())
}

/// Dispatch entry for `ironbus dev`.
///
/// # Errors
/// [`CliError::Usage`] on a bad flag; on Unix, [`CliError::Unreachable`] if the broker never comes
/// up and [`CliError::Internal`] on an orchestration failure; on non-Unix, always
/// [`CliError::Internal`] (the broker is Unix-only in v1).
pub(crate) fn run_dev(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return print_dev_help(out);
    }
    let parsed = parse_dev_args(args)?;
    run_dev_impl(parsed, out)
}

/// Builds the copy-paste produce/consume snippet: the real `ironbus` verbs pointed at THIS broker's
/// bound `wire` / `health` addresses, referencing the demo `stream`. Pure + cross-platform so the
/// snippet-correctness unit test exercises exactly what a newcomer would paste.
#[cfg(unix)]
fn dev_snippet(wire: &str, health: &str, stream: &str, seed: u64) -> String {
    // `write!` into a String is infallible; the discarded `fmt::Result` is clippy's endorsed fix for
    // `format_push_string` (which forbids `push_str(&format!(..))`). Each literal starts with its own
    // two-space indent, so the rendered snippet is indented exactly as a newcomer sees it.
    use std::fmt::Write as _;
    let mut s = String::from("Try it now — in another terminal:\n\n");
    let _ = write!(
        s,
        "  # consume the default stream (this blocks, waiting for messages):\n  \
         ironbus sub --addr {wire} --group {stream} --ack\n\n"
    );
    let _ = write!(
        s,
        "  # produce a message — watch it land in the consumer above:\n  \
         ironbus pub --addr {wire} --key {stream}.hello 'hello from ironbus dev'\n\n"
    );
    let _ = write!(
        s,
        "  # watch live traffic — the pre-declared `{stream}` stream and any seeded activity are here:\n  \
         ironbus top --addr {wire}\n\n"
    );
    let _ = write!(
        s,
        "  # or grab the raw /admin JSON snapshot:\n  \
         ironbus admin --health-addr {health}\n"
    );
    if seed > 0 {
        let _ = write!(
            s,
            "\n  # the {seed} seeded messages already sit in `{stream}` — watch them in `ironbus top`.\n"
        );
    }
    s
}

/// The running dev session: the child broker + the ephemeral data dir. Its [`Drop`] is the cleanup
/// backstop — it runs on EVERY exit path (a clean stop, the broker exiting on its own, a Ctrl-C /
/// SIGTERM that broke the wait loop, an early `?` error, or a panic) and reaps the broker before
/// removing the temp dir so the dir is never held by the broker's data-dir lock at removal.
#[cfg(unix)]
struct DevSession {
    child: std::process::Child,
    data_dir: std::path::PathBuf,
}

#[cfg(unix)]
impl Drop for DevSession {
    fn drop(&mut self) {
        // Reap the broker FIRST (releasing its exclusive data-dir lock), THEN remove the ephemeral
        // dir. Both are best-effort: cleanup must never itself panic.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// The Unix orchestration: pick friendly ports, mint the ephemeral dir, spawn the SAME `ironbus
/// serve`, wait for it, pre-declare the demo topology, optionally seed, print the snippet, then
/// block until a stop signal or the broker exits — cleanup runs via [`DevSession`]'s `Drop`.
#[cfg(unix)]
fn run_dev_impl(args: DevArgs, out: &mut impl Write) -> Result<(), CliError> {
    use ironbus_client::ClientConfig;

    // 1. Resolve the two loopback binds (friendly default, or the explicit override), each falling
    //    back to an OS-assigned free port if the default is busy — never a panic.
    let wire = resolve_dev_addr(args.addr, DEFAULT_DEV_WIRE_PORT, out)?;
    let health = resolve_dev_addr(args.health_addr, DEFAULT_DEV_HEALTH_PORT, out)?;

    // 2. The ephemeral data dir (a fresh temp dir owned by `dev`, removed on exit).
    let data_dir = make_ephemeral_dir()?;
    let data_display = data_dir.display().to_string();

    // 3. Spawn the SAME broker a `serve` would run — this binary re-invoked as `serve`, so the
    //    broker code path is byte-for-byte unchanged. `dev` owns the temp dir, not the broker.
    let exe = std::env::current_exe().map_err(|e| {
        CliError::Internal(format!(
            "could not locate the ironbus binary to launch the broker: {e}"
        ))
    })?;
    let data_arg = data_dir.to_str().ok_or_else(|| {
        CliError::Internal("the ephemeral data-dir path is not valid UTF-8".to_string())
    })?;
    let child = std::process::Command::new(&exe)
        .args([
            "serve",
            "--data-dir",
            data_arg,
            "--addr",
            &wire,
            "--health-addr",
            &health,
            "--enable-admin",
        ])
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            CliError::Internal(format!("could not start the dev broker (`serve`): {e}"))
        })?;

    // From here on, `session`'s Drop is the cleanup backstop on every exit path.
    let mut session = DevSession { child, data_dir };

    // 4. Advertise stream addressing so declare/bind/publish-to work, and reuse this readiness
    //    connection to declare the demo topology.
    let config = ClientConfig {
        understands_streams: true,
        ..ClientConfig::default()
    };
    let mut client = wait_for_broker(&wire, &config, &mut session.child)?;
    if !client.streams_enabled() {
        return Err(CliError::Internal(
            "the dev broker did not negotiate stream addressing (cannot pre-declare the demo stream)"
                .to_string(),
        ));
    }

    // 5. Pre-declare the demo stream + subjects over the live declare surface (idempotent).
    client
        .declare_stream(DEMO_STREAM)
        .map_err(|e| crate::classify(&wire, "declaring the demo stream on", &e))?;
    for pattern in DEMO_SUBJECTS {
        client
            .bind_subject(DEMO_STREAM, pattern)
            .map_err(|e| crate::classify(&wire, "binding a demo subject on", &e))?;
    }

    // 6. Optional synthetic seed into the demo stream.
    if args.seed > 0 {
        seed_demo(&mut client, args.seed, &wire)?;
    }
    drop(client);

    // 7. Print the banner + the copy-paste snippet.
    print_ready_banner(out, &wire, &health, &data_display, args.seed)?;

    // 8. Block until Ctrl-C / SIGTERM or the broker exits, then fall through so `session`'s Drop
    //    reaps the broker and removes the temp dir.
    block_until_stop(out, &mut session.child)
    // `session` drops here (and on any early return above): broker reaped, temp dir removed.
}

/// Prints the "ready" banner and the copy-paste produce/consume snippet, flushing so it is visible
/// before `dev` blocks.
#[cfg(unix)]
fn print_ready_banner(
    out: &mut impl Write,
    wire: &str,
    health: &str,
    data_display: &str,
    seed: u64,
) -> Result<(), CliError> {
    let subjects = DEMO_SUBJECTS.join(", ");
    writeln!(out)?;
    writeln!(out, "ironbus dev: local quickstart broker is ready.")?;
    writeln!(out, "  wire (produce/consume): {wire}")?;
    writeln!(out, "  admin  (/admin, top):   {health}")?;
    writeln!(
        out,
        "  ephemeral data dir:     {data_display} (removed on exit)"
    )?;
    writeln!(
        out,
        "  pre-declared stream:    {DEMO_STREAM} (subjects: {subjects})"
    )?;
    if seed > 0 {
        writeln!(
            out,
            "  seeded:                 {seed} messages into `{DEMO_STREAM}`"
        )?;
    }
    writeln!(out)?;
    write!(out, "{}", dev_snippet(wire, health, DEMO_STREAM, seed))?;
    writeln!(out)?;
    writeln!(
        out,
        "ironbus dev: press Ctrl-C to stop (the ephemeral data dir is removed on exit)."
    )?;
    out.flush()?;
    Ok(())
}

/// Blocks until Ctrl-C / SIGTERM (the flag flips) or the broker exits on its own. Registering the
/// stop signals REPLACES the default terminate-without-cleanup disposition, so the caller's
/// `DevSession` `Drop` still runs (and removes the temp dir) on a stop signal.
#[cfg(unix)]
fn block_until_stop(out: &mut impl Write, child: &mut std::process::Child) -> Result<(), CliError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(sig, Arc::clone(&stop)).map_err(|e| {
            CliError::Internal(format!(
                "could not install the dev stop-signal handler: {e}"
            ))
        })?;
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            writeln!(
                out,
                "\nironbus dev: stopping; removing the ephemeral data dir."
            )?;
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                writeln!(
                    out,
                    "\nironbus dev: the broker exited ({status}); cleaning up."
                )?;
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => {
                return Err(CliError::Internal(format!(
                    "waiting on the dev broker failed: {e}"
                )))
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Resolves one loopback bind: the explicit `override_addr` verbatim, else `127.0.0.1:preferred_port`
/// when that is free, else an OS-assigned free loopback port (with a friendly note). Never panics
/// and never blocks — the probe listener is dropped immediately, so `serve` binds it moments later.
#[cfg(unix)]
fn resolve_dev_addr(
    override_addr: Option<String>,
    preferred_port: u16,
    out: &mut impl Write,
) -> Result<String, CliError> {
    use std::net::TcpListener;
    if let Some(addr) = override_addr {
        return Ok(addr);
    }
    let preferred = format!("127.0.0.1:{preferred_port}");
    if TcpListener::bind(&preferred).is_ok() {
        return Ok(preferred);
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| CliError::Internal(format!("could not find a free loopback port: {e}")))?;
    let chosen = listener
        .local_addr()
        .map_err(|e| CliError::Internal(format!("could not read the chosen port: {e}")))?;
    drop(listener);
    writeln!(
        out,
        "ironbus dev: 127.0.0.1:{preferred_port} is in use; using {chosen} instead."
    )?;
    Ok(chosen.to_string())
}

/// Creates a fresh, owner-only (0700) ephemeral data dir under the system temp dir, named uniquely
/// from the pid + a nanosecond clock so parallel `dev` runs never collide. `dev` owns it and removes
/// it on exit; `serve` opens the existing empty dir.
#[cfg(unix)]
fn make_ephemeral_dir() -> Result<std::path::PathBuf, CliError> {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0u32..1024 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let candidate = base.join(format!("ironbus-dev-{pid}-{nanos}-{attempt}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => {
                // Match serve's created-dir posture (owner-only); best-effort for a throwaway dir.
                let _ =
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700));
                return Ok(candidate);
            }
            // A name collision (same pid + nanos + attempt) just retries the next attempt.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(CliError::Internal(format!(
                    "could not create the ephemeral data dir under {}: {e}",
                    base.display()
                )))
            }
        }
    }
    Err(CliError::Internal(
        "could not create a unique ephemeral data dir after 1024 attempts".to_string(),
    ))
}

/// Polls the broker until it accepts the stream-addressing handshake, returning that connected
/// client (reused to declare the demo topology). Detects a broker that died during startup (e.g. a
/// lost port race) and reports it as unreachable rather than spinning to the timeout.
#[cfg(unix)]
fn wait_for_broker(
    wire: &str,
    config: &ironbus_client::ClientConfig,
    child: &mut std::process::Child,
) -> Result<ironbus_client::Client, CliError> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| CliError::Internal(format!("waiting on the dev broker failed: {e}")))?
        {
            return Err(CliError::Unreachable(format!(
                "the dev broker exited during startup ({status}); is another broker already bound to {wire}?"
            )));
        }
        if let Ok(client) = ironbus_client::Client::connect_with(wire, config) {
            return Ok(client);
        }
        if Instant::now() >= deadline {
            return Err(CliError::Unreachable(format!(
                "the dev broker did not become ready within 20s at {wire}"
            )));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Publishes `n` synthetic at-least-once messages into [`DEMO_STREAM`] over the live wire, so `top`
/// and `/admin` show instant activity.
#[cfg(unix)]
fn seed_demo(client: &mut ironbus_client::Client, n: u64, wire: &str) -> Result<(), CliError> {
    use ironbus_proto::message::PubBody;
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    for i in 0..n {
        let payload = format!("seed message {i}");
        let key = format!("{DEMO_STREAM}.seed.{i}");
        client
            .publish_to(
                DEMO_STREAM,
                &PubBody {
                    flags: 0,
                    timestamp_ms: now_ms,
                    key: key.as_bytes(),
                    headers: b"",
                    dedup: None,
                    fire_and_forget: false,
                    payload: payload.as_bytes(),
                },
            )
            .map_err(|e| crate::classify(wire, "seeding the demo stream on", &e))?;
    }
    Ok(())
}

/// The non-Unix stub: `dev` runs a local broker, which is Unix-only in v1. Consumes every `DevArgs`
/// field and `out` so the cross-platform struct has no "never read" field and no unused parameter on
/// the non-Unix `-D warnings` build (the #288/#99 footgun the Windows cross-check catches).
#[cfg(not(unix))]
fn run_dev_impl(args: DevArgs, out: &mut impl Write) -> Result<(), CliError> {
    let DevArgs {
        seed,
        addr,
        health_addr,
    } = args;
    let _ = (seed, addr, health_addr);
    let _ = out;
    Err(CliError::Internal(
        "`ironbus dev` runs a local broker, which is supported on Unix only in v1".to_string(),
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn dev_snippet_references_the_demo_stream_and_the_bound_addresses() {
        let wire = "127.0.0.1:7777";
        let health = "127.0.0.1:7778";
        let snippet = dev_snippet(wire, health, DEMO_STREAM, 5);
        // Paste-and-run correctness: the real pub/sub verbs pointed at THIS broker's wire address.
        assert!(
            snippet.contains(&format!("ironbus sub --addr {wire}")),
            "snippet missing the sub line:\n{snippet}"
        );
        assert!(
            snippet.contains(&format!("ironbus pub --addr {wire}")),
            "snippet missing the pub line:\n{snippet}"
        );
        // References the demo stream + the health/admin address.
        assert!(
            snippet.contains(DEMO_STREAM),
            "snippet missing the demo stream:\n{snippet}"
        );
        assert!(
            snippet.contains(&format!("ironbus top --addr {wire}")),
            "snippet missing the top line:\n{snippet}"
        );
        assert!(
            snippet.contains(&format!("ironbus admin --health-addr {health}")),
            "snippet missing the admin line:\n{snippet}"
        );
        // The seed note appears only when seeding.
        assert!(
            snippet.contains("5 seeded messages"),
            "snippet missing the seed note:\n{snippet}"
        );
    }

    #[test]
    fn dev_snippet_omits_the_seed_note_when_nothing_is_seeded() {
        let snippet = dev_snippet("127.0.0.1:7777", "127.0.0.1:7778", DEMO_STREAM, 0);
        assert!(
            !snippet.contains("seeded messages"),
            "snippet should have no seed note at seed=0:\n{snippet}"
        );
        // The paste-and-run verbs are still present.
        assert!(snippet.contains("ironbus pub --addr 127.0.0.1:7777"));
        assert!(snippet.contains("ironbus sub --addr 127.0.0.1:7777"));
    }

    #[test]
    fn parse_dev_args_reads_seed_and_addr_overrides() {
        let args = vec![
            "--seed".to_string(),
            "7".to_string(),
            "--addr".to_string(),
            "127.0.0.1:9001".to_string(),
        ];
        let parsed = parse_dev_args(&args).expect("parse");
        assert_eq!(parsed.seed, 7);
        assert_eq!(parsed.addr.as_deref(), Some("127.0.0.1:9001"));
        assert_eq!(parsed.health_addr, None);
    }

    #[test]
    fn parse_dev_args_defaults_seed_to_zero() {
        let parsed = parse_dev_args(&[]).expect("parse empty");
        assert_eq!(parsed.seed, 0);
        assert!(parsed.addr.is_none());
        assert!(parsed.health_addr.is_none());
    }

    #[test]
    fn parse_dev_args_rejects_an_unknown_flag() {
        let args = vec!["--nope".to_string()];
        assert!(parse_dev_args(&args).is_err());
    }

    #[test]
    fn parse_dev_args_rejects_a_non_numeric_seed() {
        let args = vec!["--seed".to_string(), "lots".to_string()];
        assert!(parse_dev_args(&args).is_err());
    }
}
