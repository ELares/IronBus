// SPDX-License-Identifier: MIT OR Apache-2.0
//! `ironbus`, the command-line interface: run a broker and talk to one.
//!
//! The single binary is both the broker and the client tooling (per #136). This initial
//! slice implements three of the frozen command map's verbs:
//! - `serve` starts an on-disk broker (Unix only in v1: storage uses positioned IO that the
//!   Windows path does not yet implement).
//! - `pub` connects to a broker, appends one message, and prints its durable offset.
//! - `sub` fetches up to a credit of messages, prints each, and optionally acks them.
//!
//! `pub` and `sub` are thin wrappers over `ironbus-client`, so they run anywhere. Argument
//! parsing is hand-rolled (no external dependency) for this small surface; the broader
//! command tree and the versioned `--json` contract from #91 are follow-ups. Every failure
//! is a typed [`CliError`] mapped to the frozen exit-code scheme: 0 clean, 1 usage,
//! 5 broker-unreachable, 70 internal (the not-found and corruption codes belong to the
//! offline verbs not yet implemented).

use ironbus_client::{Client, ClientError};
use ironbus_core::clock::Clock;
use ironbus_proto::message::PubBody;
use ironbus_server::clock::SystemClock;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

#[cfg(unix)]
use ironbus_core::delivery::DeliveryConfig;
#[cfg(unix)]
use ironbus_core::lease::LeaseConfig;
#[cfg(unix)]
use ironbus_server::engine::{Engine, EngineConfig};
#[cfg(unix)]
use ironbus_server::health::serve_health;
#[cfg(unix)]
use ironbus_server::server::{serve, SharedEngine};
#[cfg(unix)]
use ironbus_storage::fs::StdFs;
#[cfg(unix)]
use ironbus_storage::log::LogConfig;
#[cfg(unix)]
use std::net::TcpListener;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex};

/// The default broker address: loopback only, so a zero-config broker is never exposed off
/// the host without an explicit choice.
const DEFAULT_ADDR: &str = "127.0.0.1:7777";
/// The default fetch credit for `sub`.
const DEFAULT_FETCH: u32 = 10;
/// The default connection cap for `serve`.
const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// The default in-flight window for the `serve` engine.
#[cfg(unix)]
const DEFAULT_MAX_IN_FLIGHT: u32 = 1024;
/// The default cursor-checkpoint interval for the `serve` engine: at most this many messages
/// are redelivered after an abrupt crash (a clean disconnect flushes the cursor sooner).
const DEFAULT_CHECKPOINT_INTERVAL: u64 = 1024;
/// The default escalating nack backoff schedule (nanoseconds), indexed by delivery attempt and
/// clamped to the last entry: 100 ms, 500 ms, 2 s, 10 s, 30 s. Applied when a nack carries no
/// explicit delay, so a flapping consumer backs off instead of hot-looping a retry.
#[cfg(unix)]
const DEFAULT_NACK_BACKOFF_NANOS: [u64; 5] = [
    100_000_000,
    500_000_000,
    2_000_000_000,
    10_000_000_000,
    30_000_000_000,
];

/// Frozen exit codes (subset in use for these verbs), per issue #91.
const EXIT_USAGE: u8 = 1;
const EXIT_UNREACHABLE: u8 = 5;
const EXIT_INTERNAL: u8 = 70;

const USAGE: &str = "\
ironbus: a durable edge message queue.

USAGE:
    ironbus serve --data-dir <dir> [--addr <host:port>] [--max-connections <n>]
                  [--checkpoint-interval <n>] [--health-addr <host:port>]
    ironbus pub   [--addr <host:port>] [--key <key>] [<payload>]
    ironbus sub   [--addr <host:port>] [--max <n>] [--ack | --nack [--delay-ms <n>] | --term]
    ironbus help

Notes:
    The default address is 127.0.0.1:7777 (loopback only).
    pub reads the payload from the argument, or from stdin if omitted (an empty input
    publishes an empty message, which is a valid record).
    sub prints one line per message; at most one disposition applies to the batch:
    --ack commits, --nack requeues (after --delay-ms), --term drops without dead-lettering.
    Exit codes: 0 clean, 1 usage, 5 broker unreachable, 70 internal.";

/// A command-line failure, mapped to a frozen exit code by [`main`].
#[derive(Debug)]
enum CliError {
    /// Bad or missing arguments (exit 1).
    Usage(String),
    /// The broker could not be reached (exit 5).
    Unreachable(String),
    /// An internal or runtime failure, including an unsupported platform (exit 70).
    Internal(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Unreachable(_) => EXIT_UNREACHABLE,
            CliError::Internal(_) => EXIT_INTERNAL,
        }
    }
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CliError::Usage(m) | CliError::Unreachable(m) | CliError::Internal(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Internal(format!("io error: {e}"))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match run(&args, &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            if let CliError::Usage(_) = e {
                eprintln!("\n{USAGE}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Parses `args` (without the program name) and dispatches the subcommand, writing normal
/// output to `out`.
///
/// # Errors
/// Returns a [`CliError`] for a usage problem, an unreachable broker, or a runtime failure.
fn run(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| CliError::Usage("no subcommand given".to_string()))?;
    match cmd.as_str() {
        "pub" => run_pub(rest, out),
        "sub" => run_sub(rest, out),
        "serve" => run_serve(rest, out),
        "help" | "--help" | "-h" => {
            writeln!(out, "{USAGE}")?;
            Ok(())
        }
        other => Err(CliError::Usage(format!("unknown subcommand `{other}`"))),
    }
}

/// Returns the value following `flag` at `args[*i]`, advancing `*i` past both tokens.
fn take_value(flag: &str, args: &[String], i: &mut usize) -> Result<String, CliError> {
    let value = args
        .get(*i + 1)
        .ok_or_else(|| CliError::Usage(format!("`{flag}` needs a value")))?
        .clone();
    *i += 2;
    Ok(value)
}

/// Classifies a client error against the frozen exit-code scheme. A connection-level failure
/// (the broker is down, or dropped us mid-request) is broker-unreachable (5); a broker that
/// answered but spoke a wrong-shape or error frame is an internal/protocol fault (70). Used
/// at every client call site so "broker down" is exit 5 whether it was down before the dial
/// or died one request into the exchange.
fn classify(addr: &str, doing: &str, e: &ClientError) -> CliError {
    let message = format!("{doing} broker at {addr}: {e}");
    match e {
        ClientError::Io(_) | ClientError::Closed => CliError::Unreachable(message),
        _ => CliError::Internal(message),
    }
}

fn connect(addr: &str) -> Result<Client, CliError> {
    Client::connect(addr).map_err(|e| classify(addr, "connecting to", &e))
}

fn run_pub(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut key = String::new();
    let mut payload_arg: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--key" => key = take_value("--key", args, &mut i)?,
            "--" => {
                // End of options: every remaining token is the payload (at most one), so a
                // payload that begins with `--` can still be published from the argument form.
                i += 1;
                while i < args.len() {
                    if payload_arg.is_some() {
                        return Err(CliError::Usage(
                            "pub takes at most one payload argument".to_string(),
                        ));
                    }
                    payload_arg = Some(args[i].clone());
                    i += 1;
                }
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for pub")))
            }
            _ => {
                if payload_arg.is_some() {
                    return Err(CliError::Usage(
                        "pub takes at most one payload argument".to_string(),
                    ));
                }
                payload_arg = Some(args[i].clone());
                i += 1;
            }
        }
    }
    // Payload from the argument, or from stdin if the argument is omitted.
    let payload = if let Some(p) = payload_arg {
        p.into_bytes()
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    };
    cmd_pub(&addr, key.as_bytes(), &payload, out)
}

fn cmd_pub(addr: &str, key: &[u8], payload: &[u8], out: &mut impl Write) -> Result<(), CliError> {
    let mut client = connect(addr)?;
    let timestamp_ms = SystemClock::new().now_unix_millis();
    let offset = client
        .produce(&PubBody {
            flags: 0,
            timestamp_ms,
            key,
            headers: b"",
            payload,
        })
        .map_err(|e| classify(addr, "publishing to", &e))?;
    writeln!(out, "{offset}")?;
    Ok(())
}

/// What `sub` does with each fetched message.
#[derive(Clone, Copy)]
enum Disposition {
    /// Print only; the message stays in flight and redelivers after the visibility timeout.
    Peek,
    /// Commit each message (`--ack`).
    Ack,
    /// Requeue each message for redelivery; `None` uses the broker's backoff schedule (`--nack`).
    Nack { delay_ms: Option<u64> },
    /// Drop each message without dead-lettering (`--term`).
    Term,
}

/// The chosen `sub` disposition verb (before the nack delay is known). A typed slot keeps the
/// build-the-`Disposition` match exhaustive and compiler-checked, so a verb can never be
/// silently dropped to a peek by a typo.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DispositionKind {
    Ack,
    Nack,
    Term,
}

/// Records a chosen `sub` disposition, rejecting a second one (the three are exclusive).
fn set_dispose(slot: &mut Option<DispositionKind>, kind: DispositionKind) -> Result<(), CliError> {
    if slot.is_some() {
        return Err(CliError::Usage(
            "sub takes at most one of `--ack`, `--nack`, `--term`".to_string(),
        ));
    }
    *slot = Some(kind);
    Ok(())
}

fn run_sub(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut max = DEFAULT_FETCH;
    let mut dispose: Option<DispositionKind> = None;
    let mut delay_ms: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--max" => {
                let raw = take_value("--max", args, &mut i)?;
                max = raw
                    .parse::<u32>()
                    .map_err(|_| CliError::Usage(format!("`--max` needs a number, got `{raw}`")))?;
            }
            "--ack" => {
                set_dispose(&mut dispose, DispositionKind::Ack)?;
                i += 1;
            }
            "--nack" => {
                set_dispose(&mut dispose, DispositionKind::Nack)?;
                i += 1;
            }
            "--term" => {
                set_dispose(&mut dispose, DispositionKind::Term)?;
                i += 1;
            }
            "--delay-ms" => {
                let raw = take_value("--delay-ms", args, &mut i)?;
                delay_ms = Some(raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--delay-ms` needs a number, got `{raw}`"))
                })?);
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for sub")))
            }
            other => {
                return Err(CliError::Usage(format!(
                    "sub takes no positional arguments, got `{other}`"
                )))
            }
        }
    }
    if delay_ms.is_some() && dispose != Some(DispositionKind::Nack) {
        return Err(CliError::Usage(
            "`--delay-ms` is only valid with `--nack`".to_string(),
        ));
    }
    let disposition = match dispose {
        Some(DispositionKind::Ack) => Disposition::Ack,
        Some(DispositionKind::Nack) => Disposition::Nack { delay_ms },
        Some(DispositionKind::Term) => Disposition::Term,
        None => Disposition::Peek,
    };
    cmd_sub(&addr, max, disposition, out)
}

fn cmd_sub(
    addr: &str,
    max: u32,
    disposition: Disposition,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut client = connect(addr)?;
    let messages = client
        .fetch(max)
        .map_err(|e| classify(addr, "fetching from", &e))?;
    for m in &messages {
        writeln!(
            out,
            "#{} gen={} key={} payload={}",
            m.offset,
            m.generation,
            String::from_utf8_lossy(&m.key),
            String::from_utf8_lossy(&m.payload),
        )?;
        match disposition {
            Disposition::Peek => {}
            Disposition::Ack => {
                let ok = client
                    .ack(m.offset, m.generation)
                    .map_err(|e| classify(addr, "acking to", &e))?;
                writeln!(out, "  ack {}", if ok { "committed" } else { "fenced" })?;
            }
            Disposition::Nack { delay_ms } => {
                let ok = client
                    .nack(m.offset, m.generation, delay_ms)
                    .map_err(|e| classify(addr, "nacking to", &e))?;
                writeln!(out, "  nack {}", if ok { "requeued" } else { "fenced" })?;
            }
            Disposition::Term => {
                let ok = client
                    .term(m.offset, m.generation)
                    .map_err(|e| classify(addr, "terminating on", &e))?;
                writeln!(out, "  term {}", if ok { "dropped" } else { "fenced" })?;
            }
        }
    }
    writeln!(out, "fetched {} message(s)", messages.len())?;
    Ok(())
}

fn run_serve(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut addr = DEFAULT_ADDR.to_string();
    let mut data_dir: Option<String> = None;
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;
    let mut checkpoint_interval = DEFAULT_CHECKPOINT_INTERVAL;
    let mut health_addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--max-connections" => {
                let raw = take_value("--max-connections", args, &mut i)?;
                max_connections = raw.parse::<usize>().map_err(|_| {
                    CliError::Usage(format!("`--max-connections` needs a number, got `{raw}`"))
                })?;
            }
            "--checkpoint-interval" => {
                let raw = take_value("--checkpoint-interval", args, &mut i)?;
                checkpoint_interval = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!(
                        "`--checkpoint-interval` needs a number, got `{raw}`"
                    ))
                })?;
            }
            "--health-addr" => health_addr = Some(take_value("--health-addr", args, &mut i)?),
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for serve")))
            }
            other => {
                return Err(CliError::Usage(format!(
                    "serve takes no positional arguments, got `{other}`"
                )))
            }
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("serve requires `--data-dir <dir>`".to_string()))?;
    if max_connections == 0 {
        // A zero cap binds and looks healthy but refuses every connection: reject it.
        return Err(CliError::Usage(
            "`--max-connections` must be at least 1".to_string(),
        ));
    }
    cmd_serve(
        &addr,
        Path::new(&data_dir),
        max_connections,
        checkpoint_interval,
        health_addr.as_deref(),
        out,
    )
}

#[cfg(unix)]
fn cmd_serve(
    addr: &str,
    data_dir: &Path,
    max_connections: usize,
    checkpoint_interval: u64,
    health_addr: Option<&str>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let shared = open_disk_engine(data_dir, DEFAULT_MAX_IN_FLIGHT, checkpoint_interval)?;
    let listener = TcpListener::bind(addr)
        .map_err(|e| CliError::Internal(format!("cannot bind {addr}: {e}")))?;
    let local = listener
        .local_addr()
        .map_err(|e| CliError::Internal(format!("cannot read local address: {e}")))?;
    writeln!(
        out,
        "ironbus listening on {local}, data dir {}",
        data_dir.display()
    )?;
    // The flag is never flipped here: the broker runs until the process is signalled.
    // Durability holds across an abrupt termination because every ack is fsynced first, so
    // a clean-shutdown handler is a follow-up, not a correctness requirement.
    let shutdown = Arc::new(AtomicBool::new(false));

    // Optionally start the health endpoints on their own loopback HTTP port.
    let health_handle = if let Some(haddr) = health_addr {
        let health_listener = TcpListener::bind(haddr)
            .map_err(|e| CliError::Internal(format!("cannot bind health {haddr}: {e}")))?;
        let health_local = health_listener
            .local_addr()
            .map_err(|e| CliError::Internal(format!("cannot read health address: {e}")))?;
        writeln!(
            out,
            "ironbus health endpoints on {health_local} (/healthz, /readyz, /metrics)"
        )?;
        let engine = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        Some(std::thread::spawn(move || {
            let _ = serve_health(&health_listener, &engine, &shutdown);
        }))
    } else {
        None
    };

    let result = serve(&listener, &shared, &shutdown, max_connections)
        .map_err(|e| CliError::Internal(format!("serve loop failed: {e}")));
    // The wire serve returns only when shutdown is set, so flip it for the health thread too.
    shutdown.store(true, Ordering::Release);
    if let Some(h) = health_handle {
        let _ = h.join();
    }
    result?;
    Ok(())
}

#[cfg(not(unix))]
fn cmd_serve(
    addr: &str,
    data_dir: &Path,
    max_connections: usize,
    checkpoint_interval: u64,
    health_addr: Option<&str>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (
        addr,
        data_dir,
        max_connections,
        checkpoint_interval,
        health_addr,
        out,
    );
    Err(CliError::Internal(
        "ironbus serve requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// Opens (creating the directory if absent) the on-disk broker engine rooted at `data_dir`.
#[cfg(unix)]
fn open_disk_engine(
    data_dir: &Path,
    max_in_flight: u32,
    checkpoint_interval: u64,
) -> Result<SharedEngine<StdFs, SystemClock>, CliError> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| CliError::Internal(format!("cannot create {}: {e}", data_dir.display())))?;
    let fs = StdFs::new(data_dir.to_path_buf());
    let delivery = DeliveryConfig::new(5, false, DEFAULT_NACK_BACKOFF_NANOS.to_vec())
        .map_err(|e| CliError::Internal(format!("delivery config: {e:?}")))?;
    let engine = Engine::open(
        fs,
        SystemClock::new(),
        EngineConfig {
            log: LogConfig::default(),
            lease: LeaseConfig::default(),
            delivery,
            max_in_flight,
            checkpoint_interval,
        },
    )
    .map_err(|e| CliError::Internal(format!("opening broker at {}: {e}", data_dir.display())))?;
    Ok(Arc::new(Mutex::new(engine)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    use ironbus_server::engine::{Engine, EngineConfig};
    use ironbus_server::server::{serve, SharedEngine};
    use ironbus_storage::fs::InMemoryFs;
    use ironbus_storage::log::LogConfig;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// Starts an in-process broker over an in-memory filesystem (cross-platform), returning
    /// the bound address, a shutdown flag, and the serve thread handle.
    fn start_inmem_server() -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::default(),
                delivery: DeliveryConfig::new(5, false, Vec::new()).unwrap(),
                max_in_flight: 16,
                checkpoint_interval: 1024,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });
        (addr, shutdown, handle)
    }

    #[test]
    fn pub_then_sub_with_ack_round_trip() {
        let (addr, shutdown, handle) = start_inmem_server();
        let a = addr.to_string();

        let mut published = Vec::new();
        cmd_pub(&a, b"the-key", b"hello-cli", &mut published).unwrap();
        assert_eq!(String::from_utf8(published).unwrap(), "0\n");

        let mut consumed = Vec::new();
        cmd_sub(&a, 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("#0 gen="), "missing offset line: {text}");
        assert!(text.contains("key=the-key"), "missing key: {text}");
        assert!(
            text.contains("payload=hello-cli"),
            "missing payload: {text}"
        );
        assert!(text.contains("ack committed"), "missing ack: {text}");
        assert!(
            text.contains("fetched 1 message(s)"),
            "missing count: {text}"
        );

        // Acked: a second sub sees nothing.
        let mut again = Vec::new();
        cmd_sub(&a, 10, Disposition::Peek, &mut again).unwrap();
        assert_eq!(String::from_utf8(again).unwrap(), "fetched 0 message(s)\n");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn sub_on_an_empty_queue_reports_zero() {
        let (addr, shutdown, handle) = start_inmem_server();
        let mut buf = Vec::new();
        cmd_sub(&addr.to_string(), 5, Disposition::Ack, &mut buf).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "fetched 0 message(s)\n");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn run_dispatches_help_without_a_server() {
        let mut buf = Vec::new();
        run(&["help".to_string()], &mut buf).unwrap();
        assert!(String::from_utf8(buf).unwrap().contains("USAGE:"));
    }

    #[test]
    fn unknown_subcommand_is_a_usage_error() {
        let mut buf = Vec::new();
        let e = run(&["frobnicate".to_string()], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("frobnicate")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn no_subcommand_is_a_usage_error() {
        let mut buf = Vec::new();
        assert_eq!(run(&[], &mut buf).unwrap_err().exit_code(), EXIT_USAGE);
    }

    #[test]
    fn bad_max_is_a_usage_error_before_connecting() {
        // A parse error must surface (exit 1) without ever dialing a broker.
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--max".to_string(),
                "not-a-number".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_flag_value_is_a_usage_error() {
        let mut buf = Vec::new();
        let e = run(&["pub".to_string(), "--key".to_string()], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--key")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_requires_a_data_dir() {
        let mut buf = Vec::new();
        let e = run(&["serve".to_string()], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--data-dir")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_unreachable_broker_maps_to_exit_five() {
        // Port 1 on loopback refuses immediately, so this does not hang on the connect timeout.
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_UNREACHABLE, "{e}");
        assert!(matches!(e, CliError::Unreachable(_)));
    }

    #[test]
    fn sub_rejects_two_dispositions() {
        let mut buf = Vec::new();
        let e = run(
            &["sub".to_string(), "--ack".to_string(), "--nack".to_string()],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        assert!(matches!(e, CliError::Usage(_)));
    }

    #[test]
    fn delay_ms_requires_nack() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--ack".to_string(),
                "--delay-ms".to_string(),
                "5".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        assert!(matches!(e, CliError::Usage(m) if m.contains("--delay-ms")));
    }

    #[test]
    fn nack_delay_is_order_independent() {
        // `--delay-ms` before `--nack` must be accepted (the validation runs after the parse
        // loop). With no broker it then fails to connect (exit 5), proving the flags parsed
        // rather than tripping a usage error (exit 1).
        let mut buf = Vec::new();
        let e = run(
            &[
                "sub".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
                "--delay-ms".to_string(),
                "7".to_string(),
                "--nack".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(
            e.exit_code(),
            EXIT_UNREACHABLE,
            "parsed then failed to connect: {e}"
        );
    }

    #[test]
    fn sub_nack_requeues_and_sub_term_drops() {
        let (addr, shutdown, handle) = start_inmem_server();
        let a = addr.to_string();

        // Nack: the message is requeued and redelivers on the next fetch (the default 30s
        // visibility means the redelivery is the nack's doing, not a timeout).
        cmd_pub(&a, b"", b"retry", &mut Vec::new()).unwrap();
        let mut nout = Vec::new();
        cmd_sub(&a, 10, Disposition::Nack { delay_ms: None }, &mut nout).unwrap();
        assert!(String::from_utf8(nout).unwrap().contains("nack requeued"));
        let mut aout = Vec::new();
        cmd_sub(&a, 10, Disposition::Ack, &mut aout).unwrap();
        let atext = String::from_utf8(aout).unwrap();
        assert!(atext.contains("payload=retry"), "redelivered: {atext}");
        assert!(atext.contains("ack committed"), "acked: {atext}");

        // Term: the message is dropped (committed past) and a re-fetch is empty.
        cmd_pub(&a, b"", b"drop", &mut Vec::new()).unwrap();
        let mut tout = Vec::new();
        cmd_sub(&a, 10, Disposition::Term, &mut tout).unwrap();
        assert!(String::from_utf8(tout).unwrap().contains("term dropped"));
        let mut eout = Vec::new();
        cmd_sub(&a, 10, Disposition::Peek, &mut eout).unwrap();
        assert_eq!(String::from_utf8(eout).unwrap(), "fetched 0 message(s)\n");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn serve_on_disk_round_trips_and_survives_a_restart() {
        // Exercise the CLI-specific disk wiring (create dir, StdFs, Engine::open), a full
        // publish/fetch/ack round-trip over a real directory, and durability across a restart.
        let dir = std::env::temp_dir().join(format!("ironbus-cli-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let shared = open_disk_engine(&dir, 64, 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });

        let a = addr.to_string();
        let mut published = Vec::new();
        cmd_pub(&a, b"k", b"on-disk", &mut published).unwrap();
        assert_eq!(String::from_utf8(published).unwrap(), "0\n");

        let mut consumed = Vec::new();
        cmd_sub(&a, 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("payload=on-disk"), "missing payload: {text}");
        assert!(text.contains("ack committed"), "missing ack: {text}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();

        // Restart: reopen the SAME data dir. With checkpoint_interval = 1, the server
        // persisted the committed cursor synchronously when it acked offset 0, so a clean
        // restart RESUMES past the acked message (it does not redeliver), and the durable log
        // continues at offset 1 rather than overwriting offset 0.
        let reopened = open_disk_engine(&dir, 64, 1).unwrap();
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let shutdown2 = Arc::new(AtomicBool::new(false));
        let handle2 = std::thread::spawn({
            let shutdown2 = Arc::clone(&shutdown2);
            move || serve(&listener2, &reopened, &shutdown2, 16).unwrap()
        });
        let a2 = addr2.to_string();

        let mut after_restart = Vec::new();
        cmd_sub(&a2, 10, Disposition::Peek, &mut after_restart).unwrap();
        assert_eq!(
            String::from_utf8(after_restart).unwrap(),
            "fetched 0 message(s)\n",
            "acked message redelivered after restart: cursor was not checkpointed"
        );

        let mut next = Vec::new();
        cmd_pub(&a2, b"k", b"after-restart", &mut next).unwrap();
        assert_eq!(
            String::from_utf8(next).unwrap(),
            "1\n",
            "log did not persist offset 0 across restart"
        );

        shutdown2.store(true, Ordering::Release);
        handle2.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
