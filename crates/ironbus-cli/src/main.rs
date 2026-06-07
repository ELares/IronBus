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

/// The `serve` data-directory lifecycle and the single-broker lock (#89). Unix-only, like `serve`
/// itself; the non-Unix `cmd_serve` stub errors out before any of it runs, so the module is gated.
#[cfg(unix)]
mod dirlock;

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
use ironbus_server::engine::{DiskFullPolicy, Engine, EngineConfig};
#[cfg(unix)]
use ironbus_server::health::serve_health;
#[cfg(unix)]
use ironbus_server::server::{serve, SharedEngine};
#[cfg(unix)]
use ironbus_storage::dlq::{read_dlq_entries, DlqEntry};
#[cfg(unix)]
use ironbus_storage::fs::StdFs;
#[cfg(unix)]
use ironbus_storage::log::LogConfig;
#[cfg(unix)]
use ironbus_storage::loss::LossReport;
#[cfg(unix)]
use ironbus_storage::offline::OfflineReader;
#[cfg(unix)]
use ironbus_storage::segment::{OwnedRecord, StorageError};
#[cfg(unix)]
use std::net::TcpListener;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::{Arc, Mutex, PoisonError};

/// The default broker address: loopback only, so a zero-config broker is never exposed off
/// the host without an explicit choice.
const DEFAULT_ADDR: &str = "127.0.0.1:7777";
/// The default fetch credit for `sub`.
const DEFAULT_FETCH: u32 = 10;
/// The default connection cap for `serve`.
const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// The default in-flight window for the `serve` engine.
/// The default max-ack-pending window for `serve`.
const DEFAULT_MAX_IN_FLIGHT: u32 = 1024;

/// The default per-CONSUMER (per-connection) in-flight credit for `serve` (#65), aliased to the
/// engine's [`ironbus_server::engine::DEFAULT_CONSUMER_CREDIT`] so the CLI default and the engine
/// default are a single source of truth and cannot drift. It is the most un-acked messages one
/// connection may hold at once, the consumer-side half of credit-based flow control; the effective
/// Flow bound is min(this, the per-group `--max-in-flight` window). Floored to 1 by the engine.
const DEFAULT_CONSUMER_CREDIT: u32 = ironbus_server::engine::DEFAULT_CONSUMER_CREDIT;

/// The default per-CONSUMER (per-connection) in-flight BYTE budget for `serve` (#275), aliased to
/// the engine's [`ironbus_server::engine::DEFAULT_CONSUMER_CREDIT_BYTES`] so the CLI default and the
/// engine default are a single source of truth and cannot drift. It is the most un-acked payload
/// bytes one connection may hold at once, the RAM-side companion to the message-count credit; the
/// effective Flow bound is min(message credit, byte budget) with a hard floor of one message. `0`
/// means unlimited (the byte budget is off, only the message credit binds).
const DEFAULT_CONSUMER_CREDIT_BYTES: u64 = ironbus_server::engine::DEFAULT_CONSUMER_CREDIT_BYTES;

/// The default segment size cap for `serve` (64 MiB, matching the storage default).
const DEFAULT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;

/// The default durable-log total byte cap for `serve` (0 = unlimited, matching the storage
/// default): the spill-by-default behavior is unchanged until an operator opts in to the shed.
const DEFAULT_MAX_TOTAL_BYTES: u64 = 0;

/// The default consumer-safe size-retention bound for `serve` (0 = unlimited, retention OFF,
/// matching the engine default): the broker never reaps old sealed segments until an operator
/// opts in, so existing behavior is unchanged.
const DEFAULT_MAX_RETAINED_BYTES: u64 = 0;

/// The default consumer-safe AGE-retention bound for `serve`, in MILLISECONDS (0 = disabled,
/// matching the engine default): the broker never reaps a segment for age until an operator opts
/// in. Milliseconds (not a duration string) so the flag takes a bare integer.
const DEFAULT_MAX_AGE_MS: u64 = 0;

/// The default consumer-safe COUNT-retention bound for `serve`, in messages (0 = disabled,
/// matching the engine default): the broker never reaps a segment for count until an operator
/// opts in.
const DEFAULT_MAX_MESSAGES: u64 = 0;

/// The default cap on the number of live work-groups for `serve` (refs #240, #9, #10), aliased to
/// the engine's [`ironbus_server::engine::DEFAULT_MAX_GROUPS`] so the CLI default and the engine
/// default are a single source of truth and cannot drift. It bounds total consumer-state memory
/// once the wire can name groups, so an unauthenticated client cannot exhaust memory by naming
/// endless groups. `0` = unlimited (the cap is off); the default is non-zero (1024).
const DEFAULT_MAX_GROUPS: usize = ironbus_server::engine::DEFAULT_MAX_GROUPS;

/// The default idle window after which an idle, fully-caught-up, lease-free NAMED work-group is
/// evicted for `serve` (refs #277, #240), in MILLISECONDS, aliased to the engine's
/// [`ironbus_server::engine::DEFAULT_GROUP_IDLE_EVICT_MS`] so the CLI and engine default are a single
/// source of truth. `0` = DISABLED (never evict), the default: an operator opts in to reclaiming
/// idle named groups. Eviction never deletes a durable checkpoint, so a re-subscribe still resumes.
const DEFAULT_GROUP_IDLE_EVICT_MS: u64 = ironbus_server::engine::DEFAULT_GROUP_IDLE_EVICT_MS;

/// The default disk-full overflow policy for `serve` (`drop-new`, matching the engine default):
/// an over-cap produce is shed, the older accepted data preserved, so existing behavior is
/// unchanged. `drop-oldest` opts in to force-reaping the oldest sealed segment to make room.
const DEFAULT_DISK_FULL_POLICY: &str = "drop-new";

/// The disk-full overflow policy parsed from `serve --disk-full-policy` (#82). A platform-neutral,
/// `Copy` mirror of the engine's policy enum, so it lives in the (non-Unix-gated) `ServeConfig` and
/// is validated on every platform; the Unix on-disk path maps it to the engine's `DiskFullPolicy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskFullPolicyArg {
    /// Shed an over-cap produce (the drop-new default).
    DropNew,
    /// Force-reap the oldest sealed segment to make room, then accept the over-cap produce.
    DropOldest,
}

impl DiskFullPolicyArg {
    /// Parses the `--disk-full-policy` flag value, accepting `drop-new` or `drop-oldest`.
    fn parse(value: &str) -> Option<DiskFullPolicyArg> {
        match value {
            "drop-new" => Some(DiskFullPolicyArg::DropNew),
            "drop-oldest" => Some(DiskFullPolicyArg::DropOldest),
            _ => None,
        }
    }
}

/// The smallest segment size cap `serve` accepts: below this, segments proliferate
/// pathologically (one record each), so reject it as a misconfiguration.
const MIN_MAX_SEGMENT_BYTES: u64 = 4096;

/// The default visibility timeout for `serve` (30 s, matching the lease default).
const DEFAULT_VISIBILITY_MS: u64 = 30_000;

/// The default lease hard cap for `serve` (5 minutes). The effective cap is the larger of
/// this and the visibility timeout, so it is never below one redelivery window. Used only by
/// the Unix on-disk broker, so it is cfg-gated to keep the non-Unix build free of a dead const.
#[cfg(unix)]
const DEFAULT_HARD_CAP_MS: u64 = 300_000;

/// The default max delivery attempts before a poison message is dead-lettered.
const DEFAULT_MAX_DELIVER: u32 = 5;
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
/// The data directory (or path) an offline verb was pointed at does not exist.
const EXIT_NOT_FOUND: u8 = 2;
/// An offline verb found the data directory structurally corrupt (a broken segment chain
/// or an undecodable header), distinct from a clean torn tail it can still read past.
const EXIT_CORRUPT: u8 = 4;

const USAGE: &str = "\
ironbus: a durable edge message queue.

USAGE:
    ironbus serve --data-dir <dir> [--addr <host:port>] [--max-connections <n>]
                  [--checkpoint-interval <n>] [--max-deliver <n>] [--allow-unlimited-deliver]
                  [--backoff-ms <ms,ms,...>] [--max-in-flight <n>]
                  [--consumer-credit <n>] [--consumer-credit-bytes <n>]
                  [--max-segment-bytes <n>] [--max-total-bytes <bytes>]
                  [--max-retained-bytes <bytes>] [--max-age-ms <ms>] [--max-messages <n>]
                  [--max-groups <n>] [--group-idle-evict-ms <ms>]
                  [--disk-full-policy <drop-new|drop-oldest>]
                  [--key-shared-group <name>]...
                  [--visibility-timeout-ms <n>] [--health-addr <host:port>] [--enable-admin]
    ironbus pub   [--addr <host:port>] [--key <key>] [<payload>]
    ironbus sub   [--addr <host:port>] [--group <name>] [--max <n>]
                  [--ack | --nack [--delay-ms <n>] | --term]
    ironbus peek  --data-dir <dir> [--from-offset <n>] [--limit <n>] [--json]
    ironbus dump  --data-dir <dir> [--limit <n>] [--json] [--dlq]
    ironbus help

Notes:
    The default address is 127.0.0.1:7777 (loopback only).
    --max-in-flight bounds the per-GROUP in-flight (max-ack-pending) window; --consumer-credit
    (default 64) bounds the per-CONNECTION un-acked set, so in a competing group one stuck
    consumer cannot consume a peer's budget. A fetch delivers min(requested, consumer credit,
    group window). --consumer-credit-bytes (default 8388608, 8 MiB; 0 = unlimited) is the parallel
    per-CONNECTION un-acked BYTE budget, so a large-payload consumer cannot blow the RAM ceiling
    despite a small message count: a fetch also stops once a connection's in-flight bytes reach the
    budget, with a hard floor of one message (a single over-budget message is still delivered so it
    never wedges the consumer).
    --max-deliver (default 5) caps delivery attempts before a poison message is dead-lettered.
    0 (and the maximum 4294967295) mean unlimited delivery, allowed ONLY with
    --allow-unlimited-deliver, which also prints a startup WARN: an unlimited cap lets a single
    poison payload redeliver forever and is never dead-lettered.
    --backoff-ms <ms,ms,...> sets the escalating per-attempt nack/redelivery delay schedule
    (e.g. 100,500,2000), indexed by attempt and clamped to the last entry; it applies when a nack
    carries no explicit delay. Omitted, a built-in default schedule is used; a single 0 disables
    backoff (retry as soon as the visibility timeout allows).
    Retention reaps whole old, fully-consumed sealed segments under three composable, consumer-safe
    bounds, each 0 = off (the default): --max-retained-bytes (durable record bytes),
    --max-age-ms (a segment whose newest record is older than this many milliseconds), and
    --max-messages (total record count). A segment is reaped if ANY enabled bound trips, oldest
    first, never below the slowest consumer's committed offset, never the active segment.
    --max-groups (default 1024, 0 = unlimited) caps the number of live work-groups, including the
    default group, so once the wire can name groups a client cannot exhaust memory by naming
    endless groups. A new named group past the cap is rejected; the default group is never counted.
    --group-idle-evict-ms (default 0 = disabled) evicts an idle NAMED work-group from memory after
    it has been idle this many milliseconds, reclaiming its slot against --max-groups. Only a
    fully-caught-up (committed at the head, no acked-ahead set), lease-free, non-key-shared named
    group is evicted; the default group is never evicted and a group that is behind is never evicted,
    so a consumer's committed position is never lost. The durable per-group checkpoint is kept, so a
    re-subscribe resumes where it left off. The sweep is clock-driven (run on produce and poll, no
    background thread). An explicit unsub of a now-idle named group reclaims it immediately.
    --disk-full-policy (default drop-new) sets what an over-cap produce does once --max-total-bytes
    is hit: drop-new sheds it (preserving older data); drop-oldest force-reaps the oldest sealed
    segment to make room then accepts it, so a slow consumer whose records are reaped gets a
    one-time truncation notice and resumes at the oldest record still present.
    --key-shared-group <name> (repeatable, default none) runs the named competing group in
    key_shared ordering: a record's key routes to one live member, so same-key records keep their
    order while the group drains in parallel across keys. A group not named here stays plain
    competing distribution (the default), unaffected.
    --enable-admin (default off) turns on the read-only /admin introspection endpoint on the health
    server (so it needs --health-addr): a JSON snapshot of broker counters, per-group lag/in-flight,
    DLQ state, and the effective config bounds, for debugging. It is READ-ONLY (GET only, no path
    mutates state) and UNAUTHENTICATED, sharing /metrics's trust model, so run it only on loopback or
    a trusted network. Off, /admin is a 404 like any unknown path.
    pub reads the payload from the argument, or from stdin if omitted (an empty input
    publishes an empty message, which is a valid record).
    sub prints one line per message; at most one disposition applies to the batch:
    --ack commits, --nack requeues (after --delay-ms), --term drops without dead-lettering.
    peek and dump decode a stopped broker's data directory with no server running; they
    read only up to the durable high-water mark and mark, never hide, any torn or corrupt
    tail. peek shows a window (default 10 records); dump streams every record, one per line
    (NDJSON with --json). Both bound memory to one segment at a time.
    dump --dlq instead streams the durable dead-letter SINK (the dlq/ subdirectory): one line
    per poison record showing dlq_offset, source_offset, group, attempt, ts_ms, and the
    key/payload sizes (NDJSON with --json). It is read-only and never mutates the directory;
    an empty or never-poisoned broker shows nothing.
    Every serve setting can also be supplied via an environment variable IRONBUS_<FLAG>, the flag
    name uppercased with dashes as underscores (--max-total-bytes -> IRONBUS_MAX_TOTAL_BYTES,
    --data-dir -> IRONBUS_DATA_DIR, --addr -> IRONBUS_ADDR). Precedence is flag > env > default: an
    explicit flag overrides the env var, which overrides the compiled default. A bad env value (e.g.
    non-numeric where a number is expected) is a usage error naming the env var. See docs/CLI.md.
    On serve, the --data-dir is created (parents too, mode 0700) if absent and verified writable; a
    path that exists but is not a directory, or a read-only mount, is a fatal error naming the path.
    serve takes an exclusive lock on the data dir, so a second broker on the same data dir fails
    fast rather than corrupting the log with concurrent writers.
    Exit codes: 0 clean, 1 usage, 2 not found, 4 corrupt data, 5 broker unreachable, 70 internal.";

/// A command-line failure, mapped to a frozen exit code by [`main`].
#[derive(Debug)]
enum CliError {
    /// Bad or missing arguments (exit 1).
    Usage(String),
    /// The broker could not be reached (exit 5).
    Unreachable(String),
    /// An internal or runtime failure, including an unsupported platform (exit 70).
    Internal(String),
    /// An offline verb's data directory does not exist (exit 2). Constructed only on Unix,
    /// where the offline verbs run; documented in the exit-code scheme on every platform.
    #[cfg_attr(not(unix), allow(dead_code))]
    NotFound(String),
    /// An offline verb's data directory is structurally corrupt (exit 4). Constructed only
    /// on Unix, where the offline verbs run; documented on every platform.
    #[cfg_attr(not(unix), allow(dead_code))]
    Corrupt(String),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            CliError::Usage(_) => EXIT_USAGE,
            CliError::Unreachable(_) => EXIT_UNREACHABLE,
            CliError::Internal(_) => EXIT_INTERNAL,
            CliError::NotFound(_) => EXIT_NOT_FOUND,
            CliError::Corrupt(_) => EXIT_CORRUPT,
        }
    }
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CliError::Usage(m)
            | CliError::Unreachable(m)
            | CliError::Internal(m)
            | CliError::NotFound(m)
            | CliError::Corrupt(m) => write!(f, "{m}"),
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
        "peek" => run_peek(rest, out),
        "dump" => run_dump(rest, out),
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

/// Like [`take_value`] but parses the value as a number, mapping a non-numeric value to the same
/// `` `{flag}` needs a number, got `{raw}` `` usage error every numeric `serve` flag returns. This
/// collapses the per-flag parse boilerplate to one call so the flag parser stays compact.
fn take_number<T>(flag: &str, args: &[String], i: &mut usize) -> Result<T, CliError>
where
    T: std::str::FromStr,
{
    let raw = take_value(flag, args, i)?;
    raw.parse::<T>()
        .map_err(|_| CliError::Usage(format!("`{flag}` needs a number, got `{raw}`")))
}

/// Like [`take_number`] but parses a comma-separated LIST of `u64` values (e.g. `100,500,2000`),
/// for the `--backoff-ms` schedule (#63). Whitespace around a value is tolerated; an empty list,
/// an empty element (a stray comma), or a non-numeric element is a usage error, so a typo is
/// caught before the broker opens rather than silently dropping a stage of the schedule.
fn take_number_list(flag: &str, args: &[String], i: &mut usize) -> Result<Vec<u64>, CliError> {
    let raw = take_value(flag, args, i)?;
    // Shared with the env-var path (`IRONBUS_BACKOFF_MS`, #89) via `parse_u64_list`, so the flag and
    // the env var accept exactly the same grammar and emit the same error shape (naming the source).
    parse_u64_list(flag, &raw)
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
    let mut group = String::new();
    let mut max = DEFAULT_FETCH;
    let mut dispose: Option<DispositionKind> = None;
    let mut delay_ms: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => addr = take_value("--addr", args, &mut i)?,
            "--group" => group = take_value("--group", args, &mut i)?,
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
    cmd_sub(&addr, &group, max, disposition, out)
}

fn cmd_sub(
    addr: &str,
    group: &str,
    max: u32,
    disposition: Disposition,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut client = connect(addr)?;
    // Join the named work-group before fetching (#9); an empty name keeps the default group.
    if !group.is_empty() {
        client
            .subscribe(group)
            .map_err(|e| classify(addr, "subscribing to", &e))?;
    }
    // Re-fetch until `max` is reached or a batch comes back empty. The per-consumer credit (#65)
    // caps a single Flow at the in-flight window, so a larger `--max` can only drain when each
    // batch is committed past: Ack and Term advance the cursor, freeing credit so the next fetch
    // serves new records. Peek and Nack do not advance (Peek keeps the records leased, Nack
    // requeues them), so re-fetching would only re-serve the same batch (under Nack, an immediate
    // redelivery storm); for those we take a single window-bounded batch and stop.
    let drains = matches!(disposition, Disposition::Ack | Disposition::Term);
    let mut total: u32 = 0;
    loop {
        let want = max - total;
        if want == 0 {
            break;
        }
        let fetched = client
            .fetch(want)
            .map_err(|e| classify(addr, "fetching from", &e))?;
        let got = u32::try_from(fetched.messages.len()).unwrap_or(u32::MAX);
        for m in &fetched.messages {
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
        // Surface any in-band dead-letter advisories: offsets the broker dropped as poison
        // (over MaxDeliver) and skipped from delivery (#63), so a consumer is not left silently
        // never seeing them.
        for dl in &fetched.dead_letters {
            let reason = if dl.reason == 0 {
                "max-deliver"
            } else {
                "reserved"
            };
            writeln!(out, "dead-letter offset={} reason={reason}", dl.offset)?;
        }
        // Surface any truncation advisories: the broker reset this cursor below the oldest retained
        // record because the disk-full drop-oldest policy reaped its records (#82, #84), so the
        // consumer learns it lost a span and where delivery resumed rather than silently skipping.
        for t in &fetched.truncations {
            writeln!(
                out,
                "truncated: resumed at offset {}, skipped {} record(s)",
                t.earliest_retained, t.skipped
            )?;
        }
        total = total.saturating_add(got);
        if got == 0 || !drains {
            break;
        }
    }
    writeln!(out, "fetched {total} message(s)")?;
    Ok(())
}

/// An injectable environment-variable lookup (#89): maps an env-var NAME to its value, or `None`
/// if it is unset. A `serve` setting reads its `IRONBUS_<FLAG>` var through this seam rather than
/// touching `std::env` directly, so a test can drive the env layer deterministically with a fixed
/// map (no global, racy process-environment mutation) while production passes a closure over the
/// real [`std::env::var`]. The precedence is flag > env > default: an explicit CLI flag overrides
/// the env var, which overrides the compiled default.
type EnvFn<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Reads the `IRONBUS_<flag>` env var for `flag` (e.g. `--data-dir` -> `IRONBUS_DATA_DIR`) through
/// the injected `env` seam, returning the raw string if set. The mapping is the flag name minus its
/// leading `--`, uppercased, with `-` -> `_`, prefixed `IRONBUS_`; documented in `docs/CLI.md`.
fn env_var_name(flag: &str) -> String {
    let base = flag
        .trim_start_matches('-')
        .replace('-', "_")
        .to_uppercase();
    format!("IRONBUS_{base}")
}

/// Resolves a STRING setting with the flag > env > default precedence: the explicit CLI `flag`
/// value if given, else the `IRONBUS_<flag>` env var if set, else `default`.
fn resolve_string(flag: &str, cli: Option<String>, env: &EnvFn<'_>, default: &str) -> String {
    cli.or_else(|| env(&env_var_name(flag)))
        .unwrap_or_else(|| default.to_string())
}

/// Resolves an OPTIONAL string setting (one with no compiled default, e.g. `--data-dir`,
/// `--health-addr`): the explicit CLI value if given, else the env var if set, else `None`.
fn resolve_opt_string(flag: &str, cli: Option<String>, env: &EnvFn<'_>) -> Option<String> {
    cli.or_else(|| env(&env_var_name(flag)))
}

/// Resolves a NUMERIC setting with the flag > env > default precedence. If the CLI flag was given
/// its already-parsed value wins; otherwise the `IRONBUS_<flag>` env var is parsed, and a
/// non-numeric env value is a usage error NAMING THE ENV VAR (e.g. ``IRONBUS_MAX_TOTAL_BYTES needs
/// a number, got `x` ``), exactly as a bad flag value names the flag; absent the env var, `default`.
fn resolve_number<T>(flag: &str, cli: Option<T>, env: &EnvFn<'_>, default: T) -> Result<T, CliError>
where
    T: std::str::FromStr,
{
    if let Some(value) = cli {
        return Ok(value);
    }
    let name = env_var_name(flag);
    match env(&name) {
        Some(raw) => raw
            .parse::<T>()
            .map_err(|_| CliError::Usage(format!("`{name}` needs a number, got `{raw}`"))),
        None => Ok(default),
    }
}

/// Resolves a comma-separated `u64` LIST setting (`--backoff-ms`) with flag > env > default. The
/// CLI list wins if given; else the `IRONBUS_BACKOFF_MS` env var is parsed with the same grammar as
/// the flag (comma-separated, whitespace-tolerant), a bad element a usage error naming the env var;
/// absent the env var, the empty list (meaning "use the built-in default schedule").
fn resolve_number_list(
    flag: &str,
    cli: Option<Vec<u64>>,
    env: &EnvFn<'_>,
) -> Result<Vec<u64>, CliError> {
    if let Some(list) = cli {
        return Ok(list);
    }
    let name = env_var_name(flag);
    match env(&name) {
        Some(raw) => parse_u64_list(&name, &raw),
        None => Ok(Vec::new()),
    }
}

/// Parses a comma-separated `u64` list (the shared `--backoff-ms` grammar), naming `source` (a flag
/// or an env var) in the error. Whitespace around an element is tolerated; an empty element (a
/// stray comma) or a non-numeric element is a usage error.
fn parse_u64_list(source: &str, raw: &str) -> Result<Vec<u64>, CliError> {
    let mut values = Vec::new();
    for part in raw.split(',') {
        let value = part.trim().parse::<u64>().map_err(|_| {
            CliError::Usage(format!(
                "`{source}` needs a comma-separated list of numbers, got `{raw}`"
            ))
        })?;
        values.push(value);
    }
    if values.is_empty() {
        return Err(CliError::Usage(format!(
            "`{source}` needs at least one number"
        )));
    }
    Ok(values)
}

/// Resolves a BOOLEAN flag with flag > env > default(false). The flag is set on the command line
/// (no value), else the `IRONBUS_<flag>` env var is read: `1`/`true` (case-insensitive) enables it,
/// `0`/`false` disables it, any other value is a usage error naming the env var; absent, `false`.
fn resolve_bool(flag: &str, cli_set: bool, env: &EnvFn<'_>) -> Result<bool, CliError> {
    if cli_set {
        return Ok(true);
    }
    let name = env_var_name(flag);
    match env(&name) {
        Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" => Ok(true),
            "0" | "false" => Ok(false),
            other => Err(CliError::Usage(format!(
                "`{name}` must be `true`/`1` or `false`/`0`, got `{other}`"
            ))),
        },
        None => Ok(false),
    }
}

/// The fully-parsed `serve` invocation: the assembled tuning config plus the connection-level
/// arguments (the bind address, the optional data dir and health address, and the declared
/// `key_shared` groups) that are not part of [`ServeConfig`].
#[derive(Debug)]
struct ParsedServe {
    addr: String,
    data_dir: Option<String>,
    config: ServeConfig,
    key_shared_groups: Vec<String>,
    health_addr: Option<String>,
}

fn run_serve(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    // Production reads the real process environment through the injected seam; tests drive
    // `parse_serve_flags_with_env` with a fixed map so the env layer is deterministic (#89).
    let env = |name: &str| std::env::var(name).ok();
    let parsed = parse_serve_flags_with_env(args, &env)?;
    finish_serve(
        &parsed.addr,
        parsed.data_dir.as_deref(),
        &parsed.config,
        &parsed.key_shared_groups,
        parsed.health_addr.as_deref(),
        out,
    )
}

/// Parses the `serve` flag list into a [`ParsedServe`]. Split out of [`run_serve`] so the
/// flag-parsing loop is one self-contained concern (and stays under the per-function line bound).
/// The `serve` flags as EXPLICITLY GIVEN on the command line: each settable knob is `Some` only if
/// its flag appeared, `None` otherwise, so the env/default layer ([`parse_serve_flags_with_env`])
/// can fill the unset slots with flag > env > default precedence (#89). The repeatable
/// `--key-shared-group` is a plain `Vec` (CLI-only, no env mapping); the booleans are `true` only if
/// their bare flag appeared.
#[derive(Default)]
struct ServeFlags {
    addr: Option<String>,
    data_dir: Option<String>,
    max_connections: Option<usize>,
    checkpoint_interval: Option<u64>,
    max_deliver: Option<u32>,
    allow_unlimited_deliver: bool,
    backoff_ms: Option<Vec<u64>>,
    max_in_flight: Option<u32>,
    consumer_credit: Option<u32>,
    consumer_credit_bytes: Option<u64>,
    max_segment_bytes: Option<u64>,
    max_total_bytes: Option<u64>,
    max_retained_bytes: Option<u64>,
    max_age_ms: Option<u64>,
    max_messages: Option<u64>,
    max_groups: Option<usize>,
    group_idle_evict_ms: Option<u64>,
    disk_full_policy: Option<String>,
    visibility_ms: Option<u64>,
    enable_admin: bool,
    health_addr: Option<String>,
    key_shared_groups: Vec<String>,
}

/// Collects the `serve` arg list into [`ServeFlags`], each knob `Some` only if its flag appeared.
/// The env/default resolution is a separate pass so the precedence (flag > env > default) lives in
/// one place and the parse error for a bad FLAG value still names the flag (#89).
// One flat arm per `serve` flag: a single linear concern (the arg loop) that reads better unbroken
// than split across helpers, so the line count is allowed past the default ceiling.
#[allow(clippy::too_many_lines)]
fn collect_serve_flags(args: &[String]) -> Result<ServeFlags, CliError> {
    let mut f = ServeFlags::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => f.addr = Some(take_value("--addr", args, &mut i)?),
            "--data-dir" => f.data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--max-connections" => {
                f.max_connections = Some(take_number("--max-connections", args, &mut i)?);
            }
            "--checkpoint-interval" => {
                f.checkpoint_interval = Some(take_number("--checkpoint-interval", args, &mut i)?);
            }
            "--max-deliver" => f.max_deliver = Some(take_number("--max-deliver", args, &mut i)?),
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins.
            "--allow-unlimited-deliver" => {
                f.allow_unlimited_deliver = true;
                i += 1;
            }
            "--backoff-ms" => {
                f.backoff_ms = Some(take_number_list("--backoff-ms", args, &mut i)?);
            }
            "--max-in-flight" => {
                f.max_in_flight = Some(take_number("--max-in-flight", args, &mut i)?);
            }
            "--consumer-credit" => {
                f.consumer_credit = Some(take_number("--consumer-credit", args, &mut i)?);
            }
            "--consumer-credit-bytes" => {
                f.consumer_credit_bytes =
                    Some(take_number("--consumer-credit-bytes", args, &mut i)?);
            }
            "--max-segment-bytes" => {
                f.max_segment_bytes = Some(take_number("--max-segment-bytes", args, &mut i)?);
            }
            "--max-total-bytes" => {
                f.max_total_bytes = Some(take_number("--max-total-bytes", args, &mut i)?);
            }
            "--max-retained-bytes" => {
                f.max_retained_bytes = Some(take_number("--max-retained-bytes", args, &mut i)?);
            }
            "--max-age-ms" => f.max_age_ms = Some(take_number("--max-age-ms", args, &mut i)?),
            "--max-messages" => {
                f.max_messages = Some(take_number("--max-messages", args, &mut i)?);
            }
            "--max-groups" => f.max_groups = Some(take_number("--max-groups", args, &mut i)?),
            "--group-idle-evict-ms" => {
                f.group_idle_evict_ms = Some(take_number("--group-idle-evict-ms", args, &mut i)?);
            }
            "--disk-full-policy" => {
                f.disk_full_policy = Some(take_value("--disk-full-policy", args, &mut i)?);
            }
            "--key-shared-group" => {
                f.key_shared_groups
                    .push(take_value("--key-shared-group", args, &mut i)?);
            }
            "--visibility-timeout-ms" => {
                f.visibility_ms = Some(take_number("--visibility-timeout-ms", args, &mut i)?);
            }
            "--health-addr" => f.health_addr = Some(take_value("--health-addr", args, &mut i)?),
            // A bare boolean flag (no value): advance ONE token, not two, or the loop spins.
            "--enable-admin" => {
                f.enable_admin = true;
                i += 1;
            }
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
    Ok(f)
}

/// Parses the `serve` flag list with NO env layer, resolving every unset knob to its compiled
/// default. The convenience entry for unit tests that assert flag parsing and defaults; production
/// goes through [`parse_serve_flags_with_env`] with the real process environment (#89).
#[cfg(test)]
fn parse_serve_flags(args: &[String]) -> Result<ParsedServe, CliError> {
    parse_serve_flags_with_env(args, &|_| None)
}

/// Parses the `serve` flag list into a [`ParsedServe`], resolving each knob with the flag > env >
/// default precedence (#89): an explicit CLI flag wins, else the `IRONBUS_<flag>` env var read
/// through the injected `env` seam, else the compiled default. A non-numeric env value is a usage
/// error naming the env var, exactly like a bad flag. Split into a flag-collection pass
/// ([`collect_serve_flags`]) and this resolution pass so the precedence lives in one place.
// One `resolve_*` call per knob: a single linear concern (resolve every flag against env/default)
// that reads better as one flat block than split across helpers, so the line count is allowed past
// the default ceiling, like `collect_serve_flags`.
#[allow(clippy::too_many_lines)]
fn parse_serve_flags_with_env(args: &[String], env: &EnvFn<'_>) -> Result<ParsedServe, CliError> {
    let f = collect_serve_flags(args)?;
    // The disk-full policy is an enum string, so it resolves like a string but is then parsed: name
    // the source (the flag if it was explicit, else the env var) in a bad-value error so the
    // operator knows where it came from.
    let policy_from_flag = f.disk_full_policy.is_some();
    let disk_full_policy_arg = resolve_string(
        "--disk-full-policy",
        f.disk_full_policy,
        env,
        DEFAULT_DISK_FULL_POLICY,
    );
    let disk_full_policy = DiskFullPolicyArg::parse(&disk_full_policy_arg).ok_or_else(|| {
        let source = if policy_from_flag {
            "--disk-full-policy".to_string()
        } else {
            env_var_name("--disk-full-policy")
        };
        CliError::Usage(format!(
            "`{source}` must be `drop-new` or `drop-oldest`, got `{disk_full_policy_arg}`"
        ))
    })?;
    Ok(ParsedServe {
        addr: resolve_string("--addr", f.addr, env, DEFAULT_ADDR),
        data_dir: resolve_opt_string("--data-dir", f.data_dir, env),
        config: ServeConfig {
            max_connections: resolve_number(
                "--max-connections",
                f.max_connections,
                env,
                DEFAULT_MAX_CONNECTIONS,
            )?,
            checkpoint_interval: resolve_number(
                "--checkpoint-interval",
                f.checkpoint_interval,
                env,
                DEFAULT_CHECKPOINT_INTERVAL,
            )?,
            max_deliver: resolve_number("--max-deliver", f.max_deliver, env, DEFAULT_MAX_DELIVER)?,
            allow_unlimited_deliver: resolve_bool(
                "--allow-unlimited-deliver",
                f.allow_unlimited_deliver,
                env,
            )?,
            backoff_ms: resolve_number_list("--backoff-ms", f.backoff_ms, env)?,
            max_in_flight: resolve_number(
                "--max-in-flight",
                f.max_in_flight,
                env,
                DEFAULT_MAX_IN_FLIGHT,
            )?,
            consumer_credit: resolve_number(
                "--consumer-credit",
                f.consumer_credit,
                env,
                DEFAULT_CONSUMER_CREDIT,
            )?,
            consumer_credit_bytes: resolve_number(
                "--consumer-credit-bytes",
                f.consumer_credit_bytes,
                env,
                DEFAULT_CONSUMER_CREDIT_BYTES,
            )?,
            max_segment_bytes: resolve_number(
                "--max-segment-bytes",
                f.max_segment_bytes,
                env,
                DEFAULT_MAX_SEGMENT_BYTES,
            )?,
            max_total_bytes: resolve_number(
                "--max-total-bytes",
                f.max_total_bytes,
                env,
                DEFAULT_MAX_TOTAL_BYTES,
            )?,
            max_retained_bytes: resolve_number(
                "--max-retained-bytes",
                f.max_retained_bytes,
                env,
                DEFAULT_MAX_RETAINED_BYTES,
            )?,
            max_age_ms: resolve_number("--max-age-ms", f.max_age_ms, env, DEFAULT_MAX_AGE_MS)?,
            max_messages: resolve_number(
                "--max-messages",
                f.max_messages,
                env,
                DEFAULT_MAX_MESSAGES,
            )?,
            max_groups: resolve_number("--max-groups", f.max_groups, env, DEFAULT_MAX_GROUPS)?,
            group_idle_evict_ms: resolve_number(
                "--group-idle-evict-ms",
                f.group_idle_evict_ms,
                env,
                DEFAULT_GROUP_IDLE_EVICT_MS,
            )?,
            disk_full_policy,
            visibility_ms: resolve_number(
                "--visibility-timeout-ms",
                f.visibility_ms,
                env,
                DEFAULT_VISIBILITY_MS,
            )?,
            enable_admin: resolve_bool("--enable-admin", f.enable_admin, env)?,
        },
        key_shared_groups: f.key_shared_groups,
        health_addr: resolve_opt_string("--health-addr", f.health_addr, env),
    })
}

/// Resolves the required `--data-dir`, validates the assembled config, and dispatches to the
/// platform `cmd_serve`. Split out of `run_serve` so the flag-parsing loop stays a single concern.
fn finish_serve(
    addr: &str,
    data_dir: Option<&str>,
    config: &ServeConfig,
    key_shared_groups: &[String],
    health_addr: Option<&str>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("serve requires `--data-dir <dir>`".to_string()))?;
    validate_serve_config(config)?;
    cmd_serve(
        addr,
        Path::new(data_dir),
        config,
        key_shared_groups,
        health_addr,
        out,
    )
}

/// Rejects an out-of-range `serve` tuning value with a usage error before the broker opens.
fn validate_serve_config(config: &ServeConfig) -> Result<(), CliError> {
    if config.max_connections == 0 {
        // A zero cap binds and looks healthy but refuses every connection: reject it.
        return Err(CliError::Usage(
            "`--max-connections` must be at least 1".to_string(),
        ));
    }
    if (config.max_deliver == 0 || config.max_deliver == u32::MAX)
        && !config.allow_unlimited_deliver
    {
        // Both 0 and u32::MAX mean unlimited delivery (the lease counter saturates at the max,
        // so a poison message loops forever). Unlimited is reachable but must be DELIBERATE: it is
        // allowed only behind `--allow-unlimited-deliver` (which also emits a startup WARN, see
        // `cmd_serve`), else it is a usage error before the broker opens (#63).
        return Err(CliError::Usage(
            "`--max-deliver` must be at least 1 and below 4294967295 (0 and that maximum both \
             mean unlimited delivery; pass `--allow-unlimited-deliver` to enable it deliberately)"
                .to_string(),
        ));
    }
    if config.max_in_flight == 0 {
        // A zero window delivers nothing; the engine rejects it, so catch it as a usage error.
        return Err(CliError::Usage(
            "`--max-in-flight` must be at least 1".to_string(),
        ));
    }
    if config.consumer_credit == 0 {
        // A zero per-consumer credit would deliver nothing to any connection (#65). The engine
        // floors it to 1, but reject it loudly here so a typo is caught before the broker opens
        // rather than silently behaving as a credit of 1.
        return Err(CliError::Usage(
            "`--consumer-credit` must be at least 1".to_string(),
        ));
    }
    if config.max_segment_bytes < MIN_MAX_SEGMENT_BYTES {
        return Err(CliError::Usage(format!(
            "`--max-segment-bytes` must be at least {MIN_MAX_SEGMENT_BYTES} (smaller caps make \
             segments proliferate one record at a time)"
        )));
    }
    if config.visibility_ms == 0 {
        // A zero visibility timeout makes every delivered message instantly redeliverable,
        // a hot redelivery loop; require a positive window.
        return Err(CliError::Usage(
            "`--visibility-timeout-ms` must be at least 1".to_string(),
        ));
    }
    Ok(())
}

/// The broker tuning knobs parsed from the `serve` flags.
// Not `Copy`: `backoff_ms` is a `Vec`. The config is moved (never re-used after the move) through
// `finish_serve`/`cmd_serve`, so `Clone` suffices. `Debug` lets a test assert on a `ParsedServe`.
#[derive(Clone, Debug)]
struct ServeConfig {
    max_connections: usize,
    checkpoint_interval: u64,
    max_deliver: u32,
    /// Allow `--max-deliver 0` (unlimited delivery, refs #63). A poison message under an unlimited
    /// cap redelivers forever, so it is opt-in: without this flag a zero (or `u32::MAX`) cap is a
    /// usage error; with it, the broker starts and emits a startup WARN.
    allow_unlimited_deliver: bool,
    /// The escalating per-attempt nack backoff schedule in MILLISECONDS (refs #63), indexed by
    /// delivery attempt and clamped to the last entry. Applied when a nack carries no explicit
    /// delay, so a flapping consumer backs off instead of hot-looping a retry. Empty means use the
    /// built-in [`DEFAULT_NACK_BACKOFF_NANOS`] schedule; a single `0` disables backoff (retry as
    /// soon as the visibility timeout allows).
    backoff_ms: Vec<u64>,
    max_in_flight: u32,
    /// Per-CONSUMER (per-connection) standing in-flight credit (#65): the most un-acked messages one
    /// connection may hold at once, the consumer-side half of credit-based flow control. The
    /// effective Flow bound is min(this, the per-group `max_in_flight` window). Default 64 (NOT
    /// 65535), floored to 1 by the engine.
    consumer_credit: u32,
    /// Per-CONSUMER (per-connection) standing in-flight BYTE budget (#275): the most un-acked
    /// payload bytes one connection may hold at once, the RAM-side companion to `consumer_credit`.
    /// The effective Flow bound is min(message credit, byte budget) with a hard floor of one message
    /// (a single over-budget message is still delivered so it never wedges the consumer). Default
    /// 8 MiB; `0` = unlimited (the byte budget is off, only the message credit binds).
    consumer_credit_bytes: u64,
    max_segment_bytes: u64,
    /// Hard durable-log total byte cap, the drop-new shed backstop (#10). `0` means unlimited
    /// (the cap is off), which is the default and preserves the spill-by-default behavior.
    max_total_bytes: u64,
    /// Consumer-safe size-retention bound (#13, #80): the broker reaps old fully-consumed sealed
    /// segments while the durable log is over this many RECORD bytes. `0` means unlimited
    /// (retention off), the default, so existing behavior is unchanged.
    max_retained_bytes: u64,
    /// Consumer-safe AGE-retention bound (#13, #80), in MILLISECONDS: the broker reaps an old
    /// fully-consumed sealed segment whose newest record is older than this. `0` = disabled, the
    /// default. Milliseconds (not a duration string) so the flag is a bare integer.
    max_age_ms: u64,
    /// Consumer-safe COUNT-retention bound (#13, #80): the broker reaps old fully-consumed sealed
    /// segments while the log's total record count is over this many messages. `0` = disabled,
    /// the default.
    max_messages: u64,
    /// The cap on the number of live work-groups, including the default (refs #240, #9, #10):
    /// bounds consumer-state memory once the wire can name groups, so an unauthenticated client
    /// cannot exhaust memory by naming endless groups. `0` = unlimited (the cap is off); the
    /// default is non-zero (1024). A new named group past the cap is rejected by the engine.
    max_groups: usize,
    /// The idle window after which an idle, fully-caught-up, lease-free NAMED work-group is evicted
    /// from memory (refs #277, #240), in MILLISECONDS: the lifecycle reclaim that complements the
    /// `max_groups` cap. `0` = DISABLED (never evict), the default; a non-zero value opts in. The
    /// durable per-group checkpoint is never deleted, so a re-subscribe resumes; only fully-caught-up
    /// groups are evicted, so a consumer's committed position is never lost.
    group_idle_evict_ms: u64,
    /// The disk-full overflow policy (#82): `DropNew` (the default) sheds an over-cap produce,
    /// `DropOldest` force-reaps the oldest sealed segment to make room then accepts it. Honored only
    /// when `max_total_bytes` is set; with no cap, no produce is ever over-cap.
    disk_full_policy: DiskFullPolicyArg,
    visibility_ms: u64,
    /// Enable the OPT-IN read-only `/admin` introspection endpoint on the health server (#99). OFF
    /// by default: only with `--enable-admin` (and only when `--health-addr` is set) does `/admin`
    /// serve a JSON operational snapshot; otherwise it is a 404 like any unknown path. It is
    /// READ-ONLY and UNAUTHENTICATED, sharing `/metrics`'s trust model (loopback or a trusted
    /// network, the #105/#107 threat model), so it must run only where `/metrics` is already
    /// trusted. It exposes no mutating action and no secret material.
    enable_admin: bool,
}

/// Maps a data-dir lifecycle/lock failure (#89) onto the frozen CLI exit-code scheme. A
/// non-directory path is an operator MISCONFIGURATION (usage, exit 1); an unwritable mount, a
/// lock-IO fault, and the "another broker already running" contention are RUNTIME faults that fail
/// the broker start (internal, exit 70). All carry the typed message naming the data dir.
#[cfg(unix)]
fn map_dir_error(e: &dirlock::DirError) -> CliError {
    match e {
        dirlock::DirError::NotADirectory(_) => CliError::Usage(e.to_string()),
        dirlock::DirError::NotWritable(..)
        | dirlock::DirError::AlreadyLocked(_)
        | dirlock::DirError::LockIo(..) => CliError::Internal(e.to_string()),
    }
}

#[cfg(unix)]
fn cmd_serve(
    addr: &str,
    data_dir: &Path,
    config: &ServeConfig,
    key_shared_groups: &[String],
    health_addr: Option<&str>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    // Data-dir lifecycle then the single-broker lock (#89), BEFORE the engine opens. `prepare`
    // creates the dir (0700) if absent, rejects a non-directory path, and proves it writable; the
    // lock makes a SECOND `serve` on the same data dir fail fast rather than corrupt the log with
    // concurrent writers. The `DirLock` is held in `_dir_lock` for the whole serve lifetime and is
    // released by the OS when it drops on return (and unconditionally on process exit).
    dirlock::prepare_data_dir(data_dir).map_err(|e| map_dir_error(&e))?;
    let _dir_lock = dirlock::DirLock::acquire(data_dir).map_err(|e| map_dir_error(&e))?;
    let shared = open_disk_engine(data_dir, config, key_shared_groups)?;
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
    if config.allow_unlimited_deliver && (config.max_deliver == 0 || config.max_deliver == u32::MAX)
    {
        // Unlimited delivery is opt-in but LOUD (#63): a single poison payload can redeliver
        // forever, so the operator who chose it sees it on every startup.
        writeln!(
            out,
            "WARN: --max-deliver is unlimited (--allow-unlimited-deliver): a poison message can \
             redeliver forever and is never dead-lettered"
        )?;
    }
    // The shared shutdown flag the serve loop polls. The wire serve uses a non-blocking accept that
    // re-checks this flag every ~50 ms (its ACCEPT_POLL), so flipping it breaks the accept loop
    // within a bounded time rather than only after the next connection. A SIGINT/SIGTERM/SIGHUP
    // handler flips it for a graceful stop (#195); the broker then stops accepting and, on exit
    // below, flushes every group's committed cursor so a restart does not redeliver acked messages.
    // Durability across an ABRUPT termination still holds (every ack is fsynced first); this handler
    // additionally makes a CLEAN operator stop non-redelivering by flushing the lagging cursor.
    let shutdown = Arc::new(AtomicBool::new(false));
    install_signal_handler(&shutdown)?;

    // The opt-in read-only `/admin` introspection endpoint (#99) needs the health server, which
    // only runs when `--health-addr` is set. A `--enable-admin` with no health address can never
    // take effect, so warn loudly rather than silently no-op.
    if config.enable_admin && health_addr.is_none() {
        writeln!(
            out,
            "WARN: --enable-admin has no effect without --health-addr (the /admin endpoint is \
             served by the health server)"
        )?;
    }
    // Optionally start the health endpoints on their own loopback HTTP port.
    let health_handle = if let Some(haddr) = health_addr {
        let health_listener = TcpListener::bind(haddr)
            .map_err(|e| CliError::Internal(format!("cannot bind health {haddr}: {e}")))?;
        let health_local = health_listener
            .local_addr()
            .map_err(|e| CliError::Internal(format!("cannot read health address: {e}")))?;
        // The admin route is only advertised when opted in, so the default startup line is
        // unchanged for an operator who has not enabled it.
        if config.enable_admin {
            writeln!(
                out,
                "ironbus health endpoints on {health_local} (/healthz, /readyz, /metrics, \
                 /admin [read-only, unauthenticated])"
            )?;
        } else {
            writeln!(
                out,
                "ironbus health endpoints on {health_local} (/healthz, /readyz, /metrics)"
            )?;
        }
        let engine = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        let admin_enabled = config.enable_admin;
        Some(std::thread::spawn(move || {
            let _ = serve_health(&health_listener, &engine, &shutdown, admin_enabled);
        }))
    } else {
        None
    };

    let result = serve(&listener, &shared, &shutdown, config.max_connections)
        .map_err(|e| CliError::Internal(format!("serve loop failed: {e}")));
    // The wire serve returns only when shutdown is set (a signal, or a fatal listener error that
    // ends the loop), so flip it for the health thread too.
    shutdown.store(true, Ordering::Release);
    if let Some(h) = health_handle {
        let _ = h.join();
    }
    result?;
    // Graceful-shutdown cursor flush (#195): the serve loop has stopped accepting and every
    // connection handler has been signalled to wind down. Force a final checkpoint of EVERY live
    // work-group's committed cursor so a restart after this clean stop resumes past the acked
    // messages rather than redelivering up to `--checkpoint-interval` of them. A long-lived
    // consumer still connected at the signal does not get to run its own close-path flush (its
    // handler thread is detached, not joined), so this server-side flush is what makes the clean
    // stop non-redelivering. It runs on a normal serve exit only; a serve error returned above.
    {
        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .checkpoint_all_groups()
            .map_err(|e| CliError::Internal(format!("flushing cursors on shutdown: {e}")))?;
    }
    Ok(())
}

/// Installs the process-wide signal handler that flips `shutdown` on SIGINT, SIGTERM, or SIGHUP, so
/// `serve` performs a graceful stop (#195): the serve loop's next poll observes the flag, stops
/// accepting, and the broker flushes its cursors before exiting 0. The `ironbus` binary runs exactly
/// one subcommand per process, so this is installed at most once per process. `try_set_handler` (not
/// `set_handler`) is used so the install is fallible-not-panicking: a `MultipleHandlers` error (a
/// handler already present, which the single-subcommand binary never produces but a future caller
/// might) is surfaced as an internal error rather than a panic, keeping the no-panic library bar.
/// `ctrlc` catches SIGINT; its `termination` feature (enabled in `Cargo.toml`) adds SIGTERM and
/// SIGHUP, so the one handler covers all three signals an operator stop might deliver.
#[cfg(unix)]
fn install_signal_handler(shutdown: &Arc<AtomicBool>) -> Result<(), CliError> {
    let flag = Arc::clone(shutdown);
    ctrlc::try_set_handler(move || {
        // Async-signal context: a single atomic store, nothing else. The serve loop polls this flag
        // on its next accept cycle and unwinds the accept-stop, cursor-flush, exit-0 path itself.
        flag.store(true, Ordering::Release);
    })
    .map_err(|e| CliError::Internal(format!("cannot install the shutdown signal handler: {e}")))
}

#[cfg(not(unix))]
fn cmd_serve(
    addr: &str,
    data_dir: &Path,
    config: &ServeConfig,
    key_shared_groups: &[String],
    health_addr: Option<&str>,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (
        addr,
        data_dir,
        config.max_connections,
        config.checkpoint_interval,
        config.max_deliver,
        config.allow_unlimited_deliver,
        &config.backoff_ms,
        config.max_in_flight,
        config.consumer_credit,
        config.consumer_credit_bytes,
        config.max_segment_bytes,
        config.max_total_bytes,
        config.max_retained_bytes,
        config.max_age_ms,
        config.max_messages,
        config.max_groups,
        config.group_idle_evict_ms,
        config.enable_admin,
        config.disk_full_policy,
        config.visibility_ms,
        key_shared_groups,
        health_addr,
        out,
    );
    Err(CliError::Internal(
        "ironbus serve requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// Opens (creating the directory if absent) the on-disk broker engine rooted at `data_dir`.
/// `key_shared_groups` (#64) are declared server-side: each is put into `key_shared` ordering when
/// a consumer first subscribes; an empty slice leaves every group plain competing (the default).
#[cfg(unix)]
fn open_disk_engine(
    data_dir: &Path,
    config: &ServeConfig,
    key_shared_groups: &[String],
) -> Result<SharedEngine<StdFs, SystemClock>, CliError> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| CliError::Internal(format!("cannot create {}: {e}", data_dir.display())))?;
    let fs = StdFs::new(data_dir.to_path_buf());
    // An explicit --backoff-ms wins; an empty schedule (the flag was not passed) uses the built-in
    // default. Each stage is milliseconds on the wire, nanoseconds in the engine; saturate rather
    // than overflow on an absurd value.
    let backoff_nanos: Vec<u64> = if config.backoff_ms.is_empty() {
        DEFAULT_NACK_BACKOFF_NANOS.to_vec()
    } else {
        config
            .backoff_ms
            .iter()
            .map(|ms| ms.saturating_mul(1_000_000))
            .collect()
    };
    let delivery = DeliveryConfig::new(
        config.max_deliver,
        config.allow_unlimited_deliver,
        backoff_nanos,
    )
    .map_err(|e| CliError::Internal(format!("delivery config: {e:?}")))?;
    let visibility_ms = config.visibility_ms;
    let engine = Engine::open(
        fs,
        SystemClock::new(),
        EngineConfig {
            // Both caps are honored: `new` validates and sets the segment cap, the builder
            // layers on the durable-log total byte cap (the drop-new shed; `0` = unlimited).
            log: LogConfig::new(config.max_segment_bytes)
                .map_err(|e| CliError::Internal(format!("log config: {e}")))?
                .with_max_total_bytes(config.max_total_bytes),
            lease: LeaseConfig::from_millis(visibility_ms, visibility_ms.max(DEFAULT_HARD_CAP_MS)),
            delivery,
            max_in_flight: config.max_in_flight,
            // The per-CONSUMER (per-connection) standing in-flight credit (#65): the most un-acked
            // messages one connection may hold, the consumer-side half of credit-based flow control.
            // The effective Flow bound is min(this, the per-group max_in_flight window). Floored to
            // 1 by the engine. Default 64 (NOT 65535), memory-justified by Little's Law (#19).
            consumer_credit: config.consumer_credit,
            // The per-CONSUMER (per-connection) in-flight BYTE budget (#275): the RAM-side companion
            // to the message-count credit. The effective Flow bound is min(message credit, byte
            // budget) with a hard floor of one message. Default 8 MiB; `0` = unlimited (off).
            consumer_credit_bytes: config.consumer_credit_bytes,
            checkpoint_interval: config.checkpoint_interval,
            // Consumer-safe retention (#13, #80), each `0` = disabled (off), the default. Size in
            // record bytes, age in milliseconds (against the engine clock), count in messages; the
            // bounds compose, so a segment is reaped if ANY enabled bound trips.
            max_retained_bytes: config.max_retained_bytes,
            max_age_ms: config.max_age_ms,
            max_messages: config.max_messages,
            // The work-group cap (refs #240, #9, #10): bounds consumer-state memory once the wire
            // can name groups. `0` = unlimited (off); the default is non-zero (1024). A new named
            // group past the cap is rejected by the engine before it allocates.
            max_groups: config.max_groups,
            // Idle named-group eviction (refs #277, #240): the lifecycle reclaim that completes the
            // #240 cap. `0` = disabled (off, the default), a non-zero value is the idle window in ms
            // after which a fully-caught-up, lease-free named group is reclaimed. Never deletes a
            // durable checkpoint, so a re-subscribe resumes; only caught-up groups are evicted, so a
            // consumer's committed position is never lost.
            group_idle_evict_ms: config.group_idle_evict_ms,
            // The disk-full overflow policy (#82): drop-new (default) sheds, drop-oldest force-reaps
            // the oldest sealed segment then accepts. Honored only when `max_total_bytes` is set.
            disk_full_policy: match config.disk_full_policy {
                DiskFullPolicyArg::DropNew => DiskFullPolicy::DropNew,
                DiskFullPolicyArg::DropOldest => DiskFullPolicy::DropOldest,
            },
        },
    )
    .map_err(|e| CliError::Internal(format!("opening broker at {}: {e}", data_dir.display())))?;
    let mut engine = engine;
    // Declare the key_shared groups (#64) server-side: a configured group enters key_shared mode
    // when a consumer first subscribes. An empty slice is a no-op, so every group stays competing.
    engine.set_configured_key_shared_groups(key_shared_groups.iter().cloned());
    Ok(Arc::new(Mutex::new(engine)))
}

/// The default number of records `peek` shows when `--limit` is not given.
const DEFAULT_PEEK_LIMIT: u64 = 10;

/// Parses and runs `peek`: show a bounded window of durable records from a data directory, with
/// no server running.
///
/// # Errors
/// Returns a [`CliError`] for a usage problem, a missing directory (not found), a corrupt
/// segment chain (corrupt), or an IO failure (internal).
fn run_peek(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut from_offset: u64 = 0;
    let mut limit: u64 = DEFAULT_PEEK_LIMIT;
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--from-offset" | "--offset" => {
                let raw = take_value("--from-offset", args, &mut i)?;
                from_offset = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--from-offset` needs a number, got `{raw}`"))
                })?;
            }
            "--limit" => {
                let raw = take_value("--limit", args, &mut i)?;
                limit = raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--limit` needs a number, got `{raw}`"))
                })?;
            }
            "--json" => {
                json = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for peek")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "peek takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("peek requires `--data-dir <dir>`".to_string()))?;
    cmd_inspect(Path::new(&data_dir), from_offset, Some(limit), json, out)
}

/// Parses and runs `dump`: stream every durable record from a data directory, one per line
/// (NDJSON with `--json`), with no server running, honoring `--limit`.
///
/// # Errors
/// As [`run_peek`].
fn run_dump(args: &[String], out: &mut impl Write) -> Result<(), CliError> {
    let mut data_dir: Option<String> = None;
    let mut limit: Option<u64> = None;
    let mut json = false;
    let mut dlq = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => data_dir = Some(take_value("--data-dir", args, &mut i)?),
            "--limit" => {
                let raw = take_value("--limit", args, &mut i)?;
                limit = Some(raw.parse::<u64>().map_err(|_| {
                    CliError::Usage(format!("`--limit` needs a number, got `{raw}`"))
                })?);
            }
            "--json" => {
                json = true;
                i += 1;
            }
            "--dlq" => {
                dlq = true;
                i += 1;
            }
            flag if flag.starts_with("--") => {
                return Err(CliError::Usage(format!("unknown flag `{flag}` for dump")));
            }
            other => {
                return Err(CliError::Usage(format!(
                    "dump takes no positional arguments, got `{other}`"
                )));
            }
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| CliError::Usage("dump requires `--data-dir <dir>`".to_string()))?;
    if dlq {
        return cmd_inspect_dlq(Path::new(&data_dir), limit, json, out);
    }
    cmd_inspect(Path::new(&data_dir), 0, limit, json, out)
}

/// Decodes a data directory offline and writes its durable records (from `from_offset`, at most
/// `limit` of them) to `out`, then a final note for any torn or corrupt tail recovery would
/// skip, so the holes are shown, not hidden. Shared by `peek` (a bounded window) and `dump`
/// (the whole log). Memory is bounded to one segment at a time; a per-record streaming reader
/// for a multi-GB segment within a fixed RAM ceiling is tracked in #92.
#[cfg(unix)]
fn cmd_inspect(
    data_dir: &Path,
    from_offset: u64,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let reader = OfflineReader::open(StdFs::new(data_dir.to_path_buf()))
        .map_err(|e| map_offline_err(data_dir, &e))?;
    let mut shown: u64 = 0;
    'segments: for &id in reader.segment_ids() {
        if limit.is_some_and(|max| shown >= max) {
            break;
        }
        let records = reader
            .read_segment(id)
            .map_err(|e| map_offline_err(data_dir, &e))?;
        for record in &records {
            if record.offset.get() < from_offset {
                continue;
            }
            if limit.is_some_and(|max| shown >= max) {
                break 'segments;
            }
            write_record(record, json, out)?;
            shown += 1;
        }
    }
    write_loss(reader.loss_report(), json, out)?;
    Ok(())
}

/// Writes one record as a human line or a single NDJSON object. `crc` is always `ok` because
/// the offline reader only yields records that passed their CRC; `codec` is always `none`
/// until on-disk compression (#12) lands.
#[cfg(unix)]
fn write_record(record: &OwnedRecord, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    if json {
        writeln!(
            out,
            "{{\"offset\":{},\"ts_ms\":{},\"bytes\":{},\"key_bytes\":{},\"crc\":\"ok\",\"codec\":\"none\"}}",
            record.offset.get(),
            record.timestamp_ms,
            record.payload.len(),
            record.key.len(),
        )?;
    } else {
        writeln!(
            out,
            "offset={} ts_ms={} bytes={} key_bytes={} crc=ok codec=none",
            record.offset.get(),
            record.timestamp_ms,
            record.payload.len(),
            record.key.len(),
        )?;
    }
    Ok(())
}

/// Writes a final summary of any torn or corrupt tail the durable prefix dropped (marking the
/// holes, not hiding them). Nothing is written for a clean directory, so a clean `dump --json`
/// stays pure record NDJSON.
#[cfg(unix)]
fn write_loss(report: &LossReport, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    if report.is_empty() {
        return Ok(());
    }
    if json {
        write!(
            out,
            "{{\"loss\":{{\"bytes\":{},\"events\":[",
            report.total_bytes_skipped()
        )?;
        for (n, e) in report.events.iter().enumerate() {
            if n > 0 {
                write!(out, ",")?;
            }
            write!(
                out,
                "{{\"segment\":{},\"start\":{},\"end\":{},\"reason\":\"{}\"}}",
                e.segment_id,
                e.byte_offset_start,
                e.byte_offset_end,
                e.reason_code.metric_label(),
            )?;
        }
        writeln!(out, "]}}}}")?;
    } else {
        writeln!(
            out,
            "note: {} byte(s) past the durable head are torn or corrupt and were not shown ({} event(s))",
            report.total_bytes_skipped(),
            report.events.len(),
        )?;
        for e in &report.events {
            writeln!(
                out,
                "  segment {} bytes [{}, {}) reason={}",
                e.segment_id,
                e.byte_offset_start,
                e.byte_offset_end,
                e.reason_code.metric_label(),
            )?;
        }
    }
    Ok(())
}

/// Decodes a stopped broker's DURABLE DEAD-LETTER SINK (the `dlq/` subdirectory) offline and writes
/// its dead-letter records (at most `limit` of them) to `out`, READ-ONLY, never mutating the
/// directory (#63). Each line shows the DLQ position, the source offset, the original timestamp, the
/// group, the attempt, and the key/payload lengths. An ABSENT or empty DLQ shows nothing (a clean,
/// never-poisoned broker), which is not an error. Reuses the same offline reader as `dump`, so the
/// frozen offline exit codes apply (a missing DATA directory is still not-found).
#[cfg(unix)]
fn cmd_inspect_dlq(
    data_dir: &Path,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    // A missing DATA directory is not-found (exit 2), matching plain `dump`; an absent `dlq/`
    // subdirectory inside an existing data directory is simply an empty DLQ (shown as nothing).
    if !data_dir.is_dir() {
        return Err(CliError::NotFound(format!(
            "no data directory at {}",
            data_dir.display()
        )));
    }
    let entries = read_dlq_entries(&StdFs::new(data_dir.to_path_buf()))
        .map_err(|e| map_offline_err(data_dir, &e))?;
    // `--limit` caps how many records are shown; `usize::MAX` (no limit) shows them all.
    let cap = limit.map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    for entry in entries.iter().take(cap) {
        write_dlq_entry(entry, json, out)?;
    }
    Ok(())
}

/// Writes one DLQ entry as a human line or a single NDJSON object. Like `write_record`, this
/// reports only sizes (not the raw key/payload bytes), so a binary payload never corrupts the
/// terminal or the NDJSON stream.
#[cfg(unix)]
fn write_dlq_entry(entry: &DlqEntry, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    if json {
        writeln!(
            out,
            "{{\"dlq_offset\":{},\"source_offset\":{},\"group\":\"{}\",\"attempt\":{},\"ts_ms\":{},\"bytes\":{},\"key_bytes\":{}}}",
            entry.dlq_offset.get(),
            entry.source_offset,
            escape_json(&entry.group),
            entry.attempt,
            entry.timestamp_ms,
            entry.payload.len(),
            entry.key.len(),
        )?;
    } else {
        writeln!(
            out,
            "dlq_offset={} source_offset={} group={:?} attempt={} ts_ms={} bytes={} key_bytes={}",
            entry.dlq_offset.get(),
            entry.source_offset,
            entry.group,
            entry.attempt,
            entry.timestamp_ms,
            entry.payload.len(),
            entry.key.len(),
        )?;
    }
    Ok(())
}

/// Escapes a string for embedding in a JSON string literal (backslash, double-quote, and the
/// control characters the format requires). Group names are graphic ASCII today, but the escape is
/// unconditional so a future relaxation cannot produce invalid NDJSON.
#[cfg(unix)]
fn escape_json(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // A writeln/write into a String never fails, so the result is discarded.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Maps an offline-reader storage error to the frozen offline exit-code scheme: a missing data
/// directory is not-found (2), a broken segment chain or an undecodable header is corruption
/// (4), and anything else is an internal failure (70).
#[cfg(unix)]
fn map_offline_err(data_dir: &Path, e: &StorageError) -> CliError {
    let at = data_dir.display();
    match e {
        StorageError::Io(io) if io.kind() == io::ErrorKind::NotFound => {
            CliError::NotFound(format!("no data directory at {at}"))
        }
        StorageError::Io(io) => CliError::Internal(format!("reading {at}: {io}")),
        StorageError::Record(_)
        | StorageError::Segment(_)
        | StorageError::FooterSegmentMismatch { .. }
        | StorageError::UnsealedPredecessor { .. }
        | StorageError::SegmentIdMismatch { .. }
        | StorageError::SegmentChainBroken { .. } => {
            CliError::Corrupt(format!("corrupt data directory at {at}: {e}"))
        }
        other => CliError::Internal(format!("reading {at}: {other}")),
    }
}

/// `peek` / `dump` require Unix in v1 (the on-disk storage uses positioned IO the Windows path
/// does not yet implement), matching `serve`.
#[cfg(not(unix))]
fn cmd_inspect(
    data_dir: &Path,
    from_offset: u64,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, from_offset, limit, json, out);
    Err(CliError::Internal(
        "ironbus peek/dump require a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

/// `dump --dlq` requires Unix in v1 for the same reason as `dump` (the on-disk storage uses
/// positioned IO the Windows path does not yet implement).
#[cfg(not(unix))]
fn cmd_inspect_dlq(
    data_dir: &Path,
    limit: Option<u64>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let _ = (data_dir, limit, json, out);
    Err(CliError::Internal(
        "ironbus dump --dlq requires a Unix host in v1: on-disk storage is Unix-only".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironbus_core::delivery::DeliveryConfig;
    use ironbus_core::lease::LeaseConfig;
    #[cfg(unix)]
    use ironbus_core::types::RecordFlags;
    use ironbus_server::engine::{DiskFullPolicy, Engine, EngineConfig};
    use ironbus_server::server::{serve, SharedEngine};
    use ironbus_storage::fs::InMemoryFs;
    #[cfg(unix)]
    use ironbus_storage::log::Append;
    use ironbus_storage::log::LogConfig;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// A [`ServeConfig`] for a disk-engine test: the given in-flight window and checkpoint
    /// interval, every other knob the production default (retention and the total cap both off).
    #[cfg(unix)]
    fn test_serve_config(max_in_flight: u32, checkpoint_interval: u64) -> ServeConfig {
        ServeConfig {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            checkpoint_interval,
            max_deliver: DEFAULT_MAX_DELIVER,
            allow_unlimited_deliver: false,
            backoff_ms: Vec::new(),
            max_in_flight,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_age_ms: DEFAULT_MAX_AGE_MS,
            max_messages: DEFAULT_MAX_MESSAGES,
            max_groups: DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            disk_full_policy: DiskFullPolicyArg::DropNew,
            visibility_ms: DEFAULT_VISIBILITY_MS,
            enable_admin: false,
        }
    }

    /// Builds a real on-disk data directory with `n` durable records via the engine, for
    /// the offline `peek` / `dump` verbs to read back.
    #[cfg(unix)]
    fn make_data_dir(tag: &str, n: usize) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ironbus-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let shared = open_disk_engine(&dir, &test_serve_config(64, 1), &[]).unwrap();
        {
            let mut g = shared.lock().unwrap();
            for i in 0..n {
                let payload = format!("msg-{i}");
                g.produce(&Append {
                    timestamp_ms: 100 + u64::try_from(i).unwrap(),
                    flags: RecordFlags::EMPTY,
                    key: b"k",
                    headers: b"",
                    payload: payload.as_bytes(),
                })
                .unwrap();
            }
        }
        drop(shared);
        dir
    }

    #[cfg(unix)]
    #[test]
    fn peek_shows_a_window_of_records() {
        let dir = make_data_dir("peek", 5);
        let mut buf = Vec::new();
        run_peek(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--limit".to_string(),
                "3".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "--limit honored: {text}");
        assert!(lines[0].contains("offset=0"), "{text}");
        assert!(lines[2].contains("offset=2"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn peek_honors_from_offset() {
        let dir = make_data_dir("peekoff", 5);
        let mut buf = Vec::new();
        run_peek(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--from-offset".to_string(),
                "3".to_string(),
                "--limit".to_string(),
                "10".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "offsets 3 and 4 only: {text}");
        assert!(lines[0].contains("offset=3"), "{text}");
        assert!(lines[1].contains("offset=4"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn dump_streams_all_records_as_ndjson() {
        let dir = make_data_dir("dump", 4);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--json".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "one NDJSON line per record: {text}");
        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.starts_with('{') && line.ends_with('}'),
                "ndjson: {line}"
            );
            assert!(line.contains(&format!("\"offset\":{i}")), "{line}");
            assert!(line.contains("\"crc\":\"ok\""), "{line}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn dump_marks_a_torn_tail_rather_than_hiding_it() {
        let dir = make_data_dir("torn", 4);
        // Tear three bytes off the active segment so its last record no longer parses.
        let seg = dir.join("seg-0000000000000000.log");
        let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
        let len = f.metadata().unwrap().len();
        f.set_len(len - 3).unwrap();
        f.sync_all().unwrap();
        let mut buf = Vec::new();
        run_dump(
            &["--data-dir".to_string(), dir.display().to_string()],
            &mut buf,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let text = String::from_utf8(buf).unwrap();
        assert!(
            text.contains("offset=2"),
            "the durable prefix is shown: {text}"
        );
        assert!(
            !text.contains("offset=3"),
            "the torn record is not shown: {text}"
        );
        assert!(
            text.contains("note:") && text.contains("torn"),
            "the hole is marked, not hidden: {text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_data_dir_is_not_found() {
        let dir =
            std::env::temp_dir().join(format!("ironbus-cli-absent-{}-xyz", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut buf = Vec::new();
        let e = run_peek(
            &["--data-dir".to_string(), dir.display().to_string()],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_NOT_FOUND, "{e}");
    }

    #[test]
    fn peek_requires_a_data_dir() {
        let mut buf = Vec::new();
        let e = run_peek(&[], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
    }

    #[test]
    fn dump_requires_a_data_dir() {
        let mut buf = Vec::new();
        let e = run_dump(&[], &mut buf).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
    }

    /// Builds a real on-disk data directory that has dead-lettered exactly one poison message into
    /// its durable DLQ sink, by driving an engine over a manual clock so a redelivery expires
    /// deterministically. Returns the data directory path.
    #[cfg(unix)]
    fn make_dlq_data_dir(tag: &str) -> std::path::PathBuf {
        use ironbus_core::clock::ManualClock;
        let dir = std::env::temp_dir().join(format!("ironbus-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(ManualClock::new());
        let mut e = Engine::open(
            StdFs::new(dir.clone()),
            Arc::clone(&clock),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig {
                    visibility_nanos: 30,
                    hard_cap_nanos: 100,
                },
                delivery: DeliveryConfig::new(1, false, Vec::new()).unwrap(), // max_deliver = 1
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        e.produce(&Append {
            timestamp_ms: 777,
            flags: RecordFlags::EMPTY,
            key: b"kk",
            headers: b"",
            payload: b"poison-payload",
        })
        .unwrap();
        let _ = e.poll_now().unwrap(); // delivery 1
        clock.advance_monotonic_nanos(40);
        match e.poll_now().unwrap() {
            ironbus_server::engine::Poll::Parked { .. } => {}
            other => panic!("expected the poison to be parked, got {other:?}"),
        }
        drop(e);
        dir
    }

    #[cfg(unix)]
    #[test]
    fn dump_dlq_shows_the_dead_letter_records_read_only() {
        let dir = make_dlq_data_dir("dumpdlq");
        // Snapshot the directory tree before the read, to prove the inspector never mutates it.
        let before = dir_snapshot(&dir);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one dead-letter record: {text}");
        assert!(lines[0].contains("source_offset=0"), "{text}");
        assert!(lines[0].contains("attempt=2"), "{text}");
        assert!(lines[0].contains("ts_ms=777"), "{text}");
        assert!(lines[0].contains("bytes=14"), "the payload length: {text}");
        assert!(lines[0].contains("key_bytes=2"), "{text}");

        // The --json form is one NDJSON object with the same fields.
        let mut jbuf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
                "--json".to_string(),
            ],
            &mut jbuf,
        )
        .unwrap();
        let jtext = String::from_utf8(jbuf).unwrap();
        assert!(jtext.contains("\"source_offset\":0"), "{jtext}");
        assert!(jtext.contains("\"attempt\":2"), "{jtext}");
        assert!(jtext.contains("\"ts_ms\":777"), "{jtext}");

        // Read-only: the directory tree is byte-for-byte unchanged after both reads.
        let after = dir_snapshot(&dir);
        assert_eq!(
            before, after,
            "dump --dlq must not mutate the data directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dump_dlq_on_a_never_poisoned_dir_shows_nothing_and_does_not_create_the_subdir() {
        let dir = make_data_dir("dumpdlqempty", 3);
        let mut buf = Vec::new();
        run_dump(
            &[
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--dlq".to_string(),
            ],
            &mut buf,
        )
        .unwrap();
        assert!(buf.is_empty(), "an empty DLQ shows nothing");
        // The read-only inspector must not have created the dlq/ subdirectory.
        assert!(
            !dir.join("dlq").exists(),
            "dump --dlq must not create the dlq/ subdirectory on a poison-free directory"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn dump_dlq_on_a_missing_dir_is_not_found() {
        let missing =
            std::env::temp_dir().join(format!("ironbus-cli-nodir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing);
        let mut buf = Vec::new();
        let e = run_dump(
            &[
                "--data-dir".to_string(),
                missing.display().to_string(),
                "--dlq".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_NOT_FOUND);
    }

    /// A sorted snapshot of `(relative path, bytes)` for every regular file under `dir`, used to
    /// prove a read-only inspector never mutates the directory.
    #[cfg(unix)]
    fn dir_snapshot(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<(std::path::PathBuf, Vec<u8>)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if entry.file_type().unwrap().is_dir() {
                    walk(base, &path, out);
                } else {
                    let rel = path.strip_prefix(base).unwrap().to_path_buf();
                    out.push((rel, std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(dir, dir, &mut out);
        out.sort();
        out
    }

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
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
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
        cmd_sub(&a, "", 10, Disposition::Ack, &mut consumed).unwrap();
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
        cmd_sub(&a, "", 10, Disposition::Peek, &mut again).unwrap();
        assert_eq!(String::from_utf8(again).unwrap(), "fetched 0 message(s)\n");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn sub_with_a_group_fetches_from_that_group() {
        let (addr, shutdown, handle) = start_inmem_server();
        let a = addr.to_string();
        let mut published = Vec::new();
        cmd_pub(&a, b"", b"grouped", &mut published).unwrap();
        // A named group fetches and acks the message.
        let mut consumed = Vec::new();
        cmd_sub(&a, "team-a", 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("payload=grouped"), "group fetch: {text}");
        assert!(text.contains("ack committed"), "{text}");
        // A different group has an independent cursor, so it still sees the message.
        let mut other = Vec::new();
        cmd_sub(&a, "team-b", 10, Disposition::Peek, &mut other).unwrap();
        assert!(
            String::from_utf8(other)
                .unwrap()
                .contains("payload=grouped"),
            "a second group independently sees the message"
        );
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn sub_on_an_empty_queue_reports_zero() {
        let (addr, shutdown, handle) = start_inmem_server();
        let mut buf = Vec::new();
        cmd_sub(&addr.to_string(), "", 5, Disposition::Ack, &mut buf).unwrap();
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
    fn serve_rejects_a_non_numeric_max_deliver() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-deliver".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-deliver"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_max_deliver() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-md0-never-created".to_string(),
                "--max-deliver".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least 1"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_an_unlimited_max_deliver() {
        // u32::MAX is also "unlimited" (the lease counter saturates), so it is a usage error,
        // not an internal error, just like 0.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mdmax-never-created".to_string(),
                "--max-deliver".to_string(),
                u32::MAX.to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("unlimited"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    // A platform-independent baseline `ServeConfig` for the validation-level tests (the engine and
    // socket are never opened, so it needs no Unix gate). Defaults mirror the production defaults.
    fn validation_config() -> ServeConfig {
        ServeConfig {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            max_deliver: DEFAULT_MAX_DELIVER,
            allow_unlimited_deliver: false,
            backoff_ms: Vec::new(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            consumer_credit: DEFAULT_CONSUMER_CREDIT,
            consumer_credit_bytes: DEFAULT_CONSUMER_CREDIT_BYTES,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_retained_bytes: DEFAULT_MAX_RETAINED_BYTES,
            max_age_ms: DEFAULT_MAX_AGE_MS,
            max_messages: DEFAULT_MAX_MESSAGES,
            max_groups: DEFAULT_MAX_GROUPS,
            group_idle_evict_ms: DEFAULT_GROUP_IDLE_EVICT_MS,
            disk_full_policy: DiskFullPolicyArg::DropNew,
            visibility_ms: DEFAULT_VISIBILITY_MS,
            enable_admin: false,
        }
    }

    #[test]
    fn validate_rejects_unlimited_max_deliver_without_the_opt_in() {
        // 0 and u32::MAX both mean unlimited; without --allow-unlimited-deliver each is a usage
        // error, and the message points the operator at the opt-in flag (#63).
        for max in [0, u32::MAX] {
            let cfg = ServeConfig {
                max_deliver: max,
                allow_unlimited_deliver: false,
                ..validation_config()
            };
            match validate_serve_config(&cfg) {
                Err(CliError::Usage(m)) => {
                    assert!(m.contains("--allow-unlimited-deliver"), "{m}");
                }
                other => panic!("expected a usage error for max_deliver={max}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_accepts_unlimited_max_deliver_with_the_opt_in() {
        // The same unlimited caps are accepted once the operator opts in (#63). The accompanying
        // startup WARN is emitted by cmd_serve; validation only stops rejecting.
        for max in [0, u32::MAX] {
            let cfg = ServeConfig {
                max_deliver: max,
                allow_unlimited_deliver: true,
                ..validation_config()
            };
            assert!(
                validate_serve_config(&cfg).is_ok(),
                "unlimited max_deliver={max} should be accepted with the opt-in"
            );
        }
    }

    #[test]
    fn the_delivery_config_rejects_unlimited_without_the_opt_in() {
        // The core DeliveryConfig is the typed-error layer the CLI relies on (#63): unlimited
        // without the flag is the typed ConfigError, not a panic.
        use ironbus_core::delivery::ConfigError;
        assert_eq!(
            DeliveryConfig::new(0, false, Vec::new()).unwrap_err(),
            ConfigError::UnlimitedDeliverNotAllowed
        );
        // With the opt-in it builds.
        assert!(DeliveryConfig::new(0, true, Vec::new()).is_ok());
    }

    #[test]
    fn serve_parses_the_allow_unlimited_deliver_flag() {
        // The flag is a bare boolean (no value). Parsing must NOT reject it as an unknown flag; the
        // config then fails on the missing --data-dir, proving the flag itself parsed cleanly.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-deliver".to_string(),
                "0".to_string(),
                "--allow-unlimited-deliver".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        // It got past flag parsing and config validation (unlimited is now allowed) to the
        // data-dir requirement, so the flag both parsed and lifted the unlimited rejection.
        match e {
            CliError::Usage(m) => assert!(m.contains("--data-dir"), "{m}"),
            other => panic!("expected the data-dir usage error, got {other:?}"),
        }
    }

    #[test]
    fn take_number_list_parses_a_comma_separated_schedule() {
        let args = vec!["--backoff-ms".to_string(), "100, 500 ,2000".to_string()];
        let mut i = 0;
        let list = take_number_list("--backoff-ms", &args, &mut i).unwrap();
        assert_eq!(list, vec![100, 500, 2000]);
        assert_eq!(i, 2, "advances past the flag and its value");
        // A single value is a one-element schedule.
        let args = vec!["--backoff-ms".to_string(), "0".to_string()];
        let mut i = 0;
        assert_eq!(
            take_number_list("--backoff-ms", &args, &mut i).unwrap(),
            vec![0]
        );
    }

    #[test]
    fn take_number_list_rejects_a_bad_element() {
        // A non-numeric element or a stray comma (empty element) is a usage error, so a typo is
        // caught before the broker opens.
        for raw in ["100,nope,2000", "100,,200", ""] {
            let args = vec!["--backoff-ms".to_string(), raw.to_string()];
            let mut i = 0;
            match take_number_list("--backoff-ms", &args, &mut i) {
                Err(CliError::Usage(m)) => assert!(m.contains("--backoff-ms"), "{m}"),
                other => panic!("expected a usage error for `{raw}`, got {other:?}"),
            }
        }
    }

    #[test]
    fn serve_rejects_a_bad_backoff_ms() {
        // End to end through the flag parser: a malformed --backoff-ms is a usage error (exit 1).
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--backoff-ms".to_string(),
                "100,bad,2000".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--backoff-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_in_flight() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-in-flight".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-in-flight"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_max_in_flight() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mif0-never-created".to_string(),
                "--max-in-flight".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least 1"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_consumer_credit() {
        // #65: a zero per-consumer credit would deliver nothing to any connection; reject it as a
        // usage error before the broker opens (the engine also floors it to 1, but a typo is caught
        // here loudly rather than silently behaving as 1).
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-cc0-never-created".to_string(),
                "--consumer-credit".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--consumer-credit"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_segment_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-segment-bytes".to_string(),
                "big".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-segment-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_total_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-total-bytes".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-total-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_zero_max_total_bytes_meaning_unlimited() {
        // 0 is the default (unlimited) and an explicit 0 must parse the same, then fail only on
        // the unrelated unreachable bind path proves it was accepted, not rejected as usage.
        // Here we point at a never-created data dir with a valid wire addr; the flag parsing and
        // validation pass (no usage error), so the failure is internal/bind, never EXIT_USAGE.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mtb0-never-served".to_string(),
                "--max-total-bytes".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --max-total-bytes 0 (unlimited) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mtb0-never-served");
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_retained_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-retained-bytes".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-retained-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_max_retained_bytes_value() {
        // A valid --max-retained-bytes parses and validates (no usage error); the only failure is
        // the unrelated bind on an unreachable addr, proving the flag was accepted, not rejected.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mrb-never-served".to_string(),
                "--max-retained-bytes".to_string(),
                "4096".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "a valid --max-retained-bytes parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mrb-never-served");
    }

    #[test]
    fn usage_lists_the_max_retained_bytes_flag() {
        // The new retention flag is documented in the USAGE string, so `ironbus help` surfaces it.
        assert!(
            USAGE.contains("--max-retained-bytes"),
            "USAGE must document the retention flag"
        );
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_age_ms() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-age-ms".to_string(),
                "soon".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-age-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_messages() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-messages".to_string(),
                "many".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-messages"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_max_age_ms_and_max_messages_values() {
        // Both new retention flags parse and validate (no usage error); the only failure is the
        // unrelated bind on an unreachable addr, proving the flags were accepted, not rejected.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-age-count-never-served".to_string(),
                "--max-age-ms".to_string(),
                "60000".to_string(),
                "--max-messages".to_string(),
                "100000".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "valid --max-age-ms and --max-messages parse and validate: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-age-count-never-served");
    }

    #[test]
    fn usage_lists_the_age_and_count_retention_flags() {
        // Both new retention flags are documented in the USAGE string, so `ironbus help` surfaces
        // them alongside the byte bound.
        assert!(
            USAGE.contains("--max-age-ms"),
            "USAGE must document --max-age-ms"
        );
        assert!(
            USAGE.contains("--max-messages"),
            "USAGE must document --max-messages"
        );
    }

    #[test]
    fn serve_rejects_a_non_numeric_max_groups() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--max-groups".to_string(),
                "many".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--max-groups"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_a_max_groups_value() {
        // A valid --max-groups parses and validates (no usage error); the only failure is the
        // unrelated bind on an unreachable addr, proving the flag was accepted, not rejected.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mg-never-served".to_string(),
                "--max-groups".to_string(),
                "16".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "a valid --max-groups parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mg-never-served");
    }

    #[test]
    fn serve_accepts_a_zero_max_groups_meaning_unlimited() {
        // `0` = unlimited (the cap is off), matching the `0` = off convention of the other bounds.
        // An explicit 0 must parse the same as the default, so the only failure is the unrelated
        // bind path, never EXIT_USAGE.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-mg0-never-served".to_string(),
                "--max-groups".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --max-groups 0 (unlimited) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-mg0-never-served");
    }

    #[test]
    fn usage_lists_the_max_groups_flag() {
        assert!(
            USAGE.contains("--max-groups"),
            "USAGE must document --max-groups"
        );
    }

    // ----- Idle named-group eviction flag (#277) -----

    #[test]
    fn serve_parses_the_group_idle_evict_ms_flag() {
        // The --group-idle-evict-ms flag (#277) parses its value into the ServeConfig, so the engine
        // receives the configured idle window.
        let parsed = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/ironbus-cli-gie-never-served".to_string(),
            "--group-idle-evict-ms".to_string(),
            "60000".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.config.group_idle_evict_ms, 60000);
    }

    #[test]
    fn the_group_idle_evict_ms_default_is_disabled() {
        // The default is 0 (disabled / never evict), matching the engine default and the `0` = off
        // convention of the other bounds, so an unconfigured broker never reclaims named groups.
        let parsed = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/ironbus-cli-gie-default-never-served".to_string(),
        ])
        .unwrap();
        assert_eq!(
            parsed.config.group_idle_evict_ms,
            DEFAULT_GROUP_IDLE_EVICT_MS
        );
        assert_eq!(DEFAULT_GROUP_IDLE_EVICT_MS, 0);
    }

    #[test]
    fn serve_accepts_a_zero_group_idle_evict_ms_meaning_disabled() {
        // An explicit 0 (disabled) parses the same as the default, so the only failure is the
        // unrelated bind path, never EXIT_USAGE.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-gie0-never-served".to_string(),
                "--group-idle-evict-ms".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --group-idle-evict-ms 0 (disabled) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-gie0-never-served");
    }

    #[test]
    fn serve_rejects_a_non_numeric_group_idle_evict_ms() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--group-idle-evict-ms".to_string(),
                "soon".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--group-idle-evict-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_lists_the_group_idle_evict_ms_flag() {
        assert!(
            USAGE.contains("--group-idle-evict-ms"),
            "USAGE must document --group-idle-evict-ms"
        );
    }

    // ----- Per-consumer BYTE budget flag (#275) -----

    #[test]
    fn serve_parses_the_consumer_credit_bytes_flag() {
        // The --consumer-credit-bytes flag (#275) parses its value into the ServeConfig, so the
        // engine receives the configured byte budget.
        let parsed = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/ironbus-cli-ccb-never-served".to_string(),
            "--consumer-credit-bytes".to_string(),
            "65536".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.config.consumer_credit_bytes, 65536);
    }

    #[test]
    fn the_consumer_credit_bytes_default_is_eight_mib() {
        // Omitted, the flag defaults to 8 MiB, aliased to the engine default so the two never drift.
        let parsed = parse_serve_flags(&["--data-dir".to_string(), "/tmp/x".to_string()]).unwrap();
        assert_eq!(
            parsed.config.consumer_credit_bytes,
            DEFAULT_CONSUMER_CREDIT_BYTES
        );
        assert_eq!(DEFAULT_CONSUMER_CREDIT_BYTES, 8 * 1024 * 1024);
    }

    // ----- Env-var mapping with flag > env > default precedence (#89) -----

    /// Builds an injected env lookup from a fixed list of (name, value) pairs, so the env layer is
    /// driven DETERMINISTICALLY without touching (and racing on) the real process environment.
    fn fixed_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    #[test]
    fn the_env_var_name_mapping_is_ironbus_uppercase_underscored() {
        // `--max-total-bytes` -> `IRONBUS_MAX_TOTAL_BYTES`, `--data-dir` -> `IRONBUS_DATA_DIR`,
        // `--addr` -> `IRONBUS_ADDR`: leading dashes stripped, `-` -> `_`, uppercased, `IRONBUS_`.
        assert_eq!(env_var_name("--max-total-bytes"), "IRONBUS_MAX_TOTAL_BYTES");
        assert_eq!(env_var_name("--data-dir"), "IRONBUS_DATA_DIR");
        assert_eq!(env_var_name("--addr"), "IRONBUS_ADDR");
        assert_eq!(env_var_name("--enable-admin"), "IRONBUS_ENABLE_ADMIN");
    }

    #[test]
    fn env_var_sets_a_value_when_no_flag_is_given() {
        // No `--max-total-bytes` flag, but `IRONBUS_MAX_TOTAL_BYTES` set: the env value applies.
        let env = fixed_env(&[
            ("IRONBUS_MAX_TOTAL_BYTES", "4096"),
            ("IRONBUS_DATA_DIR", "/tmp/ironbus-env-dd"),
            ("IRONBUS_ADDR", "127.0.0.1:9999"),
        ]);
        let parsed = parse_serve_flags_with_env(&[], &env).expect("env-only serve config resolves");
        assert_eq!(parsed.config.max_total_bytes, 4096, "env value applied");
        assert_eq!(parsed.data_dir.as_deref(), Some("/tmp/ironbus-env-dd"));
        assert_eq!(parsed.addr, "127.0.0.1:9999");
    }

    #[test]
    fn an_explicit_flag_overrides_the_env_var() {
        // The flag wins over the env var (flag > env): `--max-total-bytes 100` beats the env's 4096.
        let env = fixed_env(&[
            ("IRONBUS_MAX_TOTAL_BYTES", "4096"),
            ("IRONBUS_ADDR", "127.0.0.1:9999"),
        ]);
        let parsed = parse_serve_flags_with_env(
            &[
                "--max-total-bytes".to_string(),
                "100".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1234".to_string(),
            ],
            &env,
        )
        .unwrap();
        assert_eq!(parsed.config.max_total_bytes, 100, "the flag overrides env");
        assert_eq!(parsed.addr, "127.0.0.1:1234", "the flag overrides env");
    }

    #[test]
    fn the_default_applies_when_neither_flag_nor_env_is_given() {
        // Neither a flag nor an env var: the compiled default (flag > env > default).
        let env = fixed_env(&[]);
        let parsed = parse_serve_flags_with_env(&[], &env).unwrap();
        assert_eq!(parsed.config.max_total_bytes, DEFAULT_MAX_TOTAL_BYTES);
        assert_eq!(parsed.addr, DEFAULT_ADDR);
        assert_eq!(
            parsed.data_dir, None,
            "no data dir from flag, env, or default"
        );
    }

    #[test]
    fn an_invalid_env_value_is_a_typed_error_naming_the_env_var() {
        // A non-numeric env value where a number is expected is a usage error that NAMES THE ENV VAR
        // (not the flag), exactly as a bad flag value names the flag.
        let env = fixed_env(&[("IRONBUS_MAX_TOTAL_BYTES", "not-a-number")]);
        let e = parse_serve_flags_with_env(&[], &env).unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => {
                assert!(
                    m.contains("IRONBUS_MAX_TOTAL_BYTES"),
                    "names the env var: {m}"
                );
                assert!(m.contains("not-a-number"), "echoes the bad value: {m}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_env_supplied_bool_and_list_resolve_through_the_seam() {
        // The boolean (`IRONBUS_ENABLE_ADMIN`) and the comma-separated list (`IRONBUS_BACKOFF_MS`)
        // resolve through the env seam with the same grammar as their flags.
        let env = fixed_env(&[
            ("IRONBUS_ENABLE_ADMIN", "true"),
            ("IRONBUS_BACKOFF_MS", "100, 500 ,2000"),
        ]);
        let parsed = parse_serve_flags_with_env(&[], &env).unwrap();
        assert!(
            parsed.config.enable_admin,
            "env-supplied bool enabled admin"
        );
        assert_eq!(
            parsed.config.backoff_ms,
            vec![100, 500, 2000],
            "env list parsed"
        );
        // An invalid bool value names the env var.
        let bad = parse_serve_flags_with_env(&[], &fixed_env(&[("IRONBUS_ENABLE_ADMIN", "maybe")]))
            .unwrap_err();
        match bad {
            CliError::Usage(m) => assert!(m.contains("IRONBUS_ENABLE_ADMIN"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn an_env_supplied_disk_full_policy_resolves_and_a_bad_one_names_the_env_var() {
        let parsed = parse_serve_flags_with_env(
            &[],
            &fixed_env(&[("IRONBUS_DISK_FULL_POLICY", "drop-oldest")]),
        )
        .unwrap();
        assert_eq!(
            parsed.config.disk_full_policy,
            DiskFullPolicyArg::DropOldest
        );
        let bad = parse_serve_flags_with_env(
            &[],
            &fixed_env(&[("IRONBUS_DISK_FULL_POLICY", "drop-everything")]),
        )
        .unwrap_err();
        match bad {
            CliError::Usage(m) => assert!(m.contains("IRONBUS_DISK_FULL_POLICY"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_and_cli_docs_document_the_env_var_mapping() {
        // The env-var surface is documented in the usage banner and in docs/CLI.md (#89).
        assert!(
            USAGE.contains("IRONBUS_"),
            "USAGE must document the env-var mapping"
        );
    }

    // ----- data_dir lifecycle and the single-broker lock on serve (#89) -----

    #[cfg(unix)]
    #[test]
    fn serve_creates_a_missing_data_dir() {
        // serve creates the data dir (and parents) if absent. We point it at an UNBINDABLE address so
        // the call errors at the bind step (after the dir is prepared), proving creation happened
        // without leaving a broker running.
        let dir = std::env::temp_dir().join(format!(
            "ironbus-cli-serve-mkdir-{}/nested/leaf",
            std::process::id()
        ));
        let base =
            std::env::temp_dir().join(format!("ironbus-cli-serve-mkdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        assert!(!dir.exists());
        let mut buf = Vec::new();
        // Port 0 binds fine, so use a host the OS refuses to bind to force a post-prepare error.
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--addr".to_string(),
                "240.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        // It got past the data-dir lifecycle (the dir now exists) and failed later (bind).
        assert!(
            dir.is_dir(),
            "serve created the missing data dir and parents: {e}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn serve_on_a_non_directory_data_dir_is_a_usage_error() {
        // A --data-dir that exists but is a regular file is a typed usage error naming the path,
        // before the broker opens.
        let base =
            std::env::temp_dir().join(format!("ironbus-cli-serve-nondir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                file.display().to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE, "{e}");
        match &e {
            CliError::Usage(m) => assert!(m.contains("not a directory"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn serve_fails_fast_when_the_data_dir_is_already_locked() {
        // Hold the single-broker lock, then attempt a serve on the same data dir: it must fail fast
        // with the typed "already running" error (a non-zero exit), NOT double-open and corrupt.
        let dir =
            std::env::temp_dir().join(format!("ironbus-cli-serve-locked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dirlock::prepare_data_dir(&dir).unwrap();
        let held = dirlock::DirLock::acquire(&dir).unwrap();
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                dir.display().to_string(),
                "--addr".to_string(),
                "127.0.0.1:0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(e.exit_code(), 0, "a contended serve exits non-zero: {e}");
        let msg = e.to_string();
        assert!(
            msg.contains("already running"),
            "the typed single-broker error: {msg}"
        );
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_enable_admin_is_off_by_default_and_set_by_the_flag() {
        // The read-only /admin endpoint (#99) is opt-in: absent the flag it is off.
        let off = parse_serve_flags(&["--data-dir".to_string(), "/tmp/x".to_string()]).unwrap();
        assert!(!off.config.enable_admin, "admin is off by default");
        // `--enable-admin` is a bare boolean (no value): it sets the flag and the loop advances one
        // token, so a following flag still parses.
        let on = parse_serve_flags(&[
            "--data-dir".to_string(),
            "/tmp/x".to_string(),
            "--enable-admin".to_string(),
            "--max-in-flight".to_string(),
            "8".to_string(),
        ])
        .unwrap();
        assert!(on.config.enable_admin, "admin is on with --enable-admin");
        assert_eq!(on.config.max_in_flight, 8, "the trailing flag still parses");
    }

    #[test]
    fn serve_accepts_a_zero_consumer_credit_bytes_meaning_unlimited() {
        // `0` = unlimited (the byte budget is off), matching the `0` = off convention of the other
        // byte bounds. Unlike --consumer-credit (where 0 is a usage error), a 0 byte budget is a
        // valid, meaningful value (only the message credit binds), so it must parse and validate.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-ccb0-never-served".to_string(),
                "--consumer-credit-bytes".to_string(),
                "0".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "an explicit --consumer-credit-bytes 0 (unlimited) parses and validates: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-ccb0-never-served");
    }

    #[test]
    fn serve_rejects_a_non_numeric_consumer_credit_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--consumer-credit-bytes".to_string(),
                "lots".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--consumer-credit-bytes"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_lists_the_consumer_credit_bytes_flag() {
        assert!(
            USAGE.contains("--consumer-credit-bytes"),
            "USAGE must document --consumer-credit-bytes"
        );
    }

    #[test]
    fn serve_accepts_repeated_key_shared_group_flags() {
        // The repeatable --key-shared-group flag (#64) parses and validates; the only failure is
        // the unrelated bind on an unreachable addr, proving the flag was accepted.
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-ksg-never-served".to_string(),
                "--key-shared-group".to_string(),
                "orders".to_string(),
                "--key-shared-group".to_string(),
                "events".to_string(),
                "--addr".to_string(),
                "127.0.0.1:1".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_ne!(
            e.exit_code(),
            EXIT_USAGE,
            "repeated --key-shared-group flags parse and validate: {e}"
        );
        let _ = std::fs::remove_dir_all("/tmp/ironbus-cli-ksg-never-served");
    }

    #[test]
    fn serve_rejects_a_key_shared_group_without_a_value() {
        let mut buf = Vec::new();
        let e = run(
            &["serve".to_string(), "--key-shared-group".to_string()],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--key-shared-group"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn usage_lists_the_key_shared_group_flag() {
        assert!(
            USAGE.contains("--key-shared-group"),
            "USAGE must document --key-shared-group"
        );
    }

    #[test]
    fn serve_rejects_a_tiny_max_segment_bytes() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-msb-never-created".to_string(),
                "--max-segment-bytes".to_string(),
                "100".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_non_numeric_visibility_timeout() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--visibility-timeout-ms".to_string(),
                "soon".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("--visibility-timeout-ms"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn serve_rejects_a_zero_visibility_timeout() {
        let mut buf = Vec::new();
        let e = run(
            &[
                "serve".to_string(),
                "--data-dir".to_string(),
                "/tmp/ironbus-cli-vt0-never-created".to_string(),
                "--visibility-timeout-ms".to_string(),
                "0".to_string(),
            ],
            &mut buf,
        )
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_USAGE);
        match e {
            CliError::Usage(m) => assert!(m.contains("at least 1"), "{m}"),
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
        cmd_sub(&a, "", 10, Disposition::Nack { delay_ms: None }, &mut nout).unwrap();
        assert!(String::from_utf8(nout).unwrap().contains("nack requeued"));
        let mut aout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Ack, &mut aout).unwrap();
        let atext = String::from_utf8(aout).unwrap();
        assert!(atext.contains("payload=retry"), "redelivered: {atext}");
        assert!(atext.contains("ack committed"), "acked: {atext}");

        // Term: the message is dropped (committed past) and a re-fetch is empty.
        cmd_pub(&a, b"", b"drop", &mut Vec::new()).unwrap();
        let mut tout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Term, &mut tout).unwrap();
        assert!(String::from_utf8(tout).unwrap().contains("term dropped"));
        let mut eout = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut eout).unwrap();
        assert_eq!(String::from_utf8(eout).unwrap(), "fetched 0 message(s)\n");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn a_poison_message_is_dead_lettered_after_exceeding_max_deliver() {
        // The golden-path poison case end to end over the wire: a short visibility timeout
        // (so the redelivery is fast) and max_deliver = 1. The first peek leases the message
        // (delivery 1); after the timeout the next fetch is delivery 2, which exceeds the cap,
        // so the engine dead-letters it (parked, not redelivered) and records the drop with
        // its offset. This is platform-agnostic (in-memory fs) but uses the real clock for the
        // visibility timeout, with a 10x sleep margin so it is not flaky.
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::from_millis(50, 300_000),
                delivery: DeliveryConfig::new(1, false, Vec::new()).unwrap(),
                max_in_flight: 16,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let shared = Arc::clone(&shared);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });
        let a = addr.to_string();

        cmd_pub(&a, b"", b"poison", &mut Vec::new()).unwrap();

        // Delivery 1: peeked (leased), not acked.
        let mut first = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut first).unwrap();
        assert!(
            String::from_utf8(first).unwrap().contains("payload=poison"),
            "the first delivery is served"
        );

        // Past the visibility timeout, delivery 2 exceeds max_deliver = 1: dead-lettered, so
        // the re-fetch is empty.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut second = Vec::new();
        cmd_sub(&a, "", 10, Disposition::Peek, &mut second).unwrap();
        assert_eq!(
            String::from_utf8(second).unwrap(),
            "dead-letter offset=0 reason=max-deliver\nfetched 0 message(s)\n",
            "the consumer is told the poison message was dead-lettered via the in-band advisory \
             (#63); it is not redelivered"
        );

        // The engine recorded the drop and its offset (the resilience signal).
        {
            let g = shared.lock().unwrap();
            assert_eq!(g.counters().dead_lettered, 1, "exactly one dead-letter");
            assert!(
                g.last_dead_lettered_offset().is_some_and(|o| o.get() == 0),
                "the dead-lettered offset is reported"
            );
        }

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
    }

    #[test]
    fn the_in_flight_window_bounds_each_delivery_batch() {
        // Backpressure / no unbounded in-flight (#133 overload): with max_in_flight = 2, each
        // fetch delivers at most 2 messages even with a credit of 10 and 4 produced. The
        // window, not the credit, is the cap; acks free slots for the next batch.
        let engine = Engine::open(
            InMemoryFs::new(),
            SystemClock::new(),
            EngineConfig {
                log: LogConfig::default(),
                lease: LeaseConfig::from_millis(30_000, 300_000),
                delivery: DeliveryConfig::new(5, false, Vec::new()).unwrap(),
                max_in_flight: 2,
                consumer_credit: 64,
                consumer_credit_bytes: 0,
                checkpoint_interval: 1024,
                max_retained_bytes: 0,
                max_age_ms: 0,
                max_messages: 0,
                max_groups: DEFAULT_MAX_GROUPS,
                group_idle_evict_ms: 0,
                disk_full_policy: DiskFullPolicy::DropNew,
            },
        )
        .unwrap();
        let shared: SharedEngine<InMemoryFs, SystemClock> = Arc::new(Mutex::new(engine));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            let shared = Arc::clone(&shared);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });
        let a = addr.to_string();

        for (i, payload) in [&b"a"[..], b"b", b"c", b"d"].into_iter().enumerate() {
            let mut out = Vec::new();
            cmd_pub(&a, b"", payload, &mut out).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), format!("{i}\n"));
        }

        // Observe the per-batch window at the Flow layer: `cmd_sub --ack` deliberately drains
        // across batches up to `--max` (#65 SHOULD-FIX), so a single CLI call no longer exposes one
        // window-bounded batch. Drive the protocol directly to assert each fetch is capped at the
        // in-flight window of 2, not the credit of 10.
        let mut client = Client::connect(&a).unwrap();

        // First fetch: capped at the window of 2 despite a credit of 10 and 4 available.
        let batch1 = client.fetch(10).unwrap();
        assert_eq!(
            batch1.messages.len(),
            2,
            "the in-flight window caps the batch at 2, not the credit of 10"
        );
        assert_eq!(batch1.messages[0].payload.as_slice(), b"a");
        assert_eq!(batch1.messages[1].payload.as_slice(), b"b");
        for m in &batch1.messages {
            assert!(client.ack(m.offset, m.generation).unwrap(), "ack committed");
        }

        // The acks freed the window; the next fetch delivers the next two.
        let batch2 = client.fetch(10).unwrap();
        assert_eq!(
            batch2.messages.len(),
            2,
            "the next batch is also capped at 2"
        );
        assert_eq!(batch2.messages[0].payload.as_slice(), b"c");
        assert_eq!(batch2.messages[1].payload.as_slice(), b"d");
        for m in &batch2.messages {
            assert!(client.ack(m.offset, m.generation).unwrap(), "ack committed");
        }

        // All four committed: the stream is drained.
        let batch3 = client.fetch(10).unwrap();
        assert!(batch3.messages.is_empty(), "the stream is drained");

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

        let shared = open_disk_engine(&dir, &test_serve_config(64, 1), &[]).unwrap();
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
        cmd_sub(&a, "", 10, Disposition::Ack, &mut consumed).unwrap();
        let text = String::from_utf8(consumed).unwrap();
        assert!(text.contains("payload=on-disk"), "missing payload: {text}");
        assert!(text.contains("ack committed"), "missing ack: {text}");

        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();

        // Restart: reopen the SAME data dir. With checkpoint_interval = 1, the server
        // persisted the committed cursor synchronously when it acked offset 0, so a clean
        // restart RESUMES past the acked message (it does not redeliver), and the durable log
        // continues at offset 1 rather than overwriting offset 0.
        let reopened = open_disk_engine(&dir, &test_serve_config(64, 1), &[]).unwrap();
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let shutdown2 = Arc::new(AtomicBool::new(false));
        let handle2 = std::thread::spawn({
            let shutdown2 = Arc::clone(&shutdown2);
            move || serve(&listener2, &reopened, &shutdown2, 16).unwrap()
        });
        let a2 = addr2.to_string();

        let mut after_restart = Vec::new();
        cmd_sub(&a2, "", 10, Disposition::Peek, &mut after_restart).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn a_restart_redelivers_only_the_uncommitted_tail() {
        // Durability across a restart with a PARTIAL ack: produce three messages, ack only the
        // first, then restart on the same data dir. The acked message stays committed (never
        // redelivers), and the uncommitted tail (offsets 1 and 2) redelivers. The core
        // no-acked-write-lost / uncommitted-tail-redelivers invariant, end to end over the wire.
        let dir = std::env::temp_dir().join(format!("ironbus-cli-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let shared = open_disk_engine(&dir, &test_serve_config(64, 1), &[]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let shutdown = Arc::clone(&shutdown);
            move || serve(&listener, &shared, &shutdown, 16).unwrap()
        });
        let a = addr.to_string();
        for (i, payload) in [&b"m0"[..], b"m1", b"m2"].into_iter().enumerate() {
            let mut out = Vec::new();
            cmd_pub(&a, b"", payload, &mut out).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), format!("{i}\n"));
        }
        // A credit of 1 leases and acks exactly the first message (offset 0); the cursor is
        // checkpointed (checkpoint_interval = 1, plus the clean disconnect).
        let mut acked = Vec::new();
        cmd_sub(&a, "", 1, Disposition::Ack, &mut acked).unwrap();
        let acked = String::from_utf8(acked).unwrap();
        assert!(
            acked.contains("payload=m0"),
            "acked the first message: {acked}"
        );
        assert!(acked.contains("ack committed"), "committed: {acked}");
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();

        // Restart on the same dir: only the uncommitted tail (offsets 1 and 2) redelivers.
        let reopened = open_disk_engine(&dir, &test_serve_config(64, 1), &[]).unwrap();
        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let shutdown2 = Arc::new(AtomicBool::new(false));
        let handle2 = std::thread::spawn({
            let shutdown2 = Arc::clone(&shutdown2);
            move || serve(&listener2, &reopened, &shutdown2, 16).unwrap()
        });
        let a2 = addr2.to_string();
        let mut tail = Vec::new();
        cmd_sub(&a2, "", 10, Disposition::Peek, &mut tail).unwrap();
        let tail = String::from_utf8(tail).unwrap();
        assert!(
            tail.contains("fetched 2 message(s)"),
            "the two uncommitted messages redeliver: {tail}"
        );
        assert!(
            tail.contains("payload=m1") && tail.contains("payload=m2"),
            "the tail content redelivers: {tail}"
        );
        assert!(
            !tail.contains("payload=m0"),
            "the acked message must not redeliver after a restart: {tail}"
        );

        shutdown2.store(true, Ordering::Release);
        handle2.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
