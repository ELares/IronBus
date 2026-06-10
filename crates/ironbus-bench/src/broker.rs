// SPDX-License-Identifier: MIT OR Apache-2.0
//! Launching and addressing the SHIPPING `ironbus` binary over a real loopback socket.
//!
//! The harness measures the real product, not an in-process stub: it spawns `ironbus serve` exactly
//! as an operator would (the same launch pattern the golden-path acceptance test uses), binds an
//! ephemeral loopback port, and parses the broker's first stdout line to learn the address. The
//! sender and receiver then drive it through the real #11 client over that socket.
//!
//! The broker is killed and reaped on drop, so a panicking measurement never leaks a `serve`
//! process. The PID is exposed so the injected-stall self-test can `SIGSTOP`/`SIGCONT` it.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// An error launching or addressing the broker.
#[derive(Debug)]
pub enum BrokerError {
    /// The `ironbus serve` process could not be spawned (the binary path is wrong, or the OS
    /// refused). Carries the underlying IO error.
    Spawn(std::io::Error),
    /// The broker did not print its listening line within the boot timeout.
    BootTimeout,
    /// The broker exited before it listened; carries whatever it wrote to stderr.
    ExitedEarly(String),
    /// The listening line was printed but its address could not be parsed.
    UnparsableAddr(String),
}

impl core::fmt::Display for BrokerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BrokerError::Spawn(e) => write!(f, "could not spawn ironbus serve: {e}"),
            BrokerError::BootTimeout => write!(f, "ironbus serve did not print a listening line"),
            BrokerError::ExitedEarly(err) => {
                write!(f, "ironbus serve exited before it listened: {err}")
            }
            BrokerError::UnparsableAddr(line) => {
                write!(f, "could not parse the listening line: {line:?}")
            }
        }
    }
}

impl std::error::Error for BrokerError {}

/// A running `ironbus serve` broker on a loopback port, killed and reaped on drop.
#[derive(Debug)]
pub struct Broker {
    child: Child,
    addr: String,
}

impl Broker {
    /// Spawns `ironbus serve` over `data_dir` on an ephemeral loopback port, returning once it has
    /// printed its listening address. `extra` flags are appended verbatim (for example a
    /// `--max-total-bytes` cap to drive the #10 shed-not-OOM overload workload).
    ///
    /// `bin` is the path to the built `ironbus` binary; both the harness binary and the self-test
    /// obtain it from [`resolve_ironbus_binary`], which locates it in the workspace target dir.
    ///
    /// # Errors
    /// Returns a [`BrokerError`] if the process cannot be spawned, exits before listening, or does
    /// not print a parseable listening line within the boot timeout.
    pub fn spawn(bin: &Path, data_dir: &Path, extra: &[&str]) -> Result<Broker, BrokerError> {
        let mut args: Vec<String> = vec![
            "serve".into(),
            "--data-dir".into(),
            data_dir.display().to_string(),
            "--addr".into(),
            "127.0.0.1:0".into(),
            // Persist the cursor synchronously per ack so a run is deterministic and the data dir
            // reflects every committed offset (the write-amplification sampler reads it).
            "--checkpoint-interval".into(),
            "1".into(),
            // Pin the codec EXPLICITLY to `lz4`, the shipped ADR-0003 default (#430, #439),
            // instead of inheriting whatever the binary's default happens to be: a recorded
            // baseline must self-describe what it measured, and a future default-codec flip must
            // not silently change the workload the #114 rolling-median gate compares across
            // releases. `extra` is appended AFTER these args and the serve parser takes the LAST
            // occurrence of a repeated flag, so a caller can still override (e.g.
            // `--compression none` for an explicit raw-write-path comparison run).
            "--compression".into(),
            "lz4".into(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_string()));

        let child = Command::new(bin)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(BrokerError::Spawn)?;
        // Guard immediately: a bare Child does not kill on drop, so any early return below would
        // otherwise orphan the broker.
        let mut broker = Broker {
            child,
            addr: String::new(),
        };

        let stdout = broker
            .child
            .stdout
            .take()
            .ok_or_else(|| BrokerError::ExitedEarly("no piped stdout".into()))?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let n = BufReader::new(stdout).read_line(&mut line).unwrap_or(0);
            let _ = tx.send((n, line));
        });
        let (n, line) = rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| BrokerError::BootTimeout)?;
        if n == 0 {
            let mut err = String::new();
            if let Some(mut se) = broker.child.stderr.take() {
                let _ = se.read_to_string(&mut err);
            }
            return Err(BrokerError::ExitedEarly(err));
        }
        // "ironbus listening on 127.0.0.1:<port>, data dir <dir>"
        let addr = line
            .split("listening on ")
            .nth(1)
            .and_then(|rest| rest.split(',').next())
            .map(str::trim)
            .ok_or_else(|| BrokerError::UnparsableAddr(line.clone()))?;
        broker.addr = addr.to_string();
        Ok(broker)
    }

    /// The `host:port` the broker is listening on.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The broker process id, for the injected-stall self-test's `SIGSTOP`/`SIGCONT`.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        // Always SIGCONT-then-kill: a test that paused the broker and panicked must not leave a
        // stopped, unkillable-by-SIGTERM process behind. `kill` sends SIGKILL, which a stopped
        // process still receives, so the continue is belt-and-suspenders for portability.
        #[cfg(unix)]
        resume(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Resolves the path to the built `ironbus` binary from the running executable's location.
///
/// The shipping binary sits at `target/<profile>/ironbus`. The harness binary sits right next to it
/// (`target/<profile>/ironbus-bench`), and a `cargo test` integration binary sits one level deeper
/// in `target/<profile>/deps/`. So this checks the executable's own directory AND its parent,
/// covering both the `run` and the `test` layouts. Returns `None` if neither holds the binary,
/// which a caller treats as "the broker is not built; skip" rather than a hard failure.
#[must_use]
pub fn resolve_ironbus_binary() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "ironbus.exe"
    } else {
        "ironbus"
    };
    let me = std::env::current_exe().ok()?;
    let dir = me.parent()?;
    // The binary's own profile dir (the harness-binary case), then up one from `deps/` (the
    // integration-test case).
    let candidates = [dir.join(name), dir.parent().map(|p| p.join(name))?];
    candidates.into_iter().find(|p| p.exists())
}

/// Sends `SIGSTOP` to `pid`, freezing the process (Unix only). Used by the injected-stall
/// self-test to model a broker that wedges mid-run.
#[cfg(unix)]
pub fn stop(pid: u32) {
    // SAFETY: `kill` is a foreign function (a plain syscall wrapper), not a memory-unsafe
    // operation: it takes two integers and touches no memory we own. We pass our own child's pid
    // and a valid signal; a failure (e.g. the process already exited) is harmless and ignored.
    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::kill(pid_to_libc(pid), libc::SIGSTOP);
    }
}

/// Sends `SIGCONT` to `pid`, resuming a stopped process (Unix only).
#[cfg(unix)]
pub fn resume(pid: u32) {
    // SAFETY: identical to `stop`: a plain `kill` syscall on our own child's pid with a valid
    // signal, touching no memory we own.
    #[allow(unsafe_code)]
    unsafe {
        let _ = libc::kill(pid_to_libc(pid), libc::SIGCONT);
    }
}

/// Narrows a `u32` process id to the platform `pid_t` for `libc::kill`. A real OS pid is far below
/// `i32::MAX`, so the conversion never truncates in practice; a pathological value saturates rather
/// than wrapping into another process's id.
#[cfg(unix)]
fn pid_to_libc(pid: u32) -> libc::pid_t {
    libc::pid_t::try_from(pid).unwrap_or(libc::pid_t::MAX)
}
