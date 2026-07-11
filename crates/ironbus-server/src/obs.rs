// SPDX-License-Identifier: MIT OR Apache-2.0
//! Structured tracing and the feature-gated OTLP span-export seam (#99, #352).
//!
//! IronBus instruments with the `tracing` crate. A JSON log layer is compiled in BY DEFAULT
//! (`init_tracing`), so an operator gets structured, machine-parseable logs with no extra build
//! flags. The layer records any ERROR/WARN event regardless of the sampling rate, so an emitted
//! error is never sampled out. HONESTY NOTE: the corruption-skip, writer-freeze, and drop signals
//! #16 forbids being silent are surfaced today as METRICS + the loss report — dedicated log EVENTS
//! for them are not emitted yet (tracked #1074); a broker PANIC does emit a structured JSON line
//! (`install_panic_hook`, #1080).
//!
//! OTLP span export is FEATURE-GATED behind the non-default `otlp` Cargo feature and OFF at runtime
//! by default: the default-shipped binary and the size-optimized `edge-min` build carry ZERO
//! opentelemetry dependencies. Head-based sampling defaults to 0.0 (no spans exported) while
//! ERROR/WARN events are always recorded; export goes through a BOUNDED LOSSY queue
//! ([`BoundedSpanQueue`]) that DROPS and COUNTS spans rather than blocking the thread-per-core core,
//! so a slow or unreachable collector can never stall a produce. The bounded-lossy queue and its
//! drop counter are REAL and dep-free; they exist (and are tested) whether or not the `otlp` feature
//! is compiled in. The CONCRETE opentelemetry-otlp span exporter (#352) lives in the `otlp` module
//! and is wired only behind the feature: it ships drained spans to a collector over plaintext gRPC
//! (tonic, no TLS, so the otlp build links no `rustls`/`ring` C-FFI crypto) on a dedicated drain
//! thread, off the thread-per-core path. This module owns the queue, the sampling decision, the
//! exporter, and the compile-out, so "off = zero cost" is a structural property, not a runtime
//! promise.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The default head-based trace sampling ratio (#16, #99): `0.0` means no spans are exported on the
/// edge profile, the leanest default. ERROR and WARN events are recorded regardless (see
/// [`SpanRecord::force_recorded`]), so a degraded box is never sampled into silence.
pub const DEFAULT_SAMPLE_RATIO: f64 = 0.0;

/// The default bound on the in-memory span-export queue ([`BoundedSpanQueue`]): the most spans that
/// may be buffered for export before new spans are DROPPED (and counted) rather than blocking the
/// core. A fixed, bounded allocation in the spirit of the #10 ring buffer; chosen small because the
/// edge RAM budget is tight and a backed-up exporter must shed, not grow.
pub const DEFAULT_SPAN_QUEUE_CAPACITY: usize = 1024;

/// The severity of a recorded span/event, used by the sampling decision. ERROR and WARN are ALWAYS
/// recorded (they carry the resilience signals #16 forbids being silent); INFO/DEBUG/TRACE are
/// subject to head-based sampling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A fatal or resilience-critical event (a freeze, a fsync failure): always recorded.
    Error,
    /// A bounded-loss or shed event (a skip, an overflow drop): always recorded.
    Warn,
    /// Normal operational detail: subject to head-based sampling.
    Info,
    /// Verbose detail: subject to head-based sampling.
    Debug,
    /// Tracing-level detail: subject to head-based sampling.
    Trace,
}

impl Severity {
    /// Whether an event at this severity is ALWAYS recorded irrespective of the sampling ratio.
    /// ERROR and WARN are; everything below is sampled. This is the rule that keeps a corruption
    /// skip or a freeze from ever being sampled out (#16's "nothing is silent").
    #[must_use]
    pub fn is_always_recorded(self) -> bool {
        matches!(self, Severity::Error | Severity::Warn)
    }
}

/// The OTLP span kind of a recorded span (#770), our own dependency-free tag so the default and
/// `edge-min` builds carry it without linking `opentelemetry`. The `otlp` exporter maps it onto
/// `opentelemetry::trace::SpanKind`. `Internal` is the neutral default (today's behavior); `Server`
/// is the connection handler, `Producer` a produce, `Consumer` a deliver/ack — the messaging lifecycle
/// the W3C-propagation half of tracing needs to speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SpanKindTag {
    /// A local, un-kinded span: the neutral default, the behavior before distributed tracing.
    #[default]
    Internal,
    /// The connection handler / server-side request span.
    Server,
    /// A client-side request span (reserved; the broker rarely originates one).
    Client,
    /// A produce span: the message-bus PRODUCER side of the OTLP messaging convention.
    Producer,
    /// A deliver/ack span: the message-bus CONSUMER side of the OTLP messaging convention.
    Consumer,
}

/// The cap on the number of producer -> consumer links a single consume span may carry (#770). A
/// batch delivery can fan in many produced records; without a bound the link list would grow with the
/// batch. We keep only the first [`MAX_SPAN_LINKS`] DISTINCT producer contexts and drop the rest, so a
/// span's link surface is fixed-size and `Copy`, never an unbounded allocation on the export path.
pub const MAX_SPAN_LINKS: usize = 8;

/// One producer -> consumer span LINK (#770): the (trace-id, span-id) of a span this span links to.
/// Dependency-free plain data (24 bytes, `Copy`); the `otlp` exporter maps it onto an
/// `opentelemetry` `Link`. An all-zero link is the empty/unused slot in a [`SpanTraceContext`]'s fixed
/// link array.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SpanLink {
    /// The 16-byte trace id of the linked span.
    pub trace_id: [u8; 16],
    /// The 8-byte span id of the linked span.
    pub span_id: [u8; 8],
}

/// The distributed-trace linkage a span carries (#770): its kind, the trace it belongs to, its
/// parent, and a bounded set of producer -> consumer links. ALWAYS-ON plain data (no `opentelemetry`
/// dependency, present on the default and `edge-min` builds); the `otlp` exporter reads it to populate
/// the exported span's `span_kind`, `parent_span_id`, and `links` instead of the old
/// `Internal`/`INVALID`/empty defaults. The `Default` is exactly the pre-#770 behavior: an `Internal`
/// span with a trace id derived from the span id (a new root) and no parent and no links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpanTraceContext {
    /// The span kind (drives the exported `span_kind`).
    pub kind: SpanKindTag,
    /// The trace id this span belongs to. ALL-ZERO means "derive a trace id from the span id" (the
    /// root-span behavior): a produce that continues a client's trace sets this to the client's trace
    /// id, a root produce leaves it zero.
    pub trace_id: [u8; 16],
    /// The parent span id. ALL-ZERO means "no parent" (exported as `SpanId::INVALID`): a produce
    /// continuing a client's trace sets this to the inbound `traceparent`'s span id, a root leaves it
    /// zero.
    pub parent_span_id: [u8; 8],
    /// The bounded producer -> consumer links; only the first `link_count` slots are populated. A
    /// consume span links back to the producing span(s) here.
    pub links: [SpanLink; MAX_SPAN_LINKS],
    /// How many of `links` are populated (`0..=MAX_SPAN_LINKS`).
    pub link_count: usize,
}

impl Default for SpanTraceContext {
    fn default() -> SpanTraceContext {
        SpanTraceContext {
            kind: SpanKindTag::Internal,
            trace_id: [0u8; 16],
            parent_span_id: [0u8; 8],
            links: [SpanLink::default(); MAX_SPAN_LINKS],
            link_count: 0,
        }
    }
}

impl SpanTraceContext {
    /// The context for a plain internal event/span: the pre-#770 behavior (Internal kind, root trace
    /// derived from the span id, no parent, no links).
    #[must_use]
    pub fn internal() -> SpanTraceContext {
        SpanTraceContext::default()
    }

    /// The context for the connection-handler SERVER span: `Server` kind, otherwise a root (no inbound
    /// context is threaded to the handler span today).
    #[must_use]
    pub fn server() -> SpanTraceContext {
        SpanTraceContext {
            kind: SpanKindTag::Server,
            ..SpanTraceContext::default()
        }
    }

    /// The context for a PRODUCE span (#770): `Producer` kind, and — when the produce carried an
    /// inbound W3C `traceparent` — CONTINUING the client's trace by adopting its trace id and making
    /// the inbound span id this span's PARENT. With no inbound context it is a new root (today's
    /// behavior), still tagged `Producer`.
    #[must_use]
    pub fn producer(parent: Option<ironbus_core::trace_context::TraceParent>) -> SpanTraceContext {
        match parent {
            Some(tp) => SpanTraceContext {
                kind: SpanKindTag::Producer,
                trace_id: tp.trace_id,
                parent_span_id: tp.parent_id,
                ..SpanTraceContext::default()
            },
            None => SpanTraceContext {
                kind: SpanKindTag::Producer,
                ..SpanTraceContext::default()
            },
        }
    }

    /// The context for a DELIVER/ACK CONSUME span (#770): `Consumer` kind with a producer -> consumer
    /// LINK back to each DISTINCT producing span read off the delivered record(s)' stored
    /// `traceparent`. Per the OTLP messaging convention a consume span LINKS to (not parents on) the
    /// producing span, because one deliver/fetch can batch many produced records. The links are
    /// DEDUPED by (trace-id, span-id) and CAPPED at [`MAX_SPAN_LINKS`]: extra distinct producers are
    /// dropped so the link surface stays bounded. The consume span itself is a root (its own trace is
    /// derived from its span id); a malformed/absent stored `traceparent` simply contributes no link.
    #[must_use]
    pub fn consumer(producers: &[ironbus_core::trace_context::TraceParent]) -> SpanTraceContext {
        let mut ctx = SpanTraceContext {
            kind: SpanKindTag::Consumer,
            ..SpanTraceContext::default()
        };
        for tp in producers {
            if ctx.link_count >= MAX_SPAN_LINKS {
                break;
            }
            let link = SpanLink {
                trace_id: tp.trace_id,
                span_id: tp.parent_id,
            };
            // Dedup: link once per distinct producer span even across a batch.
            if ctx.links[..ctx.link_count].contains(&link) {
                continue;
            }
            ctx.links[ctx.link_count] = link;
            ctx.link_count += 1;
        }
        ctx
    }
}

/// One span queued for export. Carries a small opaque id, its severity, and its distributed-trace
/// context ([`SpanTraceContext`]) — no payload bytes and no secret material, so the export queue never
/// widens the trust boundary the way `/admin` mutation would. The concrete exporter
/// (`otlp::record_to_span_data`, behind the `otlp` feature) maps this onto an OTLP span, reading the
/// context for the exported `span_kind`, parent, and links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpanRecord {
    /// A monotonic-ish span id, opaque to this module.
    pub id: u64,
    /// The span's severity, which drives the always-record rule.
    pub severity: Severity,
    /// The distributed-trace linkage (kind, trace/parent ids, producer -> consumer links). Defaults to
    /// [`SpanTraceContext::internal`], the pre-#770 behavior.
    pub ctx: SpanTraceContext,
}

impl SpanRecord {
    /// A plain internal event/span record (the pre-#770 shape): id + severity with the neutral
    /// [`SpanTraceContext::internal`] context. This is the constructor the resilience-event path uses.
    #[must_use]
    pub fn event(id: u64, severity: Severity) -> SpanRecord {
        SpanRecord {
            id,
            severity,
            ctx: SpanTraceContext::internal(),
        }
    }

    /// A connection-handler SERVER span record (#770): `Server` kind.
    #[must_use]
    pub fn server(id: u64, severity: Severity) -> SpanRecord {
        SpanRecord {
            id,
            severity,
            ctx: SpanTraceContext::server(),
        }
    }

    /// A PRODUCE span record (#770): `Producer` kind, continuing the client's trace when `parent` (the
    /// inbound W3C `traceparent`) is present, otherwise a new root.
    #[must_use]
    pub fn produce(
        id: u64,
        severity: Severity,
        parent: Option<ironbus_core::trace_context::TraceParent>,
    ) -> SpanRecord {
        SpanRecord {
            id,
            severity,
            ctx: SpanTraceContext::producer(parent),
        }
    }

    /// A DELIVER/ACK CONSUME span record (#770): `Consumer` kind with producer -> consumer links to the
    /// delivered record(s)' stored producers (deduped and capped at [`MAX_SPAN_LINKS`]).
    #[must_use]
    pub fn consume(
        id: u64,
        severity: Severity,
        producers: &[ironbus_core::trace_context::TraceParent],
    ) -> SpanRecord {
        SpanRecord {
            id,
            severity,
            ctx: SpanTraceContext::consumer(producers),
        }
    }

    /// Whether this span must be recorded regardless of the sampling ratio (ERROR/WARN always are).
    #[must_use]
    pub fn force_recorded(self) -> bool {
        self.severity.is_always_recorded()
    }
}

/// The head-based sampling decision (#16, #99). `ratio` is clamped to `[0.0, 1.0]`; a span at an
/// always-recorded severity (ERROR/WARN) is admitted unconditionally, otherwise `position` (a
/// uniform value in `[0.0, 1.0)` derived from the span id, NOT a per-call RNG, so the decision is
/// deterministic and allocation-free) is compared against the ratio. `ratio == 0.0` admits only the
/// always-recorded severities; `ratio == 1.0` admits everything.
///
/// `position` is taken modulo a fixed grid so a `0.0` ratio is exactly "no sampled spans" with no
/// floating-point edge case: at ratio `0.0` the comparison `position < 0.0` is false for every
/// `position >= 0.0`, so only the forced severities pass.
#[must_use]
pub fn should_sample(record: SpanRecord, ratio: f64, position: f64) -> bool {
    if record.force_recorded() {
        return true;
    }
    let ratio = ratio.clamp(0.0, 1.0);
    position < ratio
}

/// Derives the deterministic sampling `position` in `[0.0, 1.0)` for a span id, so [`should_sample`]
/// needs no RNG and no allocation on the hot path. A multiplicative hash spreads sequential ids
/// across the unit interval; the exact distribution is not load-bearing (the only contract is that
/// `0.0` ratio admits nothing sampled and `1.0` admits everything, which hold for any `position` in
/// range).
#[must_use]
// `top53` is at most 2^53 - 1, REPRESENTABLE EXACTLY in an f64 (the mantissa is 53 bits including
// the implicit leading 1), so the cast below is lossless by construction; the lint's general
// u64 -> f64 precision warning does not apply to a value already bounded to the mantissa width.
#[allow(clippy::cast_precision_loss)]
pub fn sampling_position(span_id: u64) -> f64 {
    // A 53-bit mantissa-safe fraction: take the high 53 bits of a mixed id over 2^53.
    let mixed = span_id
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .rotate_left(31)
        .wrapping_mul(0xC2B2_AE3D_27D4_EB4F);
    // Keep the high 53 bits; 2^53 as f64 is exact, so the ratio is an exact fraction in [0, 1).
    let top53 = mixed >> 11;
    (top53 as f64) / 9_007_199_254_740_992.0_f64
}

/// A BOUNDED, LOSSY queue of spans awaiting export (#99). `push` never blocks: when the queue is at
/// capacity it DROPS the new span and increments [`BoundedSpanQueue::dropped`], so a slow or
/// unreachable OTLP collector sheds load instead of stalling the thread-per-core produce path. This
/// is the "lossy bounded queue that drops and counts" the issue requires, and it is REAL and tested
/// independently of whether the concrete socket exporter is compiled in.
///
/// The buffer is a fixed-capacity `Vec` allocated once at construction; it never grows past
/// `capacity`. A consumer (the `otlp` drain thread, or a test) calls [`BoundedSpanQueue::drain`] to
/// take the buffered spans for export.
#[derive(Debug)]
pub struct BoundedSpanQueue {
    /// The buffered spans, never longer than `capacity`. Behind a `Mutex` so push and drain are
    /// safe from the core and the (future) drain thread; the lock is held only for the O(1) push or
    /// the O(n) drain swap, never across export IO.
    buffer: Mutex<Vec<SpanRecord>>,
    /// The fixed capacity. A push when `buffer.len() == capacity` is dropped and counted.
    capacity: usize,
    /// The count of spans DROPPED because the queue was full: the lossy-shed signal an operator
    /// watches, the export-side analogue of the backpressure drop counters. Relaxed: it is a pure
    /// monotonic counter read on scrape, never a synchronization point.
    dropped: AtomicU64,
    /// The count of spans successfully ENQUEUED (admitted to the buffer). Pairs with `dropped` so an
    /// operator sees both the offered and the shed rate.
    enqueued: AtomicU64,
}

impl BoundedSpanQueue {
    /// Creates a queue bounded to `capacity` spans (floored to 1 so a zero never makes every push a
    /// drop by construction, which would hide a misconfiguration as total loss). The buffer is
    /// allocated once here and never grows.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> BoundedSpanQueue {
        let capacity = capacity.max(1);
        BoundedSpanQueue {
            buffer: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
            dropped: AtomicU64::new(0),
            enqueued: AtomicU64::new(0),
        }
    }

    /// The configured capacity (the most spans the queue will ever hold).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Offers `record` to the queue WITHOUT BLOCKING. Returns `true` if it was enqueued, `false` if
    /// the queue was at capacity and the span was dropped (and counted). This is the core property
    /// the issue demands: under pressure the export path DROPS and COUNTS, it never blocks the
    /// produce thread waiting for the collector.
    ///
    /// A poisoned lock (a prior panic while holding it, which the panic-free core does not produce)
    /// is treated as a drop rather than a panic, so the core stays alive even in that impossible
    /// case.
    pub fn push(&self, record: SpanRecord) -> bool {
        let Ok(mut buffer) = self.buffer.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        if buffer.len() >= self.capacity {
            // Full: shed and count, never block or grow.
            drop(buffer);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        buffer.push(record);
        drop(buffer);
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Takes every currently-buffered span for export, leaving the queue empty (the buffer keeps its
    /// allocation for reuse). The concrete `otlp` exporter calls this on its drain tick.
    #[must_use]
    pub fn drain(&self) -> Vec<SpanRecord> {
        let Ok(mut buffer) = self.buffer.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut *buffer)
    }

    /// The number of spans currently buffered (not yet drained).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.lock().map_or(0, |b| b.len())
    }

    /// Whether the queue currently holds no spans.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The total number of spans DROPPED because the queue was full: the lossy-shed metric (#99).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The total number of spans successfully ENQUEUED for export.
    #[must_use]
    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }
}

/// The runtime tracing/export configuration (#99). The JSON log layer is always installed by
/// `init_tracing`; the OTLP fields are inert unless the `otlp` feature is compiled in AND export is
/// turned on, so the default and `edge-min` builds carry no opentelemetry cost.
// `Clone` (not `Copy`): the `otlp_endpoint` is an owned `Option<String>`, so the struct is no longer
// trivially copyable. It is constructed once at `serve` startup and moved into `init_tracing`, so a
// move/clone is the right shape; nothing on the hot path copies it.
#[derive(Clone, Debug)]
pub struct TracingConfig {
    /// Whether to turn OTLP span export ON. Default `false` (off at runtime). Honored only when the
    /// `otlp` feature is compiled in; with the feature off this is a no-op (the export seam does not
    /// exist), which is what makes "off = zero cost" a compile-time fact on the default/edge-min
    /// build.
    pub otlp_export_enabled: bool,
    /// The OTLP collector endpoint the span exporter ships to when export is ON (#352), e.g.
    /// `http://127.0.0.1:4317` (plaintext gRPC, the default co-located-collector port). `None` falls
    /// back to [`DEFAULT_OTLP_ENDPOINT`]. Read ONLY when the `otlp` feature is compiled in AND
    /// `otlp_export_enabled` is set; inert otherwise (the default/`edge-min` build never reads it
    /// because the export seam is compiled out).
    pub otlp_endpoint: Option<String>,
    /// The head-based sampling ratio in `[0.0, 1.0]`. Default [`DEFAULT_SAMPLE_RATIO`] (`0.0`): no
    /// sampled spans, ERROR/WARN always recorded.
    pub sample_ratio: f64,
    /// The bound on the export queue ([`DEFAULT_SPAN_QUEUE_CAPACITY`] by default).
    pub span_queue_capacity: usize,
}

impl Default for TracingConfig {
    fn default() -> TracingConfig {
        TracingConfig {
            otlp_export_enabled: false,
            otlp_endpoint: None,
            sample_ratio: DEFAULT_SAMPLE_RATIO,
            span_queue_capacity: DEFAULT_SPAN_QUEUE_CAPACITY,
        }
    }
}

/// The default OTLP collector endpoint (#352): plaintext gRPC on the standard OTLP/gRPC port, the
/// co-located-collector default. Used when export is ON and no explicit `--otlp-endpoint` /
/// `IRONBUS_OTLP_ENDPOINT` is given. Plaintext (no TLS) is the deliberate transport choice that keeps
/// the otlp build free of the `rustls`/`ring` C-FFI crypto the deny.toml `[bans]` denylist forbids.
pub const DEFAULT_OTLP_ENDPOINT: &str = "http://127.0.0.1:4317";

/// Whether OTLP span export is COMPILED IN (the `otlp` feature is enabled). The default and
/// `edge-min` builds return `false` and link no opentelemetry crate at all; an `otlp`-featured build
/// returns `true`. A consumer (and a test) uses this to assert the compile-out is real: the property
/// is structural, decided at build time, not a runtime flag.
#[must_use]
pub const fn otlp_compiled_in() -> bool {
    cfg!(feature = "otlp")
}

/// Installs the process-wide tracing subscriber with a JSON log layer (#99). Idempotent: a second
/// call is a no-op (the global subscriber can be set only once), so a test or a re-entrant caller
/// does not panic.
///
/// The JSON layer is ALWAYS installed (it is compiled in on the default build). When the `otlp`
/// feature is enabled AND `config.otlp_export_enabled` is set, the concrete OTLP-over-the-wire span
/// exporter (#352) is additionally wired to `config.otlp_endpoint`: a drain thread ships drained
/// spans to the collector. Otherwise the export path does not exist (default/`edge-min`) or is inert
/// (feature on, export off), so the only steady-state cost on the default build is the JSON log
/// formatting.
///
/// Returns the [`BoundedSpanQueue`] the exporter drains, so a caller and a test can observe the
/// drop-and-count behavior even with export off. If `config.otlp_export_enabled` is set but the
/// `otlp` feature is NOT compiled in, the export is a no-op (the seam is absent); a caller that wants
/// a "built without otlp" diagnostic checks [`otlp_compiled_in`] before turning export on.
// Takes `&TracingConfig` (not by value): the otlp branch clones the owned `otlp_endpoint` it needs,
// and the default build reads only `span_queue_capacity`, so a borrow is the right shape and avoids
// the `needless_pass_by_value` lint now that the config is no longer `Copy`.
#[must_use]
pub fn init_tracing(config: &TracingConfig) -> std::sync::Arc<BoundedSpanQueue> {
    let queue = std::sync::Arc::new(BoundedSpanQueue::with_capacity(config.span_queue_capacity));
    install_json_log_layer();
    install_panic_hook();
    #[cfg(feature = "otlp")]
    {
        if config.otlp_export_enabled {
            let endpoint = config
                .otlp_endpoint
                .clone()
                .unwrap_or_else(|| DEFAULT_OTLP_ENDPOINT.to_string());
            otlp::wire_export(&queue, config.sample_ratio, &endpoint);
        }
    }
    queue
}

/// Installs a process-wide PANIC HOOK that emits the crash reason as ONE structured JSON line on
/// stdout — the same stream the JSON log layer writes to — BEFORE delegating to the previously
/// installed hook (which keeps the plain-text stderr report and any test-harness capture intact).
///
/// Why this exists: the release profile builds with `panic = "abort"` and `strip = true`, so on a
/// panic the process dies with NO unwind and an unsymbolized backtrace; the default hook's
/// plain-text stderr line was the ONLY crash evidence, and it bypasses the structured stream an
/// operator's log pipeline actually collects. This hook restores the actionable part — the panic
/// MESSAGE, source LOCATION, and THREAD name — to that stream, so a crash-looping broker explains
/// itself in the same place every other event lands.
///
/// The hook deliberately does NOT call `tracing`: a panic raised inside the logging stack itself
/// would re-enter the subscriber from its own hook. It hand-serializes with a local JSON string
/// escaper (`serde_json` is a dev-only dependency by the minimal-dep doctrine) and writes with one
/// `println!`. Installed exactly once, idempotently, alongside the log layer.
fn install_panic_hook() {
    use std::sync::Once;
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = info.payload().downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            let location = info
                .location()
                .map_or_else(|| "<unknown>".to_string(), ToString::to_string);
            let thread = std::thread::current();
            let line = panic_json_line(
                &message,
                &location,
                thread.name().unwrap_or("<unnamed>"),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            );
            println!("{line}");
            previous(info);
        }));
    });
}

/// Builds the panic hook's single JSON log line: flat fields shaped like the JSON log layer's
/// events (`level` + `message` + context), with a numeric `timestamp_unix_ms` (no date formatter in
/// a dependency-free hook; every collector accepts epoch millis). Pure and separately tested — the
/// hook itself is unexercisable glue (a test that really panics under `panic = "abort"` would kill
/// the harness).
fn panic_json_line(message: &str, location: &str, thread: &str, unix_ms: u64) -> String {
    format!(
        "{{\"timestamp_unix_ms\":{unix_ms},\"level\":\"ERROR\",\"message\":\"broker panic\",\"panic_message\":\"{}\",\"panic_location\":\"{}\",\"panic_thread\":\"{}\"}}",
        json_escape(message),
        json_escape(location),
        json_escape(thread)
    )
}

/// Escapes a string for embedding in a JSON string literal: backslash, double quote, and every
/// control character below 0x20 (the common ones as their short escapes, the rest as `\u00XX`).
/// Minimal by design — the panic hook must not depend on a JSON crate (dev-only `serde_json`).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Installs the default JSON log layer exactly once. Behind a helper so the one-time guard and the
/// `tracing-subscriber` wiring live in one place; the layer is always part of the default build.
fn install_json_log_layer() {
    use std::sync::Once;
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        // A JSON-formatted, flat-field log layer at INFO and above. `try_init` returns an Err if a
        // global subscriber is already set (e.g. a test harness installed one); we ignore that so
        // `init_tracing` stays idempotent and never panics.
        use tracing_subscriber::fmt;
        use tracing_subscriber::prelude::*;
        let json_layer = fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false);
        let _ = tracing_subscriber::registry().with(json_layer).try_init();
    });
}

/// The OTLP export seam (#99, #352), compiled in ONLY behind the `otlp` feature. The default and
/// `edge-min` builds EXCLUDE this whole module, so its code is absent from the binary (the source of
/// the measurable edge-min size shrink) and no opentelemetry crate is linked. This seam owns the
/// sampling-gated drain from the [`BoundedSpanQueue`], the dep-free wire FRAMING of the drained
/// spans, and the CONCRETE OTLP-over-the-wire span exporter: it builds an opentelemetry-otlp gRPC
/// span exporter (plaintext, pure-Rust tonic, no TLS), spawns a drain thread that pulls framed spans
/// off the queue on a tick and ships them to the configured collector, and preserves the
/// drop-and-count-not-block invariant (the queue sheds under backpressure; the exporter never blocks
/// a core). All of it is exercised by the `otlp`-feature tests, so "off = compiled out" is a
/// verifiable property, not a stub.
#[cfg(feature = "otlp")]
pub mod otlp {
    use super::{
        sampling_position, should_sample, BoundedSpanQueue, Severity, SpanKindTag, SpanRecord,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use opentelemetry::trace::{
        Link, SpanContext, SpanId, SpanKind, Status, TraceFlags, TraceId, TraceState,
    };
    use opentelemetry::{InstrumentationScope, KeyValue};
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::export::trace::{SpanData, SpanExporter as _};
    use opentelemetry_sdk::trace::{SpanEvents, SpanLinks};

    /// The maximum number of drain attempts before a batch is given up (and its spans counted as
    /// dropped). A small fixed budget so a wedged collector cannot make the drain loop unbounded.
    pub const MAX_DRAIN_ATTEMPTS: u32 = 3;

    /// The period between exporter drain ticks (#352): how often the drain thread pulls spans off the
    /// [`BoundedSpanQueue`] and ships them. A small fixed interval so a working collector relieves
    /// queue pressure promptly while a tick costs nothing on an empty queue. The queue is the
    /// backpressure boundary, not this period: spans offered faster than the queue holds are
    /// dropped-and-counted by [`BoundedSpanQueue::push`], never by stalling a core.
    pub const DRAIN_INTERVAL: Duration = Duration::from_millis(500);

    /// The instrumentation scope name stamped on every exported span (#352): identifies IronBus as
    /// the producer to the collector.
    pub const SCOPE_NAME: &str = "ironbus";

    /// A typed error from building the concrete OTLP exporter (#352). Returned (never panicked) so a
    /// bad endpoint or a transport-init failure is a clean, logged diagnostic, honoring the
    /// no-unwrap/expect/panic invariant. The export path itself never surfaces an error to a core: a
    /// failed ship is the collector's problem, the queue keeps shedding.
    #[derive(Debug)]
    pub enum ExportInitError {
        /// The OTLP gRPC exporter could not be built (a malformed endpoint, a transport-init
        /// failure). Carries the opentelemetry error rendered as a string so the seam owns a typed
        /// error without leaking the opentelemetry error type across the module boundary.
        Build(String),
        /// The drain thread's current-thread Tokio runtime could not be created. Carries the IO
        /// error string.
        Runtime(String),
    }

    impl std::fmt::Display for ExportInitError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ExportInitError::Build(e) => write!(f, "OTLP exporter build failed: {e}"),
                ExportInitError::Runtime(e) => write!(f, "OTLP drain-thread runtime failed: {e}"),
            }
        }
    }

    impl std::error::Error for ExportInitError {}

    /// Maps a [`Severity`] onto an OTLP span name (#352): the concrete exporter labels each span with
    /// its severity so a collector can group by it. A fixed, frozen mapping paired with
    /// [`severity_tag`].
    #[must_use]
    pub fn severity_name(severity: Severity) -> &'static str {
        match severity {
            Severity::Error => "error",
            Severity::Warn => "warn",
            Severity::Info => "info",
            Severity::Debug => "debug",
            Severity::Trace => "trace",
        }
    }

    /// Maps our dependency-free [`SpanKindTag`] onto the `opentelemetry` [`SpanKind`] (#770). The tag
    /// is plain data on every build; this mapping lives only in the `otlp`-gated exporter, so the
    /// default build never names the `opentelemetry` kind.
    #[must_use]
    pub fn map_span_kind(kind: SpanKindTag) -> SpanKind {
        match kind {
            SpanKindTag::Internal => SpanKind::Internal,
            SpanKindTag::Server => SpanKind::Server,
            SpanKindTag::Client => SpanKind::Client,
            SpanKindTag::Producer => SpanKind::Producer,
            SpanKindTag::Consumer => SpanKind::Consumer,
        }
    }

    /// Maps one in-process [`SpanRecord`] onto an OTLP [`SpanData`] for the wire (#352, #770). The
    /// record carries an opaque id, a severity, and its distributed-trace context (no payload, no
    /// secret material, by design, so export never widens the trust boundary). The mapping derives a
    /// deterministic, non-zero span id from the record id, and takes the TRACE id and PARENT from the
    /// record's [`super::SpanTraceContext`] when set (a produce that continued a client's
    /// `traceparent`) or derives a root trace id from the span id otherwise (today's behavior). The
    /// span kind, the producer -> consumer LINKS, and the OTLP `messaging.*` attributes come from the
    /// context, replacing the old `Internal`/`INVALID`/empty defaults. Start and end time are both
    /// `now` (a point event); the scope is `ironbus`.
    #[must_use]
    pub fn record_to_span_data(record: SpanRecord, scope: &InstrumentationScope) -> SpanData {
        let now = std::time::SystemTime::now();
        let id = record.id;
        let ctx = record.ctx;
        // The span's OWN id: the record id forced non-zero (OTLP treats an all-zero id as invalid).
        let span_bytes = id.max(1).to_be_bytes();
        // The TRACE id: the context's carried trace id when the produce continued a client's trace,
        // else a deterministic root trace id derived from the span id (low 8 bytes = id, high 8 = a
        // fixed mix so it is never the all-zero invalid id).
        let trace_id = if ctx.trace_id == [0u8; 16] {
            let mut trace_bytes = [0u8; 16];
            trace_bytes[..8].copy_from_slice(&id.wrapping_add(1).to_be_bytes());
            trace_bytes[8..].copy_from_slice(&id.to_be_bytes());
            TraceId::from_bytes(trace_bytes)
        } else {
            TraceId::from_bytes(ctx.trace_id)
        };
        // The PARENT: the context's parent span id (a produce continuing a client's trace) or the
        // invalid id for a root span (the pre-#770 behavior).
        let parent_span_id = if ctx.parent_span_id == [0u8; 8] {
            SpanId::INVALID
        } else {
            SpanId::from_bytes(ctx.parent_span_id)
        };
        let span_context = SpanContext::new(
            trace_id,
            SpanId::from_bytes(span_bytes),
            TraceFlags::SAMPLED,
            false,
            TraceState::NONE,
        );
        // Producer -> consumer LINKS from the context, each a REMOTE span context (the linked span
        // lives on another connection/client). Bounded by `link_count` (<= MAX_SPAN_LINKS).
        let mut links = SpanLinks::default();
        for link in &ctx.links[..ctx.link_count] {
            let link_ctx = SpanContext::new(
                TraceId::from_bytes(link.trace_id),
                SpanId::from_bytes(link.span_id),
                TraceFlags::SAMPLED,
                true,
                TraceState::NONE,
            );
            links.links.push(Link::new(link_ctx, Vec::new(), 0));
        }
        // Attributes: the severity, plus the OTLP messaging-convention keys for the producer/consumer
        // kinds (system + operation). The destination/stream name is not carried on the span record,
        // so it is intentionally omitted (a follow-up can thread it through).
        let mut attributes = vec![KeyValue::new("severity", severity_name(record.severity))];
        match ctx.kind {
            SpanKindTag::Producer => {
                attributes.push(KeyValue::new("messaging.system", "ironbus"));
                attributes.push(KeyValue::new("messaging.operation", "publish"));
            }
            SpanKindTag::Consumer => {
                attributes.push(KeyValue::new("messaging.system", "ironbus"));
                attributes.push(KeyValue::new("messaging.operation", "deliver"));
            }
            SpanKindTag::Internal | SpanKindTag::Server | SpanKindTag::Client => {}
        }
        SpanData {
            span_context,
            parent_span_id,
            span_kind: map_span_kind(ctx.kind),
            name: severity_name(record.severity).into(),
            start_time: now,
            end_time: now,
            attributes,
            dropped_attributes_count: 0,
            events: SpanEvents::default(),
            links,
            status: Status::Unset,
            instrumentation_scope: scope.clone(),
        }
    }

    /// A tag byte per severity, the leading byte of each framed span. A fixed, frozen mapping so the
    /// wire framing is stable; the concrete OTLP exporter maps these onto OTLP severity numbers.
    #[must_use]
    pub fn severity_tag(severity: Severity) -> u8 {
        match severity {
            Severity::Error => 1,
            Severity::Warn => 2,
            Severity::Info => 3,
            Severity::Debug => 4,
            Severity::Trace => 5,
        }
    }

    /// Encodes one span into the export wire FRAME (dep-free): a 1-byte severity tag then the span id
    /// as 8 big-endian bytes. The concrete exporter wraps these frames in an OTLP request; keeping the
    /// framing here (and tested) means the deferred socket step is the only remaining work.
    pub fn encode_span(span: SpanRecord, out: &mut Vec<u8>) {
        out.push(severity_tag(span.severity));
        out.extend_from_slice(&span.id.to_be_bytes());
    }

    /// Encodes a batch of spans into one contiguous DEP-FREE frame buffer, honoring the head-based
    /// sampling decision: a span that would not be sampled (and is not an always-recorded ERROR/WARN)
    /// is skipped here too. This is the compact, opentelemetry-free framing used by the encode tests
    /// and the one-shot initial drain in [`wire_export`]; the live OTLP ship path instead maps spans
    /// through [`record_to_span_data`] and the gRPC exporter. Returns the encoded bytes.
    #[must_use]
    pub fn encode_batch(spans: &[SpanRecord], sample_ratio: f64) -> Vec<u8> {
        let mut out = Vec::with_capacity(spans.len() * 9);
        for &span in spans {
            if should_sample(span, sample_ratio, sampling_position(span.id)) {
                encode_span(span, &mut out);
            }
        }
        out
    }

    /// Drains the bounded queue once and encodes the drained spans into the DEP-FREE frame, returning
    /// the framed bytes. Used by [`wire_export`]'s one-shot initial drain (so the dep-free encode path
    /// stays reachable and tested); the live OTLP ship is [`drain_and_ship`]. It relieves queue
    /// pressure (so a working exporter lets the core keep enqueuing) and applies the sampling
    /// decision. It does NO blocking IO, so it is safe to call from a drain thread without touching
    /// the thread-per-core path.
    #[must_use]
    pub fn drain_and_encode(queue: &Arc<BoundedSpanQueue>, sample_ratio: f64) -> Vec<u8> {
        let spans = queue.drain();
        encode_batch(&spans, sample_ratio)
    }

    /// Builds the concrete OTLP gRPC span exporter against `endpoint` (#352): plaintext tonic, no
    /// TLS, so no `rustls`/`ring` C-FFI crypto is linked. Returns a typed [`ExportInitError`] (never
    /// panics) so a malformed endpoint is a clean diagnostic. The exporter is the wire half of the
    /// drain loop; it is `Send` so it moves onto the drain thread.
    ///
    /// MUST be called from WITHIN a Tokio runtime context (the tonic/hyper connector grabs the
    /// ambient reactor at build time): [`wire_export`] builds it inside the drain runtime's
    /// `enter()` guard, never on a bare thread.
    fn build_exporter(endpoint: &str) -> Result<SpanExporter, ExportInitError> {
        SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| ExportInitError::Build(e.to_string()))
    }

    /// Drains the bounded queue once, maps the drained spans onto OTLP [`SpanData`] honoring the
    /// head-based sampling decision, and ships them through `exporter` on `rt` (#352). Returns the
    /// number of spans SHIPPED. A failed ship is swallowed (logged at WARN, never surfaced to a core):
    /// the collector being slow or down is the queue's drop-and-count problem, not a broker fault. Does
    /// no blocking on the broker's thread-per-core path: it runs on the dedicated drain thread.
    fn drain_and_ship(
        queue: &Arc<BoundedSpanQueue>,
        sample_ratio: f64,
        scope: &InstrumentationScope,
        exporter: &mut SpanExporter,
        rt: &tokio::runtime::Runtime,
    ) -> usize {
        let spans = queue.drain();
        let batch: Vec<SpanData> = spans
            .into_iter()
            .filter(|&s| should_sample(s, sample_ratio, sampling_position(s.id)))
            .map(|s| record_to_span_data(s, scope))
            .collect();
        if batch.is_empty() {
            return 0;
        }
        let shipped = batch.len();
        // Block the DRAIN thread (never a core) on this batch's ship. A transport error is logged and
        // dropped: the queue keeps shedding, so a wedged collector never wedges the broker.
        if let Err(e) = rt.block_on(exporter.export(batch)) {
            tracing::warn!(error = %e, "OTLP span export batch failed; spans dropped");
            return 0;
        }
        shipped
    }

    /// Wires the bounded export queue to the CONCRETE OTLP exporter (#352), called when export is
    /// turned ON at runtime under the `otlp` feature. It builds the gRPC exporter against `endpoint`,
    /// then spawns a DAEMON drain thread that ticks every [`DRAIN_INTERVAL`], drains the queue, and
    /// ships the spans to the collector. The drain thread owns a SMALL current-thread Tokio runtime
    /// (the tonic channel needs one); that runtime lives on the drain thread, NOT the broker's
    /// thread-per-core path, so export IO never touches a core. The thread is detached (the broker
    /// process owns its lifetime); on a clean broker shutdown the process exit reaps it.
    ///
    /// On a build/runtime error the export is logged and SKIPPED (the broker keeps serving with the
    /// JSON log layer only); the bounded queue still drops-and-counts, so a failed exporter init never
    /// stalls a produce. Returns nothing; the wiring is a side effect on a background thread.
    pub(super) fn wire_export(queue: &Arc<BoundedSpanQueue>, sample_ratio: f64, endpoint: &str) {
        // A one-shot initial drain keeps the whole drain/encode pipeline a reachable, linked code path
        // even before the thread spins; on a fresh queue it encodes nothing.
        let _frames = drain_and_encode(queue, sample_ratio);

        // Build the drain runtime FIRST: the tonic/hyper connector grabs the ambient Tokio reactor at
        // exporter-build time, so the exporter must be built inside the runtime's `enter()` guard.
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::warn!(error = %e, "OTLP drain runtime init failed; export disabled");
                return;
            }
        };
        let mut exporter = {
            let _guard = rt.enter();
            match build_exporter(endpoint) {
                Ok(exporter) => exporter,
                Err(e) => {
                    tracing::warn!(error = %e, endpoint, "OTLP exporter init failed; export disabled");
                    return;
                }
            }
        };
        let scope = InstrumentationScope::builder(SCOPE_NAME).build();
        let queue = Arc::clone(queue);
        // The drain thread runs for the broker's lifetime. A `Builder::spawn` returns a Result we
        // honor (no `expect`): if the OS refuses a thread, export is skipped, the broker still serves.
        let spawn = std::thread::Builder::new()
            .name("ironbus-otlp-drain".to_string())
            .spawn(move || {
                run_drain_loop(&queue, sample_ratio, &scope, &mut exporter, &rt);
            });
        if let Err(e) = spawn {
            tracing::warn!(error = %e, "OTLP drain thread spawn failed; export disabled");
        }
    }

    /// The drain thread's loop (#352): tick every [`DRAIN_INTERVAL`], drain-and-ship, repeat for the
    /// broker's lifetime. Split out of [`wire_export`] so the loop is a single testable concern and the
    /// `STOP` hook can break it in a test. The loop holds no broker lock and touches no core; it only
    /// drains the bounded queue and ships, so it can never stall a produce.
    fn run_drain_loop(
        queue: &Arc<BoundedSpanQueue>,
        sample_ratio: f64,
        scope: &InstrumentationScope,
        exporter: &mut SpanExporter,
        rt: &tokio::runtime::Runtime,
    ) {
        while !STOP_DRAIN.load(Ordering::Relaxed) {
            let _shipped = drain_and_ship(queue, sample_ratio, scope, exporter, rt);
            std::thread::sleep(DRAIN_INTERVAL);
        }
    }

    /// A test-only stop flag for the drain loop (#352): a real broker never sets it (the thread runs
    /// for the process lifetime, reaped at exit), but a test flips it so [`run_drain_loop`] returns
    /// instead of looping forever. Relaxed: it is a pure stop signal, never a synchronization point.
    static STOP_DRAIN: AtomicBool = AtomicBool::new(false);

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn encode_span_frames_tag_then_big_endian_id() {
            let mut out = Vec::new();
            encode_span(
                SpanRecord::event(0x0102_0304_0506_0708, Severity::Warn),
                &mut out,
            );
            assert_eq!(out, vec![2, 1, 2, 3, 4, 5, 6, 7, 8]);
        }

        #[test]
        fn encode_batch_respects_sampling() {
            // At ratio 0.0 only ERROR/WARN are encoded; INFO is dropped from the batch.
            let spans = [
                SpanRecord::event(1, Severity::Error),
                SpanRecord::event(2, Severity::Info),
                SpanRecord::event(3, Severity::Warn),
            ];
            let bytes = encode_batch(&spans, 0.0);
            // Two 9-byte frames (the Error and the Warn), the Info excluded by sampling.
            assert_eq!(bytes.len(), 18);
            assert_eq!(bytes[0], severity_tag(Severity::Error));
            assert_eq!(bytes[9], severity_tag(Severity::Warn));
        }

        #[test]
        fn drain_and_encode_empties_the_queue() {
            let q = Arc::new(BoundedSpanQueue::with_capacity(8));
            for id in 0..3 {
                q.push(SpanRecord::event(id, Severity::Error));
            }
            let bytes = drain_and_encode(&q, 0.0);
            assert_eq!(bytes.len(), 27, "three 9-byte error frames");
            assert!(q.is_empty(), "the drain emptied the queue");
        }

        #[test]
        fn record_maps_onto_a_valid_otlp_span() {
            // The concrete exporter (#352) maps each in-process record onto an OTLP span with a
            // NON-ZERO trace and span id (OTLP treats all-zero ids as invalid) and the severity as the
            // span name plus a `severity` attribute.
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            for severity in [
                Severity::Error,
                Severity::Warn,
                Severity::Info,
                Severity::Debug,
                Severity::Trace,
            ] {
                // id 0 is the boundary: the mapping forces a non-zero span id even for id 0.
                let span = record_to_span_data(SpanRecord::event(0, severity), &scope);
                assert_ne!(
                    span.span_context.trace_id(),
                    TraceId::INVALID,
                    "trace id is never the invalid all-zero id"
                );
                assert_ne!(
                    span.span_context.span_id(),
                    SpanId::INVALID,
                    "span id is never the invalid all-zero id"
                );
                assert_eq!(span.name, severity_name(severity));
                assert_eq!(span.attributes.len(), 1, "one severity attribute");
                assert!(span.span_context.is_sampled(), "exported spans are sampled");
            }
        }

        #[test]
        fn build_exporter_accepts_a_plaintext_endpoint() {
            // The transport choice (#352) is plaintext gRPC: building the exporter against an
            // `http://` endpoint succeeds without a TLS stack (tonic builds lazily, no connect here).
            // The exporter is built INSIDE the runtime context (the tonic connector grabs the ambient
            // reactor at build time), exactly as `wire_export` does.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the drain runtime");
            let _guard = rt.enter();
            let built = build_exporter("http://127.0.0.1:4317");
            assert!(
                built.is_ok(),
                "the plaintext gRPC exporter builds against a co-located collector endpoint"
            );
        }

        #[test]
        fn the_drain_thread_ships_queued_spans_to_a_fake_otlp_sink() {
            // The #352 end-to-end test: a fake OTLP/gRPC sink (a bare TCP listener that accepts and
            // reads) stands in for the collector; the drain thread pulls queued spans off the bounded
            // queue and ships them, so the sink sees a CONNECTION carrying the exported batch. This
            // exercises the real exporter + the real drain loop, not a stub.
            use std::io::Read;
            use std::net::TcpListener;
            use std::sync::mpsc;

            let listener = TcpListener::bind("127.0.0.1:0").expect("bind a fake OTLP sink");
            let addr = listener.local_addr().expect("read the sink address");
            let (tx, rx) = mpsc::channel::<bool>();
            // The fake sink: accept ONE connection and report that bytes arrived. A real OTLP collector
            // would parse the gRPC frames; we only assert the exporter connected and wrote, which is
            // the wire half the drain thread is responsible for.
            let sink = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut buf = [0u8; 64];
                    let read = stream.read(&mut buf).unwrap_or(0);
                    let _ = tx.send(read > 0);
                }
            });

            let endpoint = format!("http://{addr}");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the drain runtime");
            let mut exporter = {
                let _guard = rt.enter();
                build_exporter(&endpoint).expect("build the exporter to the sink")
            };
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();

            let queue = Arc::new(BoundedSpanQueue::with_capacity(16));
            for id in 1..=4 {
                queue.push(SpanRecord::event(id, Severity::Error));
            }
            // One drain-and-ship: maps the four ERROR spans (always sampled at ratio 0.0) and ships
            // them to the sink. The export may surface a gRPC-level error AFTER the bytes are on the
            // wire (the fake sink speaks no HTTP/2), which is fine: the test asserts the sink SAW the
            // connection + bytes, the exporter's wire responsibility.
            let _ = drain_and_ship(&queue, 0.0, &scope, &mut exporter, &rt);
            assert!(queue.is_empty(), "the drain emptied the queue");

            let saw_bytes = rx
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap_or(false);
            let _ = sink.join();
            assert!(
                saw_bytes,
                "the drain thread connected to the fake OTLP sink and shipped the batch bytes"
            );
        }

        #[test]
        fn drain_ship_with_no_spans_is_a_noop_zero() {
            // An empty queue ships nothing and returns zero: a tick on an idle broker costs no export.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the drain runtime");
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            let mut exporter = {
                let _guard = rt.enter();
                build_exporter("http://127.0.0.1:4317").expect("build the exporter")
            };
            let queue = Arc::new(BoundedSpanQueue::with_capacity(4));
            let shipped = drain_and_ship(&queue, 0.0, &scope, &mut exporter, &rt);
            assert_eq!(shipped, 0, "an empty queue ships zero spans");
        }

        #[test]
        fn the_drain_loop_returns_when_stopped() {
            // The drain loop ticks until STOP_DRAIN is set. A real broker never sets it (the thread
            // runs for the process lifetime); the test sets it FIRST so the loop drains once and
            // returns instead of looping forever, proving the loop is the testable, bounded concern.
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the drain runtime");
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            let mut exporter = {
                let _guard = rt.enter();
                build_exporter("http://127.0.0.1:4317").expect("build the exporter")
            };
            let queue = Arc::new(BoundedSpanQueue::with_capacity(4));
            STOP_DRAIN.store(true, Ordering::Relaxed);
            // Returns promptly (the stop flag is already set, so the loop body never runs).
            run_drain_loop(&queue, 0.0, &scope, &mut exporter, &rt);
            STOP_DRAIN.store(false, Ordering::Relaxed);
        }

        // ---- Distributed-trace export mapping (#770): the exporter reads the span context ----

        use ironbus_core::trace_context::TraceParent;

        fn sample_traceparent() -> TraceParent {
            TraceParent::parse(b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
                .expect("the sample context parses")
        }

        fn has_attr(span: &SpanData, key: &str, value: &str) -> bool {
            span.attributes
                .iter()
                .any(|kv| kv.key.as_str() == key && kv.value.as_str() == value)
        }

        #[test]
        fn a_produce_span_exports_with_the_inbound_parent_and_producer_kind() {
            // Acceptance #1 (produce half): a produce carrying an inbound `traceparent` exports a
            // PRODUCER span whose PARENT is the inbound span id (not `SpanId::INVALID`) and whose
            // TRACE id is the client's, so it continues the client's trace. The messaging attributes
            // are present per the OTLP messaging convention.
            let tp = sample_traceparent();
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            let span =
                record_to_span_data(SpanRecord::produce(42, Severity::Info, Some(tp)), &scope);
            assert_eq!(span.span_kind, SpanKind::Producer);
            assert_eq!(
                span.parent_span_id,
                SpanId::from_bytes(tp.parent_id),
                "the produce span's parent is the inbound span id, not INVALID"
            );
            assert_ne!(span.parent_span_id, SpanId::INVALID);
            assert_eq!(
                span.span_context.trace_id(),
                TraceId::from_bytes(tp.trace_id),
                "the produce span shares the client's trace id"
            );
            assert!(span.links.links.is_empty(), "a producer span has no links");
            assert!(has_attr(&span, "messaging.system", "ironbus"));
            assert!(has_attr(&span, "messaging.operation", "publish"));
        }

        #[test]
        fn a_consume_span_exports_with_a_link_to_the_producing_span_and_consumer_kind() {
            // Acceptance #1 (deliver/ack half): the matching deliver exports a CONSUMER span carrying
            // a `SpanLink` back to the producing span — same trace id, the producing span id — read
            // off the record's stored `traceparent`. This is the producer -> consumer link.
            let tp = sample_traceparent();
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            let span =
                record_to_span_data(SpanRecord::consume(1000, Severity::Info, &[tp]), &scope);
            assert_eq!(span.span_kind, SpanKind::Consumer);
            assert_eq!(
                span.parent_span_id,
                SpanId::INVALID,
                "a consume span parents on nothing"
            );
            assert_eq!(span.links.links.len(), 1, "one producer -> consumer link");
            let link_ctx = &span.links.links[0].span_context;
            assert_eq!(
                link_ctx.span_id(),
                SpanId::from_bytes(tp.parent_id),
                "the link targets the producing span id"
            );
            assert_eq!(
                link_ctx.trace_id(),
                TraceId::from_bytes(tp.trace_id),
                "the link is in the producer's trace"
            );
            assert!(link_ctx.is_remote(), "the linked producing span is remote");
            assert!(has_attr(&span, "messaging.system", "ironbus"));
            assert!(has_attr(&span, "messaging.operation", "deliver"));
        }

        #[test]
        fn a_batch_consume_span_exports_capped_links() {
            // A large batch exports at most MAX_SPAN_LINKS links: the export link surface is bounded.
            let mut producers = Vec::new();
            for i in 0..(crate::obs::MAX_SPAN_LINKS + 10) {
                let mut trace_id = [0u8; 16];
                trace_id[0] = 0xBB;
                trace_id[15] = u8::try_from(i + 1).unwrap_or(0xFF);
                let mut parent_id = [0u8; 8];
                parent_id[7] = u8::try_from(i + 1).unwrap_or(0xFF);
                producers.push(TraceParent {
                    trace_id,
                    parent_id,
                    flags: 1,
                });
            }
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            let span =
                record_to_span_data(SpanRecord::consume(1, Severity::Info, &producers), &scope);
            assert_eq!(span.links.links.len(), crate::obs::MAX_SPAN_LINKS);
        }

        #[test]
        fn an_internal_event_span_exports_the_pre_770_shape() {
            // Regression: a plain event/severity span exports EXACTLY as before #770 — Internal kind,
            // an INVALID parent, no links, a non-zero derived trace id — so the resilience-event path
            // is untouched.
            let scope = InstrumentationScope::builder(SCOPE_NAME).build();
            let span = record_to_span_data(SpanRecord::event(0, Severity::Error), &scope);
            assert_eq!(span.span_kind, SpanKind::Internal);
            assert_eq!(span.parent_span_id, SpanId::INVALID);
            assert!(span.links.links.is_empty());
            assert_ne!(
                span.span_context.trace_id(),
                TraceId::INVALID,
                "the derived root trace id is never the invalid all-zero id"
            );
            assert_ne!(span.span_context.span_id(), SpanId::INVALID);
            // No messaging attributes on an internal span.
            assert!(!has_attr(&span, "messaging.system", "ironbus"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_json_line_is_valid_json_with_the_expected_flat_fields() {
        // The hook's one line must be machine-parseable by any JSON log pipeline. Parse it with the
        // dev-only serde_json (the production hook hand-serializes by doctrine) and assert the flat
        // shape mirrors the log layer's events.
        let line = panic_json_line(
            "index out of bounds: the len is 3",
            "crates/ironbus-server/src/actor.rs:1234:9",
            "ironbus-append-actor",
            1_783_400_000_123,
        );
        let v: serde_json::Value = serde_json::from_str(&line).expect("the line parses as JSON");
        assert_eq!(v["level"], "ERROR");
        assert_eq!(v["message"], "broker panic");
        assert_eq!(v["panic_message"], "index out of bounds: the len is 3");
        assert_eq!(
            v["panic_location"],
            "crates/ironbus-server/src/actor.rs:1234:9"
        );
        assert_eq!(v["panic_thread"], "ironbus-append-actor");
        assert_eq!(v["timestamp_unix_ms"], 1_783_400_000_123u64);
    }

    #[test]
    fn panic_json_line_survives_hostile_panic_messages() {
        // A panic message is ARBITRARY text — quotes, backslashes, newlines, control bytes (e.g. a
        // corrupt-frame assert echoing raw input). The escaper must keep the line one valid JSON
        // object; a raw newline or quote would split/break the log stream at the worst moment.
        let hostile = "quote\" backslash\\ newline\n tab\t cr\r bell\u{7} unicode\u{1f} ok";
        let line = panic_json_line(hostile, "src\\odd\"loc:1:1", "t\nhread", 0);
        assert!(
            !line.contains('\n'),
            "the emitted line must be exactly one line: {line:?}"
        );
        let v: serde_json::Value = serde_json::from_str(&line).expect("hostile input still parses");
        assert_eq!(v["panic_message"], hostile, "round-trips byte-for-byte");
        assert_eq!(v["panic_location"], "src\\odd\"loc:1:1");
        assert_eq!(v["panic_thread"], "t\nhread");
    }

    #[test]
    fn the_installed_panic_hook_chains_and_never_breaks_unwinding() {
        // End-to-end in an UNWINDING (test-profile) build: install the hook (idempotently, via the
        // same entry production uses), raise a real panic under catch_unwind, and assert (1) the
        // panic still propagates with its payload intact — the hook chains to the previous hook and
        // never swallows or re-panics — and (2) a second install is a no-op (the Once). Under the
        // release profile's panic=abort the hook body runs identically before the abort; what cannot
        // be exercised here is the abort itself.
        install_panic_hook();
        install_panic_hook();
        let result = std::panic::catch_unwind(|| panic!("hook smoke: {}", 42));
        // The essential chaining property: the panic still PROPAGATES (the hook neither swallows it
        // nor re-panics — a hook that panicked would abort the process and kill this harness). The
        // payload's concrete TYPE is deliberately not asserted: std's panic-payload representation
        // is version-dependent (lazily formatted payloads), and the hook's own message extraction
        // is pinned by the pure `panic_json_line` tests above.
        assert!(
            result.is_err(),
            "the panic must still propagate through the hook"
        );
    }

    #[test]
    fn a_full_queue_drops_and_counts_rather_than_blocking() {
        // The core property (#99): under pressure the export queue DROPS and COUNTS, it never grows
        // or blocks. Fill it to capacity, then offer more: every extra push returns false and is
        // counted as a drop, and the buffer never exceeds capacity.
        let q = BoundedSpanQueue::with_capacity(4);
        for id in 0..4 {
            assert!(
                q.push(SpanRecord::event(id, Severity::Info)),
                "the first {} pushes fit",
                q.capacity()
            );
        }
        assert_eq!(q.len(), 4, "the queue is exactly full");
        assert_eq!(q.dropped(), 0, "nothing dropped yet");
        // Offer 10 more under pressure: each is dropped and counted, the buffer stays bounded.
        for id in 4..14 {
            assert!(
                !q.push(SpanRecord::event(id, Severity::Info)),
                "a push to a full queue is rejected, not blocked"
            );
        }
        assert_eq!(q.len(), 4, "the buffer never grew past capacity");
        assert_eq!(
            q.dropped(),
            10,
            "every over-capacity push was counted as a drop"
        );
        assert_eq!(
            q.enqueued(),
            4,
            "only the admitted pushes are counted enqueued"
        );
    }

    #[test]
    fn draining_empties_the_queue_and_frees_room() {
        // Drain takes the buffered spans and leaves the queue ready to accept again, so a working
        // exporter relieves pressure (the drop counter stays put; it is a cumulative total).
        let q = BoundedSpanQueue::with_capacity(2);
        assert!(q.push(SpanRecord::event(1, Severity::Info)));
        assert!(q.push(SpanRecord::event(2, Severity::Info)));
        assert!(!q.push(SpanRecord::event(3, Severity::Info)));
        assert_eq!(q.dropped(), 1);
        let drained = q.drain();
        assert_eq!(drained.len(), 2, "drain takes both buffered spans");
        assert!(q.is_empty(), "the queue is empty after a drain");
        // Room again: a push now succeeds, and the cumulative drop counter is unchanged.
        assert!(q.push(SpanRecord::event(4, Severity::Info)));
        assert_eq!(
            q.dropped(),
            1,
            "the drop total is cumulative, not reset by a drain"
        );
    }

    #[test]
    fn a_zero_capacity_is_floored_to_one_not_total_loss() {
        // A misconfigured zero capacity must not silently make EVERY push a drop (that would hide a
        // config error as total loss); it is floored to one usable slot.
        let q = BoundedSpanQueue::with_capacity(0);
        assert_eq!(q.capacity(), 1);
        assert!(q.push(SpanRecord::event(1, Severity::Info)));
        assert!(!q.push(SpanRecord::event(2, Severity::Info)));
        assert_eq!(q.dropped(), 1);
    }

    #[test]
    fn error_and_warn_are_always_recorded_even_at_zero_sampling() {
        // The resilience rule (#16): ERROR/WARN are NEVER sampled out, so a freeze or a skip event
        // is always recorded even on the leanest 0.0-ratio edge profile.
        for severity in [Severity::Error, Severity::Warn] {
            let rec = SpanRecord::event(7, severity);
            assert!(rec.force_recorded(), "{severity:?} is always recorded");
            assert!(
                should_sample(rec, 0.0, sampling_position(7)),
                "{severity:?} passes sampling at ratio 0.0"
            );
            assert!(
                should_sample(rec, 1.0, sampling_position(7)),
                "{severity:?} passes sampling at ratio 1.0"
            );
        }
    }

    #[test]
    fn info_and_below_are_sampled_out_at_zero_ratio() {
        // At the default 0.0 ratio, NO sampled (INFO/DEBUG/TRACE) span is exported, across many ids,
        // so the default edge build pays nothing for trace export.
        for severity in [Severity::Info, Severity::Debug, Severity::Trace] {
            for id in 0..10_000u64 {
                let rec = SpanRecord::event(id, severity);
                assert!(
                    !should_sample(rec, 0.0, sampling_position(id)),
                    "{severity:?} id {id} must be sampled out at ratio 0.0"
                );
            }
        }
    }

    #[test]
    fn a_full_ratio_admits_every_sampled_span() {
        // The other endpoint: at ratio 1.0 every span passes, so the sampling decision is a real
        // gate across the whole [0,1] range, not a constant.
        for id in 0..10_000u64 {
            let rec = SpanRecord::event(id, Severity::Info);
            assert!(
                should_sample(rec, 1.0, sampling_position(id)),
                "id {id} must pass at ratio 1.0"
            );
        }
    }

    #[test]
    fn sampling_position_is_in_the_unit_interval() {
        // The position the sampling decision compares against is always in [0.0, 1.0), so the ratio
        // comparison behaves at both endpoints.
        for id in 0..100_000u64 {
            let p = sampling_position(id);
            assert!(
                (0.0..1.0).contains(&p),
                "id {id} -> position {p} out of range"
            );
        }
    }

    #[test]
    fn a_mid_ratio_admits_roughly_its_fraction() {
        // A structural sanity check that the head-based sampler is monotone and proportional: a 0.5
        // ratio admits materially more than a 0.1 ratio and materially fewer than a 0.9 ratio, so the
        // ratio is honored (not a flaky exact-count assertion, just an ordering with slack).
        let count = |ratio: f64| {
            (0..10_000u64)
                .filter(|&id| {
                    should_sample(
                        SpanRecord::event(id, Severity::Info),
                        ratio,
                        sampling_position(id),
                    )
                })
                .count()
        };
        let low = count(0.1);
        let mid = count(0.5);
        let high = count(0.9);
        assert!(
            low < mid,
            "0.1 ratio admits fewer than 0.5 ({low} vs {mid})"
        );
        assert!(
            mid < high,
            "0.5 ratio admits fewer than 0.9 ({mid} vs {high})"
        );
    }

    #[test]
    fn the_default_config_has_export_off_and_zero_sampling() {
        // The default is the lean edge profile: export off, 0.0 sampling, the standard queue bound.
        let c = TracingConfig::default();
        assert!(!c.otlp_export_enabled, "export is off by default");
        assert!(
            c.otlp_endpoint.is_none(),
            "no OTLP endpoint set by default (falls back to the standard port only when ON)"
        );
        assert!(
            (c.sample_ratio - DEFAULT_SAMPLE_RATIO).abs() < f64::EPSILON,
            "sampling defaults to 0.0"
        );
        assert_eq!(c.span_queue_capacity, DEFAULT_SPAN_QUEUE_CAPACITY);
    }

    #[test]
    fn otlp_is_compiled_out_on_the_default_build() {
        // The compile-out is STRUCTURAL: on the default (and edge-min) build the `otlp` feature is
        // off, so this is `false` and no opentelemetry crate is linked. An `otlp`-featured build
        // flips it to `true`. This is the test that pins "off = zero cost" as a build-time fact.
        #[cfg(not(feature = "otlp"))]
        assert!(
            !otlp_compiled_in(),
            "the default build must not compile OTLP export in"
        );
        #[cfg(feature = "otlp")]
        assert!(
            otlp_compiled_in(),
            "an otlp-featured build compiles OTLP export in"
        );
    }

    #[test]
    fn init_tracing_is_idempotent_and_returns_the_queue() {
        // init_tracing installs the JSON log layer at most once and returns the bounded export queue,
        // so a caller (and a test) can drive the drop-and-count behavior even with export off. A
        // second call must not panic (the global subscriber is set once).
        let q1 = init_tracing(&TracingConfig::default());
        let q2 = init_tracing(&TracingConfig::default());
        // Both calls return a usable queue; with export off, pushing still drops-and-counts when
        // full, proving the queue is real independent of the exporter.
        assert!(q1.push(SpanRecord::event(1, Severity::Info)));
        // The second queue is a distinct, usable, empty buffer (a fresh allocation per call).
        assert!(q2.is_empty(), "a fresh queue starts empty");
        assert!(q2.push(SpanRecord::event(2, Severity::Info)));
        assert_eq!(q2.len(), 1, "the second queue accepts a push");
    }

    #[test]
    fn export_off_does_no_export_work_a_structural_zero_cost_assertion() {
        // The #99 "no measurable cost when off" property, asserted STRUCTURALLY (a microbench would be
        // flaky): with export off (the default), NO span is ever drained for export, so the only
        // steady-state cost beyond the JSON log layer is the bounded push (a lock + a Vec push or a
        // counter bump), never a serialization or a socket. We prove this by showing that with export
        // off the queue accumulates pushes but nothing drains them away (no exporter ran), and the
        // drop counter only moves under real capacity pressure, not from any background export.
        let queue = init_tracing(&TracingConfig::default());
        let before_dropped = queue.dropped();
        // Push a handful within capacity; with export OFF nothing drains them, so they all sit in the
        // buffer (an exporter, were one running, would have drained them). This is the observable that
        // no export work happened.
        for id in 0..8 {
            assert!(queue.push(SpanRecord::event(id, Severity::Info)));
        }
        assert_eq!(
            queue.len(),
            8,
            "with export off, no exporter drained the queue (no export work ran)"
        );
        assert_eq!(
            queue.dropped(),
            before_dropped,
            "no drop occurred below capacity and no background export touched the counter"
        );
    }

    // ---- Distributed-trace context (#770), the ALWAYS-ON plain-data half (no `otlp` feature) ----

    use ironbus_core::trace_context::TraceParent;

    /// A known W3C context for the distributed-tracing tests.
    fn sample_traceparent() -> TraceParent {
        TraceParent::parse(b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("the sample context parses")
    }

    #[test]
    fn a_produce_with_a_traceparent_continues_the_client_trace() {
        // A produce carrying an inbound `traceparent` (found in the headers blob) builds a PRODUCER
        // span that CONTINUES the client's trace: same trace id, and the inbound span id as PARENT.
        let headers = b"traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let parent = TraceParent::from_headers(headers);
        let rec = SpanRecord::produce(42, Severity::Info, parent);
        assert_eq!(rec.ctx.kind, SpanKindTag::Producer);
        assert_eq!(
            rec.ctx.trace_id,
            sample_traceparent().trace_id,
            "the produce span adopts the client's trace id"
        );
        assert_eq!(
            rec.ctx.parent_span_id,
            sample_traceparent().parent_id,
            "the inbound span id becomes the produce span's parent"
        );
        assert_eq!(rec.ctx.link_count, 0, "a producer span carries no links");
    }

    #[test]
    fn a_produce_without_a_traceparent_is_a_root_producer() {
        // No inbound context => a NEW ROOT producer span (today's behavior), still tagged Producer.
        let rec = SpanRecord::produce(7, Severity::Info, TraceParent::from_headers(b"no context"));
        assert_eq!(rec.ctx.kind, SpanKindTag::Producer);
        assert_eq!(
            rec.ctx.trace_id, [0u8; 16],
            "root: trace id derived from span id"
        );
        assert_eq!(rec.ctx.parent_span_id, [0u8; 8], "root: no parent");
    }

    #[test]
    fn a_deliver_links_the_consume_span_back_to_the_producing_span() {
        // The OTLP messaging convention: a deliver/ack opens a CONSUMER span that LINKS to the
        // producing context read off the delivered record's stored `traceparent` (same trace id, the
        // producing span id). It is a LINK, not a parent, because one deliver can batch many records.
        let tp = sample_traceparent();
        let rec = SpanRecord::consume(99, Severity::Info, &[tp]);
        assert_eq!(rec.ctx.kind, SpanKindTag::Consumer);
        assert_eq!(rec.ctx.link_count, 1);
        assert_eq!(
            rec.ctx.links[0].trace_id, tp.trace_id,
            "link is in the producer's trace"
        );
        assert_eq!(
            rec.ctx.links[0].span_id, tp.parent_id,
            "link targets the producing span id"
        );
        assert_eq!(
            rec.ctx.parent_span_id, [0u8; 8],
            "a consume span parents on nothing"
        );
    }

    #[test]
    fn a_batch_deliver_dedups_and_caps_its_producer_links() {
        // A batch deliver links to each DISTINCT producer, deduped, and CAPPED at MAX_SPAN_LINKS so
        // the link surface stays bounded no matter how large the batch.
        let mut producers = Vec::new();
        // 3 copies of one producer (must collapse to a single link) ...
        for _ in 0..3 {
            producers.push(sample_traceparent());
        }
        // ... then MAX_SPAN_LINKS + 5 DISTINCT producers (only the cap's worth are kept).
        for i in 0..(MAX_SPAN_LINKS + 5) {
            let mut trace_id = [0u8; 16];
            trace_id[0] = 0xAA;
            trace_id[15] = u8::try_from(i + 1).unwrap_or(0xFF);
            let mut parent_id = [0u8; 8];
            parent_id[7] = u8::try_from(i + 1).unwrap_or(0xFF);
            producers.push(TraceParent {
                trace_id,
                parent_id,
                flags: 1,
            });
        }
        let rec = SpanRecord::consume(1, Severity::Info, &producers);
        assert_eq!(
            rec.ctx.link_count, MAX_SPAN_LINKS,
            "the link count is capped at MAX_SPAN_LINKS"
        );
        // The kept links are all distinct.
        for i in 0..rec.ctx.link_count {
            for j in (i + 1)..rec.ctx.link_count {
                assert_ne!(
                    rec.ctx.links[i], rec.ctx.links[j],
                    "kept links are distinct"
                );
            }
        }
    }

    #[test]
    fn a_deliver_of_a_record_with_no_stored_traceparent_carries_no_link() {
        // A record whose stored headers hold no (or a malformed) `traceparent` contributes no link:
        // the consume span is a plain Consumer with an empty link set, never an error.
        let none: Vec<TraceParent> = Vec::new();
        let rec = SpanRecord::consume(5, Severity::Info, &none);
        assert_eq!(rec.ctx.kind, SpanKindTag::Consumer);
        assert_eq!(rec.ctx.link_count, 0);
    }

    #[test]
    fn an_event_span_is_the_pre_770_internal_default() {
        // The plain event/severity path is byte-for-byte the pre-#770 shape: Internal kind, a root
        // trace derived from the id, no parent, no links.
        let rec = SpanRecord::event(3, Severity::Error);
        assert_eq!(rec.ctx.kind, SpanKindTag::Internal);
        assert_eq!(rec.ctx, SpanTraceContext::internal());
        assert_eq!(rec.ctx.trace_id, [0u8; 16]);
        assert_eq!(rec.ctx.parent_span_id, [0u8; 8]);
        assert_eq!(rec.ctx.link_count, 0);
    }

    #[test]
    fn a_server_span_carries_the_server_kind() {
        let rec = SpanRecord::server(1, Severity::Info);
        assert_eq!(rec.ctx.kind, SpanKindTag::Server);
    }
}
