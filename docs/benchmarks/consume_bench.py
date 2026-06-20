#!/usr/bin/env python3
"""Single-consumer CONSUME corpus runner (IronBus #554, V2-M1 headline proof).

The consume-side twin of `corpus_bench.py`. It measures DURABLE single-consumer
consume throughput head-to-head:

  ironbus / tier-s-streaming  IronBus Tier-S streaming consumer (batched StreamFetch +
                              bounded read-ahead + periodic cumulative StreamCommit,
                              the #662 default): the merged streaming-tier consume path.
  nats    / js-pull           NATS JetStream durable PULL consumer, explicit batched ack
                              against a file-backed stream (the durability-matched peer).

plus two context legs (appendix, NOT a durable head-to-head):

  ironbus / tier-w-work       IronBus Tier-W per-message-lease work queue (the path IronBus
                              used to be measured on, where it lost ~3-20x to NATS).
  nats-core / core-sub        NATS CORE subscriber: no JetStream, no persistence, no replay
                              (at-most-once live delivery, a different durability tier).

Both durable sides drain a pre-filled durable file-backed prefix and persist their
consume cursor, so a crash redelivers only the uncommitted span (at-least-once). The
rows feed `cargo run -p ironbus-bench --bin consume-corpus`, whose durability-label
lint refuses a mislabeled (durable-vs-non-durable) consume comparison.

Emits one JSONL row per (system, tier, payload). Run on the rig (a t4g AWS Graviton2
here), all loopback. NOT for CI. Self-contained: each NATS server runs on a scratch
dir/port and is stopped after; nothing is left running.

Reproduce:
  python3 consume_bench.py --ironbus /path/to/ironbus --out consume-rows.jsonl
  cargo run -p ironbus-bench --bin consume-corpus -- \
      --rows consume-rows.jsonl --json-out consume-report.json --md-out consume-report.md
"""
import argparse, json, os, re, shutil, signal, socket, subprocess, sys, time

HOST = "127.0.0.1"
CONSUME_N = 200_000        # records pre-filled then drained for the consume metric. Larger than the
                           # produce corpus's 2k: durable streaming/pull consume is fast, so a small
                           # count is warm-up-dominated; 200k gives a steady drain rate.
FETCH_BATCH = 256          # the consumer window on BOTH durable sides (IronBus --fetch-batch /
                           # StreamConsumerConfig.max_records; NATS --consumerbatch), so the tiers,
                           # not the window sizes, are what differ.


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def free_port():
    s = socket.socket()
    s.bind((HOST, 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def parse_msgs_sec(txt):
    """Pulls the first `<n> msgs/sec` figure out of a `nats bench` summary."""
    m = re.search(r"([\d,]+(?:\.\d+)?)\s+msgs/sec", txt)
    return float(m.group(1).replace(",", "")) if m else None


# ---------- IronBus (native bench CLI, spawns its own broker) ----------
def ironbus_consume(binpath, tier, payload, records):
    """Drains `records` pre-filled durable records via the chosen consume tier and returns the
    measured drain throughput. The bench pre-fills the queue itself (pipelined, group-committed),
    then times only the drain; `--no-fsync` keeps the PRE-FILL off the SD fsync path (the drain rate,
    the metric, is durability-independent), exactly as the produce corpus's consume row does."""
    consume_tier = "streaming" if tier == "tier-s-streaming" else "work"
    args = [
        binpath, "bench", "--mode", "subscribe",
        "--consume-tier", consume_tier,
        "--count", str(records),
        "--payload-bytes", str(payload),
        "--payload-shape", "realistic",
        "--fetch-batch", str(FETCH_BATCH),
        "--no-fsync", "--json",
    ]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=1200)
        if out.returncode != 0:
            log(f"  ironbus {tier}/{payload}/{records} rc={out.returncode}: {(out.stderr or out.stdout)[:300]}")
            return None
        r = json.loads(out.stdout)["results"]
        return dict(throughput=r["msgs_per_sec"], p50=r.get("latency_p50_us"),
                    p99=r.get("latency_p99_us"), p999=r.get("latency_p999_us"))
    except Exception as e:
        log(f"  ironbus {tier}/{payload}/{records} FAILED: {e}")
        return None


# ---------- NATS JetStream durable PULL consumer ----------
def nats_js_pull(payload, records):
    """Pre-fills a file-backed JetStream stream with `records` records, then drains it with a SINGLE
    durable PULL consumer (explicit batched ack), measuring the consume rate. This is the durable
    single-consumer consume head-to-head for IronBus Tier-S streaming."""
    port = free_port()
    sd = f"/tmp/nats-consume-{port}"
    shutil.rmtree(sd, ignore_errors=True)
    os.makedirs(sd)
    cfg = f"/tmp/nats-consume-{port}.conf"
    open(cfg, "w").write(f'host: "{HOST}"\nport: {port}\njetstream {{ store_dir: "{sd}" }}\n')
    srv = subprocess.Popen(["nats-server", "-c", cfg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port):
            log("  nats-js: no start")
            return None
        url = f"nats://{HOST}:{port}"
        subj = f"consume.{port}"
        size = str(payload)
        # PRE-FILL: async JS publish defines + fills the default benchstream. --purge first so the
        # stream starts empty; the consume run reads exactly this durable prefix.
        fill = ["nats", "-s", url, "bench", subj, "--js", "--pub", "1",
                "--msgs", str(records), "--size", size, "--purge", "--no-progress",
                "--pubbatch", "200"]
        f = subprocess.run(fill, capture_output=True, text=True, timeout=600)
        if f.returncode != 0:
            log(f"  nats-js fill/{payload}/{records} rc={f.returncode}: {(f.stderr or f.stdout)[:300]}")
            return None
        # DRAIN: one durable pull consumer, explicit batched ack, consumerbatch = FETCH_BATCH. Does
        # NOT --purge (read the prefill), does NOT re-publish.
        con = ["nats", "-s", url, "bench", subj, "--js", "--sub", "1", "--pull",
               "--consumerbatch", str(FETCH_BATCH), "--msgs", str(records), "--no-progress"]
        o = subprocess.run(con, capture_output=True, text=True, timeout=600)
        thr = parse_msgs_sec(o.stdout + o.stderr)
        if thr is None:
            log(f"  nats-js consume/{payload}/{records}: {(o.stdout + o.stderr)[:300]}")
        return dict(throughput=thr, p50=None, p99=None, p999=None) if thr else None
    except Exception as e:
        log(f"  nats-js/{payload}/{records} FAILED: {e}")
        return None
    finally:
        srv.send_signal(signal.SIGTERM)
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        shutil.rmtree(sd, ignore_errors=True)
        if os.path.exists(cfg):
            os.remove(cfg)


# ---------- NATS Core subscriber (no JetStream: non-durable reference) ----------
def nats_core_sub(payload, records):
    """NATS CORE: no JetStream, no persistence, no replay. There is nothing to pre-fill and drain (a
    core sub only sees LIVE messages), so this measures the live pub->sub DELIVERY rate of one
    publisher into one subscriber: the at-most-once reference ceiling, NOT a durable drain. It is the
    non-durable reference point, reported in the appendix, never paired against a durable consumer."""
    port = free_port()
    cfg = f"/tmp/nats-core-consume-{port}.conf"
    open(cfg, "w").write(f'host: "{HOST}"\nport: {port}\n')  # NO jetstream block == core only
    srv = subprocess.Popen(["nats-server", "-c", cfg],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port):
            log("  nats-core: no start")
            return None
        url = f"nats://{HOST}:{port}"
        subj = f"core.consume.{port}"
        size = str(payload)
        # One publisher, one subscriber, core (no --js): the subscriber's reported rate is the live
        # delivery throughput. --pub starts after --sub is ready (nats bench coordinates them).
        cmd = ["nats", "-s", url, "bench", subj, "--pub", "1", "--sub", "1",
               "--msgs", str(records), "--size", size, "--no-progress"]
        o = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        txt = o.stdout + o.stderr
        # In pub+sub mode nats bench prints separate Pub/Sub stats blocks; take the LAST msgs/sec
        # (the aggregate/sub line) as the delivery rate.
        rates = re.findall(r"([\d,]+(?:\.\d+)?)\s+msgs/sec", txt)
        if not rates:
            log(f"  nats-core/{payload}: {txt[:300]}")
            return None
        return dict(throughput=float(rates[-1].replace(",", "")), p50=None, p99=None, p999=None)
    except Exception as e:
        log(f"  nats-core/{payload} FAILED: {e}")
        return None
    finally:
        srv.send_signal(signal.SIGTERM)
        try:
            srv.wait(5)
        except Exception:
            srv.kill()
        if os.path.exists(cfg):
            os.remove(cfg)


# The headline record-count SWEEP (256 B): IronBus Tier-S streaming durable consume vs NATS JS pull
# over the same record counts. Pre-#665 this sweep exposed a super-linear IronBus degradation (the
# server StreamFetch read SPAN was segment-wide, so each fetch read O(distance-to-segment-end) bytes
# => ~O(N^2) over the drain) that crossed UNDER NATS near ~30k records. #665 clamps the read span to
# the consumer window, so post-#665 the IronBus curve is FLAT-to-rising and beats NATS at every point
# of 20k..200k (the unconditional win). Sweeping over the same counts is what makes that flat-vs-
# crossover claim falsifiable rather than a single cherry-picked N. Recorded in PERF_LEDGER.
SWEEP_COUNTS = [20_000, 50_000, 100_000, 200_000]
# The single MATCHED record count the lint-gated corpus pairs build at (the headline scoreboard
# point). DEFAULT 20k: a realistic small/moderate prefill. Post-#665 the streaming-tier consume win
# holds across the WHOLE sweep (no NATS crossover in range), so 20k is a representative point on a
# flat curve rather than the only point where IronBus leads — the full curve is published in the
# sweep regardless.
CORPUS_N = 20_000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ironbus", required=True)
    ap.add_argument("--out", required=True, help="lint-gated corpus rows (consume-corpus input)")
    ap.add_argument("--sweep-out", help="optional JSONL of the 256B record-count sweep curve")
    ap.add_argument("--corpus-n", type=int, default=CORPUS_N,
                    help=f"matched record count for the corpus head-to-head (default {CORPUS_N})")
    ap.add_argument("--smoke", action="store_true",
                    help="a reduced sweep + record count, for a quick wiring check")
    a = ap.parse_args()
    sweep_counts = [20_000] if a.smoke else SWEEP_COUNTS
    corpus_n = 20_000 if a.smoke else a.corpus_n
    payloads = [256] if a.smoke else [256, 4096]

    outf = open(a.out, "w")
    sweepf = open(a.sweep_out, "w") if a.sweep_out else None
    rows = []

    def emit(f, system, tier, payload, records, res):
        if not res or res.get("throughput") is None:
            log(f"SKIP {system}/{tier}/{payload}/{records}")
            return
        row = dict(system=system, tier=tier, payload=payload, records=records, mode="consume", **res)
        if f is outf:
            rows.append(row)
        # The corpus reader keys on (system, tier, payload); the sweep file additionally carries
        # `records`. Both are valid JSONL; the corpus ignores the extra `records` key.
        f.write(json.dumps(row) + "\n")
        f.flush()
        log(f"OK  {system:9} {tier:16} {payload:5}B n={records:<7} -> {res['throughput']:.0f} msg/s"
            + (f" p99={res['p99']:.0f}us" if res.get('p99') else ""))

    # 1) THE HEADLINE record-count SWEEP at 256 B: IronBus Tier-S streaming vs NATS JS pull over the
    #    same counts, so the crossover is explicit. Median-free single runs (the curve, not a point).
    if sweepf is not None:
        log("== 256B record-count sweep: IronBus Tier-S streaming vs NATS JS pull ==")
        for n in sweep_counts:
            emit(sweepf, "ironbus", "tier-s-streaming", 256, n,
                 ironbus_consume(a.ironbus, "tier-s-streaming", 256, n))
            emit(sweepf, "nats", "js-pull", 256, n, nats_js_pull(256, n))

    # 2) THE LINT-GATED CORPUS rows at the matched CORPUS_N per payload (the scoreboard the
    #    consume-corpus assembler pairs and lints): Tier-S streaming vs NATS JS pull (head-to-head),
    #    plus the Tier-W work-queue + NATS core sub context legs.
    log(f"== matched corpus rows at n={corpus_n} ==")
    for payload in payloads:
        emit(outf, "ironbus", "tier-s-streaming", payload, corpus_n,
             ironbus_consume(a.ironbus, "tier-s-streaming", payload, corpus_n))
        emit(outf, "nats", "js-pull", payload, corpus_n, nats_js_pull(payload, corpus_n))
        emit(outf, "ironbus", "tier-w-work", payload, corpus_n,
             ironbus_consume(a.ironbus, "tier-w-work", payload, corpus_n))
        emit(outf, "nats-core", "core-sub", payload, corpus_n, nats_core_sub(payload, corpus_n))

    outf.close()
    if sweepf is not None:
        sweepf.close()
    log(f"\nWROTE {len(rows)} corpus rows to {a.out}"
        + (f" + sweep curve to {a.sweep_out}" if a.sweep_out else ""))


if __name__ == "__main__":
    main()
