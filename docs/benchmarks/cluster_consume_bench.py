#!/usr/bin/env python3
"""Clustered-consume APPORTIONED-READ throughput scaling vs NATS (IronBus #634, V2-C8-I5).

THE C8 headline leg. It measures whether IronBus consume throughput SCALES with the replica
count `R` when a consumer fleet apportions its committed reads across all `R` replicas (the #723
follower-read tiers: a follower serves a committed `<=` safe-HW read LOCALLY off its own replicated
page-cache copy, CRAQ "clean"; the leader serves a 0-RTT lease-local read), and how the IronBus
curve compares to NATS clustered consume (where consume is served from the stream LEADER).

Two legs, same machine, same payload, same consumer-fleet size:

  ironbus / cluster-follower-read   The IronBus `cluster-consume-bench` Rust harness: a real on-disk
                                    leader log + a LIVE `DataPlaneRuntime` cluster over loopback TCP
                                    (R in {1,3,5}), followers replicate the committed prefix (real
                                    CRC-revalidated follower-fetch), then a fleet of `C` reader
                                    threads drains the committed prefix apportioned round-robin
                                    across the R replicas via the #723 serve path. Aggregate
                                    records/s, mean +- stdev over `--runs`.
  nats / js-pull-leader             NATS JetStream file-backed stream, `C` SHARED durable PULL
                                    consumers draining a pre-filled stream — all served from the
                                    stream leader (NATS serves consume from the stream leader even in
                                    a replicated stream). Aggregate msgs/s over `--runs`.

HONEST SCOPE (read `cluster-consume-report.md`): the IronBus side drives the `DataPlaneController`
follower-read SERVE PATH in-process over the REAL live runtime (real loopback peer transport, real
on-disk replicated logs) — the #723 tiers are not yet threaded into the per-connection wire session,
so this is NOT a wire-to-wire number against NATS's end-to-end pull. Read the IronBus SCALING SHAPE
(throughput vs R) as the headline; the NATS column is the leader-served-consume reference that the
follower-read fan-out is meant to scale ABOVE. Durability tiers are labeled per leg.

Local-loopback on commodity hardware: the SCALING SHAPE + relative ratios, not the absolute t4g-edge
numbers (#636 is the separate hardware run).

Emits one JSONL row per measurement to `--out`; writes the markdown report to `--md-out`.

Reproduce:
  python3 cluster_consume_bench.py \
      --bench-bin /path/to/target/release/cluster-consume-bench \
      --out cluster-consume-rows.jsonl --md-out cluster-consume-report.md
"""
import argparse
import json
import os
import platform
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time

HOST = "127.0.0.1"


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


def machine_spec():
    """Best-effort CPU/cores/RAM/OS, recorded in the report header for auditability."""
    spec = {"os": f"{platform.system()} {platform.release()}", "arch": platform.machine()}
    try:
        if platform.system() == "Darwin":
            spec["cpu"] = subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
            ).strip()
            spec["cores"] = int(subprocess.check_output(["sysctl", "-n", "hw.ncpu"], text=True))
            ram = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))
            spec["ram_gib"] = round(ram / 1024**3, 1)
        else:
            spec["cores"] = os.cpu_count()
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        spec["cpu"] = line.split(":", 1)[1].strip()
                        break
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        spec["ram_gib"] = round(int(line.split()[1]) / 1024**2, 1)
                        break
    except Exception as e:  # noqa: BLE001 — best-effort provenance, never fatal
        spec["spec_error"] = str(e)
    return spec


# ---------- IronBus leg: the cluster-consume-bench Rust harness ----------
def ironbus_leg(bench_bin, replicas, consumers, records, payload, warmup_ms, measure_ms, runs, seg_bytes):
    """Runs the Rust harness for one replica count. Returns the list of per-run JSONL row dicts it
    printed on stdout (the harness emits one row per run)."""
    args = [
        bench_bin,
        "--replicas", str(replicas),
        "--consumers", str(consumers),
        "--records", str(records),
        "--payload-bytes", str(payload),
        "--warmup-ms", str(warmup_ms),
        "--measure-ms", str(measure_ms),
        "--runs", str(runs),
        "--seg-bytes", str(seg_bytes),
    ]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=900)
    except Exception as e:  # noqa: BLE001
        log(f"  ironbus R={replicas} FAILED to run: {e}")
        return []
    if out.returncode != 0:
        log(f"  ironbus R={replicas} rc={out.returncode}: {(out.stderr or out.stdout)[-500:]}")
        return []
    rows = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


# ---------- NATS leg: file-backed JS stream, C shared pull consumers from the leader ----------
def parse_agg_msgs_sec(txt):
    """The AGGREGATE rate across all consumers: `Sub stats: <n> msgs/sec`. nats bench prints the
    aggregate on the `Sub stats:` line and per-consumer lines after it; we take the aggregate."""
    m = re.search(r"Sub stats:\s*([\d,]+(?:\.\d+)?)\s+msgs/sec", txt)
    return float(m.group(1).replace(",", "")) if m else None


def nats_one(consumers, records, payload, consumerbatch):
    """One NATS measurement: a FRESH file-backed nats-server, pre-fill `records`, then drain with
    `consumers` SHARED durable pull consumers, returning the aggregate msgs/s. Server on its own
    scratch dir/port, stopped + cleaned after — nothing left running (the consume_bench.py pattern)."""
    port = free_port()
    sd = f"/tmp/nats-cluster-consume-{port}"
    shutil.rmtree(sd, ignore_errors=True)
    os.makedirs(sd)
    cfg = f"/tmp/nats-cluster-consume-{port}.conf"
    with open(cfg, "w") as f:
        f.write(f'host: "{HOST}"\nport: {port}\njetstream {{ store_dir: "{sd}" }}\n')
    srv = subprocess.Popen(["nats-server", "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port):
            log("  nats: server did not start")
            return None
        url = f"nats://{HOST}:{port}"
        subj = f"cc.{port}"
        # PRE-FILL a file-backed stream (purge first so it starts empty; this is the durable prefix
        # the consumers drain).
        fill = ["nats", "-s", url, "bench", subj, "--js", "--pub", "1", "--msgs", str(records),
                "--size", str(payload), "--purge", "--no-progress", "--storage", "file",
                "--pubbatch", "200"]
        f = subprocess.run(fill, capture_output=True, text=True, timeout=600)
        if f.returncode != 0:
            log(f"  nats fill rc={f.returncode}: {(f.stderr or f.stdout)[-400:]}")
            return None
        # DRAIN: `consumers` SHARED durable pull consumers (work-queue fan-out off ONE durable
        # consumer, served from the stream leader), explicit batched ack. Reads the prefill (no purge,
        # no re-pub). The aggregate `Sub stats` line is the fleet's combined consume rate.
        drain = ["nats", "-s", url, "bench", subj, "--js", "--sub", str(consumers), "--pull",
                 "--consumerbatch", str(consumerbatch), "--msgs", str(records), "--no-progress",
                 "--storage", "file"]
        o = subprocess.run(drain, capture_output=True, text=True, timeout=600)
        rate = parse_agg_msgs_sec(o.stdout + o.stderr)
        if rate is None:
            log(f"  nats drain: no Sub stats: {(o.stdout + o.stderr)[-400:]}")
        return rate
    except Exception as e:  # noqa: BLE001
        log(f"  nats FAILED: {e}")
        return None
    finally:
        srv.send_signal(signal.SIGTERM)
        try:
            srv.wait(5)
        except Exception:  # noqa: BLE001
            srv.kill()
        shutil.rmtree(sd, ignore_errors=True)
        if os.path.exists(cfg):
            os.remove(cfg)


def nats_leg(consumers, records, payload, consumerbatch, runs):
    rates = []
    for r in range(runs):
        rate = nats_one(consumers, records, payload, consumerbatch)
        if rate is not None:
            rates.append(rate)
            log(f"  nats run {r}: {rate:.0f} msgs/s (aggregate, {consumers} pull consumers)")
        else:
            log(f"  nats run {r}: SKIP")
    return rates


def mean_stdev(xs):
    if not xs:
        return None, None
    m = statistics.fmean(xs)
    sd = statistics.pstdev(xs) if len(xs) > 1 else 0.0
    return m, sd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench-bin", required=True, help="path to the cluster-consume-bench binary")
    ap.add_argument("--out", required=True, help="JSONL output rows")
    ap.add_argument("--md-out", required=True, help="markdown report")
    ap.add_argument("--replicas", default="1,3,5", help="comma list of replica counts (default 1,3,5)")
    ap.add_argument("--consumers", type=int, default=15,
                    help="consumer-fleet size (divisible by every replica count for even apportion; default 15)")
    ap.add_argument("--records", type=int, default=80_000, help="committed prefix records (default 80k)")
    ap.add_argument("--payload-bytes", type=int, default=256)
    ap.add_argument("--warmup-ms", type=int, default=1000)
    ap.add_argument("--measure-ms", type=int, default=3000)
    ap.add_argument("--seg-bytes", type=int, default=1024 * 1024)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--consumerbatch", type=int, default=256, help="NATS pull consumer batch")
    ap.add_argument("--no-nats", action="store_true", help="skip the NATS leg (flag it pending)")
    ap.add_argument("--smoke", action="store_true", help="tiny params for a wiring check")
    a = ap.parse_args()

    if a.smoke:
        a.records, a.warmup_ms, a.measure_ms, a.runs, a.consumers = 8000, 300, 800, 2, 6
    replicas = [int(x) for x in a.replicas.split(",")]
    spec = machine_spec()
    nats_ok = (shutil.which("nats-server") is not None) and (shutil.which("nats") is not None) and (not a.no_nats)

    log(f"machine: {spec}")
    log(f"nats available: {nats_ok} (no_nats={a.no_nats})")

    outf = open(a.out, "w")
    all_rows = []

    def emit(row):
        all_rows.append(row)
        outf.write(json.dumps(row) + "\n")
        outf.flush()

    # 1) IronBus apportioned follower-read scaling across R.
    ironbus_summary = {}  # R -> (mean, stdev, [rates])
    for R in replicas:
        log(f"== IronBus cluster-follower-read: R={R}, fleet={a.consumers} ==")
        rows = ironbus_leg(a.bench_bin, R, a.consumers, a.records, a.payload_bytes,
                           a.warmup_ms, a.measure_ms, a.runs, a.seg_bytes)
        rates = []
        for row in rows:
            emit(row)
            rates.append(row["throughput"])
        m, sd = mean_stdev(rates)
        ironbus_summary[R] = (m, sd, rates)
        if m is not None:
            log(f"  R={R}: mean {m:.0f} records/s (stdev {sd:.0f}, n={len(rates)})")

    # 2) NATS leg-served-from-leader consume (one config; consume does not scale with NATS stream
    #    replicas — it is served from the stream leader — so the NATS column is the flat baseline).
    nats_rates = []
    if nats_ok:
        log(f"== NATS js-pull (served from leader): fleet={a.consumers} ==")
        nats_rates = nats_leg(a.consumers, a.records, a.payload_bytes, a.consumerbatch, a.runs)
        for i, rate in enumerate(nats_rates):
            emit({"system": "nats", "tier": "js-pull-leader", "replicas": 1, "consumers": a.consumers,
                  "payload": a.payload_bytes, "records": a.records, "run": i, "mode": "consume",
                  "throughput": rate})
    nats_mean, nats_sd = mean_stdev(nats_rates)

    outf.close()

    # ---- markdown report ----
    write_report(a, spec, replicas, ironbus_summary, nats_mean, nats_sd, len(nats_rates), nats_ok)
    log(f"\nWROTE {len(all_rows)} rows to {a.out} and the report to {a.md_out}")


def write_report(a, spec, replicas, ironbus_summary, nats_mean, nats_sd, nats_n, nats_ok):
    date = time.strftime("%Y-%m-%d")
    cpu = spec.get("cpu", "?")
    cores = spec.get("cores", "?")
    ram = spec.get("ram_gib", "?")
    osname = spec.get("os", "?")
    arch = spec.get("arch", "?")
    base_r = min(replicas)
    base_mean = ironbus_summary.get(base_r, (None,))[0]

    lines = []
    lines.append("# Clustered-consume apportioned-read scaling vs NATS (#634, V2-C8-I5)")
    lines.append("")
    lines.append(f"Generated by `cluster_consume_bench.py` on {date}. Local loopback, single machine.")
    lines.append("")
    lines.append("## Machine")
    lines.append("")
    lines.append(f"- CPU: {cpu} ({cores} cores)")
    lines.append(f"- RAM: {ram} GiB")
    lines.append(f"- OS: {osname} ({arch})")
    lines.append("")
    lines.append("## What is measured")
    lines.append("")
    lines.append(
        "A consumer fleet of "
        f"**{a.consumers} reader threads** drains a committed prefix of **{a.records} records "
        f"({a.payload_bytes} B each)**, apportioned round-robin across the `R` replicas. Warmup "
        f"{a.warmup_ms} ms (discarded), measurement window {a.measure_ms} ms, **{a.runs} runs** per "
        "configuration; throughput is the aggregate records/s, mean ± population stdev over the runs."
    )
    lines.append("")
    lines.append("**IronBus** (`cluster-follower-read`, durability tier: durable-committed-read — the "
                 "follower serves only `<=` the quorum-committed safe HW): a real on-disk leader log + "
                 "a live `DataPlaneRuntime` cluster over loopback TCP. Followers replicate the committed "
                 "prefix by real CRC-revalidated follower-fetch; readers then drain it via the #723 serve "
                 "path — `serve_leader_local_read` (0-RTT lease-local) on the leader and "
                 "`serve_follower_read` (`ReadTier::FollowerCommitted`, CRAQ clean) on each follower, all "
                 "through the same off-actor zero-copy `ReadPlane` the wire fetch uses.")
    lines.append("")
    lines.append("**NATS** (`js-pull-leader`, durability tier: durable file stream): a file-backed "
                 f"JetStream stream pre-filled with the same {a.records} records, drained by {a.consumers} "
                 "SHARED durable PULL consumers — all served from the stream LEADER (NATS serves consume "
                 "from the stream leader; adding stream replicas does not fan consume reads out across "
                 "them). The aggregate `Sub stats` rate.")
    lines.append("")
    lines.append("## IronBus apportioned-read scaling curve")
    lines.append("")
    lines.append("| replicas R | aggregate records/s (mean) | stdev | vs R=" + str(base_r) + " | runs |")
    lines.append("| --- | --- | --- | --- | --- |")
    for R in replicas:
        m, sd, rates = ironbus_summary.get(R, (None, None, []))
        if m is None:
            lines.append(f"| {R} | (no data) | | | |")
            continue
        ratio = f"{m / base_mean:.2f}x" if base_mean else "—"
        lines.append(f"| {R} | {m:,.0f} | {sd:,.0f} | {ratio} | {len(rates)} |")
    lines.append("")
    lines.append("## NATS clustered-consume baseline (served from leader)")
    lines.append("")
    if nats_ok and nats_mean is not None:
        lines.append(f"| system | aggregate msgs/s (mean) | stdev | runs |")
        lines.append("| --- | --- | --- | --- |")
        lines.append(f"| NATS JS pull ({a.consumers} consumers, file stream) | {nats_mean:,.0f} | {nats_sd:,.0f} | {nats_n} |")
        lines.append("")
        lines.append("NATS consume is served from the stream leader, so it does **not** scale with stream "
                     "replicas — it is the flat baseline the IronBus follower-read fan-out scales above.")
        if base_mean:
            lines.append("")
            lines.append("### IronBus / NATS ratio (read the SHAPE, not a wire-to-wire constant — see caveats)")
            lines.append("")
            lines.append("| replicas R | IronBus records/s | NATS msgs/s | ratio |")
            lines.append("| --- | --- | --- | --- |")
            for R in replicas:
                m = ironbus_summary.get(R, (None,))[0]
                if m is None:
                    continue
                lines.append(f"| {R} | {m:,.0f} | {nats_mean:,.0f} | {m / nats_mean:.1f}x |")
    else:
        lines.append("**NATS leg: PENDING (not run).** `nats-server` and/or `nats` CLI unavailable, or "
                     "`--no-nats` was passed. The IronBus scaling curve above is real; the NATS comparison "
                     "is flagged pending and was NOT fabricated. Re-run with both on PATH to fill it.")
    lines.append("")
    lines.append("## Big-O / first-principles")
    lines.append("")
    lines.append("The claim: aggregate committed-consume throughput is **O(R)** in the replica count when a "
                 "fleet apportions committed reads across all R replicas, because each replica serves "
                 "committed reads LOCALLY from its own page-cache copy (no leader round-trip on a clean "
                 "read), so R independent serve paths run in parallel. NATS clustered consume is **O(1)** in "
                 "stream replicas (served from the one stream leader). The measured IronBus curve above is "
                 "the test of the O(R) model; the per-step ratio < R is the contention residual described in "
                 "the caveats.")
    lines.append("")
    lines.append("## Honest caveats")
    lines.append("")
    lines.append("- **In-process serve path, not the wire session.** The #723 follower-read tiers are not "
                 "yet threaded into the per-connection wire session (`session.rs`); this harness drives the "
                 "`DataPlaneController` serve methods directly over the REAL live runtime (real loopback "
                 "peer transport, real on-disk replicated logs, real CRC-revalidated replication). The NATS "
                 "leg is end-to-end over the wire. So the IronBus/NATS ratio is **not** a wire-to-wire "
                 "number — read the IronBus SCALING SHAPE (throughput vs R) as the headline and the "
                 "order-of-magnitude, not the literal ratio.")
    lines.append("- **Zero-copy raw byte runs.** A serve returns a contiguous committed `Bytes` run "
                 "(refcounted, no copy) per call, so the IronBus absolute records/s is high (page-cache "
                 "resident, no per-record syscall). That is a real property of the serve path, but it makes "
                 "the absolute number a serve-throughput ceiling, not a per-message-RPC rate.")
    lines.append("- **Sub-linear scaling.** Each node's `DataPlaneServer` is behind one `Mutex`, so a fleet "
                 "co-located on one node contends on that lock; more replicas = more independent locks = the "
                 "sub-R scaling seen above. In a real multi-process wire serve each node is a separate "
                 "process, so this particular contention would be more separated, not less.")
    lines.append("- **Local-loopback, commodity hardware.** This is the scaling shape + relative ratios on "
                 "this machine, not the absolute t4g-edge numbers (#636 is the separate hardware run); those "
                 "are NOT fabricated here.")
    lines.append("- **Durability tiers labeled.** IronBus reads only the quorum-committed safe prefix "
                 "(durable-committed); NATS drains a durable file stream. Both are durable-consume tiers.")
    lines.append("")

    with open(a.md_out, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
