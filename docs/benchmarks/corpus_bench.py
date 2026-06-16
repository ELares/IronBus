#!/usr/bin/env python3
"""Competitor benchmark corpus runner (IronBus #19/#114 host-residual fill).

Runs IronBus and the edge-class peers (NATS JetStream, Redis Streams, Mosquitto
MQTT) under MATCHED durability tiers on the SAME device/loopback, emitting one
JSONL row per (system, tier, payload, mode). Rows feed the `ironbus-bench`
ComparisonReport assembler, whose durability-label lint refuses a mislabeled
(marketing) comparison.

Two comparable metrics, both THROUGHPUT (the rig's primary, apples-to-apples field):
  publish  produce -> ack, at the tier's durability
  consume  drain a pre-filled store/queue as fast as possible (closes the
           never-benched consume-side gap)

Durability tiers (assigned to BOTH sides of a pair by the assembler):
  sync-per-message  power-loss-safe, one fdatasync per ack   (IB window=1; NATS pub sync + sync_interval=always; Redis appendfsync=always; -P1)
  page-cache-async  NOT power-loss-safe (labeled)            (IB --no-fsync; NATS async default; Redis appendfsync=everysec pipelined)
  memory            ephemeral, no disk                       (IB --storage memory; NATS memory store; Redis no-AOF)

Latency: reported only where the tool yields a natively-saturated percentile
(NATS pub). Cross-system latency is NOT headlined: the load models differ
(IronBus/Redis closed-loop vs NATS open-loop), so throughput is the comparable
metric, exactly as the rig's ComparisonRow centers on throughput.

MQTT is a routing protocol over session state, not a durable log: its honest
labels are mqtt-qos{0,1}, and the assembler reports it as context, never
force-paired with the log systems under a shared durability label.

Run on the hive (armv7 Raspbian), all loopback. NOT for CI. Self-contained:
each peer broker runs on a scratch dir/port and is stopped after; nothing is left
running.
"""
import argparse, json, os, re, shutil, signal, socket, subprocess, sys, time

HOST = "127.0.0.1"
PUB_DURATION = 12          # seconds, relaxed/memory publish (rate-bound)
CONSUME_N = 2000           # messages pre-filled then drained for the consume metric. Kept modest
                           # because IronBus's competing work-queue drain acks per message (cumulative
                           # ack is broadcast-only) and checkpoints the cursor, so its drain is
                           # ack-bound; peers batch their acks. Consume is reported as each system's
                           # native default consume path, NOT a durability-matched head-to-head.
DEVICE = "edge-min-pi4-1000000088e76a84"   # RPi4 armv7, the canonical edge box

def log(*a): print(*a, file=sys.stderr, flush=True)
def free_port():
    s = socket.socket(); s.bind((HOST, 0)); p = s.getsockname()[1]; s.close(); return p
def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((HOST, port), timeout=0.5): return True
        except OSError: time.sleep(0.2)
    return False

# ---------- IronBus (native bench CLI, spawns its own broker) ----------
def ironbus(binpath, tier, payload, mode):
    base = [binpath, "bench", "--payload-bytes", str(payload), "--payload-shape", "realistic", "--json"]
    if mode == "consume":
        # Drain rate is independent of write durability: pre-fill FAST (disk + --no-fsync,
        # i.e. page-cache, so the preload is not fsync-bound) and measure the subscribe
        # fetch+ack throughput. Disk (not memory) so the preload is retained in full, not
        # shed under a memory byte cap. Tier is not varied for consume.
        args = base + ["--mode", "subscribe", "--count", str(CONSUME_N),
                       "--fetch-batch", "256", "--no-fsync"]
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=600)
            r = json.loads(out.stdout)["results"]
            return dict(throughput=r["msgs_per_sec"], p50=r.get("latency_p50_us"),
                        p99=r.get("latency_p99_us"), p999=r.get("latency_p999_us"))
        except Exception as e:
            log(f"  ironbus consume/{payload} FAILED: {e}"); return None
    args = base + ["--mode", "publish", "--duration", str(PUB_DURATION)]
    if tier == "sync-per-message":   args += ["--pubwindow", "1"]
    elif tier == "group-commit-fsync": args += ["--pubwindow", "1024", "--stream"]
    elif tier == "page-cache-async": args += ["--pubwindow", "1024", "--stream", "--no-fsync"]
    elif tier == "memory":           args += ["--pubwindow", "1024", "--stream", "--storage", "memory"]
    else: return None
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=600)
        r = json.loads(out.stdout)["results"]
        return dict(throughput=r["msgs_per_sec"], p50=r.get("latency_p50_us"),
                    p99=r.get("latency_p99_us"), p999=r.get("latency_p999_us"))
    except Exception as e:
        log(f"  ironbus {tier}/{payload}/{mode} FAILED: {e}"); return None

# ---------- NATS JetStream ----------
def nats(tier, payload, mode):
    port = free_port(); sd = f"/tmp/nats-corpus-{port}"; shutil.rmtree(sd, ignore_errors=True); os.makedirs(sd)
    cfg = f"/tmp/nats-corpus-{port}.conf"
    sync = 'sync_interval: "always"' if tier == "sync-per-message" else ""
    open(cfg, "w").write(f'host: "{HOST}"\nport: {port}\njetstream {{ store_dir: "{sd}"\n{sync}\n}}\n')
    srv = subprocess.Popen(["nats-server", "-c", cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def parse(txt):
        g = lambda m: float(m.group(1).replace(",", "")) if m else None
        return dict(throughput=g(re.search(r"([\d,]+(?:\.\d+)?)\s+msgs/sec", txt)),
                    p50=g(re.search(r"P50:\s*([\d,.]+)us", txt)),
                    p99=g(re.search(r"P99:\s*([\d,.]+)us", txt)),
                    p999=g(re.search(r"P99\.9:\s*([\d,.]+)us", txt)))
    try:
        if not wait_port(port): log("  nats: no start"); return None
        url = f"nats://{HOST}:{port}"; storage = "memory" if tier == "memory" else "file"
        subj = f"corpus.{port}"; stream = f"CORP{port}"; size = f"{payload}B"
        if mode == "publish":
            if tier == "sync-per-message": pubsub, n = "sync", 3000
            else: pubsub, n = "async", 200000
            cmd = ["nats","-s",url,"bench","js","pub",pubsub,subj,"--stream",stream,"--storage",storage,
                   "--create","--purge","--msgs",str(n),"--size",size]
            if pubsub == "async": cmd += ["--batch","100"]
            o = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            res = parse(o.stdout+o.stderr)
            if res["throughput"] is None: log(f"  nats pub {tier}/{payload}: {(o.stdout+o.stderr)[:200]}")
            return res
        # consume: fill async, then drain the stream and measure the consume rate
        fill = ["nats","-s",url,"bench","js","pub","async",subj,"--stream",stream,"--storage",storage,
                "--create","--purge","--msgs",str(CONSUME_N),"--size",size,"--batch","100"]
        subprocess.run(fill, capture_output=True, text=True, timeout=300)
        con = ["nats","-s",url,"bench","js","consume","--stream",stream,"--msgs",str(CONSUME_N)]
        o = subprocess.run(con, capture_output=True, text=True, timeout=300)
        res = parse(o.stdout+o.stderr)
        if res["throughput"] is None: log(f"  nats consume {tier}/{payload}: {(o.stdout+o.stderr)[:200]}")
        return res
    except Exception as e:
        log(f"  nats {tier}/{payload}/{mode} FAILED: {e}"); return None
    finally:
        srv.send_signal(signal.SIGTERM)
        try: srv.wait(5)
        except Exception: srv.kill()
        shutil.rmtree(sd, ignore_errors=True)
        if os.path.exists(cfg): os.remove(cfg)

# ---------- Redis Streams ----------
def redis(tier, payload, mode):
    port = free_port(); d = f"/tmp/redis-corpus-{port}"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    args = ["redis-server","--port",str(port),"--bind",HOST,"--dir",d,"--save",""]
    # appendfsync=always for both durable tiers; the DIFFERENCE is concurrency (below):
    #   sync-per-message  -c 1  -P 1  -> one fsync per message, no coalescing (SD-fsync-bound),
    #                                    the apples-to-apples match for IronBus window=1 / NATS sync
    #   group-commit-fsync -c 50 -P 1 -> 50 concurrent durable writers; appendfsync=always then
    #                                    coalesces fsyncs across clients (Redis's only path to
    #                                    durable-at-throughput), the analog to IronBus group commit
    if tier in ("sync-per-message", "group-commit-fsync"):
        args += ["--appendonly","yes","--appendfsync","always"]
    elif tier == "page-cache-async":
        args += ["--appendonly","yes","--appendfsync","everysec"]
    else:
        args += ["--appendonly","no"]
    srv = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); wait_port(port)
    try:
        val = "x" * payload
        if mode == "publish":
            # -n scaled by tier: per-message fsync (sync, -c1 -P1) is ~200/s SD-bound, so a small
            # count keeps the cell to ~15s; the pipelined/coalesced tiers run a high count.
            if tier == "sync-per-message": c, pipe, n = "1", "1", "3000"
            elif tier == "group-commit-fsync": c, pipe, n = "50", "1", "50000"
            else: c, pipe, n = "50", "16", "200000"
            cmd = ["redis-benchmark","-h",HOST,"-p",str(port),"-n",n,"-c",c,"-P",pipe,"--csv",
                   "XADD","corpus","*","f",val]
            o = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            rps = None
            for ln in o.stdout.splitlines():
                mm = re.search(r'","([\d.]+)"', ln)
                if mm and "XADD" in ln: rps = float(mm.group(1))
            if rps is None: log(f"  redis pub {tier}/{payload}: out={o.stdout[:160]!r}"); return None
            return dict(throughput=rps, p50=None, p99=None, p999=None)
        # consume: pre-fill CONSUME_N via pipeline, then XREADGROUP-batch drain, measure rate
        import redis as R
        c = R.Redis(host=HOST, port=port)
        pipe = c.pipeline(transaction=False); vb = b"x"*payload
        for i in range(CONSUME_N):
            pipe.xadd("cs", {b"f": vb})
            if i % 1000 == 999: pipe.execute()
        pipe.execute()
        try: c.xgroup_create("cs", "g", id="0")
        except Exception: pass
        got = 0; t0 = time.time()
        while got < CONSUME_N:
            msgs = c.xreadgroup("g", "c", {"cs": ">"}, count=512, block=2000)
            if not msgs: break
            for _s, entries in msgs:
                if entries:
                    c.xack("cs", "g", *[e[0] for e in entries]); got += len(entries)
        elapsed = time.time()-t0
        return dict(throughput=got/elapsed if elapsed > 0 else None, p50=None, p99=None, p999=None)
    except Exception as e:
        log(f"  redis {tier}/{payload}/{mode} FAILED: {e}"); return None
    finally:
        srv.send_signal(signal.SIGTERM)
        try: srv.wait(5)
        except Exception: srv.kill()
        shutil.rmtree(d, ignore_errors=True)

# ---------- Mosquitto (MQTT) ----------
def mqtt(tier, payload, mode):
    import paho.mqtt.client as mc
    port = free_port(); d = f"/tmp/mosq-corpus-{port}"; shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
    conf = f"/tmp/mosq-corpus-{port}.conf"
    persist = "true" if tier != "memory" else "false"
    open(conf, "w").write(f"listener {port} {HOST}\nallow_anonymous true\nmax_queued_messages 0\n"
                          f"persistence {persist}\npersistence_location {d}/\nautosave_interval 1\n")
    srv = subprocess.Popen(["mosquitto","-c",conf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    qos = 1 if tier == "sync-per-message" else 0
    try:
        if not wait_port(port): log("  mqtt: no start"); return None
        pb = b"x"*payload
        if mode == "publish":
            cli = mc.Client(client_id=f"pub{port}"); cli.connect(HOST, port, 60); cli.loop_start()
            n = 20000 if qos else 100000; t0 = time.time()
            for _ in range(n):
                info = cli.publish("corpus/t", pb, qos=qos)
                if qos: info.wait_for_publish(5)
            el = time.time()-t0; cli.loop_stop(); cli.disconnect()
            return dict(throughput=n/el, p50=None, p99=None, p999=None)
        # consume: a subscriber counts delivery while a publisher floods (live pub->sub rate)
        cnt = {"n": 0}
        def on_msg(c,u,m): cnt["n"] += 1
        sub = mc.Client(client_id=f"sub{port}"); sub.on_message = on_msg
        sub.connect(HOST, port, 60); sub.subscribe("corpus/c", qos=qos); sub.loop_start(); time.sleep(0.3)
        pub = mc.Client(client_id=f"pubc{port}"); pub.connect(HOST, port, 60); pub.loop_start()
        n = 30000; t0 = time.time()
        for _ in range(n):
            info = pub.publish("corpus/c", pb, qos=qos)
            if qos: info.wait_for_publish(5)
        end = time.time()+10
        while cnt["n"] < n and time.time() < end: time.sleep(0.01)
        el = time.time()-t0
        pub.loop_stop(); pub.disconnect(); sub.loop_stop(); sub.disconnect()
        return dict(throughput=cnt["n"]/el if el > 0 else None, p50=None, p99=None, p999=None)
    except Exception as e:
        log(f"  mqtt {tier}/{payload}/{mode} FAILED: {e}"); return None
    finally:
        srv.send_signal(signal.SIGTERM)
        try: srv.wait(5)
        except Exception: srv.kill()
        shutil.rmtree(d, ignore_errors=True)
        if os.path.exists(conf): os.remove(conf)

TIERS = ["sync-per-message", "page-cache-async", "memory"]
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ironbus", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--smoke", action="store_true")
    a = ap.parse_args()
    payloads = [256] if a.smoke else [256, 1024, 4096]
    outf = open(a.out, "w"); rows = []
    def emit(system, tier, payload, mode, res):
        if not res or res.get("throughput") is None:
            log(f"SKIP {system}/{tier}/{payload}/{mode}"); return
        row = dict(system=system, tier=tier, payload=payload, mode=mode, **res)
        rows.append(row); outf.write(json.dumps(row)+"\n"); outf.flush()  # incremental: survives a timeout
        log(f"OK  {system:9} {tier:18} {payload:5}B {mode:8} -> {res['throughput']:.0f} msg/s"
            + (f" p99={res['p99']:.0f}us" if res.get('p99') else ""))
    for payload in payloads:
        # PUBLISH: matched durability tiers, head-to-head.
        for tier in TIERS:
            emit("ironbus", tier, payload, "publish", ironbus(a.ironbus, tier, payload, "publish"))
            emit("nats", tier, payload, "publish", nats(tier, payload, "publish"))
            emit("redis", tier, payload, "publish", redis(tier, payload, "publish"))
            emit("mosquitto", tier, payload, "publish", mqtt(tier, payload, "publish"))
        # Durable-at-throughput: IronBus group-commit-fsync (1 connection, pipelined) vs Redis
        # appendfsync=always with 50 concurrent writers (its only path to durable throughput).
        emit("ironbus", "group-commit-fsync", payload, "publish",
             ironbus(a.ironbus, "group-commit-fsync", payload, "publish"))
        emit("redis", "group-commit-fsync", payload, "publish",
             redis("group-commit-fsync", payload, "publish"))
        # CONSUME: drain rate is durability-independent, so measure ONCE per system
        # with a fast (memory) pre-fill. tier label is "consume".
        for sysname, fn in [("ironbus", ironbus), ("nats", nats), ("redis", redis), ("mosquitto", mqtt)]:
            res = fn(a.ironbus, "memory", payload, "consume") if sysname == "ironbus" else fn("memory", payload, "consume")
            emit(sysname, "consume", payload, "consume", res)
    outf.close()
    log(f"\nWROTE {len(rows)} rows to {a.out}")

if __name__ == "__main__": main()
