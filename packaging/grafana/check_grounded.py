#!/usr/bin/env python3
"""Local check: every ironbus_* metric the generated dashboard references is real.

Greps the IronBus server source for the authoritative emitted `ironbus_*` names
(the same set docs/METRICS.md catalogs and the frozen `(name, type)` test pins),
then asserts the generated `ironbus-dashboard.json` references only those (allowing
the Prometheus `_bucket` / `_sum` / `_count` histogram suffixes). Exit non-zero if a
panel references a name the broker does not emit -- the thing that silently breaks a
dashboard after a metric rename.

Run from the repo root after regenerating:
  python3 packaging/grafana/check_grounded.py
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DASH = os.path.join(HERE, "ironbus-dashboard.json")
SRC = os.path.join(ROOT, "crates", "ironbus-server", "src")

# Crate-path / partial-token false positives the source grep picks up that are NOT metrics.
JUNK = {"ironbus_core", "ironbus_proto", "ironbus_storage", "ironbus_x_total", "ironbus_durability_"}


def emitted_names():
    out = subprocess.run(["grep", "-rhoE", "ironbus_[a-z0-9_]+", SRC],
                         capture_output=True, text=True).stdout
    base = {n for n in out.split() if n not in JUNK}
    full = set(base)
    for m in base:
        full |= {m + "_bucket", m + "_sum", m + "_count"}
    return full


def main():
    if not os.path.isdir(SRC):
        sys.exit(f"server source not found at {SRC}; run from the repo root")
    emitted = emitted_names()
    refs = set(re.findall(r"ironbus_[a-z0-9_]+", open(DASH).read()))
    missing = sorted(r for r in refs if r not in emitted)
    print(f"dashboard references {len(refs)} distinct ironbus_* tokens; "
          f"{len(emitted)} emitted names (with histogram suffixes) in the catalog")
    if missing:
        print("UNGROUNDED (not emitted by the broker):")
        for m in missing:
            print("  -", m)
        sys.exit(1)
    print("OK: every referenced metric is emitted by the broker.")


if __name__ == "__main__":
    main()
