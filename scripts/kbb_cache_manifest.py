#!/usr/bin/env python3
"""kbb cache adapter — restructure EVERY extracted lib in an nbb-deps cache for
cljk resolution. Idempotent; run after any kbb dependency re-fetch.

Per lib dir with bare .cljc / .cljk files:
  1. bare .cljc -> moved into <ns>/<name>.cljk as the REAL file (no symlinks:
     the resolver realpaths entries and must match the manifest exactly)
  2. bare .cljk -> moved into <ns>/<name>.cljk the same way
  3. writes cljk-origin.edn with origin .cljc (dual-runtime, JS-runnable)

The namespace dir name is inferred from each file's (ns ...) form, so this
works for any cache layout without a per-lib table."""
import os, re, sys, glob

cache = sys.argv[1]  # .../nbb-deps root

def ns_of(path):
    try:
        t = open(path, encoding="utf-8", errors="replace").read(4096)
        m = re.search(r'\(ns\s+([a-zA-Z0-9.-]+)', t)
        if m:
            return m.group(1).replace(".", "/")
    except Exception:
        pass
    return None

total = 0
for libdir in sorted(os.listdir(cache)):
    d = os.path.join(cache, libdir)
    if not os.path.isdir(d):
        continue
    files = [f for f in glob.glob(os.path.join(d, "*"))
             if os.path.isfile(f) and (f.endswith(".cljc") or f.endswith(".cljk"))]
    if not files:
        continue
    nsdir = ns_of(files[0])
    if not nsdir:
        print(f"{libdir}: no ns form, skipped")
        continue
    subtree = os.path.join(d, nsdir)
    os.makedirs(subtree, exist_ok=True)
    moved = 0
    for f in files:
        base = os.path.basename(f)
        stem = base[:-5]  # strip .cljc or .cljk
        dst = os.path.join(subtree, stem + ".cljk")
        if not os.path.exists(dst):
            os.rename(f, dst)
            moved += 1
    entries = sorted(x for x in os.listdir(subtree) if x.endswith(".cljk"))
    if not entries:
        continue
    mani = ["{:format :kotoba.cljk-origin/v1", ' :renamed-on "2026-09-13"',
            ' :decision "kbb-cache adapter (scripts/kbb_cache_manifest.py)"',
            ' :rule "generated for the kbb .nbb cache"', " :origins {"]
    for e in entries:
        mani.append(f'  "{nsdir}/{e}" ".cljc"')
    mani.append("}}")
    open(os.path.join(d, "cljk-origin.edn"), "w").write("\n".join(mani) + "\n")
    print(f"{libdir}: {len(entries)} entries ({nsdir}/)")
    total += len(entries)
print(f"total {total}")
