#!/usr/bin/env python3
"""kbb cache adapter: restructure the engine's nbb-deps cache for cljk
resolution.

The engine (org-babashka-nbb) jar-extracts dependencies flat into
nbb-deps/<lib>/.cljc + .cljc.kotoba files with NO cljk-origin.edn manifest.
The cljk resolver (a) only serves .cljk-named sources listed in a manifest
under a KBB_CLJK_ROOTS root and (b) refuses bare-legacy probes when a manifest
root owns the classpath dir, and namespace require expects <ns>/<file>.cljk.
This script, per dependency lib dir:

  1. renames bare .cljc -> .cljc.kotoba (hides them from the legacy probe)
     or bare .cljk -> .cljk.hidden (same idea for .cljk extraction)
  2. moves them into a subtree <nsdir>/<name>.cljk (real files, no symlinks:
     the resolver realpaths entries and must match the manifest exactly)
  3. writes a cljk-origin.edn manifest (origin .cljc — dual-runtime, JS-runnable
     — for extracted .cljc pairs, .cljs for pure-renamed trees)

Run AFTER any kbb dependency re-fetch (the cache regenerates itself). Idempotent.
"""
import os, glob, sys

cache = sys.argv[1]  # .../nbb-deps root

def adapt(libdir, nsdir, origin):
    subtree = os.path.join(libdir, nsdir)
    os.makedirs(subtree, exist_ok=True)
    # clean stale subtree entries
    for f in os.listdir(subtree):
        p = os.path.join(subtree, f)
        os.remove(p) if (os.path.islink(p) or os.path.isfile(p)) else None
    moved = 0
    for pat, is_hidden in [("*.cljc.kotoba", False), ("*.cljk.hidden", True), ("*.cljk", None)]:
        for f in glob.glob(os.path.join(libdir, pat)):
            if os.path.dirname(f) != libdir:
                continue
            base = os.path.basename(f)
            if is_hidden:
                stem = base[:-len(".cljk.hidden")]
            elif base.endswith(".cljk"):
                if pat == "*.cljk" and os.path.exists(os.path.join(subtree, base)):
                    continue  # already moved in a previous pass
                stem = base[:-5]
            else:
                stem = base[:-len(".cljc.kotoba")]
            dst = os.path.join(subtree, stem + ".cljk")
            if not os.path.exists(dst):
                os.rename(f, dst)
                moved += 1
    entries = sorted(x for x in os.listdir(subtree) if x.endswith(".cljk"))
    if not entries:
        return 0
    mani = ["{:format :kotoba.cljk-origin/v1", ' :renamed-on "2026-09-13"',
            ' :decision "kbb-cache adapter (scripts/kbb_cache_manifest.py)"',
            ' :rule "generated for the kbb .nbb cache"',
            " :origins {"]
    for f in entries:
        mani.append(f'  "{nsdir}/{f}" "{origin}"')
    mani.append("}}")
    open(os.path.join(libdir, "cljk-origin.edn"), "w").write("\n".join(mani) + "\n")
    return len(entries)

total = 0
for name, origin in [("langgraph", ".cljc"), ("langchain", ".cljs")]:
    d = os.path.join(cache, name)
    if os.path.isdir(d):
        n = adapt(d, name, origin)
        print(f"{name}: {n} entries")
        total += n
print(f"total {total}")
