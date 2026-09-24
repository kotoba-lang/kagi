#!/usr/bin/env python3
"""kagi-native-scribe evidence script (no_agent measurement, read-only).

Measures the state of the kagi native-kexe migration (ADR 0002, stages S1-S5)
and appends one MEASURE line set to the append-only ledger.

Output: MEASURE<TAB>key<TAB>value lines. Refusals print REFUSED and exit 2.
"""
import json
import os
import subprocess
import sys
import time

WORKTREE = "/tmp/kagi-native-wt"
KAGI = "~/github/com-junkawasaki/orgs/kotoba-lang/kagi"
LEDGER = os.path.expanduser(
    "~/.hermes/profiles/kagi-native-scribe/workspace/kagi-native-ledger.jsonl")
PHASE = os.path.join(WORKTREE, "src/kagi/phase.kotoba")
AMU = "~/github/com-junkawasaki/orgs/kotoba-lang/amu/bin/amu"


def sh(cmd, cwd=None, timeout=120):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          cwd=cwd, timeout=timeout)


def ok_true(out):
    return ":ok true" in out


def main():
    now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    m = {}
    m["as-of"] = now

    # worktree state
    if not os.path.isdir(WORKTREE):
        print("REFUSED worktree missing: " + WORKTREE)
        sys.exit(2)
    r = sh("git rev-parse --abbrev-ref HEAD && git rev-parse --short HEAD && "
           "git status --porcelain | wc -l", cwd=WORKTREE)
    if r.returncode:
        print("REFUSED worktree git read failed: " + r.stderr[:200])
        sys.exit(2)
    lines = r.stdout.strip().split("\n")
    m["worktree-branch"] = lines[0]
    m["worktree-head"] = lines[1]
    m["worktree-dirty-files"] = lines[2].strip()

    # S1: landed on main? (nbb.edn + default-provider seam)
    r = sh(f"git -C {WORKTREE} show origin/main:nbb.edn >/dev/null 2>&1 && echo yes")
    m["s1-nbbedn-on-main"] = r.stdout.strip() or "no"
    r = sh(f"git -C {WORKTREE} grep -c 'default-provider' origin/main -- src/kagi/crypto.cljk")
    line = (r.stdout.strip() or ":0")
    m["s1-default-provider-on-main"] = line.split(":")[-1] or "0"

    # S2: cacao state in worktree
    r = sh(f"git -C {WORKTREE} grep -c 'java.util' origin/main -- src/kagi/cacao.cljk")
    line = (r.stdout.strip() or ":0")
    m["s2-cacao-java-on-main"] = line.split(":")[-1] or "0"
    m["s2-cacao-host-in-worktree"] = "yes" if os.path.isfile(
        os.path.join(WORKTREE, "src/kagi/cacao_host.cljk")) else "no"
    r = sh("test -f src/kagi/cacao.cljk && git -C " + WORKTREE +
           " diff --quiet -- src/kagi/cacao.cljk && echo same || echo modified")
    m["s2-cacao-worktree-state"] = r.stdout.strip()

    # S3: guest check (amu check phase.kotoba --jvm-free, one file)
    if os.path.isfile(PHASE):
        r = sh(f"{AMU} check {PHASE} --jvm-free", timeout=90)
        m["s3-phase-amu-check"] = "ok" if ok_true(r.stdout) else (
            "fail:" + (r.stdout[:80] or r.stderr[:80]))
    else:
        m["s3-phase-amu-check"] = "file-missing"

    # kbb main sync state (informational; never git-write here)
    r = sh("git fetch origin -q && git rev-parse --short origin/main", cwd=WORKTREE)
    m["kagi-origin-main"] = r.stdout.strip() or "unmeasured"

    # kexe ceiling facts (static, from amu loader docs)
    m["string-pool-native"] = "per-run KEXE_STRING_POOL (amu 2a3d4333, default 65536, max 256MiB)"

    # ledger append
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    if not os.path.isfile(LEDGER):
        with open(LEDGER, "w") as f:
            f.write(json.dumps({"bootstrap": True}) + "\n")
    with open(LEDGER, "a") as f:
        f.write(json.dumps({"as-of": now, "measures": m}) + "\n")

    for k, v in m.items():
        print(f"MEASURE\t{k}\t{v}")
    sys.exit(0)


if __name__ == "__main__":
    main()
