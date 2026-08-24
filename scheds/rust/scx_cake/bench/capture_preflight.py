#!/usr/bin/env python3
"""Prove a game capture will work BEFORE the maintainer sits down, and price it.

Why this exists (2026-07-30): a capture was fired while the maintainer sat parked
in a static scene, and the start path turned out to be QUARANTINED. Four tool
calls of discovery happened on their clock. Then the run that did fire was 310 s
when 30 s had been asked for, because nobody multiplied slots x (duration+settle)
out loud.

Two rules this enforces:
  1. Everything checkable is checked before the game is opened.
  2. The time cost is printed as a number before it is spent.

Usage:
  capture_preflight.py --game helldivers2 [--arms 2] [--duration 30] [--settle 10]
"""
import argparse
import json
import re
import os
import shutil
import subprocess
import sys

REPO = "/home/ritz/Documents/Repo/scx"
ASSETS = "/home/ritz/Documents/Repo/scx_cake_bench_assets"

# The live path. game_capture_start is QUARANTINED behind the strict
# v2-manifest/v5-receipt runner and will refuse; game_ab is what works.
LIVE_TOOL = "game_ab"
QUARANTINED = "game_capture_start"


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=20).stdout.strip()
    except Exception:
        return ""


def check(name, ok, detail=""):
    print(f"  [{'OK ' if ok else 'FAIL'}] {name}{(' -- ' + detail) if detail else ''}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--game", default="helldivers2")
    ap.add_argument("--arms", type=int, default=2,
                    help="1=single, 2=ABBA(4 slots), 3=ABCCBA(6 slots)")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--settle", type=int, default=10)
    ap.add_argument("--cpus", type=int, default=16)
    a = ap.parse_args()

    print(f"\n=== capture preflight: {a.game} ===\n")
    ok = True

    # --- things that do NOT need the game open -----------------------------
    print("Before the game is open:")
    head = sh(f"git -C {REPO} rev-parse HEAD")
    dirty = sh(f"git -C {REPO} status --porcelain -- scheds/rust/scx_cake/src")
    ok &= check("git HEAD known", bool(head), head[:12])
    ok &= check("cake source clean", not dirty,
                "uncommitted src changes -- receipt will not match" if dirty else "")

    # Match on the SCHEDULER SOURCE, not on HEAD. Doc-only commits move HEAD
    # without changing a byte of what runs, and failing on that is a false
    # blocker that costs a rebuild for nothing.
    builds = f"{REPO}/target/cake_receipt_builds"
    newest, binpath, why = None, None, "run: bash cakebench artifact ensure"
    if os.path.isdir(builds):
        for d in sorted(os.listdir(builds), reverse=True):
            cand = os.path.join(builds, d, "scx_cake")
            if not os.path.exists(cand):
                continue
            # The commit a receipt was built from is RECORDED in its own
            # receipt json. Parsing it out of the directory NAME only works for
            # receipts labelled "head-<sha12>", so any receipt built with a
            # descriptive label was invisible here and the gate demanded a
            # rebuild that `artifact ensure` then declined as already fresh --
            # an unbreakable loop on a receipt that was valid all along
            # (2026-08-08). Prefer the json; keep the name as a fallback.
            rhead = None
            try:
                with open(os.path.join(builds, d, "artifact_receipt.json")) as fh:
                    rhead = json.load(fh).get("git_head")
            except (OSError, ValueError):
                pass
            if not rhead:
                m = re.search(r"head-([0-9a-f]{12})", d)
                if not m:
                    continue
                rhead = m.group(1)
            same = subprocess.run(
                f"git -C {REPO} diff --quiet {rhead} HEAD -- scheds/rust/scx_cake/src",
                shell=True).returncode == 0
            if same:
                newest, binpath = d, cand
                why = f"{d[:40]} (src identical to HEAD)"
                break
    ok &= check("capped receipt matching cake SOURCE", bool(binpath), why)
    if binpath and os.path.exists(binpath):
        caps = sh(f"getcap {binpath}")
        ok &= check("receipt has capabilities", "cap_bpf" in caps, caps.split(" ")[-1] if caps else "none")

    ok &= check("scxctl present", bool(shutil.which("scxctl")
                                       or os.path.exists(os.path.expanduser("~/.cargo/bin/scxctl"))))
    ok &= check("no scheduler currently attached",
                not sh("cat /sys/kernel/sched_ext/root/ops 2>/dev/null"))

    # --- host noise: a COVARIATE, never a gate ----------------------------
    #
    # Standing direction (2026-07-17): noise never blocks a run. It is recorded
    # per arm and read before interpreting. What actually threatens validity is
    # arms that DISAGREE on noise, not arms that are noisy together -- and the
    # only way to learn how noise moves a score is to run at several levels and
    # keep the covariate beside every row. Blocking on it destroys exactly that
    # data. So: measure it, name its source, print it, never fail on it.
    busy = sh("""python3 -c "
import time
def r():
    v=[int(x) for x in open('/proc/stat').readline().split()[1:]]
    return sum(v), v[3]
a,ai=r(); time.sleep(2); b,bi=r()
print(round(100*(1-(bi-ai)/(b-a)),1))
" """)
    try:
        busy_f = float(busy)
    except ValueError:
        busy_f, busy = -1.0, "?"
    band = ("low" if busy_f < 15 else "moderate" if busy_f < 40 else "high") \
        if busy_f >= 0 else "unknown"
    print(f"\nHost noise -- COVARIATE, not a gate:")
    print(f"  level         : {busy}% of {a.cpus} CPUs  (band: {band})")

    # Attribution: what the noise IS. Excludes the game itself, which is signal.
    top = sh("ps -eo pcpu,comm --sort=-pcpu --no-headers | head -8")
    srcs = []
    for line in top.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        pct, comm = parts
        try:
            if float(pct) < 3.0:
                continue
        except ValueError:
            continue
        if a.game[:6].lower() in comm.lower() or comm in ("main",):
            continue          # the game under test is signal, not noise
        srcs.append(f"{comm} {pct}%")
    print(f"  sources       : {', '.join(srcs[:4]) if srcs else 'nothing above 3%'}")
    print(f"  rule          : arms must MATCH on noise, not be quiet. The harness")
    print(f"                  seals noise_class + external_cpu_avg_pct into every")
    print(f"                  row; a mirrored rotation (ABBA) shares drift across")
    print(f"                  arms by construction. Run it -- do not wait for calm.")

    # --- things that DO need the game open ---------------------------------
    print("\nNeeds the game running:")
    pids = sh(f"pgrep -f {a.game} | head -3")
    game_up = bool(pids)
    check("game process found", game_up, "" if game_up else "not open yet -- fine, rest is deferred")
    if game_up:
        socks = sh("ss -lx 2>/dev/null | grep -o 'mangohud-[0-9]*' | sort -u")
        check("MangoHud injected", bool(socks), socks.replace("\n", " ") or
              "NOT INJECTED -- capture would produce no frames")

    # --- the price ---------------------------------------------------------
    slots = {1: 1, 2: 4, 3: 6}.get(a.arms, a.arms * 2)
    rot = {1: "single arm", 2: "ABBA", 3: "ABCCBA"}.get(a.arms, f"{a.arms} arms")
    total = slots * (a.duration + a.settle)
    print(f"\n=== THE PRICE ===")
    print(f"  rotation      : {rot} = {slots} slots")
    print(f"  per slot      : {a.duration}s capture + {a.settle}s settle")
    print(f"  TOTAL         : {total}s  ({total // 60}m {total % 60}s) of held focus")
    print(f"\n  The maintainer does exactly ONE thing: focus the game and")
    print(f"  do not touch it for {total // 60}m {total % 60}s.\n")

    print(f"  live tool     : {LIVE_TOOL}   (NOT {QUARANTINED} -- that one is quarantined)")
    print(f"\n=== {'READY' if ok else 'NOT READY -- fix the FAILs above'} ===\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
