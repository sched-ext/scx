#!/usr/bin/env python3
"""
Is migration the CAUSE of a slow wake, or the scheduler's response to one?

A wake gets moved off its target precisely when that target is busy, so
"moved wakes are slow" is exactly what you would see if migration were a
CURE that is merely correlated with the disease.  The corpus already
falsified migration as the cause of the Palworld tail once (2026-07-27), so
the burden here is on a stratified comparison, not a raw one.

Stratify every wake by whether the target CPU was BUSY at wake time, then
inside each stratum compare moved against stayed:

  target idle + stayed  -> the clean baseline
  target idle + moved   -> migration with no provocation: pure cost
  target busy + stayed  -> waited for the occupant
  target busy + moved   -> fled the occupant

If (busy+moved) beats (busy+stayed), migration is HELPING and the raw
correlation is a symptom.  If it loses, migration costs even when provoked.

usage: migrate_cause.py <perf.data> <roles>
"""
import re
import subprocess
import sys
from collections import defaultdict

HEAD = re.compile(r"^\s+(.+?)\s+(\d+)\s+\[(\d+)\]\s+(\d+\.\d+):\s+sched:(\S+):\s+(.*)$")
WAKE = re.compile(r"comm=(.+?)\s+pid=(\d+)\s+prio=\d+\s+target_cpu=(\d+)")
SWITCH = re.compile(
    r"prev_comm=(.+?)\s+prev_pid=(\d+)\s+prev_prio=\d+\s+prev_state=(\S+)\s+==>\s+"
    r"next_comm=(.+?)\s+next_pid=(\d+)"
)


def pct(xs, q):
    s = sorted(xs)
    return s[min(len(s) - 1, int(q * len(s)))]


def main():
    trace, roles = sys.argv[1], [r for r in sys.argv[2].split(",") if r]
    want = set(roles)
    p = subprocess.Popen(["perf", "script", "-i", trace], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1 << 22)

    busy_pid = {}                       # cpu -> pid currently on it (0 = idle)
    pending = {}                        # pid -> (t, role, target, target_was_busy)
    cell = defaultdict(lambda: defaultdict(list))

    for line in p.stdout or ():
        m = HEAD.match(line)
        if not m:
            continue
        cpu, t, ev, rest = int(m.group(3)), float(m.group(4)) * 1e6, m.group(5), m.group(6)
        if ev.startswith("sched_wakeup"):
            w = WAKE.match(rest)
            if w and w.group(1).strip() in want:
                tgt = int(w.group(3))
                pending[int(w.group(2))] = (t, w.group(1).strip(), tgt,
                                            bool(busy_pid.get(tgt)))
            continue
        if ev != "sched_switch":
            continue
        s = SWITCH.match(rest)
        if not s:
            continue
        next_pid = int(s.group(5))
        if next_pid in pending:
            wt, role, tgt, tbusy = pending.pop(next_pid)
            d = t - wt
            if d >= 0:
                key = ("busy" if tbusy else "idle") + "+" + ("moved" if cpu != tgt else "stayed")
                cell[role][key].append(d)
        busy_pid[cpu] = next_pid
    p.wait()

    order = ["idle+stayed", "idle+moved", "busy+stayed", "busy+moved"]
    for role in roles:
        c = cell.get(role)
        if not c:
            continue
        tot = sum(len(v) for v in c.values())
        print(f"\n=== {role} ===  n={tot}")
        print(f"{'stratum':>13} {'n':>8} {'share':>7} {'mean':>8} {'p95':>7} {'p99':>7} "
              f"{'delay share':>12}")
        alldelay = sum(sum(v) for v in c.values())
        for k in order:
            v = c.get(k)
            if not v or len(v) < 20:
                continue
            print(f"{k:>13} {len(v):>8} {100*len(v)/tot:>6.1f}% {sum(v)/len(v):>8.2f} "
                  f"{pct(v,.95):>7.1f} {pct(v,.99):>7.1f} {100*sum(v)/alldelay:>11.1f}%")
        bs, bm = c.get("busy+stayed"), c.get("busy+moved")
        if bs and bm and len(bs) >= 20 and len(bm) >= 20:
            ms, mm = sum(bs) / len(bs), sum(bm) / len(bm)
            verdict = "MIGRATION HELPS" if mm < ms else "MIGRATION COSTS"
            print(f"  -> target busy: stayed {ms:.2f} vs moved {mm:.2f}  "
                  f"=> {verdict} ({mm/ms:.2f}x)")


if __name__ == "__main__":
    main()
