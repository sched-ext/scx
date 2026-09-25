#!/usr/bin/env python3
"""§G93: is a task displaced by a higher class better moved cold or waited warm?

Reads `perf script` of sched_switch / sched_waking / sched_wakeup /
sched_migrate_task (rt_displace_capture.sh) and, for the watched threads,
joins every RT/DL/stop displacement with the hold that followed on that CPU,
where the displaced task resumed (stay / stay-late / hop, by the resume CPU —
migrate lines only tag the hop kind), its resume latency and the burst it ran
next. Stays are the control. The decision (docs/PERFORMANCE.md layer 3): keep
the task home for a displacer band iff refill + hop latency > hold, claimed
when CI95_low(refill) + lat_hop > p90(hold). Today every slice>0 displacement
hops (unconditional re-enqueue), so the refill estimate with n comes from the
wake side (T5: warm home vs claimed idle) and the >150 us stays.

  perf script -i perf.data | rt_displace.py --tids sched_a.txt --main TID
  rt_displace.py -i perf.data --tids sched_a.txt --main TID
"""
import argparse, re, statistics as st, subprocess, sys
from collections import defaultdict

HEAD = re.compile(r"^\s*(\S.*?)\s+(\d+)(?:/(\d+))?\s+\[(\d+)\]\s+(\d+)\.(\d+):\s+(\S+):\s+(.*)$")
SW = re.compile(r"prev_comm=(.*?) prev_pid=(\d+) prev_prio=(-?\d+) prev_state=(\S+) ==> next_comm=(.*?) next_pid=(\d+) next_prio=(-?\d+)")
WK = re.compile(r"comm=(.*?) pid=(\d+) prio=(-?\d+) target_cpu=(\d+)")
MG = re.compile(r"comm=(.*?) pid=(\d+) prio=(-?\d+) orig_cpu=(\d+) dest_cpu=(\d+)")
US = 1000
BUCKETS = ((0, 50), (50, 100), (100, 150), (150, 10**9))
LOOKBACK_NS = 100 * US


def pctl(v, q):
    if not v:
        return float("nan")
    v = sorted(v)
    return v[min(len(v) - 1, int(q * (len(v) - 1)))]


def mean(v):
    return st.mean(v) if v else float("nan")


def ci95_low(v):
    return mean(v) - 1.96 * st.stdev(v) / len(v) ** 0.5 if len(v) > 1 else float("nan")


def displacer_class(prio, comm):
    return "dl" if prio < 0 else ("stop" if comm.startswith("migration/") else "rt")


def bucket(us):
    for lo, hi in BUCKETS:
        if lo <= us < hi:
            return f"{lo}-{hi if hi < 10**9 else 'inf'}"
    return "?"


class D:
    """One displacement of a watched task by a higher class."""
    __slots__ = ("pid", "cpu", "t_out", "run_sofar", "dcomm", "dpid", "dclass", "dmean", "hold", "hold_end",
                 "nested", "kind", "lat", "burst", "mig_kind", "hold_prev")

    def __init__(self):
        for k in self.__slots__:
            setattr(self, k, None)
        self.nested = 0
        self.mig_kind = ""


def parse(src, watched, main):
    cur = {}                       # cpu -> (pid, prio, comm)
    hold = {}                      # cpu -> D with an open hold
    disp = {}                      # pid -> D awaiting resume
    mig = defaultdict(list)        # pid -> [(t, orig, dest)]
    rt_in, rt_bursts = {}, defaultdict(list)
    last_hold_cpu = {}
    burst = {}                     # watched pid -> [cpu, t_in, d_or_None]
    ctrl = defaultdict(list)       # (pid, bucket) -> plain bursts
    last_out_cpu = {}
    wakes, pending = [], {}        # T5
    events = []
    for line in src:
        m = HEAD.match(line)
        if not m:
            continue
        cpu = int(m.group(4))
        t = int(m.group(5)) * 10**9 + int(m.group(6).ljust(9, "0")[:9])
        ev, rest = m.group(7), m.group(8)
        if ev == "sched:sched_migrate_task":
            g = MG.match(rest)
            if g:
                mig[int(g.group(2))].append((t, int(g.group(4)), int(g.group(5))))
            continue
        if ev == "sched:sched_waking":
            g = WK.match(rest)
            if g and main and int(g.group(2)) == main and main not in pending:
                home = last_out_cpu.get(main)
                occ = cur.get(home) if home is not None else None
                cls = "idle" if (occ is None or occ[0] == 0) else ("rt" if occ[1] < 100 else ("own" if occ[0] in watched else "other"))
                pending[main] = [t, home, cls, None]
            continue
        if ev != "sched:sched_switch":
            continue
        g = SW.match(rest)
        if not g:
            continue
        prev_comm, prev, pprio, pstate = g.group(1), int(g.group(2)), int(g.group(3)), g.group(4)
        next_comm, nxt, nprio = g.group(5), int(g.group(6)), int(g.group(7))
        rt_next = nprio < 100 and nxt != 0

        # T5 residual occupancy: the first switch on the home after the waking
        pw = pending.get(main) if main else None
        if pw and pw[3] is None and cpu == pw[1] and t >= pw[0]:
            pw[3] = t - pw[0]

        if pprio < 100 and prev != 0 and prev in rt_in:
            rt_bursts[prev].append(t - rt_in.pop(prev))
        if rt_next:
            rt_in[nxt] = t

        # switch-out of a watched task
        if prev in watched:
            b = burst.pop(prev, None)
            length = (t - b[1]) if b else None
            if pstate.startswith("R") and rt_next:
                d = D()
                d.pid, d.cpu, d.t_out = prev, cpu, t
                d.run_sofar = length or 0
                d.dcomm, d.dpid, d.dclass = next_comm, nxt, displacer_class(nprio, next_comm)
                rb = rt_bursts.get(nxt)
                d.dmean = st.mean(rb) if rb else float("nan")
                d.hold_prev = last_hold_cpu.get(cpu)
                disp[prev] = d
                hold[cpu] = d
                if b and b[2] is not None and b[2].burst is None:
                    b[2].burst = length      # a post-resume burst cut short by the next displacement
            elif b:
                if b[2] is not None and b[2].burst is None:
                    b[2].burst = length
                else:
                    ctrl[(prev, bucket(length // US))].append(length)
            last_out_cpu[prev] = cpu

        # hold end: the first non-RT switch-in on a CPU holding one
        h = hold.get(cpu)
        if h is not None and h.t_out != t:
            if rt_next:
                h.nested += 1
            else:
                h.hold, h.hold_end = t - h.t_out, t
                last_hold_cpu[cpu] = h.hold
                hold.pop(cpu, None)

        # switch-in of a watched task
        if nxt in watched:
            d = disp.pop(nxt, None)
            if d is not None:
                d.lat = t - d.t_out
                if cpu == d.cpu:
                    d.kind = "stay" if (d.hold_end is not None and t == d.hold_end) else "stay-late"
                else:
                    d.kind = "hop"
                    ms = [x for x in mig.get(nxt, []) if d.t_out - LOOKBACK_NS <= x[0] <= t and x[1] == d.cpu]
                    d.mig_kind = "direct" if (ms and ms[0][0] - d.t_out <= LOOKBACK_NS) else ("late" if ms else "none")
                events.append(d)
                burst[nxt] = [cpu, t, d]
            else:
                burst[nxt] = [cpu, t, None]
                if main and nxt == main and main in pending:
                    tw, home, cls, resid = pending.pop(main)
                    wakes.append((cls, cpu != home, t - tw, resid if resid is not None else 0))
        cur[cpu] = (nxt, nprio, next_comm)
    return events, ctrl, wakes, rt_bursts


def report(events, ctrl, wakes, rt_bursts, watched, main):
    print(f"# rt_displace: {len(events)} displacements of watched threads; RT tasks seen: {len(rt_bursts)}\n")
    by, nest, dm, perr, perr_cpu = defaultdict(list), defaultdict(int), defaultdict(list), defaultdict(list), defaultdict(list)
    for d in events:
        if d.hold is None:
            continue
        k = (d.dclass, d.dcomm)
        by[k].append(d.hold / US)
        nest[k] += d.nested > 0
        if d.dmean == d.dmean:
            dm[k].append(d.dmean / US)
            perr[k].append(abs(d.dmean - d.hold) / US)
        if d.hold_prev is not None:
            perr_cpu[k].append(abs(d.hold_prev - d.hold) / US)
    print("## T1 hold by displacer (us); T1b = |prediction - hold| for the two predictors\n")
    print("| class | displacer | n | p50 | p90 | p99 | nested % | displacer mean burst p50 | err(mean burst) p50 | err(prev hold on cpu) p50 |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for k in sorted(by, key=lambda k: -len(by[k]))[:12]:
        v = by[k]
        print(f"| {k[0]} | {k[1]} | {len(v)} | {pctl(v, .5):.1f} | {pctl(v, .9):.1f} | {pctl(v, .99):.1f} | {100 * nest[k] / len(v):.0f} | {pctl(dm[k], .5):.1f} | {pctl(perr[k], .5):.1f} | {pctl(perr_cpu[k], .5):.1f} |")
    byp = defaultdict(list)
    for d in events:
        byp[d.pid].append(d)
    print("\n## T2 outcome per displaced thread (resume latency us)\n")
    print("| tid:comm | n | hop | stay | stay-late | hop % | lat hop p50 | lat stay p50 | hop direct/late/none |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---|")
    for pid in sorted(byp, key=lambda p: -len(byp[p]))[:15]:
        ds = byp[pid]
        hop = [x for x in ds if x.kind == "hop"]
        stay = [x for x in ds if x.kind == "stay"]
        late = [x for x in ds if x.kind == "stay-late"]
        kinds = [sum(1 for x in hop if x.mig_kind == k) for k in ("direct", "late", "none")]
        print(f"| {pid}:{watched.get(pid, '?')} | {len(ds)} | {len(hop)} | {len(stay)} | {len(late)} | {100 * len(hop) / max(1, len(ds)):.0f} | {pctl([x.lat / US for x in hop], .5):.2f} | {pctl([x.lat / US for x in stay], .5):.2f} | {kinds[0]}/{kinds[1]}/{kinds[2]} |")
    print("\n## T3 burst after resume (us) by work done before the displacement\n")
    print("| tid:comm | bucket | n hop | mean | p50 | p90 | n stay | mean | p50 | p90 | refill = mean hop - mean stay | ci95 low | plain bursts n mean |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for pid in sorted(byp, key=lambda p: -len(byp[p]))[:6]:
        for lo, hi in BUCKETS:
            bk = bucket(lo)
            hop = [x.burst / US for x in byp[pid] if x.kind == "hop" and x.burst is not None and bucket(x.run_sofar // US) == bk]
            stay = [x.burst / US for x in byp[pid] if x.kind == "stay" and x.burst is not None and bucket(x.run_sofar // US) == bk]
            c = ctrl.get((pid, bk), [])
            if not hop and not stay:
                continue
            refill = mean(hop) - mean(stay) if (hop and stay) else float("nan")
            lo95 = ci95_low(hop) - mean(stay) if (len(hop) > 1 and stay) else float("nan")
            print(f"| {pid}:{watched.get(pid, '?')} | {bk} | {len(hop)} | {mean(hop):.1f} | {pctl(hop, .5):.1f} | {pctl(hop, .9):.1f} | {len(stay)} | {mean(stay):.1f} | {pctl(stay, .5):.1f} | {pctl(stay, .9):.1f} | {refill:.1f} | {lo95:.1f} | {len(c)} {mean([x / US for x in c]):.1f} |")
    if main and wakes:
        print("\n## T5 main-thread wake side: the home's occupant at waking\n")
        print("| occupant | n | moved % | wake->run p50 us | residual occupancy p50 us |")
        print("|---|---:|---:|---:|---:|")
        byc = defaultdict(list)
        for w in wakes:
            byc[w[0]].append(w)
        for c in ("idle", "own", "rt", "other"):
            v = byc.get(c, [])
            if v:
                res = [w[3] / US for w in v if w[3]]
                print(f"| {c} | {len(v)} | {100 * sum(1 for w in v if w[1]) / len(v):.0f} | {pctl([w[2] / US for w in v], .5):.2f} | {pctl(res, .5):.1f} |")
    print("\n## decision (docs/PERFORMANCE.md layer 3): keep home for a displacer band iff CI95_low(refill) + lat_hop > p90(hold);")
    print("## refill from T3 stays where n allows, else T5 (warm home vs claimed idle); the T4 bound sweep follows once refill is bounded.")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", help="perf.data (runs perf script); default: perf script text on stdin")
    ap.add_argument("--tids", required=True, help="tid:comm lines (sched_a.txt from the capture); all are watched")
    ap.add_argument("--main", type=int, help="the game's main thread tid, for T5")
    a = ap.parse_args()
    watched = {}
    for line in open(a.tids):
        f = line.split()
        if f and ":" in f[0]:
            tid, comm = f[0].split(":", 1)
            watched[int(tid)] = comm
    src = subprocess.Popen(["perf", "script", "-i", a.i], stdout=subprocess.PIPE, text=True).stdout if a.i else sys.stdin
    report(*parse(src, watched, a.main), watched, a.main)
    return 0


if __name__ == "__main__":
    sys.exit(main())
