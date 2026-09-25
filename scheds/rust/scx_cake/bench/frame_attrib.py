#!/usr/bin/env python3
"""Per-frame cause classes: joins a MangoHud frame log with a `perf script`
sched trace (rt_displace_capture.sh) on one clock and, for every frame, sums
what the frame thread did inside that frame: ran, waited runnable, was held
by an RT displacer, was preempted by a peer, blocked; whether it hopped; and
the compositor's longest on-CPU burst in the window. Slow frames get a class
from those terms (council 2026-09-19, V22):
  rt_displaced  the thread sat runnable behind a prio<100 task
  preempted     the thread sat runnable behind an SCX/CFS task
  wait          runnable-but-waiting for another reason (idle-CPU wake latency)
  kwin_late     the compositor ran a burst above --kwin-burst-us in the window
  idle_wait     the thread blocked most of the frame (GPU- or compositor-paced)
  cpu_bound     the thread ran most of the frame
  no_trace      the frame lies outside the trace's span (not counted)
The MangoHud clock is `elapsed` (ns since the log started); the trace clock is
perf's. --log-start gives the trace time the log was commanded; the residual
socket-to-first-row delay is fitted (--auto-offset, default) by putting frame
ends on the frame thread's block points, or given (--offset-ms).
  frame_attrib.py --log mangohud.csv -i perf.data --main TID [--kwin TID]
"""
import argparse, bisect, csv, re, statistics as st, subprocess, sys
from collections import Counter

HEAD = re.compile(r"^\s*(\S.*?)\s+(\d+)(?:/(\d+))?\s+\[(\d+)\]\s+(\d+)\.(\d+):\s+(\S+):\s+(.*)$")
SW = re.compile(r"prev_comm=(.*?) prev_pid=(\d+) prev_prio=(-?\d+) prev_state=(\S+) ==> next_comm=(.*?) next_pid=(\d+) next_prio=(-?\d+)")
WK = re.compile(r"comm=(.*?) pid=(\d+) prio=(-?\d+) target_cpu=(\d+)")
MG = re.compile(r"comm=(.*?) pid=(\d+) prio=(-?\d+) orig_cpu=(\d+) dest_cpu=(\d+)")
MS = 1e6
RT_PRIO = 100
FIT_SPAN_MS = 200.0
FIT_STEP_MS = 0.1


def pctl(v, q):
    if not v:
        return float("nan")
    v = sorted(v)
    return v[min(len(v) - 1, int(q * (len(v) - 1)))]


def read_frames(path):
    """MangoHud CSV: three header lines, then rows; frametime ms, elapsed ns."""
    with open(path, newline="") as f:
        rows = list(csv.reader(f))
    hdr = rows[2]
    ft, el = hdr.index("frametime"), hdr.index("elapsed")
    frames = []
    for r in rows[3:]:
        if len(r) <= max(ft, el):
            continue
        end = int(r[el])
        frames.append((end - float(r[ft]) * MS, end, float(r[ft])))
    return frames


def parse(src, main, kwin):
    """Frame-thread segments and compositor bursts on the trace clock (ns)."""
    seg = []          # (t0, t1, kind) kind: run / rt / preempt / wait / block
    hops = []         # migration times
    kbursts = []      # (t0, t1) compositor on-CPU
    state = None      # ("run", t, cpu) | ("wait", t, kind) | ("block", t)
    kstart = None
    for line in src:
        m = HEAD.match(line)
        if not m:
            continue
        t = int(m.group(5)) * 10**9 + int(m.group(6).ljust(9, "0")[:9])
        cpu, ev, rest = int(m.group(4)), m.group(7), m.group(8)
        if ev == "sched:sched_switch":
            s = SW.match(rest)
            if not s:
                continue
            prev, nxt, nprio = int(s.group(2)), int(s.group(6)), int(s.group(7))
            if prev == main and state and state[0] == "run":
                seg.append((state[1], t, "run"))
                if s.group(4).startswith("R"):
                    state = ("wait", t, "rt" if nprio < RT_PRIO else "preempt")
                else:
                    state = ("block", t)
            if nxt == main:
                if state and state[0] in ("wait", "block"):
                    kind = state[2] if state[0] == "wait" else "block"
                    seg.append((state[1], t, kind))
                state = ("run", t, cpu)
            if prev == kwin and kstart is not None:
                kbursts.append((kstart, t))
                kstart = None
            if nxt == kwin:
                kstart = t
        elif ev in ("sched:sched_waking", "sched:sched_wakeup"):
            w = WK.match(rest)
            if w and int(w.group(2)) == main and state and state[0] == "block":
                seg.append((state[1], t, "block"))
                state = ("wait", t, "wait")
        elif ev == "sched:sched_migrate_task":
            g = MG.match(rest)
            if g and int(g.group(2)) == main:
                hops.append(t)
    seg.sort()
    return seg, hops, kbursts


def overlap(a0, a1, b0, b1):
    return max(0, min(a1, b1) - max(a0, b0))


def block_points(seg):
    return [t0 for t0, _, k in seg if k == "block"]


def fit_offset(frames, blocks, base):
    """Offset (ns) that puts frame ends closest to the thread's block points;
    fitted on the frames the trace can see."""
    best, best_d = 0.0, float("inf")
    lo, hi = blocks[0] - base, blocks[-1] - base
    inside = [f for f in frames if lo <= f[1] <= hi]
    sample = inside[:: max(1, len(inside) // 400)]
    off = -FIT_SPAN_MS * MS
    while off <= FIT_SPAN_MS * MS:
        ds = []
        for _, end, _ in sample:
            te = base + end + off
            i = bisect.bisect_left(blocks, te)
            c = [abs(blocks[j] - te) for j in (i - 1, i) if 0 <= j < len(blocks)]
            if c:
                ds.append(min(c))
        d = st.median(ds) if ds else float("inf")
        if d < best_d:
            best, best_d = off, d
        off += FIT_STEP_MS * MS
    return best, best_d


def attrib(frames, seg, hops, kbursts, base, off, kburst_us):
    starts = [s[0] for s in seg]
    kst = [k[0] for k in kbursts]
    span = (seg[0][0], seg[-1][1]) if seg else (0, 0)
    out = []
    for f0, f1, ft in frames:
        w0, w1 = base + f0 + off, base + f1 + off
        if w0 < span[0] or w1 > span[1]:
            out.append((f1, ft, "no_trace", dict.fromkeys(("run", "rt", "preempt", "wait", "block"), 0.0), 0, 0))
            continue
        acc = Counter()
        i = bisect.bisect_left(starts, w0 - 50 * MS)
        while i < len(seg) and seg[i][0] < w1:
            t0, t1, k = seg[i]
            acc[k] += overlap(t0, t1, w0, w1)
            i += 1
        kmax = 0
        j = bisect.bisect_left(kst, w0 - 50 * MS)
        while j < len(kbursts) and kbursts[j][0] < w1:
            kmax = max(kmax, overlap(kbursts[j][0], kbursts[j][1], w0, w1))
            j += 1
        nh = bisect.bisect_left(hops, w1) - bisect.bisect_left(hops, w0)
        ms = {k: acc[k] / MS for k in ("run", "rt", "preempt", "wait", "block")}
        if ms["rt"] >= 0.1:
            cls = "rt_displaced"
        elif ms["preempt"] >= 0.1:
            cls = "preempted"
        elif ms["wait"] >= 0.1:
            cls = "wait"
        elif kmax / 1000 >= kburst_us:
            cls = "kwin_late"
        elif ms["block"] >= 0.6 * ft:
            cls = "idle_wait"
        else:
            cls = "cpu_bound"
        out.append((f1, ft, cls, ms, kmax / 1000, nh))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", required=True, help="MangoHud CSV")
    ap.add_argument("-i", "--input", help="perf.data (else perf script text on stdin)")
    ap.add_argument("--main", type=int, required=True, help="frame thread tid")
    ap.add_argument("--kwin", type=int, default=-1, help="compositor tid")
    ap.add_argument("--log-start", type=float, default=0.0, help="trace time (s) the log was commanded")
    ap.add_argument("--offset-ms", type=float, help="fixed residual offset instead of the fit")
    ap.add_argument("--slow-ms", type=float, help="slow frame threshold (default: p99 frametime)")
    ap.add_argument("--kwin-burst-us", type=float, default=1000.0)
    ap.add_argument("--top", type=int, default=30, help="slow frames to list")
    a = ap.parse_args()

    frames = read_frames(a.log)
    if a.input:
        p = subprocess.Popen(["perf", "script", "-i", a.input], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)
        seg, hops, kb = parse(p.stdout, a.main, a.kwin)
        p.wait()
    else:
        seg, hops, kb = parse(sys.stdin, a.main, a.kwin)
    base = int(a.log_start * 10**9)
    if a.offset_ms is not None:
        off, fitd = a.offset_ms * MS, float("nan")
    else:
        off, fitd = fit_offset(frames, block_points(seg), base)
    rows = attrib(frames, seg, hops, kb, base, off, a.kwin_burst_us)
    seen = [r for r in rows if r[2] != "no_trace"]
    slow = a.slow_ms if a.slow_ms else pctl([r[1] for r in seen], 0.99)

    print(f"frames {len(frames)} ({len(seen)} inside the trace)  segments {len(seg)}  hops {len(hops)}  "
          f"kwin bursts {len(kb)}")
    print(f"offset {off / MS:.1f} ms (fit residual median {fitd / MS if fitd == fitd else float('nan'):.3f} ms)  "
          f"slow >= {slow:.2f} ms")
    allc = Counter(r[2] for r in seen)
    slc = Counter(r[2] for r in seen if r[1] >= slow)
    print("\nclass          all      slow")
    for c in ("rt_displaced", "preempted", "wait", "kwin_late", "idle_wait", "cpu_bound"):
        print(f"{c:13} {allc[c]:6d} {slc[c]:8d}")
    print("\nslow frames: end_ms frametime class run rt preempt wait block kwin_us hops")
    for f1, ft, cls, ms, kus, nh in sorted((r for r in seen if r[1] >= slow), key=lambda r: -r[1])[: a.top]:
        print(f"{f1 / MS:10.1f} {ft:6.2f} {cls:12} {ms['run']:5.2f} {ms['rt']:5.2f} {ms['preempt']:5.2f} "
              f"{ms['wait']:5.2f} {ms['block']:5.2f} {kus:7.0f} {nh}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
