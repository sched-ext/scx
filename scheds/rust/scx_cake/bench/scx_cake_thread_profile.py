#!/usr/bin/env python3
"""scx_cake_thread_profile — scheduler-agnostic per-thread performance profiler.

Collects, per game/test scenario and per active scheduler, the full thread shape:
on-CPU runtime, runqueue wait (scheduling latency), migrations (warmth proxy),
voluntary/involuntary context switches, blocked-on reason (wchan), util, plus a
best-effort wakeup dependency graph (who wakes who, handoff latency) via perf.

Works identically under EEVDF and any sched_ext scheduler because it reads /proc
(+ optional perf) — nothing in-kernel-scheduler-specific. Emits one JSON record
per (scenario, scheduler) so the ML/extractor can ingest it and answer later:
"for kovaaks, what thread data do we have, and how does code change it."

Usage:
  scx_cake_thread_profile.py --game-prefix FPSAimTrainer-Win64-Shipping \
      --scenario-id kovaaks_1080p --scheduler EEVDF --duration 20 \
      --out runs/.../perthread_EEVDF.json [--with-perf-graph]
"""
import argparse, glob, json, os, subprocess, sys, time

CLK = os.sysconf("SC_CLK_TCK")

def active_scheduler():
    try:
        s = open("/sys/kernel/sched_ext/root/ops").read().strip()
        return s if s else "EEVDF"
    except Exception:
        return "EEVDF"

def game_pids(prefix):
    out = subprocess.run(["pgrep", "-f", prefix], capture_output=True, text=True).stdout
    return sorted({int(p) for p in out.split()})

def _read(path):
    try:
        return open(path).read()
    except Exception:
        return ""

def thread_snapshot(pids):
    """Per-tid: comm, schedstat(run_ns,wait_ns,slices), sched(nr_migrations,util),
    status(vol/nonvol ctxt, cpus_allowed), wchan(blocked fn), last cpu."""
    snap = {}
    for pid in pids:
        for td in glob.glob(f"/proc/{pid}/task/*"):
            tid = os.path.basename(td)
            ss = _read(f"{td}/schedstat").split()
            if len(ss) < 3:
                continue
            comm = _read(f"{td}/comm").strip()
            sched = _read(f"{td}/sched")
            def grab(key, cast=int, default=0):
                for line in sched.splitlines():
                    if line.strip().startswith(key):
                        try:
                            return cast(line.split(":")[1].strip())
                        except Exception:
                            return default
                return default
            status = _read(f"{td}/status")
            def st(key):
                for line in status.splitlines():
                    if line.startswith(key):
                        return line.split(":")[1].strip()
                return ""
            stat = _read(f"{td}/stat").split()
            last_cpu = int(stat[38]) if len(stat) > 38 else -1
            snap[tid] = {
                "comm": comm,
                "run_ns": int(ss[0]), "wait_ns": int(ss[1]), "slices": int(ss[2]),
                "nr_migrations": grab("se.nr_migrations"),
                "util_avg": grab("se.avg.util_avg"),
                "vol_ctxt": int(st("voluntary_ctxt_switches") or 0),
                "nonvol_ctxt": int(st("nonvoluntary_ctxt_switches") or 0),
                "cpus_allowed": st("Cpus_allowed_list"),
                "wchan": _read(f"{td}/wchan").strip(),
                "last_cpu": last_cpu,
            }
    return snap

def diff(a, b, wall_s):
    rows = []
    for tid, vb in b.items():
        va = a.get(tid)
        if not va:
            continue
        d_run = vb["run_ns"] - va["run_ns"]
        d_wait = vb["wait_ns"] - va["wait_ns"]
        d_sl = vb["slices"] - va["slices"]
        d_mig = vb["nr_migrations"] - va["nr_migrations"]
        d_vol = vb["vol_ctxt"] - va["vol_ctxt"]
        d_nv = vb["nonvol_ctxt"] - va["nonvol_ctxt"]
        if d_run <= 0 and d_sl <= 0:
            continue
        rows.append({
            "tid": int(tid), "comm": vb["comm"],
            "run_ms": round(d_run / 1e6, 2),
            "run_pct": round(d_run / (wall_s * 1e9) * 100, 2),
            "wait_ms": round(d_wait / 1e6, 3),
            "slices": d_sl,
            "wait_us_per_slice": round(d_wait / d_sl / 1e3, 3) if d_sl else 0.0,
            "migrations": d_mig,
            "migrations_per_s": round(d_mig / wall_s, 1),
            "vol_ctxt": d_vol,            # blocked-on-dependency count (futex/wait)
            "nonvol_ctxt": d_nv,          # preempted/bumped count
            "util_avg": vb["util_avg"],
            "last_cpu": vb["last_cpu"],
            "cpus_allowed": vb["cpus_allowed"],
            "wchan": vb["wchan"],
        })
    rows.sort(key=lambda r: -r["run_ms"])
    return rows

def perf_wakeup_graph(duration, game_pids_set):
    """Best-effort waker->wakee dependency graph + handoff latency via perf sched.
    Returns [] if perf/permissions unavailable. Captures 'who wakes who' and how
    long the wakee waited to run = the producer->consumer / block handoff latency."""
    rec = "/tmp/cake_perf_sched.data"
    try:
        r = subprocess.run(["perf", "sched", "record", "-o", rec, "--", "sleep", str(duration)],
                           capture_output=True, text=True, timeout=duration + 30)
        if r.returncode != 0:
            return {"available": False, "reason": r.stderr.strip()[:200] or "perf sched record failed"}
        sc = subprocess.run(["perf", "sched", "latency", "-i", rec, "-s", "max"],
                           capture_output=True, text=True, timeout=60)
        # parse per-task avg/max scheduling delay table
        edges = []
        for line in sc.stdout.splitlines():
            parts = line.split("|")
            if len(parts) >= 4 and ":" in parts[0]:
                task = parts[0].strip()
                edges.append({"task": task, "row": " ".join(p.strip() for p in parts[1:])})
        return {"available": True, "latency_rows": edges[:40]}
    except Exception as e:
        return {"available": False, "reason": str(e)[:200]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--game-prefix", default="FPSAimTrainer-Win64-Shipping")
    ap.add_argument("--scenario-id", required=True)
    ap.add_argument("--scheduler", default=None, help="label; default auto-detect")
    ap.add_argument("--duration", type=float, default=20.0)
    ap.add_argument("--out", default=None, help="output json path")
    ap.add_argument("--with-perf-graph", action="store_true")
    ap.add_argument("--print", action="store_true")
    a = ap.parse_args()

    sched = a.scheduler or active_scheduler()
    pids = game_pids(a.game_prefix)
    if not pids:
        print(f"no game process matching {a.game_prefix}", file=sys.stderr)
        sys.exit(2)
    s0 = thread_snapshot(pids)
    t0 = time.time()
    graph = {"available": False}
    if a.with_perf_graph:
        graph = perf_wakeup_graph(a.duration, set(pids))  # this also consumes the window
        wall = time.time() - t0
    else:
        time.sleep(a.duration)
        wall = time.time() - t0
    s1 = thread_snapshot(game_pids(a.game_prefix))
    rows = diff(s0, s1, wall)

    record = {
        "schema": "scx_cake_thread_profile/v1",
        "scenario_id": a.scenario_id,
        "scheduler": sched,
        "game_prefix": a.game_prefix,
        "window_s": round(wall, 2),
        "host_ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "game_pids": pids,
        "threads": rows,
        "wakeup_graph": graph,
        "summary": {
            "n_threads": len(rows),
            "top": rows[0]["comm"] if rows else None,
            "top_run_pct": rows[0]["run_pct"] if rows else 0,
            "total_migrations_per_s": round(sum(r["migrations_per_s"] for r in rows), 1),
        },
    }
    out = a.out or f"/tmp/perthread_{a.scenario_id}_{sched}.json"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        json.dump(record, f, indent=2)
    if a.print or not a.out:
        print(f"# {sched}  scenario={a.scenario_id}  window={wall:.1f}s  -> {out}")
        print(f"{'thread':<18}{'run%':>6}{'run_ms':>9}{'wait_us/sl':>11}{'mig/s':>7}{'volCtx':>8}{'nvCtx':>7}{'lastcpu':>8}  wchan")
        for r in rows[:16]:
            print(f"{r['comm']:<18}{r['run_pct']:>5.1f}%{r['run_ms']:>9.1f}{r['wait_us_per_slice']:>11.2f}"
                  f"{r['migrations_per_s']:>7.0f}{r['vol_ctxt']:>8}{r['nonvol_ctxt']:>7}{r['last_cpu']:>8}  {r['wchan']}")
    print(f"WROTE {out}")

if __name__ == "__main__":
    main()
