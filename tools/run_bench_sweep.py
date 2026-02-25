#!/usr/bin/env python3
"""Full PQ benchmark sweep: all configs, all thread counts, plotly output."""

import json
import subprocess
import sys

BINARY = "/home/newton/work/rrn_scx_playground/scx/target/release/scx_arena_benchmarks"
THREAD_COUNTS = [1, 2, 4, 8, 16, 32, 64, 128, 158, 256, 316]
OPS = 100000
REPS = 3
ARENA_PAGES = 8192
OUTPUT_HTML = "/home/newton/work/rrn_scx_playground/scx/bench_pq_speedup.html"

# All 6 configs run by default
CONFIGS = "rpq-2t-k2:2:2,rpq-2t-k3:2:3,rpq-2t-k4:2:4,rpq-1t-k2:1:2,single,atq"


def run(threads):
    cmd = [
        "sudo", BINARY,
        "--threads", str(threads),
        "--ops", str(OPS),
        "--arena-pages", str(ARENA_PAGES),
        "--output", "json",
        "--configs", CONFIGS,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(f"  FAIL threads={threads}: {r.stderr.strip()[:200]}", file=sys.stderr)
        return []
    results = []
    for line in r.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def generate_plotly_html(results, output_path):
    """Generate self-contained HTML with plotly.js from CDN."""

    config_styles = {
        "rpq-2t-k2": ("#2196F3", "circle",       "RPQ (2T queues, pick-2)"),
        "rpq-2t-k3": ("#00BCD4", "diamond",       "RPQ (2T queues, pick-3)"),
        "rpq-2t-k4": ("#009688", "star-triangle-up", "RPQ (2T queues, pick-4)"),
        "rpq-1t-k2": ("#9C27B0", "hexagon",       "RPQ (1T queues, pick-2)"),
        "single":    ("#F44336", "square",         "Single-queue RPQ"),
        "atq":       ("#FF9800", "cross",          "ATQ (rbtree)"),
    }

    # Group results by benchmark name
    by_name = {}
    for r in results:
        name = r["benchmark"]
        if name not in by_name:
            by_name[name] = {}
        t = r["threads"]
        if t not in by_name[name]:
            by_name[name][t] = []
        by_name[name][t].append(r)

    # Compute per-config 1-thread baseline
    bases = {}
    for name, tdata in by_name.items():
        vals = [r["mops_per_sec"] for r in tdata.get(1, [])]
        bases[name] = sum(vals) / len(vals) if vals else 1.0

    def make_trace(name):
        color, symbol, label = config_styles.get(name, ("#666", "circle", name))
        data = by_name.get(name, {})
        base = bases.get(name, 1.0)
        threads = sorted(data.keys())
        means = [sum(r["mops_per_sec"] for r in data[t]) / len(data[t]) for t in threads]
        speedups = [m / base if base > 0 else 0 for m in means]

        mins = [min(r["mops_per_sec"] for r in data[t]) / base for t in threads]
        maxs = [max(r["mops_per_sec"] for r in data[t]) / base for t in threads]
        err_minus = [s - mn for s, mn in zip(speedups, mins)]
        err_plus = [mx - s for s, mx in zip(speedups, maxs)]

        # Max latency across reps
        max_lats = [max(r.get("max_pop_ns", 0) for r in data[t]) for t in threads]

        hover = [
            f"{label}<br>Threads: {t}<br>Speedup: {s:.2f}x<br>"
            f"Throughput: {m:.1f} MOps/s<br>Max pop lat: {l/1000:.1f} us"
            for t, s, m, l in zip(threads, speedups, means, max_lats)
        ]

        return {
            "x": threads, "y": speedups,
            "mode": "lines+markers", "name": label,
            "line": {"color": color, "width": 2.5},
            "marker": {"size": 9, "symbol": symbol},
            "error_y": {
                "type": "data", "symmetric": False,
                "array": err_plus, "arrayminus": err_minus,
                "thickness": 1.5, "width": 4,
            },
            "hovertext": hover, "hoverinfo": "text",
        }

    max_t = max(THREAD_COUNTS)
    traces = [
        {
            "x": [1, max_t], "y": [1, max_t],
            "mode": "lines", "name": "Ideal (linear)",
            "line": {"dash": "dash", "color": "#BDBDBD", "width": 1.5},
            "hoverinfo": "skip",
        },
    ]

    # Order: multi-queue configs first, then baselines
    order = ["rpq-2t-k2", "rpq-2t-k3", "rpq-2t-k4", "rpq-1t-k2", "single", "atq"]
    for name in order:
        if name in by_name:
            traces.append(make_trace(name))

    layout = {
        "title": {"text": "Priority Queue Parallel Speedup (monotonic vtime)", "font": {"size": 18}},
        "xaxis": {"title": "Threads", "type": "log", "dtick": 1, "gridcolor": "#E0E0E0"},
        "yaxis": {"title": "Speedup (vs own 1-thread throughput)", "type": "log", "dtick": 1, "gridcolor": "#E0E0E0"},
        "plot_bgcolor": "white",
        "width": 1050, "height": 700,
        "legend": {"x": 0.02, "y": 0.98, "bgcolor": "rgba(255,255,255,0.8)", "font": {"size": 11}},
        "margin": {"l": 70, "r": 30, "t": 60, "b": 60},
    }

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>PQ Parallel Speedup</title>
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
</head>
<body>
  <div id="plot"></div>
  <script>
    var traces = {json.dumps(traces)};
    var layout = {json.dumps(layout)};
    Plotly.newPlot('plot', traces, layout);
  </script>
</body>
</html>
"""
    with open(output_path, "w") as f:
        f.write(html_content)


def main():
    all_results = []

    for t in THREAD_COUNTS:
        for rep in range(REPS):
            print(f"  threads={t} rep={rep+1}/{REPS} ...", end=" ", flush=True)
            results = run(t)
            if not results:
                print("FAILED")
                continue
            for r in results:
                r["rep"] = rep
            all_results.extend(results)
            names = " | ".join(f"{r['benchmark']}={r['mops_per_sec']:.1f}" for r in results)
            print(names)

    generate_plotly_html(all_results, OUTPUT_HTML)
    print(f"\nPlot saved to {OUTPUT_HTML}")

    # Print summary table
    by_name = {}
    for r in all_results:
        name = r["benchmark"]
        if name not in by_name:
            by_name[name] = {}
        t = r["threads"]
        if t not in by_name[name]:
            by_name[name][t] = []
        by_name[name][t].append(r)

    names = ["rpq-2t-k2", "rpq-2t-k3", "rpq-2t-k4", "rpq-1t-k2", "single", "atq"]
    bases = {}
    for n in names:
        vals = [r["mops_per_sec"] for r in by_name.get(n, {}).get(1, [])]
        bases[n] = sum(vals) / len(vals) if vals else 1.0

    hdr = f"{'Threads':>8}"
    for n in names:
        hdr += f"  {n:>12}"
    print(f"\n--- Throughput (MOps/s, mean) ---")
    print(hdr)
    for t in THREAD_COUNTS:
        row = f"{t:>8}"
        for n in names:
            vals = [r["mops_per_sec"] for r in by_name.get(n, {}).get(t, [])]
            m = sum(vals) / len(vals) if vals else 0
            row += f"  {m:>12.2f}"
        print(row)


if __name__ == "__main__":
    main()
