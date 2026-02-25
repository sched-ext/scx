#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This software may be used and distributed according to the terms of the
# GNU General Public License version 2.

"""
Priority Queue Throughput Benchmark Orchestrator

Sweeps thread counts, runs RPQ vs rbtree benchmarks, collects results,
and generates throughput-vs-threads plots.

Usage:
    sudo python3 tools/bench_pq.py --binary ./target/release/scx_arena_benchmarks
    sudo python3 tools/bench_pq.py --binary ./target/debug/scx_arena_benchmarks --max-threads 8
"""

import argparse
import csv
import json
import os
import subprocess
import sys


def get_max_cpus():
    """Get the number of online CPUs."""
    return os.cpu_count() or 1


def power_of_two_range(start, end):
    """Generate powers of two from start to end (inclusive)."""
    val = start
    while val <= end:
        yield val
        val *= 2


def run_benchmark(binary, bench_type, threads, ops, queues=None, queue_cap=4096,
                  prepopulate=10000, arena_pages=512):
    """Run a single benchmark and return parsed JSON result."""
    cmd = [
        binary,
        "--bench", bench_type,
        "--threads", str(threads),
        "--ops", str(ops),
        "--queue-cap", str(queue_cap),
        "--prepopulate", str(prepopulate),
        "--arena-pages", str(arena_pages),
        "--output", "json",
    ]
    if queues is not None:
        cmd.extend(["--queues", str(queues)])

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: {bench_type} threads={threads}", file=sys.stderr)
        return None

    if result.returncode != 0:
        print(
            f"  ERROR: {bench_type} threads={threads} rc={result.returncode}",
            file=sys.stderr,
        )
        if result.stderr:
            print(f"  stderr: {result.stderr.strip()}", file=sys.stderr)
        return None

    # Parse JSON lines (one per benchmark type)
    results = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return results


def main():
    parser = argparse.ArgumentParser(
        description="PQ throughput benchmark orchestrator"
    )
    parser.add_argument(
        "--binary",
        default="./target/release/scx_arena_benchmarks",
        help="Path to the benchmark binary",
    )
    parser.add_argument(
        "--min-threads", type=int, default=1,
        help="Minimum thread count (default: 1)",
    )
    parser.add_argument(
        "--max-threads", type=int, default=None,
        help="Maximum thread count (default: nr_cpus)",
    )
    parser.add_argument(
        "--ops", type=int, default=100000,
        help="Operations per thread (default: 100000)",
    )
    parser.add_argument(
        "--reps", type=int, default=3,
        help="Repetitions per data point (default: 3)",
    )
    parser.add_argument(
        "--queue-cap", type=int, default=4096,
        help="Per-heap capacity (default: 4096)",
    )
    parser.add_argument(
        "--prepopulate", type=int, default=10000,
        help="Pre-fill count (default: 10000)",
    )
    parser.add_argument(
        "--arena-pages", type=int, default=512,
        help="Static arena allocation pages (default: 512)",
    )
    parser.add_argument(
        "--output-csv", default="bench_pq_results.csv",
        help="Output CSV file (default: bench_pq_results.csv)",
    )
    parser.add_argument(
        "--plot", default=None,
        help="Output plot file (e.g., bench_pq.png). Requires matplotlib.",
    )
    parser.add_argument(
        "--no-plot", action="store_true",
        help="Skip plotting even if matplotlib is available",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"Error: binary not found: {args.binary}", file=sys.stderr)
        print("Build with: cargo build --release -p scx_arena_selftests", file=sys.stderr)
        sys.exit(1)

    max_threads = args.max_threads or get_max_cpus()
    thread_counts = list(power_of_two_range(args.min_threads, max_threads))

    # Also add max_threads if it's not a power of two
    if max_threads not in thread_counts and max_threads > thread_counts[-1]:
        thread_counts.append(max_threads)

    print(f"Benchmark configuration:")
    print(f"  Binary:       {args.binary}")
    print(f"  Thread sweep: {thread_counts}")
    print(f"  Ops/thread:   {args.ops}")
    print(f"  Repetitions:  {args.reps}")
    print(f"  Queue cap:    {args.queue_cap}")
    print(f"  Prepopulate:  {args.prepopulate}")
    print()

    all_results = []

    for threads in thread_counts:
        # Use 2*threads queues for RPQ (standard MultiQueue recommendation)
        queues = 2 * threads

        for rep in range(args.reps):
            print(
                f"Running: threads={threads} rep={rep + 1}/{args.reps} ...",
                end=" ",
                flush=True,
            )

            results = run_benchmark(
                args.binary,
                "both",
                threads,
                args.ops,
                queues=queues,
                queue_cap=args.queue_cap,
                prepopulate=args.prepopulate,
                arena_pages=args.arena_pages,
            )

            if results is None:
                print("FAILED")
                continue

            for r in results:
                r["rep"] = rep
                r["queues"] = queues
                all_results.append(r)
                print(
                    f"{r['benchmark']}={r['mops_per_sec']:.3f} MOps/s",
                    end="  ",
                )

            print()

    # Write CSV
    if all_results:
        fieldnames = [
            "benchmark", "threads", "queues", "ops_per_thread",
            "total_ops", "elapsed_ns", "mops_per_sec",
            "inserts_ok", "inserts_fail", "pops_ok", "pops_fail", "rep",
        ]
        with open(args.output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in all_results:
                writer.writerow({k: r.get(k, "") for k in fieldnames})

        print(f"\nResults written to: {args.output_csv}")

    # Plot
    plot_file = args.plot
    if not plot_file and not args.no_plot:
        plot_file = "bench_pq.png"

    if plot_file and all_results and not args.no_plot:
        try:
            plot_results(all_results, plot_file)
            print(f"Plot saved to: {plot_file}")
        except ImportError:
            print(
                "matplotlib not available, skipping plot. "
                "Install with: pip install matplotlib",
                file=sys.stderr,
            )


def plot_results(results, output_file):
    """Generate throughput-vs-threads plot."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    # Group by benchmark type
    benchmarks = {}
    for r in results:
        name = r["benchmark"]
        if name not in benchmarks:
            benchmarks[name] = {}
        threads = r["threads"]
        if threads not in benchmarks[name]:
            benchmarks[name][threads] = []
        benchmarks[name][threads].append(r["mops_per_sec"])

    fig, ax = plt.subplots(figsize=(10, 6))

    colors = {"rpq": "#2196F3", "single": "#F44336"}
    markers = {"rpq": "o", "single": "s"}

    for name, thread_data in sorted(benchmarks.items()):
        threads_list = sorted(thread_data.keys())
        means = []
        stds = []
        for t in threads_list:
            vals = thread_data[t]
            means.append(np.mean(vals))
            stds.append(np.std(vals))

        color = colors.get(name, "#666666")
        marker = markers.get(name, "^")

        ax.errorbar(
            threads_list,
            means,
            yerr=stds,
            label=name.upper(),
            marker=marker,
            color=color,
            capsize=4,
            linewidth=2,
            markersize=8,
        )

    ax.set_xlabel("Threads", fontsize=12)
    ax.set_ylabel("Throughput (MOps/s)", fontsize=12)
    ax.set_title("Priority Queue Throughput: RPQ (Multi-Queue) vs Single-Lock", fontsize=14)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_xscale("log", base=2)

    # Use integer ticks for thread counts
    thread_ticks = sorted(
        set(r["threads"] for r in results)
    )
    ax.set_xticks(thread_ticks)
    ax.set_xticklabels([str(t) for t in thread_ticks])

    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()


if __name__ == "__main__":
    main()
