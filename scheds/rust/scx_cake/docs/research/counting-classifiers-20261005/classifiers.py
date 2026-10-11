#!/usr/bin/env python3
"""Cake's task classifiers over a /proc thread snapshot (cakesim snapshot.py format).

usage: classifiers.py [snapshot.json]
"""
import collections
import json
import os
import sys

SNAP = os.path.expanduser(
    "~/Documents/Repo/scx_cake_bench/bench/cakesim/data/threads_20260927_0535.json")
M64 = (1 << 64) - 1
H, S = 1464, 64_000


def starved_today(W, R, m, n, k):
    w, r = W >> 16, R >> 16
    return bool(r) and ((w * n) & M64) > (((r << (k - 1)) * m) & M64)


def starved_exact(W, R, m, n, k):
    return bool(R) and W * n > k * R * m


def main():
    snap = json.load(open(sys.argv[1] if len(sys.argv) > 1 else SNAP))
    threads = snap["threads"]
    by_thread, by_wake = collections.Counter(), collections.Counter()
    hist = collections.Counter()
    wakes = 0
    pdiff = []
    for t in threads:
        R, W = t["sum"], t["run_delay"]
        n, m = t["nvcsw"] | 1, t["pcount"] | 1
        wt = t["nvcsw"]
        wakes += wt
        sub = (n >> 32) == 0 and R < H * n
        stage = n <= M64 // S and R >= S * n
        f = {
            "sub-handoff": sub,
            "mid": not sub and not stage,
            "stage": stage,
            "starved": starved_today(W, R, m, n, 1),
            "starved (exact)": starved_exact(W, R, m, n, 1),
            "starved_turn": starved_today(W, R, m, n, 2),
            "starved_turn (exact)": starved_exact(W, R, m, n, 2),
            "starved misread": starved_today(W, R, m, n, 1) != starved_exact(W, R, m, n, 1),
            "turn misread": starved_today(W, R, m, n, 2) != starved_exact(W, R, m, n, 2),
            "dead zone (R < 65536 ns)": (R >> 16) == 0,
            "dead zone, exactly starved": (R >> 16) == 0 and starved_exact(W, R, m, n, 1),
            "u64 wrap": (W >> 16) * n > M64 or ((R >> 16) << 1) * m > M64,
            "turn but not starved": starved_today(W, R, m, n, 2) and not starved_today(W, R, m, n, 1),
            "sub-handoff and stage": sub and stage,
        }
        for k, v in f.items():
            by_thread[k] += bool(v)
            by_wake[k] += wt * bool(v)
        hist[max(0, (R // n).bit_length() - 1)] += wt
        pdiff.append(t["pcount"] - t["nvcsw"] - t["nivcsw"])
    nt = len(threads)
    print(f"{nt} threads, uptime {snap['uptime_ns'] / 3.6e12:.1f} h")
    print(f"{'class':28s} {'threads':>8s} {'%':>7s} {'wake-weighted %':>16s}")
    for k in by_thread:
        print(f"{k:28s} {by_thread[k]:8d} {100 * by_thread[k] / nt:7.2f} {100 * by_wake[k] / wakes:16.4f}")
    print("wake-weighted mean-burst histogram (log2 ns):")
    for b in sorted(hist):
        if hist[b] * 1000 >= wakes:
            print(f"  [2^{b}, 2^{b + 1}) {100 * hist[b] / wakes:6.2f}%")
    pdiff.sort()
    print(f"pcount - (nvcsw + nivcsw): min {pdiff[0]}, median {pdiff[len(pdiff) // 2]}, max {pdiff[-1]}")


if __name__ == "__main__":
    main()
