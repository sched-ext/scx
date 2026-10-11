#!/usr/bin/env python3
"""Concurrent idle claims: wasted claim RMWs per burst for each tie-break rule.

k wakers on distinct CPUs read the same candidate set C and claim at once, in
random RMW order. A loser drops its target and retries by the same rule, up to
four tries (cake_claim_tries on a 16-CPU die); wakers left over go to the pool.
"""
import random

NCPU = 16
TRIES = 4


def target(rule, cand, waker):
    s = sorted(cand)
    if rule == "lowest":                     # ctz of the candidate word
        return s[0]
    if rule == "rotate":                     # first candidate after the waker, wrapping
        return next((c for c in s if c > waker), s[0])
    if rule == "select-j":                   # j = (waker * |C|) >> log2(NCPU)
        return s[(waker * len(s)) // NCPU]
    return random.choice(s)


def burst(rule, cand, k):
    wakers = random.sample(range(NCPU), k)
    view = {w: set(cand) for w in wakers}
    tries = dict.fromkeys(wakers, 0)
    taken, wasted, pooled = set(), 0, 0
    pending = list(wakers)
    while pending:
        random.shuffle(pending)
        retry = []
        for w in pending:
            if not view[w] or tries[w] >= TRIES:
                pooled += 1
                continue
            t = target(rule, view[w], w)
            tries[w] += 1
            if t in taken:
                wasted += 1
                view[w].discard(t)
                retry.append(w)
            else:
                taken.add(t)
        pending = retry
    return wasted, pooled


def main():
    random.seed(7)
    rules = ["lowest", "rotate", "select-j", "random"]
    print("wasted claims per burst (wakers pooled), 20000 bursts per cell")
    print(f"{'k':>2} {'|C|':>3} " + " ".join(f"{r:>14s}" for r in rules))
    for k in (2, 4, 8):
        for nc in (2, 4, 8, 12):
            cells = []
            for rule in rules:
                w = p = 0
                for _ in range(20000):
                    a, b = burst(rule, random.sample(range(NCPU), nc), k)
                    w += a
                    p += b
                cells.append(f"{w / 20000:5.2f} ({p / 20000:4.2f})")
            print(f"{k:>2} {nc:>3} " + " ".join(f"{c:>14s}" for c in cells))


if __name__ == "__main__":
    main()
