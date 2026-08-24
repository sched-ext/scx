# scx_cake — performance testing

This file explains how cake is measured and where results stand.

## Status

**No published results exist for the current build.** Recent code changes
(the G27–G36 placement work) invalidate the prior campaign numbers, so this
file carries no result tables until the current build passes the A/B gates
again. Dated internal records of past campaigns live in
[`../STATE.md`](../STATE.md) and
[`archive/EEVDF_GATE_2026-07-04.md`](./archive/EEVDF_GATE_2026-07-04.md);
read them as history, not as claims about the current code.

## Method

- Hardware: AMD Ryzen 7 9800X3D (8c/16t, single CCD, 96 MB X3D cache),
  CachyOS kernel 7.1.x, performance governor.
- Interleaved A/B pairs: cake and EEVDF run back-to-back in the same noise
  window, ≥2 repetitions per scheduler.
- Background noise is recorded per run as a covariate, not filtered out.
  Mismatched pairs are discarded. Ties are declared when ranges overlap.
- Game screens rotate arm order (A-B-B-A; A-B-C-C-B-A for three arms)
  because slot position dominates frame-time tails.
- Results come from a receipted harness: it records the exact binary and
  BPF hashes of what ran. A plain local build runs fine, but its numbers
  are not comparable.
- Futex results need a mode tag: the host has an unidentified variable
  that moves futex throughput several-fold between sessions with the same
  binary and boot. Never read a futex delta without it.

## What a result must show before it is published here

1. Scheduler identity and binary hash verified before any number is read.
2. Noise class and external CPU load reported with every run.
3. Game changes: screened on severe-frame ratio, scored on 0.1% low and
   p99.9 − median, ≥4 runs per scheduler, ≥60 s captures.
4. Regressions reported as fully as wins.
