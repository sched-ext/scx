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

## Migration verdict — when fewer migrations is a win, and how to prove it (2026-09-18)

A migration is a cost paid to avoid a wait: the thread refills L1/L2 (1 MiB per
core here; §G38 measured up to +59 % run time on a cold core), branch predictors and
TLB, plus the hop (~1 µs). It is the **right** move when the wait it avoids is longer
than that refill; the **wrong** move when the home was idle or about to be (the
thread paid the refill for nothing), or a **no-op** when the thread has no working set
(a microsecond burst: nothing to keep warm). So a migration *count* says nothing by
itself. A reduction is good only if the removed migrations were the wrong or no-op
kind and the threads did not start waiting instead.

| verdict | what the numbers show |
|---|---|
| **good reduction** | migrations/dispatch down; wait/dispatch flat (within the before-vs-before spread); run time per burst flat or down; L1d/L2 misses per instruction down; the census shows the removed migrations came from `hd_*` declines where the home was idle |
| **bad reduction** | migrations down but wait/dispatch up: the thread now queues for its home. §G47 is the recorded case (kept the IRQ CPU, doubled severe frames) |
| **empty reduction** | migrations down, misses/instruction unchanged: microbursts that were free to move anyway; no harm, no claim |
| **correct migration** (the ones that must stay) | the home was busy (`hd_notidle`, `hd_contended`) and idle capacity existed; the burst after the move is not longer than the burst after a stay |

**Three layers of proof, cheapest first.** A migration claim ships on layer 1; layer 2
attributes it; layer 3 is owed whenever a construct changes placement policy.

| layer | signal | tool | root |
|---|---|---|---|
| 1a | wait per dispatch, per chain thread | `/proc/<tid>/schedstat` run_delay / pcount deltas over the slot | no |
| 1b | run time per burst | same file, run_time / pcount | no |
| 1c | L1d / L2 misses per instruction, IPC | `perf stat -t <tid> -e cycles,instructions,L1-dcache-load-misses,l2_cache_misses_from_dc_misses` (wine/game threads carry no file caps; `perf_event_paranoid` is −1 here) | no |
| 2 | why the remaining migrations happened | probe=1 census: placement kinds (home / warm claim / pool / steal / retake / reroute) and the `hd_*` decline reasons; `bench/migrate_cause.py`, `bench/wake_migsplit.py` | no |
| 3 | per-migration outcome | `perf sched record` 30 s per arm; for each chain-thread wakeup, migrated or not, and the length of the burst that followed; burst-after-move vs burst-after-stay per thread, per arm; `bench/wake_occupant.py`, `bench/scx_cake_thread_profile.py` | tracefs (`chmod o+rx /sys/kernel/tracing`, maintainer) |

Chain threads on this host: `nvidia-modeset/kthread_q`, `nvidia-drm/timeline-*`,
`vkd3d_queue`, `vkd3d_fence`, `vkd3d-swapchain`, the game main thread. Rotation
discipline as everywhere: ABBA, scene matched (GPU % and IRQ rate as covariates),
receipts verified, go asked before attaching.

Standing: the 2026-09-18 result (chain migrations −21..−28 % per dispatch, waits flat
under 0.15 µs) has layer 1a only; 1b, 1c and 2 are owed before it is called a win
rather than a plausible one.

---
