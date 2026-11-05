# scx_cake performance testing

How cake is measured. Results live in the [STATE.md](../STATE.md) pattern ledger, with
each pattern's kernel need (🐧 stock or 🧩 patch).

## 📊 Where results stand

Lean idle `lazy` (🧩) is the one win proven in game frames. E1 (cached rq clock, 🐧 ≥ 6.14)
and native bitops (🧩) win at ns/run; bitops showed no frame change, E1's game A/B is
owed. Dated reports:
[KovaaK's A/B 09-28](KOVAAKS_KICK_ABBA_2026-09-28.md) (nightly vs the previous cake) ·
[EEVDF gate 07-04](archive/EEVDF_GATE_2026-07-04.md) (historical).

## 🧪 Method

| Rule | |
|---|---|
| Host | AMD Ryzen 7 9800X3D (8 cores / 16 threads, one CCD, 96 MiB L3); kernel, governor and boot identity come from each run's metadata |
| Levels | as in `CLAUDE.md`: game frames > appsim frames > callback ns/run > static counts; decide by the highest level measured |
| Slots | rotate arm order (A-B-B-A; A-B-C-C-B-A for three arms): slot position dominates frame tails · about 6 × 20 s slots per condition, at most 5 min per run |
| Noise | `noise_class` and `external_cpu_avg_pct` recorded per run as covariates, never filtered · mismatched pairs discarded · overlapping ranges are a tie |
| Identity | numbers come from the receipted harness (exact binary and BPF hashes); a plain local build runs fine, but its numbers are not comparable |
| Games | record CPU- or GPU-limited (KovaaK's uncapped at low resolution is CPU-limited; an FPS cap or high resolution makes it GPU-limited) |
| Futex | tag the mode: an unidentified host variable moves futex throughput several-fold between sessions with the same binary and boot |

**Before publishing a result:** identity and binary hash verified before any number is
read · noise class and outside CPU load reported · game changes screened on
severe-frame ratio and scored on 0.1 % low and p99.9 − median · regressions reported as
fully as wins.

---

## 🔀 When fewer migrations is a win (2026-09-18)

A migration trades a wait for a cache refill: L1/L2 (1 MiB per core here; §G38 measured
up to +59 % run time on a cold core), branch predictors and TLB, plus ~1 µs for the hop.
It is **right** when the wait it avoids is longer than the refill, **wrong** when the
home was idle or about to be, and a **no-op** for a microsecond burst with nothing warm.
So a migration count says nothing by itself.

| Verdict | What the numbers show |
|---|---|
| ✅ good reduction | migrations/dispatch down; wait/dispatch flat (within the before-vs-before spread); run time per burst flat or down; L1d/L2 misses per instruction down; the census shows the removed migrations were `hd_*` declines with an idle home |
| ❌ bad reduction | migrations down, wait/dispatch up: the thread now queues for its home (§G47: kept the IRQ CPU, doubled severe frames) |
| ➖ empty reduction | migrations down, misses/instruction unchanged: microbursts free to move anyway |
| ✅ correct migration | the home was busy (`hd_notidle`, `hd_contended`), idle capacity existed, and the burst after the move is no longer than after a stay |

A migration claim ships on layer 1; layer 2 explains it; layer 3 is owed whenever a
change moves placement policy.

| Layer | Signal | Tool | Root |
|---|---|---|---|
| 1a | wait per dispatch, per chain thread | `/proc/<tid>/schedstat` run_delay / pcount deltas over the slot | no |
| 1b | run time per burst | same file, run_time / pcount | no |
| 1c | L1d / L2 misses per instruction, IPC | `perf stat -t <tid> -e cycles,instructions,L1-dcache-load-misses,l2_cache_misses_from_dc_misses` (game threads carry no file caps; `perf_event_paranoid` is −1 here) | no |
| 2 | why the remaining migrations happened | `probe=1` census: placement kinds (home, warm claim, pool, steal, retake, reroute) and `hd_*` decline reasons · `bench/migrate_cause.py`, `bench/wake_migsplit.py` | no |
| 3 | per-migration outcome | `perf sched record` 30 s per arm: per chain-thread wake, moved or not, and the burst after; `bench/wake_occupant.py`, `bench/scx_cake_thread_profile.py` | tracefs (`chmod o+rx /sys/kernel/tracing`, maintainer) |

Chain threads here: `nvidia-modeset/kthread_q`, `nvidia-drm/timeline-*`, `vkd3d_queue`,
`vkd3d_fence`, `vkd3d-swapchain`, the game main thread. Same discipline as everywhere:
ABBA, matched scene (GPU % and IRQ rate as covariates), receipts verified, ask before
attaching.

⏳ The 2026-09-18 result (chain migrations −21…−28 % per dispatch, waits flat under
0.15 µs) has layer 1a only; 1b, 1c and 2 are owed before it counts as a win.
