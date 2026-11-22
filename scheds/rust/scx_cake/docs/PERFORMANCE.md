# scx_cake performance testing

How cake is measured. Results live in the [STATE.md](../STATE.md) pattern ledger, with
each pattern's kernel need (🐧 stock or 🧩 patch).

## 📊 Where results stand

The [private idle word](#private-idle-word) with its claimed word (🐧) won in KovaaK's frames on
stock 7.3.1 and tied in ShadowGate. Lean idle `lazy` (🧩), which it replaces, won the same way on
the patched kernel. E1 (cached rq clock, 🐧 ≥ 6.14)
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

## Private idle word

On a host whose present CPU ids fit in 64 bits, cake keeps really idle CPUs in one BPF-owned word,
claims them with an inline atomic on a second word on the same cache line, and turns the kernel's
idle masks off. A claimed core still reads as whole until that CPU runs, the placement lean idle
`lazy` gave only on the patched kernel. Wide hosts keep the kernel's masks and picker. The idea comes
from Andrea Righi's `lib/cid_idle.h`, [credited here](../ACCREDITATION.md). The mechanism is in
[DESIGN.md](../DESIGN.md#hardware-discovery) and the attribution in
[STATE.md](../STATE.md#2026-11-07--private-idle-word-and-claimed-word-land-g103-g104).

Measured on a 9800X3D on stock `7.3.1-1-cachyos`: nightly `c98fe0e31` against the landing
`867e5a8c1`, both 1.3.1, in mirrored pairs of 20 s windows. Every slot was valid with noise class
low, at most 1.08 % external CPU and no other GPU user. The session was locked with both monitors
off for all of it, so on-screen numbers are still owed.

Each cell is the median change, then the pairs the landing won and the signed-rank p.

| Game | Load | Pairs | avg fps | p99 ms | p99.9 ms | 0.1 % low fps | max ms |
|---|---|---:|---:|---:|---:|---:|---:|
| KovaaK's menu | CPU-limited, 810 fps, GPU 40 % | 8 | +1.29 % (8, 0.008) | -1.44 % (8, 0.008) | -12.47 % (7, 0.016) | +3.18 % (7, 0.055) | -2.36 % (4, 0.945) |
| ShadowGate Low, 1280x720 | CPU-limited, 495 fps, GPU 80 % | 6 | +0.16 % (4, 0.562) | -2.40 % (5, 0.438) | +1.68 % (2, 0.312) | -3.01 % (2, 0.562) | +2.71 % (2, 0.312) |
| ShadowGate Epic, 1280x720 | 205 fps, GPU 85 %, not fully GPU-limited | 12 | -0.26 % (5, 0.677) | -0.18 % (7, 1.000) | +1.60 % (4, 0.151) | -6.61 % (3, 0.151) | +11.54 % (3, 0.151) |

KovaaK's wins, ShadowGate Low ties, and Epic ties with a lean against at the last few frames. A 20 s
Epic window has about 3,650 frames, so its 0.1 % low is about the worst four. The counts show the size:

| Game, frames nightly / landing | Frames over each limit, nightly to landing |
|---|---|
| KovaaK's, 120,375 / 121,418 | 1.4 ms 450 to 147, 1.5 ms 215 to 87, 1.6 ms 159 to 61, 1.8 ms 32 to 19, 2 ms 7 to 6, 2.5 ms 4 to 3, 3 ms 3 to 3 |
| ShadowGate Low, 53,022 / 53,076 | 3 ms 440 to 418, 3.5 ms 114 to 127, 4 ms 34 to 42, 4.5 ms 18 to 19, 5 ms 13 to 16, 6 ms 4 to 4, 7 ms 1 to 1 |
| ShadowGate Epic, 43,917 / 43,843 | 6.5 ms 961 to 940, 7 ms 235 to 211, 7.5 ms 54 to 58, 8 ms 14 to 21, 8.5 ms 10 to 12, 9 ms 6 to 9, 10 ms 4 to 5, 12 ms 1 to 1 |

ShadowGate's input-to-simulation timer moved by under 1.5 %, with no p below 0.5: Low p50 -0.13 %,
p99 -0.46 %, Epic p50 -0.34 %, p99 -1.32 %.

Kernel schedstat wait fell for all game threads together: KovaaK's 33 to 30 ns/run, Low 113 to 109,
Epic 182 to 177. In KovaaK's, migrations fell 16 % and RenderThread's wait 24 %. Two threads rose:
KovaaK's GameThread 193 to 199 ns/run and Epic's RenderThread 94 to 97.

The word without the claimed word is 0.71 ms/s cheaper in BPF but loses tail frames: KovaaK's p99.9
+11.66 % and 0.1 % low -5.82 % (0 of 3 clean pairs), ShadowGate Low worst frame +37.68 % and 0.1 %
low -10.78 % (2 of 9). So it did not land alone.

Appsim (`cakebench cost`, 4 slots per arm of 20 s, noise low), ns/run:

| | select | enqueue | dispatch | running | stopping | update_idle | cpu_release | BPF ms/s | p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| nightly | 87.65 | 170.57 | 14.66 | 22.21 | 14.25 | 8.83 | 230.71 | 25.15 | 0.6188 |
| landing | 78.34 | 159.85 | 16.78 | 24.93 | 16.17 | 9.83 | 234.14 | 24.63 | 0.6174 |
| change | -9.31 | -10.72 | +2.12 | +2.72 | +1.92 | +1.01 | +3.43 | -0.52 | -0.0014 |

`select` and `enqueue` are the wake path, and `enqueue` also runs less often (1.7 k/s, was 2.4 k/s).
`dispatch`, `update_idle` and `cpu_release` hold added code. `running` and `stopping` run the same
programs in every build. `stopping` rises by +1.22 from the word to the claimed word on the same
code and data layout, with separate slot ranges, so it follows the new placement, by elimination.
`running`'s slot ranges overlap and its own history swings 5 to 10 ns, so +2.72 is inside the swing.
`irq_leave` fell 155 ns, the known stats-window artifact, not judged, which is 0.19 ms/s of the BPF
saving. BPF ms/s is a lower bound until `bpftool prog profile` prices the atomics in `update_idle`,
and the kernel's saving from dropping its idle mask upkeep is outside these numbers.

The final code, `4b51cd91b`, is three commits past those tables: a queued prev is only trusted on its
own CPU, the pool give-backs stay ordered off x86 on older clang, and the load test gained a shape.
Against `867e5a8c1` it ties. KovaaK's, 4 pairs on the same terms, at most 0.9 % external CPU, median
change and signed-rank p: avg fps -0.09 % (1.000), p99 -0.07 % (0.875), p99.9 +0.22 % (0.625), 0.1 %
low -0.74 % (0.875), max +13.25 % (0.625). ShadowGate did not re-run on it.

| | select | enqueue | dispatch | running | stopping | update_idle | cpu_release | BPF ms/s | p99 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `867e5a8c1` | 78.36 | 163.78 | 16.52 | 24.16 | 15.81 | 9.90 | 239.37 | 24.50 | 0.6175 |
| `4b51cd91b` | 76.56 | 162.94 | 16.27 | 24.49 | 15.82 | 9.79 | 242.43 | 24.19 | 0.6171 |
| change | -1.80 | -0.84 | -0.25 | +0.33 | +0.00 | -0.11 | +3.05 | -0.31 | -0.0003 |

The native load test (real verifier, stock 7.3.1, rodata as the loader fills it, never attached) ran
56 layouts, each with and without a cpuidle driver. Nightly refused 28 of 112, the claimed word before
the load fixes refused 30, and the final code refused none, nor 3 more layouts with hotplug headroom.
Nightly refuses real layouts: SMT-off CPUs whose cores all have their own rank, 64 threads with 8 or
more LLCs, and 96 threads and up. Those fixes cost nothing measurable (appsim against the claimed word
before them: select -1.04, enqueue -2.53, dispatch -0.24, stopping -0.47, update_idle +0.11 ns, BPF
-0.24 ms/s).

A load only proves a layout loads. No multi-CCD or hybrid host has run this. By design an idle change
writes one line where the kernel wrote two, and claims add locked operations on that line. arm64 is
compiled, not run. The comparison with `lazy` on the patched kernel is owed.

<details>
<summary>Largest verified program by layout, cpuidle on, stock 7.3.1</summary>

Instructions the verifier walked, and the program. `+N` is the SMT sibling's distance.

| Layout | nightly `c98fe0e31` | claimed word `ab963f321` | final `4b51cd91b` |
|---|---:|---:|---:|
| this host, 16 at +8, 7 ranks | 76198 enqueue | 176413 enqueue | 157485 enqueue |
| 16 at +8, no ranks | 68889 dispatch | 140910 enqueue | 141014 enqueue |
| 16 at +8, 8 ranks | 81308 enqueue | 181061 enqueue | 159363 enqueue |
| 8 no SMT, 8 ranks | REFUSED select_cpu | REFUSED select_cpu | 158899 enqueue |
| 8 no SMT, 7 ranks (this host SMT off) | 78132 enqueue | 176827 enqueue | 157021 enqueue |
| 6 no SMT, 6 ranks | REFUSED enqueue | REFUSED select_cpu | 155679 enqueue |
| 4 no SMT, 4 ranks | REFUSED enqueue | REFUSED enqueue | 152191 enqueue |
| 4 no SMT, no ranks | 39611 enqueue | 140446 enqueue | 140550 enqueue |
| 1 CPU | 24300 enqueue | 124140 enqueue | 124244 enqueue |
| 8 at +4, 4 ranks | 62464 enqueue | 162493 enqueue | 152655 enqueue |
| 12 at +6, 6 ranks | 71820 enqueue | 171765 enqueue | 156143 enqueue |
| 24 at +12, 2 LLCs, 12 ranks | 166380 dispatch | 185953 dispatch | 89215 enqueue |
| 32 at +16, 2 LLCs, 16 ranks | 245582 dispatch | 280350 dispatch | 98351 enqueue |
| 16 no SMT, 2 LLCs, 16 ranks | REFUSED select_cpu | REFUSED select_cpu | 97797 enqueue |
| 12 no SMT, 2 LLCs, 12 ranks | REFUSED select_cpu | REFUSED select_cpu | 88661 enqueue |
| 48 at +24, 4 LLCs, 24 ranks | 482276 dispatch | 580875 dispatch | 117995 enqueue |
| 64 at +32, 4 LLCs, 32 ranks | 753669 dispatch | 939528 dispatch | 137710 enqueue |
| 64 at +32, 6 LLCs, no ranks | 938417 dispatch | REFUSED dispatch | 52682 enqueue |
| 64 at +32, 8 LLCs, 32 ranks | REFUSED dispatch | REFUSED dispatch | 137710 enqueue |
| 64 at +32, 16 LLCs, 32 ranks | REFUSED dispatch | REFUSED dispatch | 228542 dispatch |
| 64 no SMT, 8 LLCs, no ranks | REFUSED dispatch | REFUSED dispatch | 55445 dispatch |
| 24 hybrid, 8 pairs 8 singles, 3 ranks | 179158 enqueue | 290224 enqueue | 279739 enqueue |
| 32 hybrid, 8 pairs 16 singles, 3 ranks | 263438 enqueue | 387258 enqueue | 391310 enqueue |
| uneven, no ranks | 94730 enqueue | 318393 enqueue | 316120 enqueue |
| 4 threads a core, 2 LLCs, 4 ranks | 206567 enqueue | 308872 enqueue | 288509 enqueue |
| 72 at +36, 2 LLCs | 811208 dispatch | 760804 dispatch | 25841 dispatch |
| 96 at +48, 4 LLCs | REFUSED dispatch | REFUSED dispatch | 33185 dispatch |
| 128 at +64 | REFUSED dispatch | REFUSED dispatch | 42977 dispatch |
| 1024 at +512 | REFUSED dispatch | REFUSED dispatch | 133097 dispatch |
| 16 at +8, 256 possible | not run | not run | 157485 enqueue |
| 64 at +32, 16 LLCs, 32 ranks, 1024 possible | not run | not run | 351071 dispatch |

</details>

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
