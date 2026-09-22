# The "master algorithm / fewer branches" thesis — priced against the corpus

**Date:** 2026-08-07. **Question (maintainer):** is there a master algorithm or formula
that reaches cake's same verdicts with fewer branches, giving a shorter hot path and
lower latency?

**Verdict: half confirmed, half already falsified — and the two halves live in
different functions.** The "fewer branches" half is dead where it was aimed. The
"better questions" half is the mechanism behind every measured win this campaign has.

Evidence class per the ledger in STATE.md: this document is CENSUS + STATIC. It carries no
performance verdict of its own; every latency number quoted is cited to the run that
measured it.

---

## 1. Fresh branch census — release object, whole `.bpf.o`

Object: `target/release/build/scx_cake-fb5cb1b0f8a481a5/out/bpf.bpf.o`, mtime
2026-08-05 17:13:09. Last commit touching `cake.bpf.c` / `intf.h`: `b607264ad`
(2026-08-03), so the object post-dates the source and matches HEAD.

Tool: `llvm-objdump -d --no-show-raw-insn`, per-function counts. `cond` = `if … goto`.
Script kept at `bench/` sibling scratch; recipe is one line, reproduce rather than trust.

| section | function | insns | cond | uncond | call | ld | st | br/insn |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| struct_ops | `cake_select_cpu` | 271 | 44 | 7 | 27 | 35 | 14 | 0.162 |
| struct_ops | `cake_enqueue` | 159 | 22 | 3 | 11 | 36 | 12 | 0.138 |
| .text | `cake_enqueue_wake` | 111 | 14 | 2 | 9 | 17 | 12 | 0.126 |
| .text | `cake_wake_notify` | 98 | 17 | 2 | 12 | 13 | 0 | 0.173 |
| struct_ops.s | `cake_init` | 97 | 14 | 5 | 17 | 6 | 4 | 0.144 |
| .text | `cake_dispatch_search` | 65 | 13 | 6 | 10 | 3 | 1 | 0.200 |
| struct_ops | `cake_stopping` | 55 | 7 | 1 | 2 | 11 | 3 | 0.127 |
| .text | `cake_ring_steal` | 47 | 10 | 0 | 2 | 3 | 0 | 0.213 |
| .text | `cake_handoff_yields` | 41 | 6 | 1 | 2 | 8 | 0 | 0.146 |
| .text | `cake_wake_preempt` | 39 | 6 | 0 | 3 | 6 | 1 | 0.154 |
| .text | `cake_occupant_live` | 37 | 4 | 1 | 3 | 5 | 1 | 0.108 |
| .text | `cake_wake_vtime` | 35 | 4 | 0 | 0 | 7 | 0 | 0.114 |
| .text | `cake_frame_observe` | 34 | 6 | 0 | 1 | 4 | 3 | 0.176 |
| .text | `cake_home_notify` | 30 | 4 | 1 | 3 | 2 | 1 | 0.133 |
| struct_ops | `cake_dispatch` | 26 | 5 | 0 | 1 | 8 | 1 | 0.192 |
| struct_ops | `cake_exit` | 25 | 1 | 0 | 3 | 8 | 1 | 0.040 |
| .text | `cake_home_claim` | 21 | 2 | 0 | 1 | 3 | 0 | 0.095 |
| struct_ops | `cake_running` | 20 | 1 | 0 | 3 | 4 | 3 | 0.050 |
| .text | `cake_pinned_wake_preempt` | 19 | 3 | 0 | 2 | 1 | 0 | 0.158 |
| fentry | `scx_lib_init_probe` | 16 | 3 | 0 | 2 | 1 | 1 | 0.188 |
| .text | `cake_system_serial` | 15 | 1 | 0 | 3 | 1 | 0 | 0.067 |
| .text | `cake_scale_vtime_slow` | 9 | 0 | 0 | 0 | 0 | 0 | 0.000 |
| .text | `cake_wake_starved` | 9 | 0 | 0 | 1 | 1 | 0 | 0.000 |
| .text | `cake_wake_idle_stamp` | 9 | 1 | 0 | 1 | 1 | 1 | 0.111 |
| struct_ops | `cake_enable` | 9 | 1 | 1 | 1 | 2 | 1 | 0.111 |
| .text | `cake_wake_serve_stamp` | 5 | 0 | 0 | 1 | 0 | 1 | 0.000 |
| **TOTAL** | | **1302** | **189** | **30** | **121** | | | **0.145** |

Read: branch density is uniform, ~0.145 across every function. There is no outlier
function drowning in predicates. The whole object is 1302 instructions and no callback
executes more than a fraction of it.

**Ceiling arithmetic.** On a 9800X3D at 5.5 GHz one cycle is ~0.18 ns. A branch that
predicts is ~free; a mispredict is ~15-20 cycles, i.e. **~3 ns**. Even an absurd
worst case — every one of `cake_select_cpu`'s 44 conditional branches mispredicting on
every wake — is ~130 ns, and real predictors do not miss on 44 of 44.

**AMENDED 2026-08-07, maintainer pushback: "schedulers are won and lost at the
nanosecond level." Correct, and the amendment sharpens rather than softens this
document.** The error above was not the 3 ns figure — it was implying that a nanosecond
lever is a small lever. It is not. The correct unit is **ns × ops/sec**, per
`MEMORY.md` §user_hardware_and_perf_scale.

Rate, from the same G12 census (45 s window, `STATE.md` §FINDING 2): 7,041,720
dispatches / 45 s = **156,483 dispatches/s** machine-wide, and `cake_select_cpu` runs on
99.86% of them. Every one sits on a wake's critical path. On a throughput benchmark the
multiplier is larger still — futex has run at 4.8M ops, where 100 ns per op is 0.48 s of
wall clock.

**So the nanoseconds decide it. The question is which nanoseconds.** Three terms compete
inside `cake_select_cpu`'s 271 instructions:

| term | count in `cake_select_cpu` | cost each | evidence class |
|---|---:|---|---|
| conditional branch, predicted | 44 | ~0 | STATIC (this census) |
| conditional branch, mispredicted | ≤44 | ~3 ns | STATIC + arch assumption |
| kfunc call | **27** | call + r1-r5 clobber, spill/refill traffic | STATIC (this census) |
| memory access | **35 ld / 14 st** | L1 ~1 ns, L3 ~9 ns, DRAM tens of ns | **ASSUMPTION — not measured this session** |

The branch term is the *smallest* of the three and the only one this document originally
priced. **The memory and call terms dominate it by roughly an order of magnitude**, and
neither is reduced by asking fewer questions — they are reduced by touching fewer lines
and calling fewer kfuncs. That is a different optimisation from the one the thesis
proposed, aimed at the same goal, and it is the one the arithmetic supports.

Consequence for §6: the steal ring becomes the recommended cut for a *second*
independent reason. A ring walk is pointer-chasing memory, so its cost is
**cache misses × ~95 per hit**, not branches × 95 — the dominant term, at the highest
rate in the object.

## 2. Where the branches actually execute — the census that decides this

`ops.enqueue` is the densest decision tree cake owns (159 insns, 22 conditional
branches, plus `cake_enqueue_wake`'s 111/14). It is also almost never reached in a game.

| regime | wake enqueues | dispatches | reach |
|---|---:|---:|---:|
| game-shaped | 10,019 | 7,041,720 | **0.142%** |
| saturated | 71,761 | 303,886 | **23.6%** |

Source: `STATE.md` §FINDING 3 (G12 census); restated in
`AUDIT_GAME_RELEVANCE_2026-08-02.md:26` (git history). **166× apart.**

Consequence, quoted from that finding: *"Every routing decision cake owns — the wake
arm, the continuation arm, the chain class, G10.2, G10.3, G12's routing — lives in a
path a game takes one time in seven hundred."* Deleting every branch in `ops.enqueue`
would change a game's scheduling by approximately nothing, and would cost the sealed
benchmark wins those arms carry (mutex-handoff +44.24%, futex modes +57.2, pipe +22.7%).

Same census also found four decision paths that never take their branch at all —
pinned-wake preempt (0% on all three workloads, now at its fifth zero dataset per
`STATE.md` §G24), preempt immunity (0 of 2 / 2 of 32,638), the starve wall (0 of
11,980), and SLEEPER_LAG-as-a-predicate (true 94-99.95%, i.e. not a predicate). Those
are removable — but they are removable as **dead code**, not as a latency lever. Their
combined cost is ~40 instructions on paths that already do not branch.

## 3. Where every measured win actually came from

None of the campaign's wins came from removing decisions. Each came from asking a
*different* question — usually a more expensive one.

| win | what changed | direction of instruction count | measured |
|---|---|---|---|
| G21 IRQ-sink avoidance | added an IRQ-line probe, changed which CPU is picked | **added** work | main mean wake **−39.9%**, renderer −25.3%, 2/2 ABBA |
| G13 cache-warm home claim | changed the claim rule | added | same-CPU gap 8.9-16.7 → 0.9-4.5 pts |
| G17 anti-collision admission | added an admission test | added | renderer wake **−17.3%** |
| G18 slice cap on frame estimate | derived the cap from the frame clock | added | wake p99 **−16%**, 2/2 |
| G11 frame clock | added a whole estimator | added | 0.05-0.4% error, locked 28/30 s |

Sources: `STATE.md` §G11-G21 and `AUDIT_GAME_RELEVANCE_2026-08-02.md` §System-by-system (git history).

This is the corpus's own conclusion in `CLAUDE.md`: *"the wins in this corpus came from
changing the decision structure, not from tuning a constant"* — and, from the falsified
list, *"hot path is 0.2% of a core, so ns-shaving is not the FRAME lever (still a
throughput lever)"*.

## 4. Where the thesis is ALIVE, and it is the good half

Strip "fewer branches" and keep "better questions", and the thesis becomes correct and
currently unexploited. Two live targets, both already flagged by the corpus:

1. **`cake_select_cpu` — 271 insns, 44 branches, 27 calls, and 99.86% of a game's
   scheduling decisions.** The G12 census's own stated consequence: *"Stop investing in
   enqueue-side routing for games. The leverage is on the direct-admission path in
   `cake_select_cpu`."* Every branch-count argument that is false for `ops.enqueue` is
   arguable here, because here the branches actually execute. Note the shape though:
   27 calls in 271 instructions is one kfunc call every 10 instructions, and a kfunc
   call is not a predicted branch — it is a real call with r1-r5 clobbered. **If a term
   in this function dominates, the call count is a better suspect than the branch
   count.**

2. **The steal ring — the thesis's textbook case.** `STATE.md` §G24: the ring *"walks on
   93-98% of all dispatches for a ~1% hit"*. That is a decision structure asking a
   question that answers "no" ~95 times per useful answer. `cake_ring_steal` has the
   highest branch density in the object (0.213) and `cake_dispatch_search` the second
   (0.200). This is exactly "one better question would replace many" — and it is already
   registered as the G25 candidate. It is a **walk**, not a branch tree, so the win
   would come from a cheaper index (a mask, a summary word), not from deleting predicates.

## 5. What would falsify each half

- **"Fewer branches lowers latency"**: already falsified for games by the 0.142% reach
  census. To re-open it, produce a regime where `ops.enqueue` reach is high AND a
  latency metric moves with branch count — the saturated regime (23.6%) is the only
  candidate, and that is a throughput regime, not a frame one.
- **"A better question replaces many"**: alive. Falsified only if a cheaper steal-ring
  index is built and measures neutral on wake latency with the walk rate confirmed down.

## 5b. G25 PRICED — `bench/qmark_price.c`, 2026-08-07

Diagnostic, non-ingesting, reader-side wallclock only. Reader pinned to CPU 0, 2M iters,
median of 5 reps, quiet machine (top process 5.7%, game closed and verified by `pgrep`).
WALK15 = 15 slots at 128 B stride, full miss walk. BITMAP1 = one u64, mask self, `ffs`,
with `__atomic_fetch_or/_and` writers so the contention this design trades INTO is paid
in its own column.

**6 rounds, arm order alternated AB/BA per round** so each arm holds first position three
times — the slot-position artifact this project already paid for on game A/Bs. Medians
across rounds:

| writers | WALK15 med (min-max) | BITMAP1 med | delta |
|---|---:|---:|---:|
| quiet (lines shared-clean) | 2.89 (2.86-2.93) | **0.27** | **−90.5%** |
| slow (~10 us flips) | 2.95 (2.91-2.97) | **0.24** | **−91.9%** |
| fast (continuous flips) | **355.33** (334.44-361.37) | **41.07** | **−88.4%** |

**Order artifact: none material.** Splitting by first-position arm, WALK15 quiet reads
2.86/2.93/2.89 when it goes first versus 2.90/2.89/2.89 when it goes second. BITMAP1
varies 0.18-0.28 ns, which is under two cycles at 5.5 GHz — the measurement floor, not a
signal. WALK15's quiet spread is **2.4%** across six rounds.

**The bitmap wins in every regime by 11-12x, and the current design's worst case is the
headline.** Under continuous invalidation the 15-line walk costs **336 ns per dispatch**:
each miss must snoop a modified remote line, so the loads serialise instead of
overlapping. At the census rate of 156,483 dispatches/s that is 52 ms/s — **5.2% of a
core** spent asking one question fifteen times.

**This RETRACTS the prior reading of §5.** An earlier, defective run suggested a
contended bitmap (56 ns) would be worse than the walk (4.4 ns), i.e. that G25 lived or
died on the qmark transition rate. That run's writers set the very bit the reader tests,
so the walk exited early and measured a HIT walk, not the 93-98% miss walk. Corrected
(`dirty_only`: owners invalidate the line, leave `.word` at zero) the direction reverses
and never flips back: higher transition rate hurts BOTH designs, but hurts a 15-line walk
about fifteen times harder than a 1-line word. **The transition-rate census now sizes the
win rather than deciding it.**

Caveat, stated as measured: `fast` is an artificial upper bound — 15 threads flipping
their own line with no other work. Real qmark transition rate is UNMEASURED. The true
operating point sits somewhere between the `quiet` and `fast` rows, and both favour the
bitmap.

## 6. Recommended next cut

**G25, the steal ring.** It is the only place where the maintainer's thesis and the
corpus's own open item point at the same function, it runs on 93-98% of all dispatches,
and its failure mode (a walk that misses) is the one cost structure in cake that a
"better question" genuinely replaces rather than shaves.

Second, unrelated to latency but free: execute the four dead-branch dispositions the
G10/G24 censuses already authorised (~40 instructions, zero trade, five zero datasets on
the pinned-wake preempt alone).
