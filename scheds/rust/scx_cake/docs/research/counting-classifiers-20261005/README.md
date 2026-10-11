# Counting, classifiers and inclusion–exclusion in Cake

Source base: `6dce0901f` (BPF code as of `567715cc8`). Question: what data Cake
decides with, at what measurement level, which classifiers it builds from that
data, which counting and set identities it relies on, and where counting or
inclusion–exclusion could lower cost.

Evidence level: §1–§10 are source review, models and censuses; §11 adds the
same-day `cakebench cost` results (levels 2–3). Game frames are owed for all. Inputs:

- Thread snapshot `scx_cake_bench/bench/cakesim/data/threads_20260927_0535.json`:
  2,038 threads, 33.1 h uptime, desktop, no game running.
- Probe census `scx_cake_bench/runs/appsim_fast_20261004T111326/probe.log`:
  appsim helldivers2 mission cut to 20 s, 30 % busy, probe on.
- Models in this directory (§10). Kernel facts are from `v7.2` and the
  7.3 merge-window tree `v7.2-11943-g2709dd5ae32f`.

## 1. Summary

- Cake decides with 29 inputs (§3). Five are task-lifetime aggregates. The rest
  are instant snapshots, per-run stamps, windowed loader signals or startup
  facts. Every timestamp is an interval scale. Cake keeps the clock families
  apart and compares them only by differences.
- One input is used at a level it does not have: raw CPU ids are nominal, but
  `ctz` turns them into an order, so every concurrent waker targets the same CPU
  first (§7.3). AMD preferred-core ranking is ordinal and static on this host,
  so reading it once at startup is correct (§3, item 15).
- The task classifiers are exact cross-multiplications except
  `cake_starved`/`cake_starved_turn`. The `>> 16` pre-scale gives them a dead
  zone below 65,536 ns of lifetime runtime. On the snapshot that misreads 2.4 %
  of threads but **0.0000 % of wakes**. In terms of switch counts, `cake_starved`
  tests wait/run > pcount/nvcsw ≈ 1 + nivcsw/nvcsw (§4).
- Cake's correctness rests on one-sided counting proofs: a zero means empty, a
  nonzero is only a hint (§5). The pool token's reset rule is an
  inclusion–exclusion over the ways a task leaves the pool, and it is exact (§7.2).
- The slice formula's one-division form is exact: 1,304,800 cases, 0 mismatches.
  The key-window liveness bound holds with 29 % margin, and shift 4 is the
  largest shift that still fits (§6).
- Ranked candidates are in §8. Largest expected payoff: make the kernel derive
  the whole-core mask (I ∩ σI) instead of storing it (K3). Cheapest: a
  waker-keyed tie-break inside the best tier, and two wide-host fixes (D, F).

## 2. Measurement levels

| Level | Valid operations | In Cake |
|---|---|---|
| Nominal | =, ≠, set membership | raw CPU id, pid, LLC id, policy, task/enqueue/wake flags, every CPU mask |
| Ordinal | <, > | rank tier, capacity tier, handoff confidence 0–3, log2 bands, burst class |
| Interval | differences; no true zero | rq clock, ktime, jiffies, `dsq_vtime`, frontier F, tick `next_event` |
| Ratio | differences and ratios | runtime, run_delay, age, burst, grant left, handler time, weights |
| Absolute | counts | nvcsw, pcount, nr_cpus_allowed, nr_queued, pool pending/unserved, idle popcount |

Two refinements apply to Cake:

- Every u64 time is a *circular* interval scale (mod 2^64). Only signed
  differences within half the range are valid, which is what `time_before` and
  `time_delta` compute.
- Each clock is a separate scale. The rq clock is per CPU (cross-CPU deltas are
  clamped), ktime is global, jiffies are coarse. Vtime is weighted
  nanoseconds with an arbitrary origin, and F makes differences meaningful.
  The comments on `cake_now`, `cake_now_rq` and `cake_task_age` keep these
  families apart.

## 3. Decision data

Scope: **L** lifetime aggregate, **R** per run, **I** instant (stale on
read), **W** windowed, **S** startup, **E** event.

| # | Datum | Source | Level | Scope | Operations | Consumers |
|---|---|---|---|---|---|---|
| 1 | `sum_exec_runtime` R | kernel | ratio | L | ÷n, cross-multiply, − run.sum | stage, sub-handoff, starved, slice, charge |
| 2 | `nvcsw` n | kernel | absolute | L | denominator (`\| 1`) | burst, slice, starved |
| 3 | `run_delay` W | sched_info | ratio | L | `>> 16`, cross-multiply | starved, starved_turn |
| 4 | `pcount` m | sched_info | absolute | L | denominator | starved |
| 5 | age (now − `start_time`) | jiffies × tick | interval → ratio | L | ÷2n | slice cap |
| 6 | `static_prio`, policy | kernel | ordinal, nominal | current | table index | vtime weight (ratio) |
| 7 | `dsq_vtime` | Cake | interval (circular) | running | + charge, clamp to [F − 3 ms − dose, F + cap] | queue order, preempt, cross-die gate |
| 8 | PF_KTHREAD, `nr_cpus_allowed`, `cpus_ptr` | kernel | nominal, absolute, set | current | test, == 1, AND | kthread and pinned arms, every pick |
| 9 | slice low 5 bits | Cake | nominal (pool + 1) | while pooled | AND/OR | pool token |
| 10 | SYNC, WAKEUP, REENQ | kernel | nominal | E | test | home, serial, routing |
| 11 | device wake token | custom kernel | nominal type + interval stamp | W (2 ms TTL) | freshness | serial veto |
| 12 | seat pid, seq | Cake | nominal + ordinal generation | until release | equality | retake, immunity, home veto |
| 13 | idle cpumask | kernel | nominal set | I | AND, ctz, popcount | every pick, serial gate |
| 14 | whole-core (SMT) mask | kernel | nominal set | I | AND | home veto, core preference |
| 15 | rank tiers (capacity, then prefcore) | loader | ordinal | **S** | lexicographic filter | `cake_pick_cold` |
| 16 | hybrid capacity word | loader | ordinal, 2 levels | S | filter | `cake_pick_cold` |
| 17 | LLC id/word/domain, preferred die | loader | nominal; nominal (X3D mode, live) | S; 1 s | AND, equality | die-local picks, pools, steal order |
| 18 | chronic IRQ cores | loader SinkMonitor | ratio → rank → set | W (1–4 s; 2 on / 3 off) | soft exclusion | picks, home and serial veto |
| 19 | IRQ depth | tracepoints | absolute → binary | I | ≠ 0 | `cake_cpu_irq_bad` |
| 20 | IRQ pressure | custom kernel | ratio (irq ns / elapsed > 1/8) | W (250 µs–4 ms) | binary | `cake_cpu_irq_bad` |
| 21 | tick `next_event` | kernel per-CPU | interval (ktime) | I | ≤ now + hop p99 | `cake_pick_idle_clean` |
| 22 | deep-idle word | cpu_idle tracepoint | ratio (exit latency) → set | I | > 1464 ns | soft exclusion (no driver on this host) |
| 23 | seat word / held bit | Cake | nominal set | until run | AND NOT | soft exclusion, dispatch deferral |
| 24 | run slot: stamp, sum, grant, pid, hint | Cake | interval, ratio, nominal, ordinal | R | differences, equality | live vtime, grant left, handoff, serial |
| 25 | qmask | Cake | nominal set (one-sided) | until drained | test | steal ring, alone kick, empty proof |
| 26 | pool pending, unserved | Cake | absolute | in flight | zero test | empty proof, interlock kick |
| 27 | pool served stamp | Cake | interval (rq clock) | refreshed when ≥ 12 ms old | now − stamp > 24 ms | starvation override |
| 28 | F, F stamp | Cake | interval | global | step ∈ [dt/16, dt], 65 µs grain | sleeper floor, vtime cap, cross-die gates |
| 29 | occupant (`cpu_curr`) | kernel | nominal identity + flags | I | equality | preempt, anti-collision, retake |

Level and scope mismatches:

1. **Raw CPU id, nominal, used as ordinal.** The `cid.h` header says it
   directly: raw CPU numbers are sparse and "ranges carry no meaning". `ctz` picks
   the lowest id, which causes the herd in §7.3. The steal order breaks ties by
   id distance. That is a harmless stagger, but it is not a locality measure.
2. **Lifetime aggregates read as current state.** Items 1–5 have no window or
   decay. A thread that changes phase (loading, then gameplay) keeps its whole
   history. A window needs per-task state, and task storage costs ≈ 14 ns per
   access (probe timing, §7.3).
3. **Preferred-core ranking: static, so one startup read is correct.**
   `amd_pstate_update_limits()` can re-rank cores on a CPPC highest-perf
   notification (`drivers/cpufreq/amd-pstate.c:918-939`), and the kernel docs
   say the ranking "can change at runtime". On this host it does not: cores
   4=5 (196) > 3 (191) > 1 (186) > 2 (181) > 0 (176) > 6 (171) > 7 (166) read the
   same on 2026-09-26 and 2026-10-06, across reboots. `core_performance.rs`
   reads it once; that stays. Re-check only if a host shows a change.
4. **Unit constants measured on one host.** 1464 ns (marked hardware-anchored)
   and 64 µs carry units. The loader measures the hop but does not drive the
   threshold: driving it cost mutex-handoff 35 % (see the `main.rs` comment).

## 4. Classifiers

Shares are thread / wake-weighted (by nvcsw) on the desktop snapshot. CPU-side
counts are from the appsim census.

| Classifier | Features | Boundary | Boundary kind | Drives | Share |
|---|---|---|---|---|---|
| `cake_subhandoff` | R, n | R/n < 1464 ns | unit constant | starved wake keeps home | 6.8 % / 35.4 % |
| `cake_stage` | R, n | R/n ≥ 64 µs | unit constant | seats, retake, SYNC home, die re-home | 21.9 % / 4.0 % |
| `cake_starved` | W, R, m, n | W/m > R/n | dimensionless | preempt veto, anti-collision, sleeper depth | 28.3 % / 42.6 % |
| `cake_starved_turn` | W, R, m, n | W/m > 2R/n | dimensionless | wake → pool route, home decline | 24.5 % / 9.8 % |
| `cake_system_serial` | idle popcount, online | idle ≥ 3/4 of die | dimensionless | serial handoff | reached 33× |
| handoff hint | used quanta | 3 consecutive < 1464 ns | capped count | serial handoff | |
| `cake_handoff_yields` | ran, R, n | burst − ran < 1464 ns | unit | serial handoff | |
| `cake_wake_preempt` | ran, protect, vtimes, starved(curr), seat | ran ≥ min(slice, 187.5 µs or 750 µs) ∧ v_p < live ∧ ¬starved ∧ ¬seat | mixed | preempt | 6 fired / 13 |
| `cake_cpu_irq_bad` | chronic set, depth, pressure | any of three | OR | exclusion | 373 rejects |
| `cake_cpu_tick_soon` | `next_event`, now, hop p99 | next ≤ now + hop | measured at start | exclusion | 1,809 / 56,173 |
| IRQ sink (loader) | handler-time deltas | widest ratio gap, minority, 2 on / 3 off | unit-free, learned | chronic set | |
| dispatch order | head vtimes, served stamp | v_pool + 3 ms < v_own ∨ unserved > 24 ms | unit margins | queue first | |
| cross-die gate | head vtime, F | v + 3 ms < F | unit | steal, rescue | |
| grant expired | stamp, grant | ran ≥ grant | ratio vs own grant | expiry preempt | 83 fired |

Findings from the snapshot (`classifiers.py`):

- **What `cake_starved` measures.** pcount = nvcsw + nivcsw holds to a median
  difference of 0 (max +1). So W·n > R·m reads as W/R > pcount/nvcsw ≈
  1 + nivcsw/nvcsw. It compares the lifetime wait/run ratio with the
  involuntary/voluntary switch mix: a task preempted often needs a higher
  wait/run ratio to count as starved. The two means divide by different event
  sets: wait per arrival, run per voluntary block.
- **Exactness.** The pre-scale does not cancel under floor. R < 65,536 ns means
  the task is never starved: 28.6 % of threads, 0.0001 % of wakes. 47 threads
  (2.3 %) are starved by the exact test and read false; wake-weighted misreads
  are 0.0000 %. There is no u64 wrap on this snapshot; old busy threads do wrap
  (sched-ext/scx#3840, cakesim `starve_spec.py`).
- **Where the constants sit.** The wake-weighted mean-burst histogram has modes
  at [2^9, 2^10) (33.5 %) and [2^11, 2^13) (36.5 %), with a trough between them
  at [2^10, 2^11) (3.7 %), where 1464 ns falls. 64 µs sits at the top of
  [2^15, 2^16) (9.3 %), just before the [2^16, 2^17) trough (1.5 %). Both
  constants are near natural breaks for this desktop mix. A game needs its own
  read: `CAKE_HIST_BURST` (probe) records exactly this.
- **Inclusions hold.** sub-handoff ∩ stage = ∅ and starved_turn ⊆ starved hold
  on every thread. The second is exact while the products do not wrap.

## 5. Proofs and hints

| State | Zero means | Error | Proved by |
|---|---|---|---|
| `qmask[cpu]` | own queue empty: set under the rq lock before insert, cleared only after a zero count | false positives only | `nr_queued`, move |
| pool `pending` | pool empty: tagged tasks are seen exactly once | false positives only | count, then move |
| `cake_seat_holders[pid & 255]` | not a holder | false positives ≈ 1 − (1 − 1/256)^h; consecutive pids never collide | task storage |
| LLC pool `mark` | no foreign work (Dekker with recheck) | false positives only | peek |
| idle-word bit | nothing: a candidate only | two-sided (stale either way) | `scx_bpf_test_and_clear_cpu_idle` |
| run slot pid match | uncharged vtime and matching stamp | tears under-price (safe side) | — |

This is Bloom-filter logic. A zero is a proof, a nonzero is a hint, and a
commit point (claim RMW, successful move, pid match) turns the hint into a fact.
§R.29 ("push beats pull") is the same rule applied to identity.

## 6. Formula ledger

| Formula | Code | Exact? | Domain, verification |
|---|---|---|---|
| slice = max(1464, min(2⌊R/n⌋, ⌊A/2n⌋, 1.5 ms)) & ~31, one divide: q = ⌊min(R, ⌊A/4⌋)/n⌋, +1 iff R − qn ≥ n ∧ ⌊A/2⌋ − 2qn ≥ n | `cake_slice_from_service` | yes | proof: ⌊⌊x⌋/n⌋ = ⌊x/n⌋, and ⌊·/n⌋ is monotone so min passes through it; 1,304,800 cases, 0 mismatches |
| charge = used · ⌊2^30/w⌋ >> 20 | `cake_scale_vtime_add` | floor | table = ⌊(1024 << 20)/w⌋ for all 40 levels and SCHED_IDLE; under-charge ≤ 22.2 ns per run ≤ 23 ms; fast path while runtime ≤ 2^64/357,913,941 (51.5 s) |
| slow path split at the radix | `cake_scale_vtime_slow` | yes | ⌊(h·2^20 + l)r / 2^20⌋ = hr + ⌊lr / 2^20⌋ |
| lead cap, branchless min | `cake_vtime_cap`, `cake_vtime_ceil` | yes | cap ∈ [65.5 µs, 102.4 ms] |
| key-window liveness | static asserts | bound | F rises ≥ dt/16; window 110.716 ms × 16 = 1.771 s ≤ 2.5 s; × 32 = 3.543 s, so 4 is the largest shift |
| stage, sub-handoff, handoff_yields | cross-multiplied | yes | R < L·n ⟺ ⌊R/n⌋ < L for integer L; guards n < 2^32, n ≤ 2^64/64000 |
| starved, starved_turn | `>> 16`, cross-multiplied | no | dead zone and wrap (§4) |
| serial gate | popcount · 4 ≥ 3 · online | yes | |
| pool tag | slice & 31 = pool + 1 | yes | ≤ 31 pools (16 used); grants lose ≤ 31 ns |
| IRQ sinks | widest ratio gap of sorted deltas | unit-free | 2 on / 3 off; set kept a minority |
| claim tries | max(4, die/4) | — | 4 on the 9800X3D and on any die ≤ 19 CPUs |

## 7. Inclusion and exclusion

### 7.1 The placement pipeline as set algebra

The candidate set is C = idle ∩ allowed ∩ die. A hard exclusion removes
members outright. A soft exclusion removes them only if something is left
(`if (best & X) best &= X`). The soft chain in `cake_pick_cold` is a
lexicographic order over attribute vectors: capacity → whole core → not a
seat → IRQ-clean (chronic or deep idle) → rank tier → lowest id.

| Rule | Kind | Where |
|---|---|---|
| affinity; die (one-word multi-LLC); seat held by another task | hard | every pick; claim_warm; home |
| home needs (¬SYNC ∨ stage) ∧ whole core idle ∧ ¬(starved_turn ∧ ¬sub-handoff) ∧ ¬IRQ-bad | hard (home only) | `cake_select_cpu` |
| capacity, whole core, seat, chronic IRQ or deep idle, rank | soft | `cake_pick_cold` |
| live IRQ, tick soon | soft, two passes | `cake_pick_idle_clean` only, not `cake_claim_warm` (72 % of claims) |
| preempt victim: ran ≥ protect, worse vtime, not starved, not on own seat | hard | `cake_wake_preempt` |
| cross-die: head a slice behind F | hard | ring steal, pool rescue |

### 7.2 Counting identities in use

- **SMT.** With σ the sibling map: whole-idle cores = I ∩ σI;
  |I ∪ σI| = 2|I| − |I ∩ σI|; threads idle beside a busy sibling = I ∖ σI.
  Cake folds σ into one shift/mask pair (`cake_smt_expand`). Its test checks
  every singleton and extends to all 2^64 subsets by OR-linearity.
- **Pool conservation.** Departures from a pool are disjoint: served moves S,
  or kernel pops K. Then N = |I| − |S| − |K| tasks remain, and
  pending = |I| − |seen| ≥ N, so **pending = 0 ⇒ N = 0**. At that point
  unserved = |I| − |S| = |K|. The reset in `cake_pool_unserved` therefore removes
  exactly the pops the serve never saw. The 2026-09-27 token leak was a
  violation of pending ≥ 0.
- **Permutations.** The ring steal starts at cpu + 1. A cyclic shift is a
  permutation, so concurrent thieves never share a first victim. The steal
  table's sibling-first order is an involution and also a permutation. The
  claim walk is the opposite case: the lowest id is a constant map, so
  concurrent wakers share every target.
- **Implication lattice.** sub-handoff ⊂ ¬stage, and starved_turn ⊂ starved.
  On today's paths this saves little (§8 E): after the 2026-09-04 redundancy
  cleanup, each select evaluates starved_turn at most once (home gate) and
  starved once (admit frame).

### 7.3 The lowest-bit herd

The top rank tier on this host is cores 4 and 5, which is CPUs {4, 5, 12, 13}.
When both cores are whole-idle, every waker's first claim is CPU 4. With a
deterministic order, k simultaneous wakers waste k(k−1)/2 claims. Past
`claim_tries` the rest go to the pool while idle CPUs remain: this is the
"queued while idle" class in the 2026-09-04 placement audit.

Model (`herd.py`): k wakers on distinct CPUs claim at once, at most 4 tries
each. Cells show wasted claims per burst, with wakers sent to the pool in
parentheses.

| k | \|C\| | lowest id | rotate after waker | waker-keyed select-j | random |
|---|---|---|---|---|---|
| 2 | 4 | 1.00 | 0.32 | 0.20 | 0.24 |
| 4 | 8 | 6.00 | 0.90 | 0.53 | 0.88 |
| 8 | 8 | 22.00 (4.00) | 6.73 (1.07) | 4.97 (0.78) | 6.54 (0.85) |
| 8 | 12 | 22.00 (4.00) | 2.08 (0.16) | 1.58 (0.08) | 3.48 (0.18) |

Census at 30 % busy (claims attempted / won):

| Claim site | Attempts | Won | Failed |
|---|---|---|---|
| warm | 2,247,710 | 2,206,488 | 1.83 % |
| home | 817,872 | 813,870 | 0.49 % |
| notify | 54,785 | 53,754 | 1.88 % |
| groove | 4,742 | 4,699 | 0.91 % |

Home claims target distinct CPUs, so the ≈ 1.3-point excess on warm claims is
the herd: about 1.5k failed claims per second. A claim costs ≈ 22 ns net
(probe pair timing: 38.2 ns minus the 15.8 ns empty pair), so the herd costs
≈ 33 µs of CPU per second at this load. That is small. Bursts grow it as k².
The census to check is a saturated run.

History: g94 started every walk at the task's previous CPU. It cut
queued-while-idle 89,891 → 60,610 on appsim, its frames were unresolved, and it
was removed in `26d62f451`. The candidate in §8 C differs in two ways:

- It keys by the **waker** CPU. Concurrent wakers run on distinct CPUs, so their
  keys are distinct by construction.
- It acts only **inside the best tier**, so the rank order stays intact.

The step itself: k = popcount(best), j = (waker · k) >> 6, clear the j lowest
bits, then `ctz`.

## 8. Candidates

| | Pattern | Kernel | Expected | Ledger | Decide by |
|---|---|---|---|---|---|
| A | K3: the kernel derives whole-core idle as I ∩ σI instead of storing it. Today the SMT mask is written when a claim takes a whole-idle core (`idle.c:79-109`) and on every idle→busy transition (`idle.c:710-733`). | custom patch | removes the SMT-mask store from those paths (a second line if the two kmalloc(8) masks do not share one); claim ≈ 60 % of select | E2 (BPF-side derive) no effect and §G83 rejected: the kernel still stored the mask | K1–K3 patch (owed #4), `cake-bpfstats` select, then game |
| B | ~~Re-read prefcore ranking every second~~ | — | — | — | **Dropped:** the ranking is static on this host (§3, mismatch 3); a 1 s poll breaks "events, not polling" for no gain |
| C | Waker-keyed select-j inside the best tier | stock; popcount 1 cycle with native bitops | herd waste −4 to −14× in the model; 1.3 points of warm claims at 30 % busy | g94 related, not the same | census under saturation (warm fail, queued-while-idle), then frames |
| D | Wide hosts: sum popcount over `cake_idle_words` in the serial gate; drop `cake_idle_nr` | stock, > 64 CPUs | per idle transition: a cmpxchg loop plus a global locked add become one `lock or` | §G82 kept the counter | tester with > 64 CPUs |
| E | Pass known verdicts: `stage` into `cake_claim_warm` (multi-LLC recomputes it); `starved = true` on the enqueue starved route | stock | ≈ 1 ns per warm claim on multi-LLC hosts; nothing on one LLC | cakesim exact_once, class onepass | `cake-bpfstats`; watch spills |
| F | Wide hosts: `update_idle` has no pool interlock kick (the one-word path has it; the kernel sets the idle bit first, `idle.c:783-790`) | stock, > 64 CPUs | closes a lost-wakeup window: a pool insert racing a CPU going idle waits for another CPU's dispatch | — | probe on a > 64-CPU tester |
| G | Conservation checks over the census at exit: pending ≥ 0, sum of sites = total, wins ≤ attempts | loader only | catches accounting bugs like the 09-27 leak | — | unit test |
| H | Confusion counts: key the hold probe (wait > 300 µs, > 1 ms) by classifier verdict | probe only | measures whether a classifier is right, not only how often it fires | hold attribution exists | probe run in a game |
| I | Exact `cake_starved` | stock | 0.0000 % of wakes misread on the snapshot | #3840 | low priority on this data |

Tidy: `CAKE_SITE_CLAIM_RETRY`, `CAKE_SITE_TACI_STAGE`, `TACI_WARM_CORE`,
`TACI_WARM_THREAD` and `TACI_HINT` are never incremented and always print 0.
Done 2026-10-05 with 13 other dead sites (§11).

## 11. Results, 2026-10-05

Built and measured the same day; `cakebench cost`, appsim 20 s slots, all slots
valid. Busy host: compare inside one round. Run paths and the ledger rows are
in STATE.md (Evidence, 2026-10-05).

| | What was built | Result | Verdict |
|---|---|---|---|
| C | Spread pick: ties in the best tier go to the first CPU above the caller. Rotate form (B), then mask form (B2), which keeps no value live across `bpf_ctz64` | Census: warm-claim failures 1.98 → 1.75 %; retakes −42 %; evictee claims −31 %. ns/run: select +8.1, +11.7, +8.3 ns in three rounds. Profile: +130 cycles per select, of which +31 instructions; the rest are stalls. Total BPF equal or +2.9 %. Appsim p99 equal | **Rejected** at levels 2–3, removed. The model was right about the direction but not the size: most failed claims are not herd collisions. The retake drop is real, and a game A/B is optional (`spread-pick.patch`) |
| D+F | Wide hosts: popcount the idle words, drop `cake_idle_nr`; `update_idle` runs the pool interlock on every host | Forced-wide on this host (`force-wide-arm.patch`), two rounds: `update_idle` −1.09 / −0.64 ns, running −2.69 / −1.05 ns; 0 stalls. One-word arm neutral: select +0.3 %, `update_idle` −1.2 % | **Keep** (uncommitted). A real > 64-CPU host is owed |
| G | Pool tokens checked at `ops.exit`; census identities checked after detach; reports read after detach (the lost `2f4bc9a6c`) | Identities exact in 4 probe slots; pending 0 at every exit; the `-v` events row is no longer 0 0 0. The 10-04 census breaks one identity by 2 (read while attached), now a unit test | **Keep** (uncommitted) |
| Tidy | 18 dead census sites removed; `PEND_HEAL` counts the proof reset | Name table 138 → 120 | **Keep** (uncommitted) |
| A | K3 premise | Idle and SMT masks sit 32 lines apart (diagnostic build): a claim on a whole-idle core writes two lines | Premise holds. Patch not written; design decision first (STATE owed 4) |
| B | Preferred-core re-read | Ranking identical on 09-26 and 10-05 | **Dropped** |
| E, H, I | — | Not built: E has nothing to save on a one-LLC host, H is probe feature work, I misreads 0 % of wakes | — |

One codegen lesson: in `update_idle`, computing the wide path's `c` and `bit`
before the interlock's kick held them in callee-saved registers on the one-word
path too (six instructions per call, ≈ +0.2 ns). Computing them after the
one-word return removed it.

## 9. Kernel changes that touch these counts

| Change | Status | Effect on Cake |
|---|---|---|
| Custom: native ctz/popcnt/clz | running | 1 cycle each vs 7/13/26 emulated; makes popcount-based designs (C, D) cheap |
| Custom: DSQ direct index | running, no hardware A/B | DSQ hash ≈ 8.5 % of Cake time under 16 hogs |
| 7.2.9: `SCX_RQ_IN_WAKEUP` only on the core wakeup path | running | baseline change (STATE) |
| `7706d6e4f2e3`: per-task `reenq_cnt`, limit 256 | 7.3-pending | 256 re-enqueues before a task runs eject Cake. The REENQ arm re-claims with IMMED. Unreachable at 1.5 % claim failure, but Cake has no bound of its own. |
| `13f1eae3b662`: insert writes deferred to insertion | 7.3-pending | pool tag still lands at insertion; token proof unaffected |
| `9cfc6ab34a31`: `SCX_TASK_PROTECTED`, `slice_oob` | 7.3-pending, unused | adds kernel slice writers; the tag needs Cake to be the only writer of a pooled task's low slice bits; re-check when used |
| `ffaab58d2175`: dispatch verdict replaces `SCX_RQ_BAL_KEEP` | 7.3-pending | re-check `cake_dispatch`'s refill-prev path |
| `d5b8f4cdd17d`: `p->scx.runnable_cpu` | 7.3-pending | exact "on this rq" identity under the rq lock |
| cid (7.2), cmask iterators (7.3) | 7.2 / 7.3 | topology-ordered ids make "lowest id" ordinal; a cpu-form scheduler's idle masks stay cpumasks |

## 10. Files

| File | Reproduces |
|---|---|
| `exact_checks.py` | slice identity, weight table, key-window bound (§6) |
| `classifiers.py [snapshot.json]` | classifier shares, misreads, pcount identity, burst histogram (§4) |
| `herd.py` | concurrent-claim model (§7.3) |
| `spread-pick.patch` | rejected construct C (mask form), against arm A′ `88988e81571c` |
| `force-wide-arm.patch` | test arm only: runs the > 64-CPU paths on a one-word host |

Open gates: game frames (level 1) for everything kept; D+F on a real > 64-CPU
host; K3. Snapshot shares are a desktop mix, not a game.
