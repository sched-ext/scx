# Research: ADPF performance hints + least-laxity-first (2026-08-09)

Background for the frame-slack input concept (see the 2026-08-09 discussion; ancestor
design: criticality-scoped protector, 2026-07-09). Two questions:

1. How does Android's ADPF Performance Hint API work — the closest shipping analog of
   "the game tells the scheduler about the frame"?
2. What is least-laxity-first (LLF), and what breaks it — since the proposed
   `Urgency = slack / (critical path + risk)` metric is laxity in disguise?

Sources: developer.android.com ADPF overview, NDK APerformanceHint reference,
source.android.com Performance Hint API, LWN OSPM 2025 report, Oh & Yang 1998 (MLLF,
RTCSA), microcontrollerslab LLF tutorial. Full links at the bottom. Anything marked
**[unverified]** is from AOSP source knowledge, not from a fetched page.

---

## Part 1 — ADPF Performance Hint API

### The shape: a closed loop on work duration, per thread group

The protocol is small. A game creates a **hint session** naming the thread IDs of its
frame-critical threads, and declares a **target work duration** — the CPU time budget
per frame. Every frame, it reports the **actual work duration**. The OS drives the
error (actual − target) toward zero by adjusting scheduling and DVFS for exactly those
threads. That is the whole contract: two numbers per frame, one thread list.

```
game:  createSession(tids, target_ns)         # "these threads produce a frame"
loop:  reportActualWorkDuration(actual_ns)    # "the frame cost this much CPU"
OS:    actuate so actual → target             # frequency, placement, boost
```

### API surface (NDK, exact names)

| call | purpose |
|---|---|
| `APerformanceHint_createSession(mgr, tids, n, target_ns)` | session = thread list + budget |
| `APerformanceHint_updateTargetWorkDuration(s, ns)` | change the budget (0 disables) |
| `APerformanceHint_reportActualWorkDuration(s, ns)` | per-frame feedback |
| `APerformanceHint_reportActualWorkDuration2(s, AWorkDuration*)` | split feedback: total + CPU + GPU durations + work-period start timestamp |
| `APerformanceHint_setThreads(s, tids, n)` | replace the thread list |
| `APerformanceHint_setPreferPowerEfficiency(s, bool)` | invert the goal (Android 15+) |
| `APerformanceHint_notifyWorkloadIncrease/Reset/Spike(s, cpu, gpu, id)` | pre-announce load changes; rate-limited |
| `ASessionCreationConfig_setGraphicsPipeline / setNativeSurfaces / setUseAutoTiming` | bind the session to surfaces; the OS times the frame itself |
| `APerformanceHint_isFeatureSupported(feature)` | probe: `APERF_HINT_GRAPHICS_PIPELINE`, `AUTO_CPU`, `AUTO_GPU`, … |

Three details worth stealing:

- **The CPU/GPU split (`AWorkDuration`).** Android 15 separates
  `setActualCpuDurationNanos` and `setActualGpuDurationNanos`. This is exactly the
  regime question: the OS learns *which side* of the pipeline consumed the frame,
  per frame, not from a global utilization counter.
- **Auto-timing (`setUseAutoTiming`, graphics pipeline mode).** The newest API stops
  trusting the game: bind the session to the surfaces it presents, and the OS measures
  frame timing itself. Android converged on "instrument the presentation path, do not
  ask the game" — which is the MangoHud-layer position on Linux.
- **Spike semantics.** `notifyWorkloadSpike` marks a cycle as non-representative, and
  the framework *excludes it from load tracking*. A one-off expensive frame must not
  retune the controller — the same reasoning as our noise-covariate rule.

### What the OS does with it

The public docs stop at "the system adjusts scheduling and performance levels to reach
a steady state" — the actuator is vendor territory. What is public:

- **Uclamp is the best-documented actuator, not the API contract.** ADPF promises
  feedback toward the target; each vendor HAL picks its own mechanism. The
  reference/Pixel route drives `uclamp_min`, which raises the schedutil frequency
  request and biases capacity-aware placement (mainline since v5.3). The OSPM 2025
  report has Hongyan Xia presenting uclamp aggregation work explicitly motivated by
  ADPF experience. Do not generalize past that.
- **The known motivation number:** without hints, a bursty task waits ~200 ms for
  utilization tracking (PELT) to ramp frequency — several dropped frames in a game.
  The hint bypasses the estimator with declared intent.
- **[unverified]** The AOSP reference Power HAL (`libperfmgr`, Pixel) implements hint
  sessions as a PID controller on (actual − target) whose output actuates `uclamp_min`
  on the session threads, with tunables shipped in `powerhint.json`. Verify against
  AOSP `power/libperfmgr` before citing further.

### What transfers to cake, and what does not

- **Transfers: the protocol shape.** Thread list + target duration + actual duration
  is a minimal, complete frame contract. Our producer (the customized MangoHud Vulkan
  layer) can emit exactly this without game cooperation — Android needed auto-timing
  mode to get there; we start there.
- **Transfers: per-frame CPU/GPU attribution** as the regime signal, replacing the
  broken `gpu_load` telemetry (constant 97.0 trap, 2026-08-01).
- **Does not transfer: the actuator.** ADPF chiefly actuates *frequency* on
  heterogeneous mobile SoCs. On the 9800X3D (one CCD, boost governed by HW), the
  frequency lever is nearly gone — cake's levers are placement, preemption, and slice.
  So we copy the *sensing contract*, not the control law. Note ADPF barely touches
  the placement questions cake actually owns (locality, preempt-or-queue, steal).

---

## Part 2 — Least-laxity-first (LLF)

### The algorithm

For each ready task: **laxity L = D − t − C_remaining** (deadline minus now minus
remaining execution). Laxity is the slack: how long the task can wait and still finish
on time. LLF always runs the task with the least laxity, recomputed continuously —
every tick is a scheduling event. Like EDF, it is optimal on a uniprocessor (if a
feasible schedule exists, LLF finds one — Mok 1983). Unlike EDF, a task's priority
rises *while it waits* (its laxity shrinks), so LLF sees a coming deadline miss before
EDF does — laxity < 0 predicts the miss in advance.

### Why nobody ships it: thrashing, and the C_remaining problem

- **Thrashing.** When two tasks reach equal least laxity, the running one gains no
  laxity but the waiting one loses it — so they leapfrog and preempt each other every
  tick. Pure LLF degenerates to context-switch soup exactly when the system is
  busiest. This is the classic named failure of the algorithm.
- **C_remaining must be known.** Laxity needs an execution-time estimate per task; EDF
  needs only deadlines. A wrong estimate silently reorders priorities. Any laxity
  scheduler is only as good as its runtime predictor.
- **Multiprocessor:** LLF loses optimality (as does EDF); the literature keeps it for
  predictability results, not deployment. Mainline Linux ships SCHED_DEADLINE on
  EDF+CBS, not LLF — fewer switches, no runtime estimate needed from the scheduler.

### The fixes: defer the switch

- **MLLF (Oh & Yang 1998):** allow bounded *laxity inversion* — the running task keeps
  the CPU past the tie, until switching is actually required to avoid a deadline miss.
  Cuts the switch count dramatically, keeps schedulability.
- **ELLF:** group tasks at equal laxity, apply EDF inside the group — ties get a
  stable secondary key instead of a leapfrog.

Both fixes are the same idea: laxity decides *whether* someone is in danger; a
hysteresis rule decides *when* to act on it.

---

## Part 3 — Synthesis for the frame-slack concept

| concept | cake mapping |
|---|---|
| ADPF target work duration | frame deadline — Class-D externally-anchored constant |
| ADPF actual work duration | `cake_burst_ns` estimator (storage-free, already live) |
| ADPF session thread list | behavioral render-role detection (protector design, 2026-07-09) — no registration needed |
| ADPF auto-timing via surfaces | MangoHud Vulkan-layer producer at submit/present |
| LLF laxity `D − t − C_rem` | `D` = predicted present deadline (presentation margin); the GPU feed horizon is a separate, throughput-side term — see Corrections |
| LLF thrashing | the registered risk for any slack-gated preempt; near-tie slack must not flap the decision |
| MLLF bounded laxity inversion | cake's young-curr floor / preempt margins — the hysteresis already exists, aim it |
| LLF C_remaining fragility | slack decisions inherit `cake_burst_ns` error; validate the estimator on render roles first |

Two design consequences, stated once:

1. **The urgency division is unnecessary.** LLF form is subtraction:
   `danger ⟺ slack − cpu_path − risk < margin`. Comparisons, no divide — fits the
   11-divide budget without spending one.
2. **The thrash guard is mandatory, not optional.** Any consumer of a slack signal
   needs an MLLF-style deferment (act only when inaction misses the deadline, hold
   decisions across a margin). Cake's existing preempt margins are the natural home.

## Corrections after external review (2026-08-09)

An external review of this doc's conclusions landed five corrections worth keeping and
made two code-level claims that verification overturned.

**Accepted corrections:**

1. **The objective is just-in-time presentation, never GPU occupancy.** A full GPU
   queue means old frames sit ahead of the newest input — an input-latency cost. NVIDIA
   Reflex (`VK_NV_low_latency2`) and AMD Anti-Lag exist precisely to pace the CPU
   *behind* the GPU. Separate three quantities: **presentation margin** (the deadline
   signal), **feed horizon** (throughput-side), and **queue age / CPU lead** (latency
   cost). The controller targets a band, two-sided.
2. **Fence wait is one noisy feature, never `gpu_queue_depth_us`.** A fence wait
   measures one sync object from the moment the host waits. Batches overlap, complete
   out of order, and span multiple queues; present is a separate stage. Demoted.
3. **The consumer is EDZL-shaped, not LLF-shaped.** Run current policy until predicted
   frame laxity crosses a threshold; then a bounded override for an identified critical
   set, rate-limited, with a deadband. No global laxity ranking, no thrash surface.
4. **Cake's preempt margins can host such a policy; they do not implement MLLF** — they
   never evaluate another task's laxity. Phrasing corrected.
5. **A zero counterfactual count on one capture rejects that proxy on that workload**,
   not the concept. Present mode, frame cap, API, and scene all change the opportunity
   set. (This matches the corpus's own depth-over-one-shot-verdicts rule.)

**Verified against this rig (vulkaninfo, NVIDIA driver, 2026-08-09):** exposed —
`VK_EXT_present_timing`, `VK_KHR_present_wait` + `wait2`, `VK_NV_low_latency2`.
Not exposed (not found by `vulkaninfo | grep` on this driver) — `VK_EXT_frame_boundary`,
`VK_AMD_anti_lag`, `VK_GOOGLE_display_timing`. The producer's Tier-1/2 sensors are
therefore real here; fence heuristics drop to a fallback feature.

**Overturned by verification (the review read a different snapshot):** `cake_burst_ns`
(cake.bpf.c:183) and `cake_frame_observe` (cake.bpf.c:214, called from :1239) are live
on nightly — the "two of three laxity inputs" claim stands. The review's proposed
insertion point `cake_busy_wake_policy_should_preempt()` exists in no snapshot
reachable here (not found by grep over the nightly working tree, `main`, and a
fresh-fetched `origin/main`); the nightly analogs are `cake_wake_preempt`
(cake.bpf.c:449) and the G24-condemned `cake_pinned_wake_preempt` (:945, deletion
queued). Any consumer design must target those, and one caveat cuts both ways: the
protector's chain propagation was a 2026-07-09 *design*, never built — nightly holds
behavioral ingredients (burst, cadence depth, frame clock), not dependency
reconstruction.

## Sources

- ADPF overview: https://developer.android.com/games/optimize/adpf
- NDK APerformanceHint reference: https://developer.android.com/ndk/reference/group/a-performance-hint
- AOSP Performance Hint API: https://source.android.com/docs/core/perf/performance-hint-api
- Kernel uclamp doc: https://docs.kernel.org/scheduler/sched-util-clamp.html
- LWN, OSPM 2025 day one (uclamp/ADPF): https://lwn.net/Articles/1020596/
- Oh & Yang 1998, "A Modified Least-Laxity-First scheduling algorithm for real-time tasks" (RTCSA): https://ieeexplore.ieee.org/document/726348/
- LLF walkthrough: https://microcontrollerslab.com/least-laxity-first-llf/
- ELLF coprocessor paper: https://www.researchgate.net/publication/221224077
