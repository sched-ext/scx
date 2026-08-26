# What cake and lavd together teach about game performance

**2026-08-06.** Sources: scx_cake 1.2.0 at `RitzDaCat/scx_cake-nightly` (full BPF +
loader read); scx_lavd at upstream `53dd054d2` (full BPF read, incl. the
`5699c7f08` warmth commit not present on the test branch). Peer versions verified
by `git diff HEAD upstream/main`. No benchmark was run for this document — every
number below is quoted from an existing record and is labelled with its source.

---

## 1. Both projects independently found the same law, from opposite directions

**cake found it by measurement.** Five-domain sweep, 2026-08-01, retained traces,
G17 rotation (`STATE.md:133`):

| domain | thread | burst | native N1/N2 | cake C1/C2 | cake advantage |
|---|---|---|---|---|---|
| audio (game) | `FAudio_AudioCli` | ~5 µs | 288.3 / 80.8 | 31.7 / 40.6 | **~5.0×** |
| input | `Window & Input` | ~6 µs | 294.6 / 93.2 | 39.0 / 47.8 | **4.5×** |
| GPU submit | `vkd3d_queue` | ~13 µs | 42.0 / 18.7 | 13.2 / 15.5 | 1.5× |
| render | `renderer` | ~40 µs | 124.0 / 87.0 | 46.7 / 47.0 | 2.2× |
| audio (RT) | `data-loop.0` | — | 2.2 / 1.5 | 2.8 / 3.1 | none — SCHED_FIFO, cake never schedules it |

Stated law: *cake's advantage scales inversely with the thread's burst.*

**lavd encodes it as a design primitive.** `lat_cri.bpf.c:128`
`calc_reverse_runtime_factor()` — shorter `avg_runtime_invr` *is* higher latency
criticality, feeding the virtual deadline directly:

```
deadline = (adjusted_runtime * greedy_penalty) / taskc->lat_cri
```

**Consequence, and it is uncomfortable for cake:** the campaign G10–G20 optimised
the **renderer** — the longest-burst thread in the set, where the measured win is
smallest. `STATE.md:154` says so outright. Input and game audio were never scored.

---

## 2. The GPU interrupt is a first-order frame lever, and both target it

Same phenomenon, attacked at two different layers.

**cake — placement layer (G21, SHIPPED, `STATE.md:95`).**
`/proc/irq/115/effective_affinity_list` = `13`; the nvidia interrupt fired
**1,266,319,129** times on CPU 13 and zero on the other fifteen. Both schedulers
were handing that CPU to game threads at ~fair share.

| metric | pre-G21 | G21 | delta |
|---|---|---|---|
| `main` mean wake | 0.79 / 0.79 | 0.47 / 0.48 | **−39.9%** |
| `renderer` mean wake | 0.91 / 0.83 | 0.66 / 0.64 | **−25.3%** |
| `renderer` CPU-13 share | 3.9% / 4.2% | 0.1% / 0.1% | 40× |

Mechanism: loader samples `/proc/interrupts` twice, freezes `cpu_irq_hot` rodata,
`ops.init` builds `nonsink_cpumask`, `select_cpu` prefers it. Binary, load-time.

**lavd — signal layer + continuous placement.**
Two separate mechanisms, neither measured in cake's corpus:

1. `lat_cri.bpf.c:52` — a task **woken by a hardirq** gets
   `LAVD_LC_WEIGHT_BOOST_HIGHEST`. The comment names the case explicitly:
   *"mouse move, keypress, disk I/O completion, or **GPU V-Sync** … the task that
   was waiting for this specific hardware signal gets the Express Lane."*
2. `sys_stat.bpf.c:370` — per-CPU `lat_headroom` = 1024 − EWMA(IRQ+steal util).
   CPUs below `LAVD_LC_LATENCY_SENSITIVE_THRESH` (top 12.5%) are **turbulent**;
   each compute domain gets a second "turbulent" DSQ, and `vuln_thresh` — the
   split point — is re-tuned every 10 ms to equalise per-capacity load.

**The difference that matters:** cake avoids the sink CPU; lavd *also* boosts the
task the interrupt woke. cake's G21 helps the render chain get scheduled
*somewhere quiet*; lavd's boost helps it get scheduled *sooner*. They are additive,
not alternatives.

---

## 3. GPU-bound is not an excuse — measured, in a 97 %-GPU scene

cake's first real frame data, HD2 main menu, 240.02 Hz VRR, ~12,400 frames/run,
ABBA 2 runs/arm (`STATE.md:486`):

| metric | native | cake G17 | verdict |
|---|---|---|---|
| avg FPS | 276.3 | 276.3 | tied — no headroom |
| **240 Hz deadline miss %** | **3.019** | **1.419** | **2/2, −53%** |
| deadline excess ms/s | 1.258 | 0.834 | 2/2, −34% |
| frame-time stddev | 0.258 | 0.217 | 2/2, −16% |
| p99 − median | 0.711 | 0.619 | 2/2, −13% |
| 0.1% low | 193.3 | 188.6 | **overlap** |
| p99.9 − median | 1.085 | 1.088 | **overlap** |

Read honestly: **the two metrics cake's own GAME-FIRST law says to score on are a
TIE.** The wins are on consistency and deadline adherence. Both statements are
true; the corpus records both.

`gpu_load` read a constant **97.0 across all 12,323 samples** — a reporting
artifact, never a saturation measurement.

---

## 4. Regime beats code, by 84×

`vkd3d_fence` wake p99: **3.16 µs** on a quiet host, **~50 µs** under 8-spinner
load (`STATE.md:605`). Same binary, same scene.

Implication for any cake-vs-lavd comparison: an A/B on a calm desktop measures the
case with nothing to fix. Every scored arm needs its load generator running and its
`noise_class` / `external_cpu_avg_pct` recorded — and cake's harness already does
this by construction.

lavd has no equivalent discipline visible in its source; its tuning constants
(`LAVD_TARGETED_LATENCY_NS = 10 ms`, `LAVD_SLICE_MIN_NS_DFL = 500 µs`) carry no
regime qualifier in-tree.

---

## 5. Where the two designs flatly contradict each other

| Question | cake's answer | lavd's answer | Testable? |
|---|---|---|---|
| Slice setter cost | direct `p->scx.slice` write; the kfunc's sub-scheduler authority check measured **+28–36% on `ops.stopping`** (`cake.bpf.c:1250`) | moved *to* `scx_bpf_task_set_slice()` everywhere (`3bc2480ff`) | yes — disassembly + a stopping-rate census |
| Preempt delivery | `scx_bpf_kick_cpu(KICK_PREEMPT)` — IPI | **avoids IPI on purpose**; writes victim `slice = 1` and lets it yield at the next scheduling point (`preempt.bpf.c:193`) | yes — wake-to-run on the victim |
| Periodic correction | **no `.tick` by design law** — "event completeness, never polling" | `ops.tick` shrinks boosted slices every tick | partly — cake's B4 node already names this as a severity multiplier |
| `task_cpu` ⊆ `cpus_ptr`? | *"post-core-validation and always in `p->cpus_ptr`"* (`cake.bpf.c:952`) | *"can be outside `p->cpus_ptr` and must be clamped"* — and upstream **added a clamp** | **open defect candidate** |

### 5a. RESOLVED AT THE KERNEL SOURCE — lavd is right, cake's comment is wrong

Read `kernel/sched/core.c` at `v7.2-rc4-503-g3dab139d4795` (running kernel
7.1.6-1-cachyos; this path is stable across both).

```c
static void
do_set_cpus_allowed(struct task_struct *p, struct affinity_context *ctx)
{
	scoped_guard (sched_change, p, DEQUEUE_SAVE)     /* core.c:2792 */
		p->sched_class->set_cpus_allowed(p, ctx);
}
```

`sched_change` is an RAII guard — `DEFINE_CLASS(sched_change, …,
sched_change_end(_T), sched_change_begin(p, flags), …)` (`sched.h:4207`).
`sched_change_begin` records `.queued = task_on_rq_queued(p)` and dequeues
(`core.c:11192`); `sched_change_end` **re-enqueues on scope exit**. Between them,
`set_cpus_allowed_common()` writes the new mask (`core.c:2781-2782`):

```c
cpumask_copy(&p->cpus_mask, ctx->new_mask);
p->nr_cpus_allowed = cpumask_weight(ctx->new_mask);
```

So the ordering is: **dequeue → mask updated → re-enqueue → `ops.enqueue` fires**.
Migration is `affine_move_task()`, which runs *after*. At that `ops.enqueue`,
`task_cpu(p)` is the **old** CPU and `p->cpus_ptr` is the **new** mask. They can
disagree — exactly as lavd's comment states.

cake's claim at `cake.bpf.c:952` — *"task_cpu is post-core-validation and always in
`p->cpus_ptr`"* — does not hold on this path. This is a comment that hands the next
reader a false model, which is the failure mode `CLAUDE.md` §Design laws names
explicitly.

### 5b. What it costs cake, and the discriminator

cake derives `s32 tcpu = (s32)p->thread_info.cpu` (`cake.bpf.c:955`) and uses it
as a DSQ id at `:1027` with only a `(u32)` cast. `grep -n 'thread_info.cpu\|tcpu'`
over the whole file finds **no `bpf_cpumask_test_cpu` guard on it**.

lavd's new comment gives the exact path where the assumption fails:
`set_cpus_allowed()`'s `DEQUEUE_SAVE`/`ENQUEUE_RESTORE` updates the mask and
re-enqueues *before* `affine_move_task()` migrates. If that reading is right, cake
can queue a task on a per-CPU DSQ for a CPU it is not allowed to run on — which is
exactly the shape of an isolated, unexplained stall (cake's own B1/B2 trunk).

**Discriminator, read-only, no policy change:** a counter incremented when
`!bpf_cpumask_test_cpu(tcpu, p->cpus_ptr)` in `cake_enqueue`. ~0 kills it.

---

## 6. What each project would gain from the other

**cake → lavd:** the *method*. lavd has no visible falsification ledger, no regime
covariate, no arm-attributed scoring rule. cake's G8 record — two consecutive
hypotheses gated on `WAKE_SYNC` for a workload where `futex_wake() →
try_to_wake_up(p, TASK_NORMAL, 0)` never sets it (`kernel/sched/core.c:4545`) — is
the kind of negative result lavd's tree does not appear to keep.

**lavd → cake:** three concrete mechanisms cake has not tried.
1. **Measured cache warmth** (`5699c7f08`): `cpu_heat` saturates over 500 µs
   residence, decays linearly over 5 ms away; the wait budget for the previous CPU
   stretches up to 2× with heat. cake asserts "continuations local" as an axiom and
   has no decay model at all.
2. **IPI-free preemption**: directly contradicts cake's measured IPI cost — one of
   them is wrong on this host.
3. **Continuous IRQ tiering** rather than cake's binary sink mask, with a
   closed-loop split point.

---

## 7. Open, in priority order

1. `task_cpu ⊄ cpus_ptr` counter in `cake_enqueue` — cheapest, and it sits on the
   game-tail trunk.
2. Score **input** and **game audio** roles, not the renderer — the sweep says the
   win is 2× larger there and neither has ever been scored.
3. cake-vs-lavd A/B under load. Blocked: the upstream lavd binary at
   `/home/ritz/Documents/Repo/scx-upstream/target/release/scx_lavd` built clean
   (exit 0, v1.1.2) but `getcap` returns empty — it cannot attach without
   capabilities, and this project never uses sudo.
