# How Linux RT picks cores — and what scx_cake can and cannot do about it

Date: 2026-07-24
Status: reference; kernel-source verified against **v7.1** (`kernel/sched/rt.c`,
`kernel/sched/cpupri.{c,h}`, `kernel/sched/ext.c`). No benchmark claims here.

Written after an observation (RT thread migrations 18–134/60 s under native →
0 under cake, n=1) prompted a mechanism hypothesis that this research
**falsified**. The falsification is the main output; keep it so the same idea
isn't re-invented.

## 0. The premise correction

**EEVDF is not the RT scheduler.** EEVDF is the fair class. RT threads are
handled by `rt_sched_class` in `kernel/sched/rt.c`, which sits above both fair
and `ext`. scx_cake replaces the **fair** class only. So in any cake-vs-native
comparison the RT placement code is *byte-identical on both arms* — there is no
"how is EEVDF configured for RT", and any observed difference must come from
interaction, never from policy.

Class order: `stop → deadline → RT → ext → fair → idle`.

## 1. Wakeup placement — `select_task_rq_rt()`

```c
/* For anything but wake ups, just return the task_cpu */
if (!(flags & (WF_TTWU | WF_FORK)))
        goto out;
...
test = curr &&
       unlikely(rt_task(donor)) &&
       (curr->nr_cpus_allowed < 2 || donor->prio <= p->prio);

if (test || !rt_task_fits_capacity(p, cpu)) {
        int target = find_lowest_rq(p);
        ...
        if (target != -1 && p->prio < cpu_rq(target)->rt.highest_prio.curr)
                cpu = target;
}
```

A waking RT task **stays on its previous CPU** unless:

- **`rt_task(donor)`** — the previous CPU is currently running *another RT
  task* whose priority is equal or higher (`donor->prio <= p->prio`), or that
  task is pinned (`nr_cpus_allowed < 2`); or
- **`!rt_task_fits_capacity(p, cpu)`** — asymmetric-capacity systems only
  (big.LITTLE). Always true, i.e. never a trigger, on a uniform 9800X3D.

**A cake task or an EEVDF task running on that CPU does not trip this.** Both
are ordinary class; `rt_task()` is false for both. This is the single most
important fact in this document.

## 2. Target selection — `find_lowest_rq()`

```c
ret = cpupri_find(&task_rq(task)->rd->cpupri, task, lowest_mask);
if (!ret)
        return -1;

/* We prioritize the last CPU that the task executed on since
   it is most likely cache-hot in that location. */
if (cpumask_test_cpu(cpu, lowest_mask))
        return cpu;

/* else: sched-domain walk */
for_each_domain(cpu, sd) {
        if (sd->flags & SD_WAKE_AFFINE) {
                if (this_cpu != -1 && cpumask_test_cpu(this_cpu, sched_domain_span(sd)))
                        return this_cpu;          /* cheaper to preempt */
                best_cpu = cpumask_any_and_distribute(lowest_mask,
                                                      sched_domain_span(sd));
                ...
        }
}
```

Order of preference: **previous CPU** (cache warmth) → **`this_cpu`**, the CPU
executing the decision, i.e. the *waker* → round-robin spread within the
sched domain → anything compatible.

## 3. `cpupri` — and the fact that kills the occupancy hypothesis

`cpupri` is a per-root-domain index of "what priority is each CPU running",
used to build `lowest_mask`.

```c
/* cpupri.h, v7.1 */
#define CPUPRI_NR_PRIORITIES    (MAX_RT_PRIO+1)
#define CPUPRI_INVALID          -1
#define CPUPRI_NORMAL            0
#define CPUPRI_HIGHER          100
```

```c
/* convert_prio() */
case 0 ... 98:          cpupri = MAX_RT_PRIO-1 - prio;  /* 1 ... 99 */
case MAX_RT_PRIO-1:     cpupri = CPUPRI_NORMAL;         /*  0 */
case MAX_RT_PRIO:       cpupri = CPUPRI_HIGHER;         /* 100 */
```

```c
/* cpupri_find_fitness() — first non-empty level wins */
for (idx = 0; idx < task_pri; idx++) {
        if (!__cpupri_find(cp, p, lowest_mask, idx))
                continue;
        ...
        return 1;
}
```

**`CPUPRI_IDLE` no longer exists.** `git grep CPUPRI_IDLE v7.1 -- kernel/sched/`
returns nothing. An **idle CPU and a CPU running a cake or EEVDF task occupy
the same level, `CPUPRI_NORMAL` (0)** — they are indistinguishable to RT
placement. `cpupri_set()` is only ever called from `inc_rt_prio()` /
`dec_rt_prio()`, so a CPU's level reflects **its RT runqueue and nothing else**.
`__cpupri_find()` masks against `p->cpus_mask` and `cpu_active_mask`; there is
no idle check anywhere in the path.

For an `SCHED_RR` priority-1 thread (kwin main, DP-2, DP-3, libinput):
`p->prio` = 98 → `task_pri` = `convert_prio(98)` = 1 → the loop runs **only
`idx = 0`** → `lowest_mask` = *every CPU not currently running an RT task*.

Combined with §2's first rule, the previous CPU is in that mask unless it is
RT-occupied, so the task goes straight back to it.

## 4. Push and pull

```c
static inline bool need_pull_rt_task(struct rq *rq, struct task_struct *prev)
{
        /* Try to pull RT tasks here if we lower this rq's prio */
        return rq->online && rq->rt.highest_prio.curr > prev->prio;
}

static int balance_rt(struct rq *rq, struct task_struct *p, struct rq_flags *rf)
{
        if (!on_rt_rq(&p->rt) && need_pull_rt_task(rq, p)) { ... pull_rt_task(rq); }
        ...
}
```

Pull fires when a CPU switches away from a **higher-priority** task and thereby
lowers its own RT priority — i.e. when leaving RT work, not when leaving cake
work. Push (`push_rt_task`) fires when a runqueue holds more than one RT task.
Both are RT-overload mechanisms.

## 5. FALSIFIED: "cake's occupancy pattern keeps RT threads from bouncing"

**The hypothesis was:** cake keeps CPUs busy (keep-running slice refill) where
native leaves them idle; RT's search therefore finds fewer attractive idle
targets under cake and leaves RT threads on their previous CPUs; the
compositor stays cache-warm; that explains the measured jitter win.

**It is wrong.** §3 shows RT placement has no idle-vs-busy distinction at all —
`CPUPRI_IDLE` was removed, and an idle CPU ranks identically to a
cake-occupied one. Cake's occupancy pattern is invisible to `cpupri` and
therefore to `find_lowest_rq`.

**Corollary — a whole class of ideas is closed.** Steering, pinning, or
reserving cake tasks to keep certain CPUs free of (or busy with) ordinary work
**cannot** influence RT placement. Do not spend a candidate on it.

## 6. What can still explain the observation

On this machine an RT thread migrates **only** when another RT thread is on its
CPU (§1) or under RT overload (§4). So the lower class can influence it through
exactly two narrow channels:

1. **Wake phase.** Cake changes when the ext-class work that *feeds* the
   compositor completes (render submission, Wayland socket writes), so kwin
   main / DP-2 / DP-3 are woken at different moments relative to one another
   and collide on each other's CPUs less often. Indirect and unproven.
2. **`this_cpu` in the domain walk (§2).** When the prev-CPU test *does* fail,
   the fallback prefers the waker's CPU. Cake changes which CPU wakes the
   compositor, so it can shift that fallback target — but only in the minority
   of cases that already failed the prev-CPU test.

And the mundane third option: **noise.** The observation is n=1 on the cake
side, and migration count is the noisiest metric measured (18 → 134 between two
*identical* native runs). Zero across three independent threads at once, with
`libinput` at 4 proving the counter is live, is what keeps it interesting —
but after §5 the prior on "real mechanism" should be *lower*, not higher.

## 7. The discriminator

Both surviving explanations predict the same thing: **RT threads are
co-resident on the same CPU more often under native than under cake.** That is
directly measurable and needs no BPF, no receipt, and no scheduler activation —
only a read-only sampler that records which CPU each RT thread is on (today's
`rt-audit` records runtime, switches, and migrations, but not residency).

Until that runs, treat the migration result as an unexplained observation, not
as a cake property.

## Source map

- `kernel/sched/rt.c` — `select_task_rq_rt()`, `find_lowest_rq()`,
  `need_pull_rt_task()`, `balance_rt()`, `push_rt_task()`, `pull_rt_task()`
- `kernel/sched/cpupri.c` — `convert_prio()`, `cpupri_find_fitness()`,
  `__cpupri_find()`; `kernel/sched/cpupri.h` — level definitions
- `kernel/sched/ext.c` — `put_prev_task_scx()` (RT preemption re-queues a
  non-IMMED scx task with `SCX_ENQ_HEAD`, front of its own CPU's local DSQ,
  resumed as soon as the CPU returns to `ext`), `set_next_task_scx()`
  (`ops.running` fires on every resume — the origin of cake's `run->stamp`
  age amnesia, see STATE.md §2026-07-24)
- Kernel tree is at 7.2-rc; read v7.1 semantics with
  `git show v7.1:kernel/sched/...` (pre-split layout, `ext.c` not `ext/`).
