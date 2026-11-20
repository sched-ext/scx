# scx_cake design

The scheduling policy in this checkout. Commands and flags: [README.md](./README.md).
Measurements and history: [STATE.md](./STATE.md).

## Idea

Run waiting tasks quickly **without moving them away from the cache they need**.
Inputs: task behaviour, idle CPUs and topology. Games are never identified by name.

| Term | Meaning |
|---|---|
| CPU | a logical CPU; SMT siblings share one core |
| LLC | last-level cache shared by a group of CPUs (an AMD CCD) |
| One-word host | every present CPU ID is below 64, so one 64-bit word holds a CPU set |
| Handoff floor | 1,464 ns: a run this short "woke someone and got out of the way" |
| Seat | one-word hosts: the CPU a stage task last blocked on. Others avoid it while it sits idle; once something else runs there, the stage may take it back |
| IRQ-busy | an IRQ sink, inside a handler now, or IRQ-hot on a patched kernel ([signals](#interrupt-aware-placement)) |

| Queue | Holds |
|---|---|
| CPU-local queue | the kernel's per-CPU queue: what that CPU runs next |
| Owner queue | one per CPU, ordered by virtual runtime; other CPUs may steal from it |
| LLC wake pool | one per LLC, ordered by virtual runtime (one shared pool when the layout does not fit) |

Task classes come from the kernel's per-task totals: mean wait = `run_delay / pcount`,
mean burst = `sum_exec_runtime / nvcsw`.

| Class | Rule | Used for |
|---|---|---|
| Starved | mean wait > mean burst | never preempted on wake; deeper wake key |
| Turn-starved | mean wait > 2 x mean burst | takes the wake path; may leave its home |
| Stage | mean burst >= 64 us | earns a seat; keeps its home on SYNC wakes; may move to the preferred LLC |
| Sub-handoff | mean burst < handoff floor | keeps its warm home even when turn-starved |

---

## Where work goes

```mermaid
flowchart TD
    W["Task wakes"] --> S["select_cpu: handoff, seat, warm home or idle claim"]
    S --> D{"Placed?"}
    D -->|Yes| L["CPU-local queue"]
    D -->|No| E["enqueue: choose a route"]
    R["Slice used up or forced requeue"] --> E
    E -->|claimed CPU or preempt| L
    E -->|stays home| O["Owner queue"]
    E -->|shared| P["LLC wake pool"]
    O --> X["dispatch: find work this CPU may run"]
    P --> X
    X -->|move| L
    L --> C["CPU runs the task"]
```

Affinity applies everywhere. A read of the idle word or mask is only a candidate list;
**the atomic idle claim decides**. Kicks and preempt requests only notify a CPU.

### 1. CPU selection (`select_cpu`)

```mermaid
flowchart LR
    A[serial handoff] -->|no| H[fixed home] -->|no| B[seat retake] -->|no| C[warm home] -->|no| D[idle claim] -->|none| U[undecided] --> E[enqueue]
    H -->|higher class and no idle claim| E
```

| Step | Rule |
|---|---|
| Serial handoff | queue behind the waker on its CPU, no preempt, when: that CPU's last 3 runs each woke a task and blocked within the handoff floor; the waker is within one handoff of its mean burst end; that CPU's own and local queues are empty; >= 3/4 of its LLC is idle; it is not IRQ-busy; the wake is not `WAKE_SYNC` or a device wake (patched kernel) |
| Fixed home | An owner can return to its allowed home. When a higher scheduling class already occupies it, Cake tries another allowed idle CPU, preferring the same LLC. If the claim fails, normal enqueue handles the wake. |
| Seat retake | a stage task takes its seat back from a queued, unpinned, non-stage task with PREEMPT (enqueue reroutes that task); only once something else ran there, never on an IRQ-busy CPU |
| Warm home | the previous CPU, if idle. Skipped for: a SYNC wake that is not a stage; a core not fully idle (one-word hosts); another task's held seat; turn-starved and not sub-handoff; IRQ-busy; a contended core (wide hosts) |
| Idle claim | one-word hosts, inside one LLC: the task's, or the waker's for a non-stage task on a multi-LLC host; a stage off the preferred LLC moves there when a whole core is free. The starting CPU first if it is a whole idle core, no seat and no IRQ sink, then up to `claim_tries` picks by: big cores (hybrid), then whole idle core, then not a seat, then no IRQ sink on the core, not in deep idle, then platform rank, then lowest ID |
| Undecided | the previous CPU runs a task that is not starved, and the wakee is neither a kernel thread nor turn-starved: claim a clean idle CPU (below). Otherwise enqueue routes it |

**Clean idle pick** (enqueue uses it too): one-word hosts rank the task's LLC as above
in two passes, first skipping IRQ-busy CPUs and those with a tick due. If
every claim loses, multi-LLC hosts give up (the caller offers the work to another LLC)
and single-LLC hosts walk the idle word again. Wide hosts ask the kernel picker. Both
take a whole idle core, then any idle CPU.

### 2. Enqueue (selection did not place it)

| Case | Route |
|---|---|
| Kernel-thread wake, unpinned | clean idle CPU, flat 3 ms slice; else the wake path |
| Kernel-thread wake, pinned | its CPU's local queue, flat 3 ms; preempts if its key is more than 3 ms earlier than the occupant's live vtime |
| Turn-starved wake, unpinned | the wake path |
| Wake whose CPU runs a task that is not starved (unpinned) | that task is past its slice, the tick has not stopped it, and it is not a stage on its own seat: preempt it; else pool + idle kick |
| Forced requeue, or seat collision (unpinned) | clean idle CPU; else pool + idle kick |
| Pinned wake, own queue empty | its CPU's local queue at once, no dispatch pass: when that CPU is idle, or to preempt its occupant by the same test, with its own slice |
| Anything else: continuation, pinned wake, other wakes | its CPU's owner queue (a pinned wake may preempt by the same test, with its own slice, sent as a kick), then kick an idle CPU unless the task is still on its CPU with nothing else waiting there or in its pool |

**Wake path**, in order:

1. A wake racing its own switch-out goes to its owner queue.
2. A clean idle CPU.
3. Preempt the CPU's occupant if the wakee's raw vtime (before the key floor) is
   earlier than the occupant's live vtime and the occupant ran >= min(wakee slice,
   187.5 us). Never a starved task or a stage on its own seat.
4. The same test on up to 3 neighbours in steal order (IDs below 128), with
   min(wakee slice, 750 us).
5. The pool, one more idle search and kick; if none is free, multi-LLC hosts offer it
   to an idle CPU on another LLC.

### 3. Dispatch

```mermaid
flowchart LR
    A[offer from another LLC] --> B[own queue or LLC pool] --> C[forward a kick] --> D[steal owner queues] --> E[other LLC pools] --> F[keep running prev]
```

| Step | Rule |
|---|---|
| Offer | multi-LLC: an idle CPU picked by another LLC serves that LLC's pool at once |
| Own queue or pool | pool first if the own queue is empty, its head's key is more than 3 ms earlier, or it went unserved for 24 ms; then the other |
| Seat stays free | a held seat with an empty own queue claims and kicks a free non-seat CPU on its LLC that can run the work, and stays idle; it serves the pool itself if no claim wins or the pool went unserved for 24 ms |
| Forward | one-word hosts, both moves failed (affinity): kick an idle CPU on this LLC that can run the pool head, non-seat first |
| Steal | other owner queues in steal order, SMT sibling first; another LLC's queue only if its head is a slice behind the frontier |
| Other pools | multi-LLC: only a head a slice behind the frontier, or a pool unserved for 24 ms |
| Nothing | both queues empty: re-pick up to 4 times for a pool insert under way; then `prev`, if still runnable, keeps running with a fresh slice |

An idle CPU can see an empty pool while the kernel is still committing an
enqueue. Cake counts the task before submitting the insert so that CPU can
wake to serve it. The task owns its count in BPF task storage. A hint in
its slice lets ordinary wakes and runs skip the lookup. When the kernel
removes a runnable task during a property change or suspend, the quiescent
callback returns its count even if the kernel has replaced the slice.
Ordinary sleeps return immediately. Cake creates the storage in
`ops.init_task`, at fork and at attach, where no rq lock is held. Every
other callback only looks it up, because a create under the rq lock can
deadlock in the memory charge. A task whose create failed goes to the
kernel's global dispatch queue.

When Cake observes 64 or more tasks in an owner queue or wake pool, it
examines up to eight tasks and asks the kernel to move one that can run
on the destination CPU. The limit applies per queue. The first choice
between the owner queue and its pool reuses the depth already read for
ordering. A steal or retry takes another depth reading. A queue can grow
after Cake reads it, including while entering a shallow queue's bulk move.
The verifier checks the deep search as a separate BPF function. Checking
it in each caller's context exceeded the verifier's instruction budget
on test layouts with 1024 possible CPU IDs.

For a game thread that wakes while real-time work holds its fixed home,
an eligible idle core can start the thread sooner. Moving can also cost
more than waiting out a short interruption because the new core has cold
private caches. Preferring a core that shares L3 limits that cost.

Only a successful queue move proves work was taken; counts and marks are hints.

---

## Hardware discovery

The loader reads CPU IDs, SMT siblings and LLCs at start; nothing from the build
machine is baked in.

```mermaid
flowchart TD
    T["Read topology"] --> B{"Possible CPU-ID span > 1024?"}
    B -->|Yes| F["Refuse to start"]
    B -->|No| N{"Present CPU IDs all < 64?"}
    N -->|No| G["Kernel idle picker, one pool"]
    N -->|Yes| Q{"At most 16 LLCs?"}
    Q -->|Yes| M["One pool per LLC"]
    Q -->|No| U["One shared pool"]
```

| Detail | |
|---|---|
| ID span | counts sparse and offline IDs, not just online CPUs |
| Steal order | same LLC, then LLCs with the same cache size, then the rest; within each, SMT sibling first, then the following IDs, wrapping. Precomputed below ID 128; wider hosts walk a ring |
| Idle word | one-word hosts: cake keeps its own word of really idle CPUs, changed only by `ops.update_idle`, the dispatch re-arm and `ops.dispatch`'s clear when a queued prev's slice ends (bypass hides idle exits), and runs without `SCX_OPS_KEEP_BUILTIN_IDLE`, so the kernel stops updating its masks. A claim sets a bit in a second word on the same line, cleared when that CPU next goes idle. Claimable is idle and not claimed; the whole-core read ignores claims, so a claimed core stays whole until that CPU runs. Wide hosts keep the kernel's masks and picker |
| Claim tries | max(4, online CPUs in the widest LLC / 4) |
| Preferred LLC | On a one-package, multi-LLC host within the idle word, prefer an LLC when all its cores outrank every core outside it. If ranks overlap on a two-LLC X3D system, use the driver's startup mode and measured unified L3 sizes. Cache mode prefers the larger L3 and frequency mode the smaller one. Ambiguous inputs give no die preference. A fixed home uses an eligible unowned core on the preferred LLC when available. |
| Deep idle | one-word hosts avoid a CPU in an idle state slower to exit than the handoff floor |
| Core ranking | At startup, scale architectural CPU capacity by comparable policy and firmware ceilings, then apply enabled preferred-core hints. An explicit preferred-core opt-out suppresses the CPPC fallback. Governor, EPP and frequency floors are reported for inspection. |
| Optional kernel features | detected at start, with fallbacks ([README table](./README.md#kernel-features)) |

Restart Cake after changing placement settings. `--print-topology` uses the same
discovery as scheduler startup and prints the selected mask and its source.

---

## Interrupt-aware placement

| Signal | Source |
|---|---|
| IRQ sink | the loader reads each CPU's handler time every 1-4 s and cuts at the widest gap; 2 windows above the cut mark a sink, 3 below clear it |
| Handler running now | IRQ and softirq entry/exit hooks keep a per-CPU depth |
| Tick about to fire | next tick within one wake hop (startup probe p99; off if that exceeds a quarter tick) |
| IRQ-hot (patched kernel) | `--kernel-signals on`: more than 1/8 of recent time in handlers |

Hints only: a noisy CPU is still used when nothing cleaner is free.

---

## CPU time and fairness

Virtual runtime charges CPU time scaled by nice weight. A shared frontier, raised in
`ops.running`, bounds how old a key can be (not a strict global order). `ops.running`
also stamps each run with the CPU's rq clock as the kernel last updated it.

| Key floor | |
|---|---|
| Normal | frontier - 3 ms |
| Starved | lower by 3/4 of (3 ms - mean burst) |
| Forced requeue | lower by 2.25 ms |

Slice (ns), with one division:

```text
n     = voluntary switches | 1
want  = min(2 * floor(runtime / n), floor(age / (2 * n)))
cap   = 750000 if want >= 3000000 else 1500000
slice = max(1464, min(want, cap))
```

A task that wants a whole 3 ms slice never blocks inside it: it is a compute task, and
its grant is capped at half of what the others get.

Age under 3 ms counts as 3 ms. The returned grant clears its low five bits
for the pool tag. Since the compute threshold is even, the implementation
can omit the low-bit correction to `want` and produce the same grant.
Kernel threads placed directly get a flat 3 ms. A slice is a budget the kernel tick
enforces, not a preemption promise: cake has no `ops.tick`.

A `sched_yield` keeps its slice unless something waits for this CPU: another task on
its run queue, work in its LLC pool, or another LLC's offer. Then the slice drops to 0,
as the kernel does without `ops.yield`.

---

## Lifecycle

```mermaid
flowchart LR
    A[toggles set] --> B[BPF loads] --> C[loader drops capabilities] --> D[running]
    D -->|kernel restart request| E[re-exec with same args] --> B
    D -->|Ctrl+C| F[release scheduler]
    D -->|deep queue with overdue work| F
```

If the eight tasks examined in a deep queue cannot run on the destination
CPU, other CPUs can still serve them. When the head has already waited
2.5 s, Cake checks that the same head still leads a deep queue before
requesting a voluntary exit. The loader reports the queue, CPU and PID.
The kernel returns queued work to native scheduling. The age check uses
the tick period measured at startup. If that measurement is unavailable,
Cake still limits the search to eight candidates. The kernel's 5 s
runnable-task watchdog also applies.

## Starvation fallback (24 ms)

| | |
|---|---|
| Stamp | each pool's served time, refreshed when served or seen empty |
| Past 24 ms (`WAKE_STARVE_WALL_NS`) | dispatch serves that pool first, overrides the seat rule, and lets other LLCs take it |
| Not | per-task timing, nor a 24 ms service promise |
| Value | eight 3 ms slices; not derived from behaviour or hardware |

## Known limits

| Limit |
|---|
| The wait and service totals are quantized before comparing their ratios. Large products take an exact 128-bit comparison in BPF. |
| A late queue mark or remote offer can delay cross-LLC service |
| Passing the verifier and the tests does not prove performance |
