# PANDEMONIUM

A Linux kernel scheduler for sched_ext, built in Rust and C, PANDEMONIUM prices every scheduling decision in nanoseconds against a live service bound and adapts that bound in real time. There is no task classifier. Slice, placement, admission and preemption each read a measured quantity — service rendered, queue backlog, accrued wait — so the question at every site is what a task is owed rather than what class it belongs to. A damped harmonic oscillator drives CoDel-inspired stall detection with the literal RFC 8289 sojourn metric, resting at an equilibrium the machine's own Laplacian spectrum chooses. Resistance affinity (effective resistance from the Laplacian pseudoinverse of the CPU topology graph) provides topology-aware task placement for pipe/IPC storms. A migration potential Φ — R_eff priced against the queueing relief a move buys — prices the work steal and the warm hold, so a task crosses a cache boundary only when the wait it relieves outweighs the cache cost. Rust folds the distance terms into per-peer tables at topology detect and the kernel reads them with one indexed lookup — the computation in the adaptive layer, the application in the kernel. Every knob the adaptive layer ships is a function of a measurement — the depth of a cache domain's lanes, the shape of its arrivals and the persistence of its backlog — computed on the tick it is applied rather than learned over a convergence window.

A seat and a lane on every CPU and no shared queue, a per-queue clock judged by CoDel's control law, an R_eff work steal priced by how long a queue's head has waited, class-free DSQ routing, a wakeup preemption gate keyed on the pair ledger, a wait-admitted placement spill, a Φ-priced warm-stay home anchor, a sojourn selector keyed on the bare arrival stamp, a slice quantum priced in the same unit, regime- and depth-derived slice tuning and an off-tick unified sojourn bound.

See the [User Guide](https://github.com/wllclngn/PANDEMONIUM/blob/main/USER-GUIDE.pdf) for an introduction — the ideas behind PANDEMONIUM in plain language, and how to read what it prints.

PANDEMONIUM is included in the [sched-ext/scx](https://github.com/sched-ext/scx) project alongside scx_rusty, scx_lavd, scx_cosmos and the rest of the sched_ext family. Thank you to Piotr Gorski and the sched-ext team. PANDEMONIUM is made possible by contributions from the sched_ext, CachyOS, Gentoo, OpenSUSE, Arch, Ubuntu and NixOS communities within the Linux ecosystem.

## Performance

12 AMD Zen CPUs (Ryzen 5 3600), kernel 7.2.11-arch1-1, clang 23.1.4.

Three iterations per Test arm and scheduler. PANDEMONIUM's two arms are the tree as it ships; EEVDF's column is the same day's earlier pass on the same boot and kernel.

### P99 Wakeup Latency (interactive probe under CPU saturation)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 1,420us     | 29us              | **17us**               |
| 4     | 115us       | 15us              | **14us**               |
| 8     | 28us        | **16us**          | 17us                   |
| 12    | **13us**    | 18us              | 20us                   |

### Burst P99 (fork/exec storm under CPU saturation)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 1,660us     | 16us              | **15us**               |
| 4     | 1,981us     | **15us**          | **15us**               |
| 8     | 2,361us     | **18us**          | **18us**               |
| 12    | 1,560us     | **20us**          | **20us**               |

### Longrun P99 (interactive latency with sustained CPU-bound long-runners)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 1,423us     | 1,016us           | **29us**               |
| 4     | 1,182us     | 1,011us           | **13us**               |
| 8     | 1,113us     | 18us              | **17us**               |
| 12    | 172us       | **19us**          | 22us                   |

### Mixed Latency P99 (interactive + batch concurrent)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 1,519us     | 1,020us           | **85us**               |
| 4     | 1,974us     | **13us**          | 14us                   |
| 8     | 710us       | 18us              | **17us**               |
| 12    | 745us       | **21us**          | 46us                   |

### Deadline Miss Ratio (16.6ms frame target)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | 15.8%       | **0.1%**          | **0.1%**               |
| 4     | 11.7%       | 0.2%              | **0.1%**               |
| 8     | 10.7%       | **0.1%**          | **0.1%**               |
| 12    | 12.5%       | **0.1%**          | **0.1%**               |

### App Launch (`fork()`+`exec()` under load, p99 us)

| Cores | EEVDF       | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-------|-------------|-------------------|------------------------|
| 2     | **2,265us** | 2,984us           | 2,793us                |
| 4     | 3,875us     | 4,440us           | **2,997us**            |
| 8     | 3,606us     | **2,462us**       | 2,485us                |
| 12    | 3,709us     | 1,574us           | **1,555us**            |

### IPC Round-Trip by Primitive (12C, p50 / p99 us)

| Primitive | EEVDF          | PANDEMONIUM (BPF) | PANDEMONIUM (ADAPTIVE) |
|-----------|----------------|-------------------|------------------------|
| pipe      | **9** / 16     | 11 / **15**       | 11 / **15**            |
| socket    | 17 / 28        | **14 / 19**       | **14 / 19**            |
| eventfd   | **9 / 17**     | 23 / 31           | 13 / 18                |
| sem       | **8 / 16**     | 24 / 31           | 12 / 21                |
| fanout    | **50** / 2,863 | 93 / **207**      | 93 / 263               |

### Fork/Thread IPC (`perf bench sched messaging -t -g 24 -l 6000`, 12C)

| Scheduler                | Time                | vs EEVDF  | IPC       | Cache Misses | CPU Migrations |
|--------------------------|---------------------|-----------|-----------|--------------|----------------|
| EEVDF                    | **15.681±0.074s**   | baseline  | **0.507** | **2.85G**    | **178.94K**    |
| PANDEMONIUM (BPF)        | 16.713±0.175s       | +6.6%     | 0.488     | 3.57G        | 366.03K        |
| PANDEMONIUM (ADAPTIVE)   | 16.708±0.278s       | +6.5%     | 0.486     | 3.56G        | 367.79K        |

Where each arm's migrations start, summed over its thread and process cells: A steal is the drain side, a CPU with nothing of its own queued taking a task from a peer's queue, and a spill is the placement side, a wakee seated on a peer instead of its own source CPU.

| Scheduler                | Steals      | Spills    | Dispatches  | Steal %   | Spill %   |
|--------------------------|-------------|-----------|-------------|-----------|-----------|
| PANDEMONIUM (BPF)        | 1,096,294   | 4,838     | 23,672,680  | 4.631%    | 0.020%    |
| PANDEMONIUM (ADAPTIVE)   | 1,157,194   | 4,955     | 24,393,834  | 4.744%    | 0.020%    |

### Energy Efficiency (`prism --dev power`, 12C)

Three runs per (scheduler, workload), 30s cooldown between runs. montauk records each run: Package energy is the run's delta of its cumulative RAPL counter (`montauk_package_energy_joules_total`), and IPC and EPI come from its system-wide PMU. Zen 2 (Ryzen 5 3600) exposes only `J_pkg` (no per-core or per-DRAM RAPL).

The `paced` workload runs the frame bench's 144 fps paced scenario for 30s, its work per frame calibrated once on EEVDF before any arm loads: Fixed work at a fixed rate on a partly loaded box, where placement decides how many cores wake and how high clocks run. Its row carries J/frame beside the run's late-frame share and 1% low, so energy saved by missing frames reads on the same line.

EEVDF's rows are the same day's earlier pass, so each table carries the package temperature its runs averaged beside their energy and no delta against EEVDF.

**Idle floor** (30s `sleep`, scheduler restlessness):

| Scheduler                | J_pkg       | Avg W      | Pkg temp |
|--------------------------|-------------|------------|----------|
| EEVDF                    | 885.97J     | 29.53W     | 67.9C    |
| PANDEMONIUM (BPF)        | 815.75J     | 27.19W     | 65.5C    |
| PANDEMONIUM (ADAPTIVE)   | **766.99J** | **25.56W** | 56.8C    |

**Messaging** (`perf bench sched messaging`, fork-storm + IPC):

| Scheduler                | Wall_s     | J_pkg         | J/op         | Pkg temp |
|--------------------------|------------|---------------|--------------|----------|
| EEVDF                    | **15.70s** | **1,043.30J** | **181.13uJ** | 77.6C    |
| PANDEMONIUM (BPF)        | 16.61s     | 1,080.91J     | 187.66uJ     | 75.0C    |
| PANDEMONIUM (ADAPTIVE)   | 16.42s     | 1,054.63J     | 183.10uJ     | 73.1C    |

**Paced** (the frame bench's 144 fps scenario, 30s):

| Scheduler                | J_pkg       | Avg W      | J/frame      | Late %   | 1% low    | Pkg temp |
|--------------------------|-------------|------------|--------------|----------|-----------|----------|
| EEVDF                    | 1,011.03J   | 33.58W     | 234.14mJ     | 0.07     | **135.5** | 67.2C    |
| PANDEMONIUM (BPF)        | 964.16J     | 32.02W     | 223.29mJ     | 0.12     | 134.1     | 64.4C    |
| PANDEMONIUM (ADAPTIVE)   | **949.79J** | **31.55W** | **219.96mJ** | **0.06** | 134.5     | 63.8C    |

## Key Features

### Dispatch Waterfall

Every runnable task waits on one CPU. Each CPU has a seat, the per-CPU DSQ that wakes and handoff partners are placed on, and a lane, a second DSQ for its own requeues, and each carries a queue clock. No queue is shared, so the steal is the one path between CPUs. `sweep_bound_preempt` runs first on every dispatch and off the tick: It reads a rotating window of eight CPUs and forces one off its resident when its seat or its lane has waited past `lag_cap_ns`, so a CPU nobody calls `dispatch()` on is still bounded and NO_HZ_FULL cannot suppress it. Between ticks it also acts on the clock's own bound: A peer's seat past `codel_target_ns` gets a preempt paced by that seat's judge, unless the peer's resident has run under one target since it took the CPU, which each CPU stamps in `running()`.

| Step | Source | Rule |
|---|---|---|
| **aged lane** | Own lane | Served first once it has waited past `codel_target_ns` and longer than the seat. Each such serve is a rescue event for the oscillator. A CPU that seated a handoff partner within one live target serves its seat first, until the lane passes `lag_cap_ns`. |
| **0** | Own seat | Cache-hot, no contention. |
| **1** | A peer's seat | One walk of the R_eff-ranked peer list [8], cross-domain peers included. A busy CPU walks at most once per CoDel target and takes a head that has waited `phi_base_cost_ns` plus the peer's distance share of one target, plus a hold of up to one target when the peer seated a pair within the last one, so a near steal does not split it. A CPU about to idle (`would_idle`) walks every time, over the whole rank, and pays the base cost alone. |
| **2** | Own lane | Its own requeues, whatever their age. |
| **3** | A peer's lane | The same walk at the same prices, except that a CPU about to idle pays the distance again past a busy CPU's budget, so a far lane keeps its hogs. A lane taken past the target is a rescue. |
| **keep-prev** | KEEP_RUNNING | `prev` still wants the CPU and nothing was dispatched. |

One task moves into the local DSQ per dispatch: The kernel runs a local task without calling `dispatch()`, so a second would wait out the first's slice on a queue no clock reads. The aged-lane step is load-bearing. Without it a CPU kept busy by its seat never visits its own requeues, and a workqueue worker starves there until the scx watchdog fires. The move happens inside the walk, so a steal lost to a racing CPU walks on to the next qualifying peer and is counted (`nr_steal_lost`).

### Placement

**select_cpu** walks one ladder, top to bottom:

- A sync wake from the wakee's handoff partner is seated on the waker's own seat, on one cache domain as on several. The waker is about to block and its own STEP 0 takes the wakee, so the kick is IDLE when the seat is the waker and PREEMPT when the spill moved it. On the adaptive arm a wake that is not sync takes the same seat when its waker has blocked within `waker_leave_ns` (25us) of each of its last eight wakes; a fan-out wake never does.
- Otherwise the wakee is anchored on its last CPU (a fresh fork on its parent's) and the R_eff walk takes the anchor if it is idle, else the nearest idle CPU in R_eff order. An idle seat with nothing queued takes the wakee straight onto its local DSQ, and a wake that may cut a busy seat cuts (see Wakeup Preemption).
- Only when the walk finds no idle CPU does an uncongested home hold the wakee: select_cpu returns it undispatched, and enqueue's TIER 0 seats it with a preempt-priced kick.
- Last, the topology-blind `scx_bpf_select_cpu_dfl`.

Every seat is the same four steps in one function, `seat_task()`: Hand off to a claimed idle CPU with an empty queue, cut if the wake may and the seat is its own per-CPU queue, else insert in deadline order, then record the arrival on that queue's clock and kick only what was queued.

**enqueue**:

- **TIER 1, idle CPU**: An R_eff walk from `last_cpu` for an idle CPU. The task goes on that CPU's seat, and the kicked CPU is the one that dispatches it.
- **TIER 0, warm-stay**: Reached only when the walk found no idle CPU, and ahead of the node-wide idle pick, which ignores distance. The anchor keeps the task while its seat's wait is within `codel_target_ns` plus its nearest-peer hold. A wakeup anchors on `home_cpu`, a fixed point set on its first run, so the pull is self-limiting; a requeued handoff partner anchors on `last_cpu`. Kthreads are excluded, and a wake that may not cut is not held: It takes an idle CPU anywhere on the node first.
- **Node-wide idle pick**: Any idle CPU on the node.
- **TIER 2, warm anchor**: A wakeup, or a handoff partner, goes to its last CPU's seat, or to the nearest R_eff sibling in the same cache domain that would admit it when that seat's wait is over one live target. A wake that may not cut first looks for a resident that never sleeps (see Wakeup Preemption).
- **TIER 3, own CPU**: Everything else stays on the CPU it is on, a plain requeue on that CPU's lane and a wake with no warm CPU to anchor on its seat, with a priced kick. A requeue on the CPU running the enqueue gets none, since that CPU reaches `dispatch()` on its own.

Admission is a wait in nanoseconds. A seat admits while its queue's wait plus its resident's remaining slice is under one live CoDel target, so the wait a task inherits on arrival is bounded by one target plus the single demand that may overshoot it. A spill moves a wakee only to a peer in the same cache domain that would admit it with the base cost of a move to spare, so a move needs a gap and not a tie, and a spill never crosses an L3.

### Wakeup Preemption

`wake_cuts()` decides whether a wakeup may preempt the running task. A wake that may cut goes to the head of its seat's local DSQ with `SCX_ENQ_PREEMPT` and a PREEMPT kick, so it runs next on that CPU ahead of anything on the seat's per-CPU DSQ. A sync wake is a handoff from a waker about to block. From the wakee's handoff partner it cuts; from any other waker it is one of many a producer fans out, and it waits. A futex wake is never sync, so the waker's own ledger reads the fan-out: A non-sync wake of a thread of the waker's own process, from a waker whose last wakes went to other pids, waits too. Timer, IRQ and fork wakes always cut.

A wake that may not cut skips TIER 0 and takes an idle CPU through TIER 1 or the node-wide pick. With none idle it is seated at TIER 2 and waits in order behind the resident, which may be the work it serves, with one exception: A resident that has kept running through its last eight stops and has had its first target in this run serves no wake, so the wake walks its cache domain in R_eff order for such a resident and takes that seat by the cut (`nr_sleepless_cut` and `nr_sleepless_miss` count the walk's outcomes).

A cut never preempts its own wakee. When the seat reschedules before the cut's kick lands, the kick zeroes the wakee's own slice; a requeue within 50us of a cut, on the CPU it was cut onto, returns to that CPU's local head with its slice and no new kick.

A requeue preempts only once its wait has passed one target plus its seat's nearest-peer penalty, paced per seat by the queue judge below.

**Pair ledger**: `same_waker_runs` counts consecutive wakes from one waker pid, and past `PAIR_OBS_MIN` (8) the task is a handoff partner. It is keyed on the waker's identity rather than a CPU, so the count does not decay when the pair migrates, and nobody qualifies at load time. The waker's side, `last_wakee_pid` and `same_wakee_runs`, counts a task's consecutive wakes of one pid: A 1:1 exchange climbs it, and a producer waking its workers in turn resets it on every wake, which the wakee's side cannot see because every worker reads the producer as its partner.

### Queue Clock

Each seat and each lane carries one cache line, `queue_clock`, holding arrivals, departures, the latest departure's sojourn, the last progress time and the judge's state. A task records which queue it is on, and `running()`, `quiescent()`, `exit_task()` and a re-insert record its departure. A queue is empty when arrivals equal departures, which no drain can erase.

- `queue_wait()` is the latest departure's sojourn plus the time since last progress. Queues are oldest-first, so the head arrived no earlier than the last task to leave and the sum bounds its wait. Every reader of a wait uses it: The steal, the aged-lane serve, the tick and the sweep.
- `seat_wait()` is a seat's full wait, its queue's wait plus what its resident has left of its slice, capped at `lag_cap_ns`. A CPU running one task with an empty queue is not a free seat, so admission, the spill and warm-stay read this one.
- `queue_act()` decides every action on a wait, acting once the wait passes a bound. At the paced sites, the requeue preempt, the tick's lane preempt and the sweep's act between ticks, each act schedules the next at pace / √acts while the wait stays above the bound, and the count resets when it falls below. That is CoDel's control law [5][6], with √ from a 65-entry integer table and the count capped at 64.

The sojourn is RFC 8289's metric [6]. `task_ctx.wait_since` is stamped on the first insert after a run, preserved across requeues and cleared in `running()`, which records `now − wait_since` as the queue's departure sojourn.

### Sojourn Selector

There is no weighted virtual time and no warp. `task_deadline()` returns `wait_since` and nothing else, so every DSQ is ordered oldest-first and the longest-waiting task is served first. A task passed over N times keeps its original claim, so a starving task rises on its own as the clock moves under a stationary base.

The latency bound is admission's, not the ordering's. Ten versions of ordering arithmetic (start tags, attained-service credits, back-dated warps) all measured null, because reordering a work-conserving queue does not change how much work completes.

### CoDel Target: A Damped Harmonic Oscillator

`codel_target_ns` is the bound every site above prices against, and it follows the damped harmonic oscillator equation:

```
ẍ + 2γẋ + ω₀²(x − c_eq) = F(t)
```

Damping is Butterworth-optimal (ζ ≈ 0.707) [12]: The flattest response available, at the cost of one bounded ~4.3% overshoot per adaptation, which probes the response boundary on each impulse instead of parking inside it.

**Feedback**: The impulse is the rescue count, every lane served after it waited past the target, by its own CPU or by a thief. A seat served late is not one: The rescue measures the backlog of work that already ran and was put back. Each tick on CPU 0 applies impulse, spring and damping, caps velocity and integrates. The target rests at `c_eq` when quiet, descends on rescue events and returns damped. Every timing constant scales from τ, so a topology change preserves the damping ratio.

**Equilibrium**: `c_eq` is a position inside the working band, set by the normalised spectral-gap deficit, how much worse the topology's bottleneck is than its typical connectivity, read from eigenvalues already computed at topology detect. A machine whose cuts are all alike gets the tightest tolerance; one with a genuine bottleneck gets a looser one. Because it is a position, it needs no clamp, and the spring pushes in both directions.

**Idle quiescence envelope**: An energy reservoir built from values the recompute already maintains drives the recompute cadence down as the oscillator contracts. Below a release threshold it recomputes every fourth tick; below a park threshold, a factor of two lower, it pins the target at its closed-form fixed point, freezes the velocity integrator and stops the arithmetic. A rescue event, the equilibrium moving or a 1024-tick heartbeat triggers a full recompute in the same tick, and a wake arriving into a parked controller unparks it from `runnable()` and kicks CPU 0, before any dispatch prices against the target, so every burst begins from the same controller state. `nr_osc_park` counts parks.

### Tick

- **Lane**: Once the CPU's own lane has waited past `codel_target_ns`, the CPU preempts its resident so `dispatch()`'s aged-lane step serves it, paced by the lane's judge to one preempt per bound. A CPU carrying a live handoff pair answers to `lag_cap_ns` instead, as the aged-lane step does: The pair keeps the CPU busy, and a kick at the target would cost it a tick and usually its CPU.
- **Coarse net**: `codel_thresh_ns` is checked on the CPU's own seat and on a rotating scan of four other CPUs per tick, which reaches CPUs whose own tick has stopped.
- **Per-CPU band**: The resident yields once its own seat's wait passes `codel_target_ns`, with no class exemption. Each CPU decides from its own queue clock, so there is no global token to race over.

sched_ext sits below the RT and deadline classes and is handed only `SCHED_NORMAL`, `SCHED_BATCH` and `SCHED_IDLE`, so a `SCHED_FIFO` or `SCHED_RR` thread never reaches these ops. Two `SCHED_FIFO` threads held against a live scheduler for 48 seconds produced zero arrivals across 49 samples.

### Starvation Bounds

Two bounds sit under the waterfall, both per CPU. The tick preempts a CPU's own resident once its lane or its seat has waited one live target. Beneath it `sweep_bound_preempt` forces a CPU back into `dispatch()` once either queue has waited past `lag_cap_ns`, `clamp(K_LAG_CAP × τ, 8ms, 80ms)`, ~13.3ms at the 12C reference, from any other CPU's dispatch, so the bound does not wait on the held CPU's own tick. A task displaced by a live handoff pair waits up to that bound and no longer.

### Topology and Distance

**Resistance affinity**: The CPU topology is modeled as a weighted electrical network, SMT and L2 siblings conducting strongly and cross-socket links weakly. The Laplacian pseudoinverse gives all-pairs migration costs through every path in the graph, and `R_eff(i,j)` is a true metric satisfying the triangle inequality [1]. R_eff is proportional to expected round-trip time for work between CPUs [2], so minimizing it between pipe partners minimizes cache-line transfer cost [1][3][4]. Up to 24 CPUs R_eff is first taken exactly, as the ratio of spanning 2-forests to spanning trees [21] by integer-preserving elimination [22], and from the pseudoinverse where the integers overflow. Per-CPU ranked peer lists, nearest cache rung first and R_eff inside a rung, are folded into a BPF map at detect, with sentinels marking unused slots so loops early-exit on small machines. The idle search spends its budget on online candidates, so hotplug never charges it for offline ranks.

**Cache domains** are cut from the cache graph, a min-conductance cut [19] along the Fiedler vector [20] of the weighted Laplacian built from the cache groups sysfs reports, so the same graph that draws the boundary gives every pair of CPUs a distance. The steal and the warm hold price a crossing; the placement spill and the sleepless walk stay inside a domain.

**Migration potential (Φ)**: R_eff ranks candidate CPUs; Φ prices a move against the queueing relief it buys. Rust folds the distance terms into per-peer tables at topology detect, and BPF reads them with one indexed lookup:

- `reff_frac` is R_eff's excess over the nearest pair as a Q16 fraction of the span: The nearest peer is 0 and the most distant 65536, and every peer is 0 when all pairs are equidistant, as on a 2-core part with one L3. Multiplied by `codel_target_ns`, it is the steal's distance price and warm-stay's hold, so an SMT sibling is relieved at the base cost and the farthest peer one target later.
- `reff_value` is R_eff scaled to τ against the most distant pair and capped at twice the CoDel equilibrium, about 1.1ms at the 12C reference. The requeue preempt adds its seat's nearest-peer value to the one target a requeue must have waited.
- `domain_phi` is the min-conductance cut price between a CPU and each ranked peer, read by the steal's pair hold.

Under all three sits `phi_base_cost_ns`, the cost of any move at all: 0.0005 τ within 5-100us, 6.7us at the 12C reference. It is the wait a queue's head must show before even an idle neighbour takes it, and the margin a spill's target must have to spare.

An idle cross-domain core is still taken freely; what Φ removes is the cheap cross-domain steal that thrashes L3 for marginal queueing gain.

### No Task Classifier

There is no task class and the dispatch key takes no class input. Slice, placement, admission and preemption each read a measured quantity in nanoseconds against the live CoDel target (service rendered, queue backlog, accrued wait), so the question at every site is what a task is owed rather than what it is. `PF_WQ_WORKER` is the one flag read, at two sites and neither an ordering or placement decision: It splits the L2 hit/miss counters into two reporting buckets, and it carries a 1.5× multiplier on the nice weight that widens the standing slice ceiling.

### Adaptive Control Loop

The Rust control plane derives every knob from a measurement rather than a search. A derived knob is correct on the tick it is computed; a learned one is correct several convergence windows later and only if the regime holds still that long.

| Sensor | Primitive | Drives | Because |
|---|---|---|---|
| **regime** | HVG mean degree, Bandt-Pompe entropy and the idle share | the base slice | Light 2ms, Mixed 1ms and Heavy 4ms, under the τ cap (0.15 τ within 0.5-8ms) and a 1ms cap at 4 CPUs or fewer. The BPF arm holds Mixed's |
| **depth** | mean depth of the domain's lanes | the slice of every CPU in that domain | A domain deeper than the machine's mean slices shorter, down to half, so it drains; a shallower one keeps the base slice, never longer, since a longer slice only lengthens the wait of the next arrival |
| **traffic shape** | Kim-Jo burstiness [13][14] of the domain's arrivals | the batch ceiling | Paced arrivals shorten the standing ceiling, up to half, since a long hold stands against work that is queued; bursty arrivals lengthen it by up to half, so a clump drains in fewer cuts |
| **persistence** | Veitch-Abry Hurst [15] of the domain's lane depth | the rescue threshold | A queue deep on a persistent domain will still be deep, so rescue sooner; a mean-reverting one waits longer. Centred on H = 0.5 |
| **tail** | the largest per-bucket mean wait of the last second | the rescue threshold | Where the tail reaches past the base threshold the domain is rescued sooner in proportion, down to half. It only lowers |
| **critical slowing** | rise of the queue clock's ranked lag-1 autocorrelation [16][17] | the rescue threshold | A domain that recovers more slowly than a tick ago is nearing a tail: Silent while the rise is noise, toward half as it reaches twice the one-sided 5% point. It only lowers |
| **queued wait** | mean wait of the domain's queued runs | the standing hold | A domain whose queued runs wait past the CoDel equilibrium lets a standing task hold the CPU for fewer targets, from four down to two. It never lengthens |
| **coupling** | Pecora-Carroll [18], pairwise | nothing | Deriving affinity from it regressed every IPC primitive on every arm, worst pipe p50 20 → 336us |

The rescue threshold written is the least of persistence's, the tail's and critical slowing's.

- **One thread, zero mutexes**: A 1-second loop on the main thread reads the per-CPU BPF stats array and depth ring and writes knobs BPF picks up on the next scheduling decision. Relating CPU *i* to CPU *j* is what BPF structurally cannot do, so the spatial dimension is the reason the loop exists.
- **Depth ring**: Each CPU's tick adds the depth of its seat, its lane and its local DSQ into a per-CPU ring of 512 slots, one slot per bucket of a shared time grid, and `running()` adds each run it starts: Whether it ended a wake, the queue wait it ended and the shortest wait of the bucket. A bucket is a quarter of the oscillator's damped period, π·2^damp ticks (6.28ms at the 12C reference), so the sensors sample four times per oscillation of the controller they defer to. The loop drains every finished bucket into windows that span 1.608s at every width, 64 to 256 samples.
- **Chaos primitives** (`chaos.rs`, pure Rust, raw windows, no EWMA): HVG mean degree λ [10] reads the idle-hit share of each bucket's runs and Bandt–Pompe D=3 permutation entropy [9] its wakes, one machine-wide sample per bucket, and with the mean idle share they set the regime. RQA determinism [11] reads the newest 64 buckets of the same share and corroborates the quiescence freeze. Burstiness reads each domain's arrivals per bucket and Hurst its lane depth, each priced by how full its window is.
- **Live load graph**: Nodes are CPUs weighted by their queue clock, the Fano burstiness and Fano-slope Hurst [24] of their arrivals, critical slowing and persistence; edges are CPU pairs weighted by priced coupling, n pairs recomputed a tick in rotation. The knobs derive per cache domain, from its CPUs' pooled series, and are written per CPU.
- **Flow between CPUs**: `running()` counts where each run came from, a wake from its waker's CPU and a migration from the task's previous one. The loop reads each tick's deltas as two directed graphs: The share crossing a domain, how closely the flow's own Fiedler cut follows the domains, the share the busiest tenth of pairs carries and the change from the tick before. Telemetry, like coupling.
- **Write on evidence**: A derived slice, batch ceiling or rescue threshold is written only when it has moved from the value last written by more than twice its own spread over its last 16 derivations. While the BPF oscillator's release point sits below rest it is already correcting the pressure, so the rescue threshold alone holds its written value; slice and batch write through. Every set passes through one clamp, so the map holds what BPF applies.
- **One controller on the rescue signal**: The oscillator owns `global_rescue_count` and nothing else adapts on it.
- **Quiescence freeze**: The loop latches frozen and skips the retune only when no depth sample in the last second, seat, lane or local DSQ, held a waiting task, and the pattern lenses that have a reading sit in their steady band. Zero is the boundary, so a saturated box never freezes and an idle one can.
- **Measured and not applied**: The refill a cross-L3 wake costs a task, read by pairing each task with itself, and each domain's starvation share, the fraction of its buckets whose shortest wait stayed above the CoDel equilibrium, are derived and reported every tick. The base cost stays τ's and the share qualifies nothing until each is scored.

### Core-Count Scaling

All timing constants scale from `tau_ns = TAU_SCALE_NS / √(λ₂ · N)` [7], the geometric mean of connectivity `1/λ₂` and capacity `1/√N`, so a well-connected but core-starved topology loosens instead of tightening. The 12C reference is τ ≈ 13.3ms (λ₂ = 12, N = 12). The CoDel floor, ceiling and equilibrium, the starvation bound, the base cost of a move and the spill and idle-search budgets all fall out of τ with safety-rail clamps, so a machine with a different topology gets different numbers by construction. The tick's four-CPU scan budget is the one count, taken from `nr_cpu_ids` directly.

- **Low-core slice discipline**: τ is largest at low core count, so the τ slice cap runs loosest exactly where a wide slice hurts most. The slice is capped to 1ms at `nr_cpus ≤ 4`; 8C and 12C keep the τ-scaled width.
- **CPU hotplug**: `cpu_online` and `cpu_offline` clear the τ snapshot and `cpu_offline` resets the oscillator's feedback, so the next tick re-derives every τ-scaled constant from the τ Rust writes for the new topology.
- **Verifier-safe**: No floats in the BPF path, integer-only arithmetic throughout, and shared state through GCC `__sync` builtins.

## Architecture

```
pandemonium.py           Build/install/benchmark manager (Python)
pandemonium_common.py    Shared infrastructure (logging, build, CPU management,
                           scheduler detection, tracefs, statistics)
export_scx.py            Automated import into sched-ext/scx monorepo
src/
  main.rs              Entry point, CLI, scheduler loop, telemetry
  lib.rs               Library root
  scheduler.rs         BPF skeleton lifecycle, tuning knobs I/O, histogram reads
  adaptive.rs          Adaptive control loop (monitor thread, per-CPU stats array,
                         live load graph, flow graphs, derived knobs, quiescence
                         freeze)
  chaos.rs             Chaos primitives on raw windows, no EWMA: HVG mean degree,
                         Bandt-Pompe D=3 permutation entropy, RQA determinism,
                         Kim-Jo and Fano burstiness, Veitch-Abry and Fano-slope
                         Hurst, ranked lag-1, Pecora-Carroll coupling
  tuning.rs            Knob types, the base profile the derivations move from,
                         the regime's slice, tau-scaled caps, the applied clamp,
                         quiescence + adaptive-rarity retune
  topology.rs          CPU topology detection, Laplacian pseudoinverse, effective
                         resistance, ranked peer lists, distance tables (sysfs -> BPF maps)
  event.rs             Pre-allocated ring buffer for stats time series
  watchdog.rs          Control-loop stall detector (10s heartbeat, abort on miss)
  bpf_intf.rs          Mirror of intf.h constants (MAX_CPUS, MAX_AFFINITY_CANDIDATES,
                         the base cost's rail), read against the header by a test
  bpf_skel.rs          libbpf-cargo-generated BPF skeleton bindings
  log.rs               Logging macros
  bpf/
    main.bpf.c         BPF scheduler
    intf.h             Shared structs: tuning_knobs, pandemonium_stats
build.rs               vmlinux.h generation + BPF compilation; keeps main.bpf.o
                         beside the skeleton
tests/
  pandemonium-tests.py Dev-tier orchestrator (scale and its cells, contention,
                         pcpu, scx, coldwake, sys)
  prism.py             One-command shareable report (montauk digest, redacted --
                         specs + ranked offenders + metrics) and the dev tier's
                         entry point
  prism-fork-thread.py Fork/thread IPC benchmark + system-wide hw counters
  prism-frame.py       Frame pacing under a synthetic game (framebench.c)
  prism-power.py       Energy-efficiency benchmark (package J/op, idle floor,
                         paced frames)
  prism-helicoprion.py Piotr Gorski's helicoprion, run from its installed
                         package under each arm
  prism-plot.py        Plot rendering for captured runs
  ipc_workload.py      Shared IPC primitive drivers
  probe.c              Wakeup latency probe
  loadgen.c            Load generator (+ loadgen_common.[ch])
  vm-matrix/           Kernel-by-scheduler matrix in QEMU guests (veristat,
                         attach, load phases, detach)
  *_gate.py            Non-compensatory regression gates (report, baseline,
                         quiescent tail, fold, install, power, fork-thread, field,
                         helicoprion)
  gate.rs              Integration test gate (load/latency/responsiveness/contention)
include/
  scx/                 Vendored sched_ext headers
```

### Data Flow

```
BPF per-CPU histograms              Monitor Thread (1s loop)
(wake_lat_hist, sleep_hist)  --->   Read + drain histograms
                                    Compute aggregate P99
                                      |
                                      v
                                    per-CPU stats array + depth ring
                                      -> quiescence freeze (occupancy)
                                      -> live load graph
                                      -> regime -> base profile
                                      -> derive each knob from its domain's
                                         series (lane depth -> slice,
                                         arrivals -> batch,
                                         persistence, tail, slowing -> rescue,
                                         queued wait -> standing hold)
                                      -> write what moved past its own spread;
                                         the rescue threshold holds while the
                                         oscillator corrects
                                      |
                                      v
                                    BPF reads knobs on next dispatch

Distance tables:  reff_value, reff_frac, domain_phi -> BPF steal, warm hold,
                  requeue preempt
Placement:        affinity_rank (rung, then R_eff) -> the seat ladder in
                  select_cpu and enqueue (BPF-internal, no Rust input)
Sojourn scan:     codel_thresh_ns knob -> BPF tick() own CPU + rotating scan
CoDel target:     codel_target_ns (BPF-internal, damped oscillation, no Rust input)
Queue clocks:     queue_clock per DSQ (BPF-internal, written at insert and departure)
Cross-domain:     nr_cross_domain path counters -> telemetry (no actuation)
```

One thread, zero mutexes. BPF produces histograms and the depth ring, Rust reads them once per second. Rust writes knobs, BPF reads them on the next scheduling decision. The CoDel target and the queue clocks are fully BPF-internal.

### Tuning Knobs (BPF map)

| Knob | Default | Owner | Purpose |
|------|---------|-------|---------|
| `slice_ns` | 1ms | Derived (regime, lane depth) | Base slice, every task that is not standing |
| `batch_slice_ns` | 20ms | Derived (traffic shape) | Standing slice ceiling, the grant for a task that has already held a CPU for a full target on each of its last two runs |
| `standing_targets` | 4 | Derived (queued wait) | Live CoDel targets a standing task may hold the CPU for, the other bound on that grant |
| `codel_thresh_ns` | 5ms | Derived (persistence, tail, critical slowing) | Age at which `tick()` kicks a CPU holding an aged waiter |
| `waker_leave_ns` | 0 | Adaptive arm (25us) | A waker that blocks this soon after each of its wakes seats its partner as a sync waker does. 0 turns the seat off, as on the BPF arm |
| `phi_base_ns` | 0 | Measured, not applied | The base cost of a move as the layer measures it. 0 leaves τ's cost standing |
| `topology_tau_ns` | 0 | Topology | Fiedler-derived time constant, capacity-aware in core count; every other bound scales from it |
| `codel_eq_ns` | 0 | Topology | Spectral CoDel equilibrium, a position inside the target band |

The distance scale is not a knob. Rust folds it into the distance tables at topology detect, so BPF reads a price by index instead of multiplying at dispatch. Topology-owned fields are written at detect and on hotplug, and the adaptive loop preserves them on every write. The knob map is per-CPU, so `topology_tau_ns` and `codel_eq_ns` must hold the same value on every CPU, and the Rust writer broadcasts them from slot 0.

## Requirements

- Linux kernel 6.12+ with `CONFIG_SCHED_CLASS_EXT=y`
- Rust toolchain
- clang (BPF compilation)
- system libbpf
- bpftool (first build only — generates vmlinux.h, can be uninstalled after)
- Root privileges (`CAP_SYS_ADMIN`)

```bash
# Arch Linux
pacman -S clang libbpf bpf rust
```

## Build & Install

```bash
# Build manager (recommended)
./pandemonium.py rebuild        # Force clean rebuild
./pandemonium.py install        # Build + install to /usr/local/bin + systemd service file
./pandemonium.py status         # Show build/install status
./pandemonium.py clean          # Wipe build artifacts

# Manual
CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build cargo build --release
```

vmlinux.h is generated from the running kernel's BTF via bpftool on first build and cached at `~/.cache/pandemonium/vmlinux.h`. The cargo target tree lives at `~/.cache/pandemonium-build` (alongside the log and vmlinux caches under `~/.cache/pandemonium`), so all per-user pandemonium state sits in one place. The `CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build` override is also what lets the vendored libbpf Makefile build cleanly when the source tree path contains spaces.

After install:

```bash
sudo systemctl start pandemonium          # Start now
sudo systemctl enable pandemonium         # Start on boot
```

## Usage

```bash
sudo scx_pandemonium                  # Default: adaptive mode
sudo scx_pandemonium --no-adaptive    # BPF-only (no Rust control loop)
sudo scx_pandemonium -v               # Verbose telemetry on stdout
```

There is no compositor allowlist, no learned name database and no behavioural tier to
earn — there is no task class at all. Every site that once asked what a task *is* now
asks what it is *owed*, in nanoseconds, against the live CoDel target. Every session,
from cold, with nothing remembered.

### Monitoring

Per-second telemetry:

```
BPF-only (--no-adaptive):
d/s: 1291 idle: 55% shared: 389 preempt: 6 keep: 12 kick: H=133 S=163 enq: W=289 R=100 wake: 26us lat_idle: 4us lat_kick: 91us reenq: 0 l2: B=88% I=63% [BPF]

Adaptive (default) adds the control loop's own readings:
... wake: 16us p99: 250us [B:250 I:25 L:0] ... sleep: io=51% slice: 1843us batch: 24906us reenq: 0 sjrn: 1ms rescue: 6735 l2: B=61% I=0% chaos: lam=1.99 H=0.99 det=1.00 x=5 frozen: 0 (n=5) retune_iv: 8 [HEAVY] graph: n=12 e=66 cpl=0.12/0.00/0.55 osc: 0.00/469us
```

| Counter | Meaning |
|---------|---------|
| d/s | Total dispatches per second |
| idle | select_cpu idle fast path (%) |
| shared | Enqueue seats, every tier |
| preempt | Tick preemptions |
| keep | KEEP_RUNNING re-slices |
| kick H/S | Hard (PREEMPT) / Soft kicks |
| enq W/R | Wakeup / Re-enqueue counts |
| wake / p99 | Average / aggregate P99 wakeup latency |
| [B/I/L] | Wakeup-latency P99 split by the `PF_WQ_WORKER` reporting bucket. `L` is a retired third lane and reads 0 always, since nothing writes it |
| lat_idle / lat_kick | Wakeup latency split: idle-placement vs kick path |
| sleep: io | I/O-wait sleep pattern (%) |
| slice / batch | Current base / standing slice knob (us) |
| reenq | Re-enqueue count |
| sjrn | The rescue threshold as written, `codel_thresh_ns`, in whole ms |
| rescue | Lanes served past the target this second, the oscillator's impulse |
| l2: B/I | L2 cache hit rate, same two reporting buckets |
| chaos: lam/H/det/x | HVG mean degree λ / Bandt-Pompe entropy / RQA determinism, -1 while its window is under 64 samples / chaos-crossing counter |
| frozen (n) | Quiescence freeze active (1/0) and cumulative frozen ticks; it latches only when nothing was queued |
| retune_iv | Adaptive-rarity retune interval (ticks between retunes) |
| [REGIME] | The regime the lenses read, LIGHT, MIXED or HEAVY; `[BPF]` on the BPF arm |
| graph: n/e/cpl | Live load graph: CPUs, pairs whose coupling computed, then mean / min / max coupling |
| osc | The oscillator's position in its band, 0 at the floor and 1 at the ceiling, and the wait at which a home releases its task (us) |

At exit the adaptive arm prints one `[KNOBS]` line, the run's regime ticks, steal, spill and sleepless-cut counts and the last slice and batch written, and a `[GRAPH]` line naming the .prom it wrote the run's graph readings to. `SIGUSR1` cuts a phase: The next tick prints the regime ticks since the last cut as a `[PHASE]` line.

## Benchmarking

One entry point. Bare `prism` is the end-user report; `--dev <name>` runs the sustained
validations behind it.

```bash
./pandemonium.py prism                   # One-command shareable report (specs + ranked misbehaving items + metrics)
./pandemonium.py prism --list            # List every workload (default profile + dev tier)
./pandemonium.py prism --schedulers scx_rusty,scx_lavd  # Compare EEVDF against the named scx schedulers (add 'pandemonium' to the list to include the PANDEMONIUM arms)
./pandemonium.py prism --all-scx         # Add the full installed scx field instead (mutually exclusive with --schedulers)
./pandemonium.py prism --workload "ffmpeg -i in.mkv out.mp4"   # Trace YOUR isolated workload instead of the fixed profile
./pandemonium.py prism --attach chrome --duration 30           # Trace an already-running program for 30s
./pandemonium.py prism-sys               # Live system telemetry capture (Ctrl+C to stop)
```

The dev tier — one or more names, or `all` for the full sweep:

```bash
./pandemonium.py prism --dev scale                    # Width sweep: throughput, latency, burst, longrun, mixed, deadline, IPC, launch
./pandemonium.py prism --dev ipc                      # IPC round-trip by primitive (pipe, socket, eventfd, sem, fanout)
./pandemonium.py prism --dev fork-thread              # Fork/thread IPC + hardware counters + regression gate
./pandemonium.py prism --dev power                    # Energy efficiency (package J/op, idle floor, paced frames)
./pandemonium.py prism --dev pcpu                     # Per-CPU DSQ correctness (4 tests)
./pandemonium.py prism --dev contention               # Contention stress (6 phases)
./pandemonium.py prism --dev frame                    # Frame pacing under a synthetic game
./pandemonium.py prism --dev scx                      # sched-ext/scx CI compatibility: Each sched_ext arm held with no workload, then under stress-ng
./pandemonium.py prism --dev helicoprion              # Piotr Gorski's helicoprion, from its installed package, under each arm
./pandemonium.py prism --dev scale --trace -- --cells latency,longrun,mixed   # The latency probe under each load, one recorded draw ahead of the timed ones
./pandemonium.py prism --dev scale ipc power          # Several in one run
./pandemonium.py prism --dev all                      # The full sweep
```

Every dev workload takes the same flags and runs any scheduler they name:

```bash
--trace               # Record montauk captures; nothing traces without it
--iterations N        # Run every arm N times, with one report over all N
--pandemonium-only    # PANDEMONIUM's two arms and nothing else
--adaptive-only       # The adaptive arm alone
--bpf-only            # The BPF arm (--no-adaptive) alone
--schedulers LIST     # Run EEVDF against exactly LIST; PANDEMONIUM runs only if named
--all-scx             # Add every installed production scx scheduler
--only LIST           # Exactly LIST, EEVDF only if named
--arm NAME=COMMAND    # Field a scheduler by its binary under the label NAME
--cores LIST          # Core widths, swept by the workload or made by prism around it
--disturb SPEC        # Take a CPU offline under each live arm, as in offline:11@3+12
```

`--dev helicoprion` runs [helicoprion](https://github.com/Seafoam-Labs/helicoprion),
Piotr Gorski's scheduler benchmark, and carries none of it: PRISM loads each arm, the
installed program measures under it, and its result file becomes rows in PRISM's
report. Where helicoprion is missing, or its package is behind the one the box can
get, PRISM asks before installing it: Through Shelly or pacman where a repository
carries the package, otherwise by building Devario's own PKGBUILD with makepkg.

`--dev scale` sweeps core counts via CPU hotplug (2, 4, 8, ..., max), and `--cores`
narrows it. In the end-user profile the width-specific faults run at native width
unless `--ultra` is given. Reports and `.prom` archive to
`~/.cache/pandemonium/`; montauk captures land in `/tmp/pandemonium/`. A run that
captures self-elevates, so invoke it without `sudo`.

`prism` is the one command a user runs to send a report. It runs a short
fixed profile — a fork/exec storm, an IPC round-trip and capped (20s)
burst-starvation and contention captures — under
your scheduler and EEVDF as a neutral reference, traces each with montauk, and
assembles one small, redacted file: Your system specs, the misbehaving items
ranked by name (hot CPUs, livelocking tasks, unsignaled waiters, idle strands),
a thermal/power block, then the key wake-to-run metrics. Process names are
hashed and the raw traces stay local — you share only the report. montauk is the
only data source; the script orchestrates and assembles, nothing more.

If montauk isn't installed, prism clones it from its repo and drives
montauk's own installer: Two prompts up front decide whether it installs montauk
permanently (capped so `--trace` needs no sudo) or builds it just for the run and
removes it after. It self-elevates for the trace, ejects any scheduler it loaded
if you Ctrl+C, and when a build dependency is missing it prints the exact install
command for your distro (CachyOS, Arch, Gentoo, OpenSUSE, Ubuntu, NixOS). Share
the resulting `prism-report-*.txt`.

If you have already isolated the problem to one program, skip the fixed profile
and capture that program directly: `--workload "<command>"` launches your
command under the loaded scheduler and traces it until it exits (or `--duration`
seconds), while `--attach <comm> --duration <s>` traces an already-running
program by name. Same report, same redaction — captured on your real workload
rather than the synthetic profile.

## Testing

```bash
CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build cargo test --release   # Unit tests (no root)
sudo CARGO_TARGET_DIR=$HOME/.cache/pandemonium-build \
     cargo test --release --test gate -- --ignored \
     --test-threads=1 full_gate                                 # Integration gate (requires root)
```

13 unit tests in `src/` hold the pure-Rust logic: The raw window's order through
wrap and span, the coupling rotation, ranked lag-1, the flow deltas and the flow's
cut, the refill pairing, the base cost's rail, the applied clamp, the mirrors of
`intf.h` and the affinity rank's rung order. The integration gate at
`tests/gate.rs` carries 5 more, `full_gate` plus the load/classify, latency,
responsiveness and contention layers (all `#[ignore]`, root-only). The Python
gates, `tests/*_gate.py`, check the harness's reducers, reports and field rules
with no root, scheduler or workload.

## sched-ext/scx Integration

PANDEMONIUM is included in the sched-ext/scx monorepo. `export_scx.py` automates the import:

```bash
./export_scx.py /path/to/scx
```

Copies source into `scheds/rust/scx_pandemonium/`, renames the crate, replaces `build.rs` with `scx_cargo::BpfBuilder`, swaps `libbpf-cargo` for `scx_cargo`, registers the workspace member and runs `cargo fmt`.

scxcli and scxtui start schedulers from scx's scheduler catalog
(`services/catalog.json`, version 2), and scx_pandemonium is listed there:
`scxcli start scx_pandemonium` runs the adaptive arm. The BPF arm needs an
option, and a profile with options comes only from an administrator's
`/etc/scx/catalog.json`, never the shipped catalog. Its profile is in
`catalog/profiles.json`, which ships in the scx crate too. To add it:

```bash
scxcli catalog show > catalog.json
# append the entry from catalog/profiles.json to "recommended"
sudo scxcli catalog save < catalog.json
scxcli start pandemonium-bpf      # scx_pandemonium --no-adaptive
sudo scxcli catalog reset         # back to scx's shipped catalog
```

The override replaces the shipped catalog whole and stops following scx's
updates to it until it is reset. `./pandemonium.py install` offers to add the
profile when scxcli and scx's scx_pandemonium are both installed, and
`export_scx.py` ships it with the crate and stops if scx's catalog no longer
lists scx_pandemonium as featured or stable.

## Attribution

- `include/scx/*` headers from the [sched_ext](https://github.com/sched-ext/scx) project (GPL-2.0)
- vmlinux.h generated from the running kernel's BTF
- Included in the [sched-ext/scx](https://github.com/sched-ext/scx) project

## References

[1] D.J. Klein, M. Randic. "Resistance Distance." *Journal of Mathematical Chemistry* 12, 81-95, 1993. [doi:10.1007/BF01164627](https://link.springer.com/article/10.1007/BF01164627)

[2] A.K. Chandra, P. Raghavan, W.L. Ruzzo, R. Smolensky, P. Tiwari. "The Electrical Resistance of a Graph Captures its Commute and Cover Times." *STOC 1989*, 574-586. Journal version: *Computational Complexity* 6(4), 312-340, 1996. [doi:10.1007/BF01270385](https://link.springer.com/article/10.1007/BF01270385)

[3] P. Christiano, J.A. Kelner, A. Madry, D.A. Spielman, S.-H. Teng. "Electrical Flows, Laplacian Systems, and Faster Approximation of Maximum Flow in Undirected Graphs." *STOC 2011*, 273-282. [arXiv:1010.2921](https://arxiv.org/abs/1010.2921)

[4] L. Chen, R. Kyng, Y.P. Liu, R. Peng, M.P. Gutenberg, S. Sachdeva. "Maximum Flow and Minimum-Cost Flow in Almost-Linear Time." *FOCS 2022*. Journal version: *Journal of the ACM* 72(3), 2025. [arXiv:2203.00671](https://arxiv.org/abs/2203.00671)

[5] K. Nichols, V. Jacobson. "Controlling Queue Delay." *ACM Queue* 10(5), 20-34, 2012. [doi:10.1145/2208917.2209336](https://doi.org/10.1145/2208917.2209336)

[6] K. Nichols, V. Jacobson. "Controlled Delay Active Queue Management." *RFC 8289*, January 2018. [rfc-editor.org/rfc/rfc8289](https://www.rfc-editor.org/rfc/rfc8289.html)

[7] M. Fiedler. "Algebraic Connectivity of Graphs." *Czechoslovak Mathematical Journal* 23(2), 298-305, 1973. [doi:10.21136/CMJ.1973.101168](https://dml.cz/dmlcz/101168)

[8] R.D. Blumofe, C.E. Leiserson. "Scheduling Multithreaded Computations by Work Stealing." *Journal of the ACM* 46(5), 720-748, 1999. [doi:10.1145/324133.324234](https://dl.acm.org/doi/10.1145/324133.324234)

[9] C. Bandt, B. Pompe. "Permutation Entropy: A Natural Complexity Measure for Time Series." *Physical Review Letters* 88(17), 174102, 2002. [doi:10.1103/PhysRevLett.88.174102](https://doi.org/10.1103/PhysRevLett.88.174102)

[10] B. Luque, L. Lacasa, F. Ballesteros, J. Luque. "Horizontal Visibility Graphs: Exact Results for Random Time Series." *Physical Review E* 80(4), 046103, 2009. [doi:10.1103/PhysRevE.80.046103](https://doi.org/10.1103/PhysRevE.80.046103)

[11] N. Marwan, M.C. Romano, M. Thiel, J. Kurths. "Recurrence Plots for the Analysis of Complex Systems." *Physics Reports* 438(5-6), 237-329, 2007. [doi:10.1016/j.physrep.2006.11.001](https://doi.org/10.1016/j.physrep.2006.11.001)

[12] S. Butterworth. "On the Theory of Filter Amplifiers." *Experimental Wireless and the Wireless Engineer* 7, 536-541, October 1930. [worldradiohistory.com, the issue's scan](https://worldradiohistory.com/UK/Experimental-Wireless/30s/Wireless-Engineer-1930-10.pdf)

[13] K.-I. Goh, A.-L. Barabási. "Burstiness and Memory in Complex Systems." *EPL (Europhysics Letters)* 81(4), 48002, 2008. [doi:10.1209/0295-5075/81/48002](https://doi.org/10.1209/0295-5075/81/48002)

[14] E.-K. Kim, H.-H. Jo. "Measuring Burstiness for Finite Event Sequences." *Physical Review E* 94(3), 032311, 2016. [doi:10.1103/PhysRevE.94.032311](https://doi.org/10.1103/PhysRevE.94.032311)

[15] D. Veitch, P. Abry. "A Wavelet-Based Joint Estimator of the Parameters of Long-Range Dependence." *IEEE Transactions on Information Theory* 45(3), 878-897, 1999. [doi:10.1109/18.761330](https://doi.org/10.1109/18.761330)

[16] M. Scheffer, J. Bascompte, W.A. Brock, V. Brovkin, S.R. Carpenter, V. Dakos, H. Held, E.H. van Nes, M. Rietkerk, G. Sugihara. "Early-Warning Signals for Critical Transitions." *Nature* 461(7260), 53-59, 2009. [doi:10.1038/nature08227](https://doi.org/10.1038/nature08227)

[17] C. Boettiger, A. Hastings. "Quantifying Limits to Detection of Early Warning for Critical Transitions." *Journal of the Royal Society Interface* 9(75), 2527-2539, 2012. [doi:10.1098/rsif.2012.0125](https://doi.org/10.1098/rsif.2012.0125)

[18] L.M. Pecora, T.L. Carroll, J.F. Heagy. "Statistics for Mathematical Properties of Maps Between Time Series Embeddings." *Physical Review E* 52(4), 3420-3439, 1995. [doi:10.1103/PhysRevE.52.3420](https://doi.org/10.1103/PhysRevE.52.3420)

[19] J. Cheeger. "A Lower Bound for the Smallest Eigenvalue of the Laplacian." In R.C. Gunning (ed.), *Problems in Analysis: A Symposium in Honor of Salomon Bochner*, Princeton University Press, 195-199, 1970. [doi:10.1515/9781400869312-013](https://doi.org/10.1515/9781400869312-013)

[20] M. Fiedler. "A Property of Eigenvectors of Nonnegative Symmetric Matrices and Its Application to Graph Theory." *Czechoslovak Mathematical Journal* 25(4), 619-633, 1975. [doi:10.21136/CMJ.1975.101357](https://dml.cz/dmlcz/101357)

[21] W. Barrett, E.J. Evans, A.E. Francis, M. Kempton, J. Sinkovic. "Spanning 2-Forests and Resistance Distance in 2-Connected Graphs." *Discrete Applied Mathematics* 284, 341-352, 2020. [doi:10.1016/j.dam.2020.03.061](https://doi.org/10.1016/j.dam.2020.03.061), [arXiv:1901.00053](https://arxiv.org/abs/1901.00053)

[22] E.H. Bareiss. "Sylvester's Identity and Multistep Integer-Preserving Gaussian Elimination." *Mathematics of Computation* 22(103), 565-578, 1968. [doi:10.1090/S0025-5718-1968-0226829-0](https://doi.org/10.1090/S0025-5718-1968-0226829-0)

[23] E.D. Sontag. "A Concept of Antifragility for Dynamical Systems." arXiv preprint, 2024. [arXiv:2410.17953](https://arxiv.org/abs/2410.17953)

[24] S.B. Lowen, M.C. Teich. *Fractal-Based Point Processes.* Wiley, 2005. [doi:10.1002/0471754722](https://doi.org/10.1002/0471754722)

## License

GPL-2.0-only. Copyright (c) 2026 Will Clingan.
