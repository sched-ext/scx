# scx_cake — Design

`scx_cake` is a `sched_ext` scheduler distilled to one master algorithm built
entirely on kernel primitives. It is a clean-slate rewrite (2026-07): the
previous codebase had grown to ~12.6k lines in a single BPF file gated by
hundreds of `CAKE_*` feature flags, to the point where debug and release
compiled to *different schedulers* and a known, understood fix could no longer
be placed. The rewrite trades that surface for a design small enough to hold
in your head — one BPF file, eight callbacks in the release build — and defends
that smallness with hard invariants. The file has grown back to ~1.75k lines
since the rewrite (roughly half comments recording why each rule exists, plus
the default-off research surface described in invariant 1); the release
decision path is a fraction of that.

Kernel-validated against Linux **7.1.x** (`kernel/sched/ext/{ext,idle}.c`,
`internal.h`). Every mechanism below carries a measured, noise-gated A/B
receipt; the falsification chain for everything that did NOT survive lives in
[`EEVDF_GATE_2026-07-04.md`](./EEVDF_GATE_2026-07-04.md) and `docs/`.

> **Exact-state note (2026-07-13):** this document records the accepted
> clean-slate/Golden design, not every compile-time research surface currently
> present in the dirty campaign tree. The current tree contains default-off
> M-DBLS/topology/peek experiments and the unpromoted SCHED_IDLE plus ordered
> direct-admission candidates. Bind any claim to the complete source snapshots
> under
> `.scx_cake_bench/candidates/full_surface_master_20260713/`; do not infer an
> exact binary from this narrative alone.

## Design invariants

1. **One shipped behavior; no runtime knobs.** Exactly one `SCX_OPS_DEFINE`,
   no loader policy options, no mutable runtime policy config, nothing a user
   can tune. One immutable loader-filled array describes real SMT siblings; it
   is machine topology, not scheduler policy.
   *Qualified as of 2026-07-13:* `intf.h` does carry a **compile-time research
   surface** (`CAKE_MDBLS_*`, `CAKE_QMARK_MODE`, `CAKE_IRQ_SHADOW_MODE`,
   `CAKE_SCALAR_PEEK`, `CAKE_DIRECT_SLICE_STORE`, the policy divisors), and
   `cake.bpf.c` is threaded with the matching `#if`. Every one of them is
   **off/at-default in the release build**, and the campaign rule is that a
   mutation is A/B'd as *two git commits*, never by flipping a cflag — the BPF
   object cache makes cflag-only toggles silently unreliable. The invariant the
   project actually holds is therefore: one *default* behavior, one build per
   commit, and a research surface that must never be live in a scored arm.
2. **One master algorithm per hot path.** Each `ops` callback is a single
   coherent decision, not a dispatch into competing subsystems.
3. **No division, no cold paths, no rescue buckets.** Reciprocal-weight table
   plus shifts and masks; every starvation concern is sealed by an ordering
   rule at the source, never by a catcher that sweeps up strays later.
4. **Cake keeps no state of its own.** No per-task storage in the release
   build, no cake-maintained history, no EWMAs, no timers. Adaptive behavior
   comes from *classifying current scheduling state* (vtime depth against the
   frontier, queue emptiness, curr's on-CPU age, backlog presence) — the same
   signal class EEVDF itself reads. Where a needed distinction is invisible
   to stateless inspection (worker-vs-handoff among deep sleepers), cake
   marks its own actions (per-CPU one-shot marks set beside kicks) rather
   than tracking tasks.
   *Precise as of S1 (2026-07-19):* cake may **read counters the kernel
   already maintains** on `task_struct` — `se.sum_exec_runtime`, `nvcsw`,
   `static_prio`, `policy`, `nr_cpus_allowed`, `flags`. `cake_cadence_depth()`
   derives a mean-burst estimate from the first two. That is task history in
   the informational sense, but it costs no map, no allocation, and no write:
   the invariant is about cake owning no storage, not about refusing signal
   the kernel publishes for free.
5. **Route by system state, not by force.** In every measured regime, added
   preempts, forced convergence, or steal-order surgery lost to minimal
   routing gates keyed on system state (seven falsifications at
   oversubscription alone). The design prefers changing *where a task waits*
   over changing *who runs now*.

## Topology

Created at `init`: one custom vtime DSQ **per possible CPU** (`dsq_id ==
cpu`), one global wake queue (`WAKE_DSQ`), one global overflow queue
(`OVF_DSQ`). All mutable shared state is a single BSS struct of
128-byte-stride slots (no false sharing, no hot-path atomics): per-CPU
run-start stamp, per-CPU `sum_exec_runtime` snapshot, the vtime frontier,
`ncpu`, and three families of one-shot hint bytes (`qmark` "queue may hold
work", `pmark` "curr was preempt-kicked", owner-cleared, benign one-shot
races). The five `SCX_*` enum values used are rebound to CO-RE load-time
immediates instead of rodata loads.

## The algorithm

**Core routing law: wakeups queue globally, continuations queue locally** —
a woken task must be findable by the FIRST CPU that blocks anywhere (pinning
wakes per-CPU collapsed futex handoffs 20–50×), while a slice-expired task
wants exactly its home CPU's queue for L1/L2 warmth (inserted under that
CPU's already-held rq lock). Everything else below is a measured refinement
of that law's edges.

### select_cpu — placement, one kfunc

`scx_bpf_select_cpu_dfl()` walks idle full core → idle SMT sibling (with
prev-CPU warmth, `WAKE_SYNC`, LLC locality); an idle hit direct-dispatches to
the local DSQ. Then, in order:

- **Sync parallelism escape**: dfl's kfunc reports `is_idle=true` for ANY
  successful pick — including its `WAKE_SYNC` waker-affinity return, which is
  the waker's still-BUSY CPU (it only requires idle capacity to exist
  somewhere). Blindly direct-dispatching there is a one-way door into
  co-location for buffered streams: the wakee's prev aliases the waker's CPU
  forever after and every message pays a context-switch round trip. Measured
  2026-07-10: pipe welded 196K ops/s at 5.09 µs/op vs native's split-parallel
  1.28M at 0.78 µs/op. When the "idle" sync pick equals the callback CPU,
  redirect to a genuinely idle CPU (`pick_idle`) before direct-dispatching. A
  genuinely serial handoff converges back on the next wake; under real
  saturation `pick_idle` fails and the wakee queues behind the about-to-sleep
  waker — the EEVDF serial-handoff shape. Futex and schbench wakes carry no
  `WAKE_SYNC`.

Under saturation two carve-outs run before giving up on placement:

- **Sync handoff** (`WAKE_SYNC`, callback/handoff CPU's local and vtime queues
  both empty): return that CPU and let enqueue perform the ordinary vtime
  insert. This gains the saturated handoff shape without a forced `LOCAL_ON`
  preempt that would bypass Cake's eligibility law.
- **Plain-wake convergence** (the wakee's raw vtime is more than half a slice
  behind the frontier, and the callback CPU's queues are empty): return the
  callback CPU with the same ordinary vtime insert to follow. A running compute
  peer keeps `dfl`'s prev placement and cache warmth.

`ALLOW_QUEUED_WAKEUP` makes callback CPU identity useful as placement state but
not as proof of the original waker. Accordingly this path reads neither
`current` nor TGID: its decision is composed only from empty-queue state,
explicit `WAKE_SYNC`, and wakee sleep depth. Removing the invalid identity gate
recovered the current-kernel futex result from 2.09M to 4.73M ops/s; narrowing
plain wakes to the wakee-only state rule retained 4.68M while avoiding the
cache collapse caused by ungated convergence.

### enqueue — the routing decision

The **sleeper clamp** runs first: `vt = max(own_vtime, frontier −
SLICE_NS)`, branchless (sign-mask select). One slice of credit, no more —
quarter-slice credit collapsed futex −72%; the kernel writes the clamped
value back at insert, which erases sleep-depth history (a hard boundary:
several otherwise-attractive classifiers die on it).

**S1 (2026-07-19), wake path only:** the uniform floor quantizes every sleeper
to one key, so a 100 µs audio burst and a full-slice compute wake tie and serve
FIFO. Wakes therefore clamp against a *cadence-deepened* floor,
`lo2 = frontier − SLICE_NS − cake_cadence_depth(p)`, where the depth is ¾ of
the task's unused slice fraction (`burst ≈ sum_exec_runtime >> log2(nvcsw|1)`;
`burst ≥ SLICE_NS` yields depth 0, so compute is unchanged). Maximum wake
credit is thus 1.75 slices, deliberately under the 2-slice peer hysteresis so
a fresh storm wake still cannot outrank own work. The sleeper/peer
*classification* still uses the undeepened distance, so class membership does
not move with the dose. Note the deepened `vt` is also the left-hand side of
the home-preempt margin below — S1 doses queue position and preempt
probability together, which is an open attribution caveat on its dose curve.

For a **wakeup**:
- self-race (`curr == p`): mark + home insert, done.
- pinned (`nr_cpus_allowed == 1`): home — the global queue's premise
  (anyone can take it) is false for pinned tasks; stranding one there
  starves it into the 5s watchdog.
- idle-owned home (`curr` vtime 0): home — the CPU is free or imminently
  free; sending this global was the pipe leak.
- local wake, shallow wakee (raw vtime within half a slice of the clamp
  line), or curr's *live* vtime behind the clamp line: home.
- peer wake onto an **empty** home queue: home anyway — warm beats the
  global detour's guaranteed cold cross-core pickup; no preempt (it fails
  eligibility against a frontier curr and waits at most one turn).
- **global backlog ⇒ home** — a wake already waiting in `WAKE_DSQ` is the
  oversubscription signature: scattering another one splits its handoff
  pair for nothing (this gate alone recovered the 2–4× futex herd 2–5×).
- otherwise: `WAKE_DSQ`, then a **targeted idle kick** — prev's loader-verified
  SMT sibling first (it shares prev's L2, so the likely collector picks the wake up
  warm; flow is preserved since the wake stays findable by anyone), else
  any idle CPU, else the global-wake preempt check.

**Home-wake preemption** (after a home insert): fire only when curr is
*young* (on-CPU less than SLICE/32 — a handoff partner ping-pongs in
microseconds, a mid-request worker runs long unswitched; flushing old currs
was a −2% RPS tax that amplified p99 at critical load) AND the wakee wins by
a real adaptive margin against curr's **live** vtime, charged mid-slice from
the run-start stamp: `SLICE/2 - curr_age/2`, bounded by the measured
`31×SLICE/64` endpoint at the edge of the young-current window. This is
pick_eevdf-style state, not task identity; bare-eligibility preempts
paid a −1% IPC flap-zone tax. **Global-wake preemption** keeps a flat
SLICE/8 protected floor instead — the wakee isn't on that CPU, so a
floor-less kick is pure churn (measured −27% futex).

**Compute-occupant preemption (mutation M, 2026-07-19).** When a globally
queued wake finds no idle CPU and its own target refuses the margin, cake
probes three ring neighbours for an occupant that has been on-CPU at least
SLICE/2 and is behind on live vtime, and preempts that one. The run-age gate
is what makes this safe: a wake-herd peer never accumulates half a slice (it
blocks within microseconds), while external compute mid-slice always does — so
the probe is structurally inert in the quiet-storm regime that falsified the
*unconditional* neighbour probe (−27% Rq), and fires only in the contended
regime where N4 traced 1.4% of global wakes waiting out whole occupant slices,
latencies quantized at exactly the 3.0 ms and 4.5 ms slice lengths. Worth
+10 pt of futex in the stack bisect.

**Pinned-user wake preemption (mutation K, 2026-07-19).** A pinned user task
(`nr_cpus_allowed == 1`) never reaches the wake path — it takes the
continuation route — and no other CPU may steal it, so a wake landing behind a
busy occupant used to wait out that occupant's entire slice. `perf bench futex
lock-pi` pins its workers and paid −86.6% for it (handoff p99 3.9 ms vs
native's 171 µs). Cake now preempts on **raw sleep depth** rather than the
clamped key, because the sleeper clamp rewrites the wakee's vtime to the same
floor the occupant started from and therefore erases exactly the deservingness
signal preemption needs. This cannot collide with the closed global
wake-service frontier: multi-CPU wakes never take this branch, and a pinned
wake has no work-conserving alternative. First movement ever on that gap —
−86.6% → −71.8% (8-block, CI [−72.5, −70.9]) — and later re-read at −1.2% once
the regime was controlled for, which is why the residual is filed as regime,
not mechanism.

**Kernel-thread wake episodes** bypass the shared wake/own arbitration and
enter their CPU's local DSQ directly; their runnable continuations retain
normal weighted-vtime ordering. Owner-queue vtime order alone is not
forward-progress protection for essential kernel threads: a 2026-07-10
20 s record-plus-parse trace stranded `ksoftirqd/13` for 6.884 s and tripped
the runnable-stall watchdog. The guard survived the identical stress.

*Widened by mutation L (2026-07-19) from pinned-only to **all** `PF_KTHREAD`
wakes.* The kernel's own scx watchdog rides UNBOUND kworkers, which under a
futex storm queued as ordinary herd citizens — wake→run p99 17 ms, max 192 ms
measured — accumulating past the 5 s check-in and getting cake evicted (the P0
stability bug, reproduced at an untouched baseline). Kernel-infrastructure
service is now bounded by one occupant slice on the selected CPU instead of by
herd order. `PF_KTHREAD` is scheduling state, not workload identity, so this
does not violate workload-neutrality. Storm survival went 3/3 then 5/5,
including two contended runs where the pre-L baseline died in the same session.

For a **continuation** (slice-expiry or preempt requeue):
- **depth-threshold overflow**: requeuing onto a home queue already holding six tasks goes
  to `OVF_DSQ` — the saturation balance nothing else provides (at 2×
  compute nothing ever idles, so the steal ring never runs and depth
  imbalance would persist forever; EEVDF's tick balance evens exactly
  this). Two guards: never a preempt-marked task (`pmark` — its handoff
  partner is on this CPU; overflowing spinners re-split pairs, futex t32
  2.13M→0.64M measured), and never under global backlog (uniform depth —
  overflow helps nobody, and it piled schbench-saturated 67K→178K).
  The overflow channel must be its **own** DSQ: routing it through
  `WAKE_DSQ` corrupted the backlog signal the herd gate reads.
- otherwise: home insert, with a 1.5× slice when queued behind a waiter
  (uninterrupted turns are the schbench win; a flat 2× starved
  deep-queue waiters −11%), then a plain idle kick (an idle third party
  stealing a homed task INTO opening capacity is load balancing, not
  waste — pinning those kicks to the home cost x265 its late-breaking
  spread).

### dispatch — one ordering rule

Clear my `qmark`, re-set it if my own queue holds work. Two *lockless*
`scx_bpf_dsq_peek` snapshots order own-vs-wake by earliest vtime with
**class-aware hysteresis**: a sleeper-class wake head (clamp-deep — the
handoff shape) crosses at one slice of margin; a frontier-peer head waits
behind own work at two slices (peers tolerate waiting — the flat versions
lose: 1× everywhere leaves +34% futex on the table, 2× everywhere collapses
futex to below native). A stranded peer ages into sleeper class as the
frontier advances — the starvation seal is structural, no rescue path.
An `OVF_DSQ` head that falls behind the global service frontier by the bounded
overflow-rescue hysteresis is
rescued before ordinary arbitration. This is the bounded-progress seal for the
overflow channel: saturated own/wake traffic can no longer prevent a compatible
overflow continuation from running indefinitely, while a fresh overflow head
does not turn the global queue into the default hot lock. Ordinary consume order
remains **own → wake → overflow**, then the staggered two-half-loop ring steal
gated by per-CPU `qmark` hints (dispatch 199→68 ns/call), then keep-running slice
refill when everything is visibly empty.

On a build host with more than one L3/CCD domain, the Rust loader precomputes a
dense victim order for every CPU: **same CCD → same cache-capacity tier → all
remaining CPUs**. The largest-cache tier naturally retains work on an
asymmetric X3D V-Cache CCD without classifying processes or routing every task
there. The final unrestricted tier is the work-conserving escape, so locality
is never hard affinity. Dispatch walks this one preordered array instead of
multiplying verifier-bound scan loops. On a single-CCD build, the topology
array, loader population, and BPF branch are all compiled out.

### running / stopping — the clock discipline

`running` stamps wall time (for preempt eligibility's live-vtime charge),
snapshots `p->se.sum_exec_runtime`, and advances the frontier with a
*conditional* store (a predictable branch beats a guaranteed RFO on the
hottest shared line). `stopping` charges vtime from the **`sum_exec_runtime`
delta — zero clock reads**: the kernel calls `update_curr_scx()` immediately
before both `ops.stopping` call sites, so the counter is boundary-exact
there. Reciprocal charging uses the original one-multiply fast path for normal
turns and an overflow-safe split product only for an exceptional uninterrupted
runtime above the fixed-point product's safe range. The law: clock reads are
only owed where mid-slice precision is
consumed (remote eligibility); switch boundaries are core-charged for free.
All clocks are `bpf_ktime_get_ns` — `scx_bpf_now()`'s per-rq cache is
cross-CPU incoherent for the stamp's remote reads (measured −37% futex).

### enable / init / exit

`enable` seeds a new task at the frontier (no windfall, no starvation —
child-runs-first credit was evaluated and declined; fork already wins).
`init` creates the DSQs and caches `nr_cpu_ids`. `exit` records UEI.

## Policy ratios and structural bounds

| constant | value | bracket |
|---|---|---|
| `SLICE_NS` | 3 ms | U-curve minimum; 1, 2, 4 ms all measured worse. Single-host (9800X3D), suite-aggregate |
| queued-turn bonus | 1.5× | 1.0× and 2.0× both measured worse |
| sleeper clamp credit | 1 slice base | 0.25 slice −72% futex; untouchable |
| S1 cadence depth (wakes) | + ¾ of the unused slice fraction, so ≤ 1.75 slices total | dose bracket /8 −16%, /4 +12%, /2 +39%, ¾ kept; bounded under the 2-slice peer hysteresis |
| sleeper/peer class line | SLICE/2 behind frontier | knife-edge flap at 0; measured on the *undeepened* distance |
| young-curr window | SLICE/32 | the spinner-vs-worker notch |
| compute-occupant probe (M) | occupant run-age ≥ SLICE/2, 3 neighbours | ungated probe −27% Rq; the run-age gate is what makes it inert there |
| home preempt margin | `SLICE/2 - curr_age/2`; endpoint 31×SLICE/64 | state-derived inside the SLICE/32 young window |
| global preempt floor | SLICE/8 | floor-less −27% futex |
| wake-head hysteresis | 1 slice (sleeper) / 2 (peer) | both flat forms lose |
| overflow depth | ≥ 6 | with pmark + empty-global guards |

`MAX_CPUS`, DSQ IDs, fixed-point radix/table geometry, cache-line padding,
UAPI scheduling-class values, unit conversions, and the watchdog are
representation/safety constants rather than workload policy. Cake rejects a
machine above `MAX_CPUS` instead of aliasing real CPU IDs through the verifier
mask. SMT sibling IDs come from Linux topology discovery rather than assuming
that logical CPU numbering is split into two equal halves.

## Verifier-budget lessons (BPF-specific, learned the hard way)

- `dispatch`'s tail is verified against every steal-ring exit state — even
  three straight-line kfunc calls there blow the 1M budget. New probes go in
  their own program (`ops.update_idle` + `KEEP_BUILTIN_IDLE` when the
  trigger is idle-entry) or a global `__noinline` function.
- `MAX_CPUS`-bounded loops survive only with tiny bodies (the ring's
  two-instruction hint-check + move); adding even one per-iteration kfunc
  (a peek gate) explodes state — cap the span or restructure.
- Duplicated kfunc call sites in a branch fork double downstream verified
  paths; reconverge on a scalar select (one insert call, data-dependent
  destination).

## What is deliberately absent

No per-task state or history (see invariant 4). No periodic balancer, no
timers (event-driven only — an SMT-vacate active balance was measured inert
where it can't trigger and harmful where it can). No `cpuperf` frequency
hints (this class of machine runs EPP=performance; firmware ignores them).
No `migration_cost`-style steal gating (statelessly it either passes
everything or starves capacity — measured both ways). No rescue paths of
any kind.

## Revision history

- **2026-07-01** — clean-slate cake-ring rewrite lands: per-CPU vtime DSQs +
  one global wake queue, "wakeups global, continuations local", the five
  invariants. All `slice_ns` knobs and the single shared DSQ of the first
  draft are gone the same week.
- **2026-07-02** — survival fixes: pinned wakes home (watchdog kill),
  own-vs-wake hysteresis (lock-storm −49%), `ALLOW_QUEUED_WAKEUP` (+8.6%
  futex). Slice-ladder falsified. Promotion gate vs packaged 1.1.1 cleared
  with zero losses.
- **2026-07-04** — the EEVDF campaign (64 mutations, ten kept mechanism
  families): waker convergence, home routing with the young-window +
  deadline-margin preempt, 3 ms slice family, qmark ring gate,
  `sum_exec` stopping charge, class-aware hysteresis, warm-sibling
  collector kick, backlog-gated regime switch, `OVF_DSQ` + `pmark`
  overflow. Full chain with every falsification:
  [`EEVDF_GATE_2026-07-04.md`](./EEVDF_GATE_2026-07-04.md).
- **2026-07-10** — queued-wakeup integration fix: replayed the July 4 binary
  on the current kernel (4.875M futex ops/s), proving the regression was in
  Cake rather than kernel drift. Removed `current`/TGID waker inference from
  `select_cpu`; plain convergence now uses wakee sleep depth only. The kept
  state-only rule restored 4.68M futex ops/s with 4.33M cache bogo-ops, 4100
  memcpy MB/s, 0.086s pipe time, and 90.496ms saturated schbench p99.
- **2026-07-10, pinned-kthread wake guard** — a service-shaped preempt-margin
  experiment (`sum_exec_runtime / nvcsw` folded into the home margin) improved
  focused `vkd3d_queue` PMU shape (IPC +11.4%, L1D miss rate −54.3%) but lost
  its clean WoW ABBA (0.1% low −17.8%, max frame time +39%) and was rejected.
  It falsified one safety assumption on the way: owner-queue vtime order alone
  did not protect pinned `ksoftirqd/13` (6.884 s strand, runnable-stall
  watchdog). The surviving fix — pinned kernel-thread wakes go directly to
  their sole CPU's local DSQ — is kept as a structural invariant.
- **2026-07-10, sync parallelism escape** — same-window native A/B on the
  7.2-rc kernel: futex +73%, ccm +45%, schbench p99 +5.5%, saturated p99
  +39%, fork +2%, thread tie — but pipe −10%. Placement sampling proved the
  mechanism: cake's pipe pair was welded to one CPU (196K ops/s, 5.09 µs/op)
  while native ran it split across two CPUs in parallel (1.28M ops/s,
  0.78 µs/op) — the pipe buffer makes parallelism profitable. The welder was
  hidden in the kfunc contract: dfl reports `is_idle=true` even for its
  `WAKE_SYNC` waker-affinity return (the waker's still-busy CPU), so the
  direct-dispatch fast path itself formed the one-way door — a post-dfl
  redirect lever measurably shifted the equilibrium (55% co-located, 223K
  ops/s) but could not close a door that opens before it runs. Fix: inside
  the `is_idle` path, a sync pick equal to the callback CPU redirects to a
  genuinely idle CPU before direct dispatch. Saturation still converges.

- **2026-07-19, the contended-regime block (K, L, M)** — three mutations kept
  in one session against the newly-opened N4 "contention collapse" target.
  **L** (`f40192df5`) widened the kthread wake guard from pinned-only to all
  `PF_KTHREAD`, fixing the P0 watchdog eviction under futex storm (5/5 storm
  survival vs a baseline that died in the same session). **K** (`f30cac430`)
  added pinned-user wake preemption by raw sleep depth, moving `futex-lock-pi`
  off its −86.6% floor for the first time. **M** (`6c7d05295`) added the
  run-age-gated compute-occupant probe. All three are described in §enqueue
  above. Note L and K were both *survival/latency* fixes found by decision-level
  census rather than by score search — the method, not the knob, was the win.
- **2026-07-20, S1 cadence-proportional sleeper depth** (`0ce54fb27`, dose
  settled at S1d `992d88bd1`) — the first term of the "when" formula: deepen a
  waking task's clamp floor in proportion to its unused slice fraction, so
  short-burst cadence tasks stop tying with full-slice compute wakes under the
  uniform floor. Recovered +65 pt of futex in the degraded quiet mode
  (1.4M → 3.3M ops/s, 3× reproduced; 8-block +12.2% vs native, CI
  [+10.1, +13.1]) and held pipe/ccm/schbench-saturated at sealed values.
  Cost: schbench-light ~0.8 pt (8-block trusted −2.24% vs −1.42% pre-stack).
  **Same session discovered that futex has host-state MODES** — identical code,
  boot, and regime reads 4.7M / 1.4M / 0.35M while native stays flat — so every
  historical futex delta must be read mode-tagged, not code-tagged.
- **2026-07-24, the K+L+M+S1d stack CLEARS its game gate.** Fellowship, parked
  scene, ABBA vs native, 2 runs/arm, scheduler identity and clean
  enable/disable verified per arm. Average FPS ties (GPU-bound at 94%, no
  throughput headroom) while the entire smoothness family moves: frame-time
  MAD −14.8%, jitter Δ median −16.6%, spikes >1.25× median −21.9%, stddev
  −6.8%, 1% low +0.97%, 0.1% low +0.95%, p99 −0.97%. The evidence is the
  coherence across metrics that all measure frame-to-frame consistency, not
  any single one. n=2 per arm — a strong screen, not a sealed result, and a
  CPU-loaded gameplay scene remains unmeasured.
  Alongside it, an unreplicated observation with **no established mechanism**:
  RT thread migrations (kwin main, DP-2, DP-3) went from 18–134 per 60 s window
  under native to zero under cake. The obvious explanation — cake's occupancy
  pattern steering RT placement — was checked against the kernel and is
  **false**: RT placement has no idle-vs-busy distinction (`CPUPRI_IDLE` does
  not exist in v7.1; idle and cake-occupied CPUs share `CPUPRI_NORMAL`), so
  cake's occupancy is invisible to `find_lowest_rq`. Cake cannot influence RT
  placement by keeping CPUs busy or free, and that whole class of levers is
  closed. Treat the observation as unexplained pending replication and a
  residency measurement. → `docs/RT_PLACEMENT_LOGIC_2026-07-24.md`

Historical campaign logs (pre-rewrite eras, May–June 2026) live in `docs/`;
they document the 12.6k-line predecessor and its mutation campaigns, not the
current design. Live campaign state, the open gap list, and the current
scoreboard live in [`STATE.md`](./STATE.md), which wins on any conflict with
this document.
