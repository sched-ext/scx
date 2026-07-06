# scx_cake — Design

`scx_cake` is a `sched_ext` scheduler distilled to one master algorithm built
entirely on kernel primitives. It is a clean-slate rewrite (2026-07): the
previous codebase had grown to ~12.6k lines in a single BPF file gated by
hundreds of `CAKE_*` feature flags, to the point where debug and release
compiled to *different schedulers* and a known, understood fix could no longer
be placed. The rewrite trades that surface for a design small enough to hold
in your head — ~870 lines of BPF (roughly half comments explaining the why),
eight callbacks — and defends that smallness with hard invariants.

Kernel-validated against Linux **7.1.x** (`kernel/sched/ext/{ext,idle}.c`,
`internal.h`). Every mechanism below carries a measured, noise-gated A/B
receipt; the falsification chain for everything that did NOT survive lives in
[`EEVDF_GATE_2026-07-04.md`](./EEVDF_GATE_2026-07-04.md) and `docs/`.

## Design invariants

1. **No feature flags, no knobs.** One build, one behavior. No `#if CAKE_*`,
   exactly one `SCX_OPS_DEFINE`, no loader options, no `const volatile`
   config. The only compile-time constants are `SLICE_NS` and topology
   *sizing* (`MAX_CPUS`, power of 2 so indexes are masks).
2. **One master algorithm per hot path.** Each `ops` callback is a single
   coherent decision, not a dispatch into competing subsystems.
3. **No division, no cold paths, no rescue buckets.** Reciprocal-weight table
   plus shifts and masks; every starvation concern is sealed by an ordering
   rule at the source, never by a catcher that sweeps up strays later.
4. **Stateless.** No per-task storage beyond the kernel's own
   `p->scx.dsq_vtime`; no history, no EWMAs, no timers. Adaptive behavior
   comes from *classifying current scheduling state* (vtime depth against the
   frontier, queue emptiness, curr's on-CPU age, backlog presence) — the same
   signal class EEVDF itself reads. Where a needed distinction is invisible
   to stateless inspection (worker-vs-handoff among deep sleepers), cake
   marks its own actions (per-CPU one-shot marks set beside kicks) rather
   than tracking tasks.
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
the local DSQ. Under saturation two carve-outs run before giving up on
placement:

- **Sync handoff** (`WAKE_SYNC`, waker's local and vtime queues both empty):
  FIFO insert onto the waker's local DSQ — EEVDF's `wake_affine` shape; the
  emptiness gate is what rules out the kernel's "unfair when oversaturated"
  caveat on this path.
- **Plain-wake convergence** (either side a genuine sleeper — raw vtime more
  than half a slice behind the frontier — and the waker's queues empty):
  return the waker's CPU with an ordinary vtime insert to follow. A split
  handoff pair is self-sustaining under prev-stickiness; converging it onto
  the waker collapses the pair into a same-CPU ping-pong that *stays*
  converged. Ungated convergence drags warm runners off prev (−12.3%
  cpu-cache-mem); sleeper-gating is the discriminator.

### enqueue — the routing decision

The **sleeper clamp** runs first: `vt = max(own_vtime, frontier −
SLICE_NS)`, branchless (sign-mask select). One slice of credit, no more —
quarter-slice credit collapsed futex −72%; the kernel writes the clamped
value back at insert, which erases sleep-depth history (a hard boundary:
several otherwise-attractive classifiers die on it).

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
- otherwise: `WAKE_DSQ`, then a **targeted idle kick** — prev's SMT sibling
  first (it shares prev's L2, so the likely collector picks the wake up
  warm; flow is preserved since the wake stays findable by anyone), else
  any idle CPU, else the global-wake preempt check.

**Home-wake preemption** (after a home insert): fire only when curr is
*young* (on-CPU less than SLICE/32 — a handoff partner ping-pongs in
microseconds, a mid-request worker runs long unswitched; flushing old currs
was a −2% RPS tax that amplified p99 at critical load) AND the wakee wins by
a real margin (half a slice against curr's **live** vtime, charged mid-slice
from the run-start stamp — pick_eevdf semantics; bare-eligibility preempts
paid a −1% IPC flap-zone tax). **Global-wake preemption** keeps a flat
SLICE/8 protected floor instead — the wakee isn't on that CPU, so a
floor-less kick is pure churn (measured −27% futex).

For a **continuation** (slice-expiry or preempt requeue):
- **depth-2 overflow**: requeuing onto a home queue already holding two goes
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
Consume order: **own → wake → overflow**, then the staggered two-half-loop
ring steal gated by `qmark` hint bytes (dispatch 199→68 ns/call), then
keep-running slice refill when everything is visibly empty.

### running / stopping — the clock discipline

`running` stamps wall time (for preempt eligibility's live-vtime charge),
snapshots `p->se.sum_exec_runtime`, and advances the frontier with a
*conditional* store (a predictable branch beats a guaranteed RFO on the
hottest shared line). `stopping` charges vtime from the **`sum_exec_runtime`
delta — zero clock reads**: the kernel calls `update_curr_scx()` immediately
before both `ops.stopping` call sites, so the counter is boundary-exact
there. The law: clock reads are only owed where mid-slice precision is
consumed (remote eligibility); switch boundaries are core-charged for free.
All clocks are `bpf_ktime_get_ns` — `scx_bpf_now()`'s per-rq cache is
cross-CPU incoherent for the stamp's remote reads (measured −37% futex).

### enable / init / exit

`enable` seeds a new task at the frontier (no windfall, no starvation —
child-runs-first credit was evaluated and declined; fork already wins).
`init` creates the DSQs and caches `nr_cpu_ids`. `exit` records UEI.

## Constants (every one dose-responsed)

| constant | value | bracket |
|---|---|---|
| `SLICE_NS` | 3 ms | U-curve minimum; 1, 2, 4 ms all measured worse |
| queued-turn bonus | 1.5× | 1.0× and 2.0× both measured worse |
| sleeper clamp credit | 1 slice | 0.25 slice −72% futex; untouchable |
| sleeper/peer class line | SLICE/2 behind frontier | knife-edge flap at 0 |
| young-curr window | SLICE/32 | the spinner-vs-worker notch |
| home preempt margin | SLICE/2 vs live vtime | /8, /4, 5/8 all worse |
| global preempt floor | SLICE/8 | floor-less −27% futex |
| wake-head hysteresis | 1 slice (sleeper) / 2 (peer) | both flat forms lose |
| overflow depth | ≥ 2 | with pmark + empty-global guards |

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

Historical campaign logs (pre-rewrite eras, May–June 2026) live in `docs/`;
they document the 12.6k-line predecessor and its mutation campaigns, not the
current design.
