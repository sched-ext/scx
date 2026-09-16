# ox-alpha code review: scx_cake

2026-08-23. Peer-review copy — findings are review opinions, not verdicts;
every measurement claim here was cross-checked against STATE.md / docs, none
re-measured. Source reviewed: `scheds/rust/scx_cake/src/bpf/cake.bpf.c`
(1888 lines), `src/bpf/intf.h`, `src/main.rs` at current HEAD.

## 1. Shape of the scheduler

Eight ops callbacks plus four irq/softirq tracepoints, no `.tick`, no
`.preempt`, no cgroup layer. All mutable hot state lives in one BSS struct
(`struct cake_state`) of 128-byte-stride slots; all host-dependent policy
lives in frozen rodata (`nr_cpu_span`, `cpu_sibling`, `cpu_irq_hot`,
`cpu_steal_order`, hop probe, toggles). The loader measures the host at
attach; the verifier prunes what a given machine never uses. This matches the
stated invariants exactly: no build-host input shapes the binary, MAX_CPUS=1024
refuses attach only via `ops.init`.

Fairness is ONE number: a global vtime `frontier`, advanced conditionally from
`ops.running` (test-before-write — hottest shared line, §R.10 honored).
Charging happens once, in `ops.stopping`, through the reciprocal-weight table
(no divide; overflow-safe split-multiply for extreme runtimes). Placement,
routing, and dispatch read the frontier; nobody else writes it.

### Placement ladder (`cake_select_cpu`, in evaluation order)

1. **Serial handoff co-location** — learned per-CPU confidence (WOKE bit +
   saturating count written by `running`/`stopping`, §R.18), gated by global
   serialness, sink veto, emptiness, and `cake_handoff_yields` (burst-relative
   yield window). Direct-dispatch LOCAL_ON|waker.
2. **Home claim** — prev-CPU cache warmth beats idle-core rank; declined on
   turn-starved, irq-bad, or SMT-contended homes. Test-and-clear claims.
3. **Ranked scan** — dfl ranking restricted to the nonsink mask
   (`select_cpu_and`), whole-machine fallback; sink rebuild is gen-gated.
4. **SYNC distrust** — a SYNC return of the waker's own busy CPU is re-ranked
   without SYNC (§R.6 weld avoidance).
5. **IRQ/tick escape** — one retry away from a CPU mid-handler or whose tick
   fires within one measured wake hop (`tick_cpu_device` next_event predictor).
6. **Ordered direct admission** — SYNC-only qmark guard: peek the claimed
   CPU's head; an OLDER head makes select_cpu return WITHOUT inserting, so the
   task falls to ops.enqueue and queues behind it in vtime order. Subtle but
   correct; the two-phase return-without-insert is the load-bearing trick.
7. **Saturated convergence** — return the callback CPU for genuine handoffs.

### Wake routing (`cake_enqueue_wake`)

Three states, one value (§R.11): ROUTE_GLOBAL (WAKE_DSQ + mark-after-insert),
ROUTE_HOME_QUEUE, ROUTE_HOME_CLAIM (earns a preempt decision). Oversubscription
signature (non-empty WAKE_DSQ probe) demotes global to home. Self-race
(curr == p) handled first and cheapest.

### Dispatch (`cake_dispatch_search`)

Two lockless head peeks pick earliest eligible of {own, wake} with a one-slice
HYSTERESIS margin (anti-lock-serialisation, not fairness slack); wall-clock
starve bound (24 ms) escalates past vtime; unconditional second consume as a
lost-mark healing net; staggered ring steal over qmask bits (one line per 64
CPUs, snapshot-per-word walk). Going-idle publishes the §G43 single-load idle
hint. Keep-prev regrant avoids idle churn.

### Starvation nets (defense in depth, each event-complete)

qmask transition atomics (§G25), wake_mark clear-then-repeek retirement
(§G41), wall-clock wake-stamp refresh gated half-a-window old (§R.16), idle
census mirror kept exact by test-gated flips (§G45), watchdog 5 s.

## 2. What is genuinely strong

- **Mark protocols are asymmetric on purpose**: owned per-CPU DSQs tolerate a
  stale CLEAR (owner rescans); the ownerless WAKE_DSQ gets the strict
  insert→mark / clear→repeek order. Getting this asymmetry right is where most
  sched_ext schedulers ship lost-wakeup bugs; cake's version is provable.
- **Every shared-line write is conditional** (frontier, qmask bits, wake_mark,
  idle_hint). The "never re-apply present value" law is applied uniformly.
- **Overflow math is exact**, not clamped: branchless sleeper clamp via sign
  extension, split-radix vtime scaling, cross-multiplied gates that cancel the
  divide. The ≥2³² escape hatches (§R.24) are consistent everywhere I looked.
- **Subprogram discipline** (§R.11) is real: ladders that stay inline vs.
  frames that absorb stack cost are chosen per-site with stated spill reasons,
  and the noinline choices (`cake_qmark_publish`, `cake_cpu_dsq_idle`) cite
  specific LLVM hoisting behavior, not vibes.
- Comments follow the kernel standard; nearly every non-obvious choice carries
  its §R/§G citation and, where falsified, the falsification (G39 SYNC
  experiment left in place as a warning). History lives in STATE.md, not here.

## 3. Findings

Severity scale: [D] design/build risk, [H] hygiene, [N] note/no action.

- **F1 [D] §G49's win depends entirely on the kfunc flavor.** The audit says
  "idle_smtmask bit read" but not which form. System-wide
  `scx_bpf_get_idle_smtmask()` returns a mask reference per call — plausibly
  MORE expensive than the `cake_cpu_curr(sib)->pid` chase it deletes. The win
  exists only via the per-CPU bit form, needing a compat-ladder arm like
  line 744's. Freshness also inherits from `update_idle` (§G45): exact while
  the census stays event-complete, so §G49 must be screened WITH §G45 on.
  Same semantics caveat: the smtmask bit answers "whole core idle," which is
  strictly stronger than "sibling idle" — same ranking outcome, but say so in
  the audit.

- **F2 [H] §G48 ordering is implied, not pinned.** The hint claim must land
  AFTER the serial-handoff block and the home claim, BEFORE the
  `sgen != nonsink_gen` rebuild + `select_cpu_and`. Earlier would let a
  published hint outrank cache warmth (rank change); later is worthless.
  Register the insertion point in STATE.md so the toggle build can't drift.

- **F3 [H] Unregistered reduction path.** "Keep-prev regrant served from the
  §G46 cache" (audit dispatch table) has no §G number and needs a
  running-task entry the cache doesn't hold. Register as G50 or mark parked;
  house rules don't leave named paths floating.

- **F4 [N] Double occupant read in `cake_wake_preempt`.**
  `cake_occupant_live()` derefs curr internally, then the caller derefs again
  for the `cake_starved(curr)` veto. Folding the veto into an
  occupant-live-plus-flag variant saves one chase but costs live-range in a
  frame already shaped around spills (§R.11). Note only — measure before
  touching.

- **F5 [N] Preemption erases an unconsumed WOKE bit.** `ops.stopping` writes
  `conf << SHIFT` unconditionally, dropping CAKE_HINT_WOKE even when
  `runnable` (preempted waker, pattern unfinished). Direction is conservative
  (undercounts handoff pairs, never fabricates them), so behavior is safe —
  but the §R.18 comment says "leaves the count alone" while the BIT is
  cleared. One clarifying sentence, or preserve WOKE on the runnable arm.

- **F6 [N] §R.5 consistency.** The anti-collision arm inserts into WAKE_DSQ
  with raw `enq_flags` while the rule (and both sibling sites) mandate the
  `CAKE_ENQ_WAKEUP` literal. Equivalent today — the arm's own guard proves
  the bit is set — but the rule should either be followed or amended.

- **F7 [N, cleared] Ring-steal matrix bound.** Suspected off-by-one:
  `if (i + 1 >= nr) break;` visits nr−1 entries. Checked against the loader:
  rows exclude self (`dst.id != src.id` filter) and fill exactly nr−1 slots.
  Bound is correct; recording the verification so nobody re-suspicioned it.

## 4. Cross-checks against the 8-23 cost audit

- Wake-path/enqueue/dispatch component tables match the source as reviewed.
- The "what EEVDF pays that cake never does" list is accurate (no .tick, no
  PELT, no softirq balancer in the ops set).
- §G48/§G49 registration text matches STATE.md §24/§25; findings F1–F3 are
  amendments those entries should absorb, not contradictions.

— ox-alpha

---

# Second pass: video-game scheduling review

2026-08-23, same source. Lens: frametime stability (0.1% low, p99.9 − median),
avg fps, and wake→run latency. Three regimes matter and they stress different
code: **menu/high-fps** (idle machine, placement cost dominates — §G48's
territory), **in-game CPU-bound** (pipeline stages, handoff pairs, preemption
gates), and **in-game GPU-bound** (nvidia kthread feed, §G47's territory).
GAME-FIRST framing throughout; findings continue the numbering above.

## What already serves games well

- The placement ladder's sink veto + live IRQ-depth word directly removes the
  classic "game thread lands mid-NIC/audio-handler" hitch class; the tick
  predictor (§G36) covers the one interrupt that IS predictable.
- Per-task slice geometry (2× burst, capped at half the task's OWN cycle)
  means stage threads never hold a CPU past their next wake — the structural
  fix for the tail-latency mode flat-slice schedulers show.
- No `.tick` callback: zero periodic accounting disturbance to a running
  render thread. This is cake's single largest structural advantage for
  frametime stability and the review confirms nothing recreates polling.
- Serial-handoff co-location with the burst-relative yield window (§G9.7)
  is exactly the futex/mutex pipeline shape games expose.

## Findings

- **F8 [D] The wake-starve wall clock is tuned for a display cake no longer
  assumes.** `WAKE_STARVE_WALL_NS` = 24 ms is documented as "~3 frames at
  120 Hz" — but the escalation bound is where a stranded globally-queued stage
  thread is RESCUED, so it is also the worst-case multi-frame stall cake will
  tolerate. At 240 Hz in-game that is 6 frames of allowed stall; in the 700 fps
  menu regime, ~170. The plumbing to fix this already exists and is unused:
  the loader republishes the voted frame period once a second
  (`cake_frame_ns`, argmax of exact buckets). Derive the window in the BPF as
  a multiple of the published frame (clamped to [some floor, 24 ms]) —
  workload-adaptive constant per the denomination law, no new input needed.
  Hypothesis: tightening the rescue window at high cadence cuts the deep tail
  (p99.9 − median) without hurting throughput; abort if median fps moves
  against. Screen on severe-frame ratio first, score on the tail.

- **F9 [H] §G47 ships default-off while being the GPU-feed fix.**
  `cake_tog_g47` rodata-defaults to 0; the ISR-successor path only runs behind
  `--toggle g47`. Its registered endpoint (GPU util gap + nvidia-kthread wake
  p99, fence tail holding) is well-defined and it is attach-smoked. Run the
  sealed screen; if the GPU-feed win separates, flip the rodata default in the
  same session so tip behavior carries the fix. An off-by-default game fix is
  indistinguishable from absent for players.

- **F10 [H] The neighbour probe is an unlisted term in the cost audit.**
  `cake_wake_notify`'s depth-3 probe calls `cake_wake_preempt` per candidate,
  and each step pays `cake_occupant_live`: a clock read, an rq deref chain,
  and weight scaling — on the global wake path, i.e., the saturated in-game
  regime. It may well be worth its price (it buys work-conserving preemption);
  but the audit's wake-path table prices `select_cpu_and` and misses this.
  Add the row, then decide: candidate gates are (a) probe only when the
  wakee is stage-class, (b) shrink depth under census-measured saturation,
  (c) leave after a screen shows it free.

- **F11 [N] Keep-prev regrant is value-blind.** When dispatch finds nothing,
  ANY queued-flag prev gets a full fresh `cake_task_slice(prev)` regardless of
  whether a game thread is about to arrive and must spend a kick + preempt to
  dislodge it. For an idler with a large cycle cap that is up to ~1.5 ms of
  borrowed residency. Micro-hypothesis for a later unit: regrant at half
  slice for prevs whose burst is far below their grant. Low priority — the
  wake path's preempt gates usually correct this within one quantum.

- **F12 [N] No wakee→waker pair learning, by design.** The handoff
  confidence is CPU-side ("wakes from here get followed by quick blocks"),
  not task-pair state — consistent with the no-task-history law. Other
  schedulers buy game latency with pair tables. Do NOT add state to chase
  this; record it as a known, accepted ceiling so a future regression isn't
  diagnosed as missing learning.

- **F13 [N] Frame-vote plumbing is policy-free (deliberate, §R.28).** If F8's
  derivation earns its screen, it becomes the FIRST consumer of
  `cake_frame_ns` — keep it that way. Any second consumer should need its own
  unit; a shared adaptive constant that two policies trust is how geometry
  coupling (the old §R.28 failure) returns.

## Suggested order of play (all behind toggles, one variable at a time)

1. **§G48 build + screen** — already registered; menu-regime fps is the
   endpoint. Highest leverage on the regime the audit names.
2. **§G47 sealed screen → default flip on separation** (F9).
3. **F8 experiment unit**: hypothesis (tighter rescue window cuts deep tail
   at high cadence), steps (rodata toggle selecting frame-derived vs fixed
   window), endpoint (severe-frame ratio + p99.9 − median on the game
   rotation), abort (median fps regresses SEPARATED). Pre-register before
   building; bench/appsim first, in-game time confirms.
4. F10 audit row + gate decision after its screen; F11 parked unless tails
   implicate it.

— ox-alpha, second pass

---

# Third pass: kernel-source grounding (linux @ /home/ritz/Documents/Repo/linux, 7.2.0)

2026-08-23. Claims in the first two passes checked against the actual EEVDF /
sched_ext source. Cites are file:line in that tree.

## §G49 verdict REVISED — the win is real on this kernel, with two notes

F1 feared a per-call mask allocation in `scx_bpf_get_idle_smtmask()`. The
source says otherwise:

- The kfunc is `guard(rcu)` + prog-aux lookup + one static branch + return of
  an existing mask pointer (`kernel/sched/ext/idle.c:1255-1272`); its put
  partner has an EMPTY body — the ACQUIRE annotation exists only to make the
  pointer trusted (`idle.c:1281-1293`). No allocation, no copy.
- There is NO per-CPU single-bit variant in this tree; the global mask form
  IS the cheap form. F1's compat-ladder concern dissolves; use
  `scx_bpf_get_idle_smtmask()` directly.
- **Semantics are exact and stronger than assumed**: `update_builtin_idle()`
  sets a core's smt bit only when the ENTIRE SMT mask is inside idle_cpus
  (`idle.c:711-730`), updated under the rq lock at every real transition via
  `__scx_update_idle()` (`idle.c:836-861`). So bit(sib) clear ⇒ sibling busy,
  precisely what `cake_core_contended()` approximates today with a remote
  `rq->curr->pid` chase — whose real cost is a potentially cache-cold remote
  task_struct line, exactly what the bit read avoids. KEEP_BUILTIN_IDLE keeps
  this tracking live (cake sets it).
- **Note A (startup transient)**: `reset_idle_masks()` starts ALL-BUSY;
  masks populate only as CPUs pass through idle re-picks
  (`idle.c:854-868`). For the first moments after attach every home claim is
  declined. Self-healing within seconds; harmless, but don't measure placement
  screens against the first second of attach.
- **Note B (race direction)**: the kernel's own comment marks smt-mask
  handling "racy but fine" — stale reads mis-veto one claim, same benign
  direction cake already accepts for qmask bits.

## EEVDF comparison claims — confirmed at source level

- Base quantum is `sysctl_sched_base_slice` = 700 µs default
  (`fair.c:85-86`), re-granted per enqueue/dequeue paths (`fair.c:6173`,
  `6186`) — vs cake's per-task 2×burst-capped grant.
- `update_curr()` does delta accounting + vruntime + deadline check per
  charge (`fair.c:2024-2065`) and rides PELT load updates in the surrounding
  paths; cake charges once in `ops.stopping` with one multiply-add. The audit's
  "running/stopping cheaper than update_curr+PELT" holds.
- `pick_eevdf()` is an rbtree eligibility search with a `next` shortcut
  (`fair.c:1177-1240`); cake's dispatch is O(1) peeks + steal ring. Different
  shape, both fine — cake's advantage remains the ABSENT tick/PELT/balancer
  work, not the pick itself.
- SIS_UTIL throttle is real and behaves as the audit describes: under an
  overloaded LLC it returns −1 and gives up scanning (`fair.c:8687-8697`).
  Cake's nonsink scan never throttles — it always answers. That is the
  placement-quality asymmetry games feel under load; it is also why the scan
  cost term (§G48) is worth deleting on the idle machine where EEVDF instead
  scans freely and wins.

## Net effect on order of play

Unchanged priorities, upgraded confidence: §G48 build/screen first; §G47
sealed screen then default flip; F8 unit pre-registered. §G49 moves from
"flavor-dependent" to "build it behind its toggle" — Note A/B recorded as
screen caveats, not blockers.

— ox-alpha, third pass

---

# Fourth pass: eBPF documentation grounding (/home/ritz/Documents/Repo/ebpf-docs)

2026-08-23. This repo is the libbpf/eBPF documentation site source. No new
findings — it CORROBORATES the review's §R.11 claims at the mechanism level,
with citations into `docs/linux/concepts/functions.md` unless noted:

- **The inline-vs-subprogram trade is a calling-convention fact, not style.**
  R1–R5 are clobbered by every call and R6–R9 are callee-saved, so each
  BPF-to-BPF call forces the CALLER to spill whatever it holds live across
  the cut (`functions.md`, "Calling convention"). That is precisely why cake
  shapes subprogram cuts as "the caller carries nothing across it" and why
  `cake_qmark_publish` must stay out-of-line (inlining pins addresses across
  the peek). Conversely "inlined functions can be optimized per call site
  since arguments are known" is the documented case FOR `__always_inline` on
  the single-shape ladders (§R.8).
- **5-argument hard limit** — structures must carry more. Grounds the
  insert_vtime args-struct compat ladder and the audit's cost table rows that
  count kfunc arguments as real costs.
- **Global-function verification since v5.6** verifies each function once,
  out of order, with stricter rules — grounding cake's choice of GLOBAL
  subprograms for the wake/enqueue halves (stable frames, independent BTF
  signatures) and the pre-6.19 void-return note in the file header.
- **Call depth ≤ 8** — cake's nesting (select_cpu → escape/hint/notify →
  preempt) sits comfortably inside; no action.
- **Trampoline entry cost is structural** (`docs/linux/concepts/trampolines.md`):
  sched_ext ops dispatch rides BPF trampolines built on ftrace NOP sites, so
  the audit's "EEVDF native calls never pay this" premise is confirmed as a
  mechanism, not just a measurement.
- **`__arg_trusted`** (`docs/ebpf-library/libbpf/ebpf/__arg_trusted.md`):
  verifier-enforced trusted-pointer tag, default non-NULL — matches cake's
  use on `p` across the wake-path subprograms; NULL-tolerant sites correctly
  keep the raw pointer + explicit check instead (e.g., `cake_cpu_curr`).

Net: nothing in the documentation contradicts any finding F1–F13; the
mechanism-level backing for §R.8/§R.11 is now citable rather than asserted.
Order of play unchanged.

— ox-alpha, fourth pass

---

# Fifth pass: kfunc / helper / trampoline inventory, cost, avoidability

2026-08-23. Every external (BPF→native) crossing in cake.bpf.c, with the
kernel-side implementation checked in the linux tree. Cost classes: **F** free
(folded or pure arithmetic in BPF), **C** cheap (a few insns + one cache line),
**M** moderate (lock/guard + lookup + possible cache miss), **H** heavy (scan
or machine-wide work). Frequency: per-wake (select_cpu/enqueue), per-dispatch,
per-switch (running/stopping), or per-IRQ (tracepoints).

## Structural (cannot be removed while sched_ext is the substrate)

- **8× ops trampoline** — every callback enters via the struct_ops/ftrace
  trampoline. This IS the floor the audit names; only fewer CALLBACK EVENTS
  beat it (cake's −28% switch count is that win).
- **4× irq/softirq tracepoint programs** — `cake_irq_enter/leave`,
  `cake_softirq_enter/leave` run on EVERY handler edge MACHINE-WIDE, at kHz
  rate under NIC load, independent of scheduling. §G35's live depth is the
  only consumer. Avoidable? Only by trading the instantaneous truth for the
  chronic mask (§G33 alone) — a measured game regression risk, not a free
  cut. Worth ONE screen: toggle the softirq pair off and read the
  softirq-heavy benches; the irq pair is the load-bearing half for GPU-feed
  placement.

## Per-wake kfuncs (the placement 2.8× lives here)

| Call | Kernel cost | Frequency | Avoidable? |
|---|---|---|---|
| `scx_bpf_select_cpu_and` | full LLC idle scan, UNTHROTTLED | every non-claimed wake | §G48 hint hit = zero; census-gate could skip it when idle_nr=0 |
| `scx_bpf_select_cpu_dfl` | second scan (fallback) | when `and` fails | skip when census says nothing idle — dfl would return prev anyway |
| `scx_bpf_test_and_clear_cpu_idle` | mask atomic + smt andnot (`idle.c:1305`) | home claims, hint claims, sibling pick | no — it IS the claim primitive |
| `scx_bpf_dsq_nr_queued` (custom DSQ) | rhashtable_lookup (`ext.c:310`) | serial gate + WAKE probe + home gate | **§G44** — qmark bit answers emptiness; measured null, parked, but it deletes an M-class call per hit |
| `scx_bpf_dsq_nr_queued` (LOCAL_ON) | preempt_disable + rq read (`ext.c:9643`) | serial gate | cheap; but the serial gate runs BOTH this AND the rhashtable form — merge to one question |
| `__COMPAT_scx_bpf_cpu_curr` | rq deref chain | core_contended, handoff_yields, notify | **§G49** removes the wake-path instance |
| `scx_bpf_kick_cpu` | guard(rcu) + IPI/resched | only when someone must run | no — it is the notification |
| `bpf_ktime_get_ns` | clock read | several sites | already minimized; tick_soon gated by rodata |
| `scx_bpf_dsq_peek` / `insert(_vtime)` / `move_to_local` | rq-lock queue ops | dispatch/insert sites | floor — these are the scheduler's actual work |

## Per-switch and gated

- running/stopping: `bpf_ktime_get_ns` + plain stores + one multiply — no
  kfuncs at all. This is why accounting is 2.2× cheaper than PELT.
- `bpf_map_lookup_elem` (frame hist): fires only for display-cadence threads
  passing the burst gate — per-switch for a handful of threads, free for the
  rest. Fine.
- `bpf_ksym_exists` / `bpf_per_cpu_ptr`: folded arithmetic. Free.

## Findings

- **F14 [D] The serial gate asks the emptiness question TWICE** —
  `cake_cpu_dsq_idle(wc)` (rhashtable, qmark-gated) AND
  `!scx_bpf_dsq_nr_queued(LOCAL_ON|wc)` (rq read). One merged qmark-gated
  check deletes an M-class call from the hottest gate. Fold into the §G44
  revival or its own unit.
- **F15 [H] Census-gate the scan fallback**: when `cake_idle_nr` reads zero,
  both `select_cpu_and` (nonsink) and `select_cpu_dfl` can be skipped toward
  the saturated-convergence return — nothing is idle, so the scans can only
  fail. This is the saturated-regime half of the 2.8× that §G48 (idle-regime
  half) does not address. New input? No — the census exists (§G45).
- **F16 [N] Tracepoint quartet is cake's only unconditional machine-wide
  tax.** Everything else scales with scheduling events. Screen its cost once
  (softirq pair off) so it is a known number, not an assumption.

Order of play unchanged; F15 slots behind §G48/§G47 as the saturated-regime
companion to §G48.

— ox-alpha, fifth pass

---

# Sixth pass: order-of-operations audit

2026-08-23. Each hot path walked gate-by-gate against one rule: cheapest and
most-decisive test first, expensive tests only when they can still change the
outcome, no side-effecting call before its veto is complete.

## Confirmed correct (no action)

- `cake_handoff_yields` — clock read + occupant deref LAST, after free gates.
- `cake_home_claim` — sleeper arithmetic → idle-owned → occupant-live,
  documented "cheapest first" and honored.
- `cake_enqueue_wake` — self-race (hottest shape) first, before the rhashtable
  probe; RT check is pure loads.
- `cake_wake_notify` — preempt tested last ("rejections stay cheap", §G10.5);
  idle pick ranked above the sibling test deliberately (§G38).
- SYNC convergence sits LAST in select_cpu on purpose: §G39 measured letting
  SYNC wakes early into co-location at pipe −36.8%. Ordering here is a
  falsification scar, not an oversight.

## Findings

- **O1 [D] The home claim pays its most expensive gate for nothing when prev
  is busy.** Gate order today: starved_turn (arith) → irq_bad (loads) →
  `cake_core_contended(prev)` — a REMOTE rq->curr deref chain, potential
  cross-CPU miss — → cpumask_test (FREE) → `test_and_clear_cpu_idle`. Under
  load, prev_cpu is BUSY most wakes, so the decisive, FREE affinity test and
  the non-consuming idle state are checked AFTER the deref chain. Two fixes:
  (a) swap `bpf_cpumask_test_cpu` ahead of `cake_core_contended` — pure win,
  zero semantic change; (b) note that the veto-before-claim order is FORCED
  by API semantics (test_and_clear CONSUMES the idle bit; a post-claim veto
  would corrupt kernel idle tracking), so the only way to make the contended
  veto cheap is a NON-consuming proxy — which §G49's smtmask bit read is.
  O1(b) upgrades §G49 from cost-fix to ordering-fix; fold this paragraph into
  its registration.
- **O2 [H] Census-gate every scan site, not just placement.**
  `cake_pick_idle_clean` runs hint-miss → core pick → thread pick at THREE
  sites (`select_cpu`'s escape path via notify line 1178, kthread arm 1418,
  enqueue tail 1488). On a saturated machine each finds nothing but pays two
  full scans per call. When the §G45 census reads zero idle, all three can go
  straight to their callers' fallbacks. This GENERALIZES F15: one toggle,
  three sites, saturated-regime savings on both wake and dispatch sides.
- **O3 [N] `cake_wake_peek` reads the clock whenever the mark is clear** —
  the common regime. The §R.16 design needs wall-clock truth, so accept it;
  the refinement (store `serve_stamp + WINDOW` as a deadline word at serve
  time so the per-dispatch check is load+compare+ktime instead of
  load+ktime+add) saves one add, not the clock read. Not worth a unit alone;
  ride along if anything else touches the file.
- **O4 [N] Micro-reorders with zero semantics:** hoist the free
  `cpumask_test_cpu(wc)` above `irq_bad` in the serial block; in
  `cake_isr_successor`, the PF_KTHREAD/enq_flags loads already precede the
  depth check correctly. Sweep once during the next touching of these
  functions.

Net: one real ordering defect (O1a, trivially fixed; O1b strengthens §G49),
one generalized gating win (O2/F15), everything else verified deliberate or
negligible. The paths are ordered by people who thought about it — the audit's
job was to find the two places that reasoning didn't reach.

— ox-alpha, sixth pass

---

# Seventh pass: standalone systems, mergers, and bloat audit

2026-08-23. Question posed: is cake carrying trees, parallel pathing logic, or
code done twice that is a mistake rather than a design? Method: enumerate every
subsystem and repeated pattern, classify CONSOLIDATABLE / DELIBERATE / DEAD.

## First, the headline: there are no trees to prune

Cake has zero self-managed tree or heap structures — fairness is one vtime
word, queues are kernel DSQs, all own state is flat arrays/bitmasks/tables.
Every decision is O(1) by construction. The EEVDF-style rbtree scan simply
does not exist here; nothing in this pass changes that.

## Subsystem census (10 systems)

frontier+reciprocal charging; qmask marks; wake_mark/starve protocol; idle
census (§G45); idle hint (§G43); sink system (chronic mask + live depth + gen
gated nonsink); handoff learning hints; frame-clock votes + loader publishing;
CCD steal matrix; departing-slice cache (§G46). Nine of ten have clear
consumers. One does not:

- **M2 [D] The frame-clock trio is a consumerless subsystem.**
  `cake_frame_ns`, `cake_frame_floor_ns`, `cake_frame_slice_ns` are published
  per second and read by NOTHING in the BPF (`§R.28` stripped the last policy
  consumer; the slice word survives only for a --verbose line). The BPF side
  still pays gated map lookups + bucket math on display threads. Either F8
  lands and this system earns its keep, or demote voting to loader-side
  telemetry. Do not carry dead policy plumbing through the §G48/§G47 era.

## Repeated code: what is a mistake, what is structure

- **M1 [H] The waker-CPU gate set is evaluated TWICE in select_cpu.** The
  serial block tests `irq_bad(wc) → affinity(wc) → emptiness(wc) ×2 →
  yields(wc)`; the saturated-convergence return then re-tests the SAME facts
  about the SAME CPU (`waker_cpu == wc`) minus yields. When serial is false
  (common) the first set short-circuits free and the second runs standalone —
  fine; but when both arms run, four M-class questions repeat. Candidate:
  hoist the common waker-CPU facts once before both blocks. CAVEAT: hoisting
  makes the non-serial case PAY for gates it previously skipped — screen it,
  don't assume it. If the screen is null, record why (short-circuit asymmetry)
  and close it.
- **M3 [H] The two-truth cleanliness test is spelled five ways** —
  `irq_bad ∥ tick_soon` appears in escape, hint claim, clean pick,
  select_cpu's verify arm, and notify's sibling check (15 call sites of the
  pair across the file). One canonical `__always_inline cake_cpu_clean(cpu)`
  would collapse them; §R.11 warns inlining expands text at each site, so the
  verdict needs `bench/fnspills.py` before AND after — merge only if spills
  hold flat. This is exactly the 'done more than once, probably a mistake'
  shape the audit was asked to find — except it isn't hurting performance
  today (each copy is already minimal); it is a maintenance hazard.
- **M4 [N] Six mechanisms answer overlapping existence/free questions**
  (qmask bits, custom-DSQ rhashtable, LOCAL_ON rq read, wake_mark, census
  words, idle bits). Not bloat individually — each serves an owner — but the
  consolidation arc ALREADY REGISTERED (§G44, F14, O2/F15) should be executed
  as ONE program with one principle ('single source of truth per question'),
  not three scattered toggles.
- **M5 [N] Four frontier-clamp variants share only one subtraction.**
  cadence-deep floor (wake_vtime), uniform clamp (continuation), claim test
  (home_claim), raw-depth preempt (pinned). Genuinely different policies;
  merging saves one load+sub per site and risks register pressure. Leave.
- **Verified NOT duplication:** pick_idle_escape IS the shared verifier
  subprogram reused by clean pick and select_cpu (the apparent triplication
  is reuse); starved vs starved_turn differ by one shift and cross-multiply
  shape; slice sources (per-task cached vs SLICE_NS flat) are deliberate
  policy split; compat ladders and qmark ops are already consolidated.

## Net

One dead subsystem (M2) pending F8's verdict; one measurable double-evaluation
(M1); one mechanical dedup gated on spill numbers (M3); one consolidation arc
to execute coherently (M4). No structural bloat, no hidden trees, no accidental
second implementations. The codebase is smaller than its behavior sheet.

— ox-alpha, seventh pass

---

# Eighth pass: source-of-truth audit — can kfunc/trampoline cost reach zero?

2026-08-23. Question: EEVDF reads kernel state natively for free; cake pays a
kfunc or trampoline per pull. Audit every fact cake consumes, its current
source, and whether an in-BPF subscription can replace the query.

## The floor, stated precisely

Trampoline entries are NOT reducible: 8 ops callbacks + 4 tracepoint programs
cross ftrace-built vectors by construction. Zero is impossible inside
sched_ext. What CAN reach zero is the PER-DECISION kfunc pull: every query
below asks about state that CHANGES ONLY AT EVENTS cake already hooks.
That is the house law (event completeness, never polling) applied to
information itself: stop querying, subscribe.

## Source-of-truth inventory

| Fact | Current source | Cost | Subscription alternative |
|---|---|---|---|
| Occupant identity/vtime/burst (4 sites: core_contended, handoff_yields, occupant_live→preempt+notify) | `cake_cpu_curr()` deref chain ×2–3 loads, cross-CPU cold possible | **M** | **Mirror into `cake_run_slot`** — see M6 below |
| CPU idle bit | `test_and_clear` / `pick_idle_cpu` / dfl scan kfuncs | C–H | Census words (§G45) already mirror it; kernel claim still needed for exclusivity |
| Queue emptiness | `nr_queued` rhashtable / rq read | M/C | qmask bits exist; §G44+F14 finish it |
| Global queue nonempty | `wake_mark` word | C | Already subscribed ✓ |
| Idle COUNT | census word or `get_idle_cpumask`+weight | C/M | Already subscribed (§G45) ✓ |
| Wall clock | `bpf_ktime_get_ns` | C | Irreducible where freshness matters; per-CPU cached `now` could serve advisory reads only |
| Next-tick time | ksym + percpu ptr + ktime | M | Rodata-gated off when probe fails ✓; leave |
| Sibling SMT-busy | deref chain today, smtmask bit under §G49 | M | smtmask = kernel-maintained subscription read as one bit ✓ |
| IRQ depth | tracepoint-maintained BSS | C | Already subscribed ✓ — but the 4 tracepoint trampolines ARE the standing tax (F16) |
| Task's own slice/vtime | task_struct fields (direct, cheap) | C | ✓ |

## M6 [D] — the big one: mirror the occupant, delete every remote deref

`ops.running`/`ops.stopping` already fire at EVERY scheduling transition and
already own the per-CPU run-slot line (§G10/R.18). Publish the occupant's
three queryable facts there — start-vtime, recip index, and a generation/pid
tag — and every downstream consumer reads ONE warm local line instead of
walking `rq->curr`:

- `cake_core_contended`: 'does the sibling carry an SCX occupant' becomes one
  tag != 0 test — this ALSO gives O1(b) its non-consuming veto, cheaper than
  §G49's smtmask read;
- `cake_occupant_live` becomes pure slot arithmetic (it already owns `stamp`);
  `handoff_yields`, `cake_wake_preempt`, `cake_home_notify`, and the anti-
  collision arm all feed from it;
- race direction stays benign-by-design: a stale mirror misprices ONE
  placement, healed at the next transition — identical trust model to qmask.

Cost added: ~2 stores per switch on a line running/stopping already dirty.
Cost deleted: 5+ call sites' worth of kfunc calls AND their worst case — a
cross-CPU task_struct miss. This is the same move as §G46 (serve inserts from
a line you own), applied to the occupant itself. EEVDF reads rq->curr warm
because the whole kernel keeps it warm; cake cannot, so it should stop reading
it entirely.

Estimate: placement's non-scan remainder drops visibly (multiple M-class pulls
per wake become line loads); combined with §G48/F15 the 28k→10k placement gap
closes to roughly parity-minus-trampoline-floor. To be measured, not assumed.

## Verdict on 'zero'

Per-decision kfunc pulls: YES, mostly eliminable — cake's truths are all
event-generated, and cake attends every event. Trampoline entries: NO —
structural; beat them with fewer events, which cake already does (−28%
switches, no .tick).

Next action: pre-register M6 as its own unit (toggle, fnspills gate on
select_cpu, A/B wallclock then game rotation). It composes with §G48/§G49 but
must screen separately — it changes the same gates they do.

— ox-alpha, eighth pass

---

# Ninth pass: shapes and structures — is another jigsaw piece better?

2026-08-23. For every structure cake uses: what job does it do, what are the
alternative shapes, and would any be faster / lower-latency? Includes the
headline question: should cake own a red-black tree like EEVDF?

## The headline: no tree — and the reason is architectural, not convenience

EEVDF needs its rbtree because IT is the class managing one big runnable set
per rq: pick_eevdf must find 'earliest eligible deadline' over ALL tasks,
O(log n) per pick, with rebalancing on every insert/delete. Cake DECENTRALIZED
that decision: placement scatters work so each CPU's local choice is 'earlier
of two queue heads', which is two O(1) peeks. A tree would re-centralize what
placement already solved — you'd pay O(log n) insert + rebalance + allocator
cost on EVERY enqueue to answer a question that is locally constant-size.
At game wake rates (tiny per-queue n, extreme event rate), O(1)-on-small beats
O(log n)-on-large precisely because placement keeps n small. The tree is the
optimal shape FOR EEVDF'S SHAPE, not for cake's.

Also decisive in BPF: a self-managed balanced tree means arena allocations,
manual rotations, verifier-unfriendly loops, and losing core integration
(activate→wakeup_preempt resched comes free with kernel DSQs).

## Piece-by-piece

| Piece | Job | Alternatives considered | Verdict |
|---|---|---|---|
| Fairness coordinate | one global vtime frontier + per-task keys | per-DSQ frontiers; rbtree total order | keep — frontier IS the shared fairness clock; conditional store ✓ |
| Queues | kernel DSQs (id=cpu + WAKE_DSQ) | BPF arena mpsc/ring queues | keep — locks, peek, steal primitive, core integration free; custom queues shave kfunc overhead but re-implement core |
| Hot state | 128B-stride BSS slots | percpu array maps; unpadded struct | keep — maps add lookups; padding kills false sharing ✓ |
| Existence bits | qmask bitmap (1 line/64 CPUs) | per-CPU bytes; linked free-list | keep — one load answers 64 questions ✓ |
| Weight math | 64-entry reciprocal rodata table | divide; log2 bands (§G11, superseded) | keep — exact nice table, no divide ✓ |
| Steal order | u16² rodata matrix + generic ring | computed topology walk per dispatch | keep — 32 KB rodata buys zero compute, folds dead on narrow hosts ✓ |
| Idle hint | ONE cpu+1 slot, last-writer-wins | N-deep ring; full recent-idle bitmap | CONDITIONAL — single slot caps hit rate when many CPUs idle together (menu regime!). If §G48's screen shows low hit rate, a 2–4 entry ring is the registered follow-up; don't pre-build |
| Slice reuse | 2-entry pid-tagged cache | LRU-N; per-task stored slice | keep — handoff pairs alternate, 2 is the measured shape (§G46) |
| Handoff learning | CPU-side saturating counter | task-pair hash (violates no-task-history law) | keep ✓ |
| Sink set | gen-gated bpf_cpumask COW | rebuild-per-wake; per-CPU flags | keep — xchg publish, one compare to detect staleness ✓ |
| Frame votes | percpu bucket array | single atomic accumulator | DEAD until M2/F8 decides (M2) — shape fine if it lives |
| Occupant facts | rq->curr queries TODAY → run-slot mirror (M6) | keep querying; smtmask bit (§G49) | M6 is the right shape and subsumes the alternative ✓ |

## Latency-shape observations

- Every latency-critical lookup in cake is ≤1 dependent load after M6 lands;
  before it, the ONLY multi-hop chains are the curr derefs. That is the last
  pointer-chase in the hot path — after M6 the design has NO hidden
  traversal anywhere (no tree walk, no mask scan on hits, no chain).
- The one place a richer structure could buy latency is the idle-hint ring
  above; everything else already sits at its floor.

— ox-alpha, ninth pass

---

# Tenth pass: unused sched_ext surface — what could help?

2026-08-23, checked against the linux tree (`kernel/sched/ext/internal.h:319+`,
`ext.c:10562`). First correction: **`.preempt` no longer exists** in this
generation of sched_ext — preemption requests arrive via `SCX_KICK_PREEMPT`
(which cake uses). Full unused surface audited:

## Genuine candidates (both micro, both need profiling justification)

- **`scx_bpf_now()`** (`ext.c:10562`) — returns the rq clock when valid
  instead of a fresh hardware read, monotone per-CPU. Cake reads ktime at
  `wake_starved` (×2/dispatch), `occupant_live`, `handoff_yields`,
  `tick_soon`. In dispatch context the rq clock is freshly updated → near-free.
  Caveat: outside the validity window it still pays the real read plus a
  preempt guard, so gains are regime-dependent. Register only if a profile
  shows ktime as a visible term; it likely isn't after M6 deletes its neighbors.
- **`scx_bpf_dsq_move()`** — identity-targeted moves would let ring steal
  take the earliest-*eligible* victim task instead of the blind head
  (fairness wobble under saturation). Iteration cost makes it a bad trade for
  latency; consider only if saturated benchmarks show vtime inversions from
  blind-head steals.

## Audited and rejected — absence is the feature

- **`.tick`** — adding it recreates EEVDF's per-tick accounting disturbance;
  cake's no-tick design IS its frametime-stability win. Hard reject.
- **`.runnable`/`.quiescent`/`.init_task`/`.exit_task`/`.disable`** — task-state
  notifiers with no consumer: cake's burst/starvation math reads kernel-
  maintained counters directly. Each added op is one more trampoline per event
  paying for nothing. Event-completeness cuts both ways: subscribe only when a
  decision consumes it.
- **`.yield`** — a custom yield-to-partner would duplicate what serial-handoff
  co-location already does better (measured §G39 history warns here).
- **cgroup family** — clean-slate refusal stands; EEVDF pays cgroup walks,
  cake wins by absence.
- **`.core_sched_before`** — only consulted under core-sched (SMT security
  mode); desktops run without it.
- **`.set_cpumask`** — no cached per-task masks exist to invalidate; all
  affinity tests are live loads already.
- **node-aware idle kfuncs / PER_NODE flag** — single-socket gaming hosts;
  relevant only for multi-NUMA server ambitions.
- **bpf_timer/hrtimer cadence work** — loader's run loop already owns periodic
  jobs; moving it into kernel adds trampoline tax to work that needs no
  scheduler-context privileges.
- **arena allocators** — BSS slots suffice; no dynamic allocation anywhere.

Net: the unused surface is unused BY DESIGN, and each rejection traces to a
measured or principled win (no-tick, no-cgroup, no-task-state, loader-owned
cadence). Two kfunc candidates noted above are the entire actionable set, both
parked behind profiling evidence.

— ox-alpha, tenth pass

---

# Eleventh pass: everything eBPF can hook or feed, and what reaches sched_ext

2026-08-23, verified against the tree. Taxonomy first, then which sources
carry signal cake doesn't already have.

## The plumbing taxonomy

**Hook points available to a BPF program:** tp_btf/raw tracepoints (BTF-typed,
cake's 4 irq/softirq programs); fentry/fexit trampolines (cheapest function
hooks); kprobes (heavier); perf_event-attached programs (PMU sampling — IPC,
cache-miss rate per CPU); LSM; XDP/tc; bpf_iter (task/cgroup walkers);
struct_ops (what sched_ext itself IS).

**Channels INTO the scheduler's decisions:**
1. **Hook → BSS slot, read by ops callbacks** — the canonical cake pattern
   (irq depth words): zero-copy, event-complete, same-address-space. Any new
   per-wake truth must take this shape.
2. **rodata const-volatile** — one-shot host facts frozen at load (topology,
   toggles, hop probe). Never changes while attached.
3. **Loader-mediated round trip** — hooks/maps → loader run loop → BSS/rodata
   republish (frame argmax, sink monitor). ~1 Hz cadence: fine for slow
   signals, wrong for per-wake truths.
4. **kfunc queries of live kernel state** — the polling form M6 is deleting.
5. **`__ksym` weak externs** — direct kernel symbols (`tick_cpu_device`).

## New sources with real game signal

- **C-state depth via `power/cpu_idle` tracepoint [the interesting one].**
  Kernel idle masks say *running-or-not*; they do NOT distinguish a CPU parked
  in C6 (~100 µs exit latency) from one that just went shallow (~1 µs). In the
  menu regime most CPUs sit DEEP — so wakeup cost is dominated by physics the
  scheduler cannot see, and 'an idle CPU behind a microsecond handler still
  beats queueing' has an unmodeled sibling: 'a deep-idle CPU behind its exit
  latency'. A tp writing a per-CPU current-state byte into BSS gives placement
  a preference order it lacks today: shallow-idle > deep-idle when both are
  otherwise clean. This may be a hidden term in BOTH schedulers' high-fps gap
  (EEVDF pays it too) — but cake could be first to model it.
- **Frequency/capacity via `scx_bpf_cpuperf_cur/cap/set`** (`ext.c:10071–10256`,
  all present in this tree). Two uses: (a) place on the *fastest available*
  core rather than merely idle (big.LITTLE matters; even desktops have boost
  residency asymmetry); (b) `cpuperf_set` lets the SCHEDULER raise a target
  CPU's performance hint directly — e.g., bump the home CPU when a GameThread
  wake lands, cutting schedutil's ramp lag out of the wake path entirely.
  That second one is potentially large for frametime consistency and nothing
  in EEVDF does it.
- **PMU sampling via perf_event progs** — per-CPU miss-rate/IPC feeding a
  contention-aware placement term. Heavy machinery; loader-side aggregation;
  only if sink-style evidence ever implicates memory-bound interference.
Parked.
- **sched_switch/sched_wakeup tracepoints** — REDUNDANT: cake's own ops see
  every transition already; subscribing twice to the same events is pure tax.
- **fentry/fexit, kprobes, LSM, XDP** — no scheduling-relevant truth cheaper
  than existing sources; tick predictor already reads `tick_cpu_device`
  directly via ksym, better than any timer hook.

## Design constraints if any of this lands

Every hook is another trampoline program at event rate (F16's lesson: price
the standing tax BEFORE adopting — cpu_idle fires at every C-state transition,
cpuperf reads are cheap kfuncs but `set` writes governor state). Owner-written,
test-gated, slot-padded, advisory-stale-tolerant — the same trust model as
everything else in cake. And the identity-free law holds: these signals are
per-CPU machine truths, never task/workload attributes.

— ox-alpha, eleventh pass

---

# Twelfth pass: more novel eBPF data sources, ranked

2026-08-23, verified in-tree.

## 1. Measured idle residency — fexit on `cpuidle_enter_state` (`drivers/cpuidle/cpuidle.c:217`)

The C-state-depth idea's deep version: the exit handler knows the CHOSEN
state AND the actual last_residency. A fexit program records per-CPU
residency history → an empirical wake-cheapness score (how expensive has
waking THIS CPU actually been), replacing table-based exit-latency guesses.
Menu-governor mispredictions become visible: a CPU predicted shallow but
repeatedly parking deep gets downranked by measurement, not by name.
Novel repo-wide; composes with the cpu_idle-tracepoint version as fallback.

## 2. Cake consuming its OWN event counters — `scx_bpf_events`
(`ext.c:10590`, list at `internal.h:1262`) — cheapest real find

The core already counts what cake wants to know about itself:
`SCX_EV_SELECT_CPU_FALLBACK` (scan misses → the exact evidence F15/G50 needs,
collectable with ZERO instrumentation of cake), `SCX_EV_DISPATCH_KEEP_LAST`
(keep-prev rate), `SCX_EV_SLICE_CLAMPED/DENIED` (slice-floor pressure),
`SCX_EV_BYPASS_*` (watchdog proximity). Loader reads these via the existing
map/debug paths on its 1 Hz loop. This turns several open questions from
'build a counter and screen' into 'read the number that already exists'.
Should be done FIRST among everything in this pass.

## 3. LLC occupancy / memory-bandwidth PMUs via perf_event programs

Per-CPU cache occupancy (resctrl/CQM family) or MBM feeding a
contention-aware placement term — 'this CCD is memory-bound, spread there'.
Heavy machinery (perf attachments, sampling windows, loader aggregation);
parked until sink-style evidence implicates memory interference.

## 4. PSI-driven adaptivity (loader-side)

CPU pressure-stall info polled by the loader into BSS could modulate the
serial threshold or hint aggressiveness on a slow cadence — §R.25's
'confidence earns a slower cadence' implemented with zero new kernel hooks.
Cheap; policy risk is coupling two adaptive systems — needs its own unit.

## Audited out

- **Thermal throttling hooks**: NO thermal tracepoint header in this tree;
  MSR/perf-power routes are fragile. Loader-side zone-temp polling is the
  honest route if ever needed.
- **BPF task local storage**: per-task key-value without touching task_struct
  — but lookup cost per event exceeds reading the fields cake uses, and it
  flirts with the no-task-history law. Reject.
- **USER_RINGBUF** streaming loader→BPF: BSS writes are simpler and already
  proven here.
- **bpf_timer in-kernel cadences**: loader run loop owns periodic work;
  moving it adds trampoline tax for no capability gain.
- **LBR / branch snapshots**: fascinating, useless here.

— ox-alpha, twelfth pass

---

# Thirteenth pass: full data-location inventory vs direct kernel reads

2026-08-23. Every piece of data cake retrieves, its location, current
mechanism, and whether a direct CO-RE kernel read (ksym + typed load, no
call) would be significantly faster.

## Inventory

| Data | Location | Current mechanism | Direct-read candidate? |
|---|---|---|---|
| Occupant task (`rq->curr`) | percpu `runqueues` | `scx_bpf_cpu_curr` kfunc, 6 sites | **YES — `runqueues` ksym + `bpf_per_cpu_ptr`, the one big conversion** |
| Local-DSQ depth | `rq->scx.local_dsq.nr` | `nr_queued(LOCAL_ON)` kfunc (serial gate, convergence) | YES via same ksym — two more call deletions |
| Custom-DSQ depth | `sch->dsq_hash` rhashtable | `nr_queued(id)` kfunc | NO — no stable symbol; qmask/census-claim is the answer |
| Idle masks | sched-internal alloc'd masks | claim/pick kfuncs | NO — and wrong anyway; census mirrors them; exclusivity needs the claim primitive |
| Wall clock | clocksource | `bpf_ktime_get_ns` / `scx_bpf_now` | NO readable symbol; `now` when rq-clock valid is the floor |
| Next-tick time | `tick_cpu_device` | `__ksym` weak extern — ALREADY direct ✓ | — |
| Task fields (vtime, slice, nvcsw, sum_exec, policy, prio, cpu, flags, cpus_ptr) | `task_struct` | direct CO-RE typed loads ✓ | already optimal |
| Own state (qmask, census, hints, run slots, sink words, sibling map) | cake BSS/rodata | plain loads ✓ | already optimal |
| Nonsink mask | `bpf_cpumask` kptr | xchg-published kptr ✓ | already optimal |
| Frame votes | percpu array map | `bpf_map_lookup_elem` helper | NO — 8 MB if BSS-sized over MAX_CPUS; gated, rare; leave |

## Speed arithmetic for the two real conversions

A kfunc call costs ~10–20 ns (call, aux resolution, guards) ON TOP OF the
identical deref chain the direct read performs. `select_cpu` hits curr-facts
2–4× per wake today at 177–202 ns/call: converting is ~20–60 ns/wake, i.e.
~15–30% of placement cost — significant, and it composes with §G48/F15
(which delete the scan term) rather than competing.

## The decision logic between this and M6

They solve overlapping problems differently: the ksym route makes each query
CHEAPER (same semantics, same sites); M6 deletes the QUERIES (different,
benign-stale trust model, feeds four consumers from one store). If the
`runqueues` ksym resolves: land it as an immediate unpatched win AND still
build M6 — the mirror then serves its four consumers while ksym covers any
residual need. If it does NOT resolve, M6 is the only route and this pass
becomes its justification. Either way the probe is five minutes and final.

Risks, stated plainly: advisory-racy reads without rq lock (already cake's
accepted trust model — `cpu_curr` does the same thing behind a call); ABI
coupling to rq layout (CO-RE relocations handle field drift); upstream-
hostile style (fine under maintainer-owned-kernel rules, noted honestly).

— ox-alpha, thirteenth pass

---

# Fourteenth pass: execution-level map — what can move kernelward?

2026-08-23. Every operation classified by level, then the migration question:
what is faster if executed deeper in the kernel?

## The level map

| Level | What lives there today |
|---|---|
| **L0 — kernel core** (no boundary) | task switching, rq locks, TTWU batching (ALLOW_QUEUED_WAKEUP), builtin idle masks, vtime ordering INSIDE DSQs, slice-expiry resched, watchdog, activate→wakeup_preempt |
| **L1 — kernel calls from BPF** | insert(_vtime), move_to_local, peek, nr_queued, test_and_clear/pick_idle_cpu(+and/dfl), kick_cpu, cpu_curr, clock reads |
| **L2 — BPF text** | ALL policy: placement ladder, routing, gates, marks, mirrors, steal walk, burst/starved math, reciprocal charging, hint learning |
| **L3 — loader (userspace)** | topology, hop probe, sink monitor (/proc poll @1 Hz), frame argmax, toggles, diagnostics |

Correct delegations already made (things scheds often wrongly re-implement in
L2): DSQ vtime ordering, idle tracking, TTWU batching — all L0, all free.

## The migration rule

MECHANISM moves kernelward freely (kernel executes it cheapest, no boundary);
POLICY stays in L2 (that is the entire point of sched_ext — safe, A/B by
commits). Test every candidate against that line.

## Candidates

- **K1 [real, unpatched] Chronic-sink accounting moves L3→L2.** Cake already
  runs irq enter/exit tracepoints; add per-CPU handler-duration accumulation
  (one stamp + one subtract per edge, lines already owned) and cpu_irq_hot
  becomes self-derived, event-complete, and live — deleting the /proc-polling
  loader dependency and its 1 Hz staleness. F16 caveat applies but it is the
  SAME programs doing ~20 ns more each; screen once.
- **K2 [patch-gated] Fused action kfuncs** (claim_idle_and_insert,
  insert_and_kick_if_idle): L1 call-count reduction below the BPF floor.
  Parked behind the out-of-tree decision.
- **K3 [patch-gated] Core argument delivery**: occupant facts handed to
  select_cpu as arguments — L1 eliminated entirely for those facts.
- **N1 [note] Core-side DSQ emptiness notifications** would replace qmark
  bookkeeping with pushed truth ('which transition failed to notify' taken
  literally). Net-neutral cost (new trampoline events vs deleted atomics);
  record as the cleaner-shape option, don't build.

## Rejected migrations

- Placement/routing/yield POLICY into core: forks the scheduler, kills A/B-by-
  commits, ends the sched_ext model.
- Frame aggregation, hop probing, topology: L3 is correct — one-shot or 1 Hz,
  zero scheduling-path presence.
- Burst/starved/slice math into core: it IS policy, and it is already pure L2
  arithmetic on L0 counters — nothing to gain.

Net: one genuine unpatched migration (K1), two patch-gated accelerants (K2/K3),
one cleaner-shape note (N1). Everything else is already at its correct level.

— ox-alpha, fourteenth pass

---

# Session close: ox-alpha vs Claude — findings ledger and performance rating

2026-08-23. Final writeup comparing the two review streams across this
session, as requested. Errors on both sides are listed as fully as wins.

## What each stream contributed that the other didn't

**ox-alpha (this doc):** the architectural finds — §M6 occupant mirror
(subscribe-don't-query; the session's biggest structural idea, built as
registered), F8 frame-derived starve window, O1 ordering defect plus the
veto-before-claim insight that reframed §G49, M2 dead frame trio, K1 sink
accounting migration, C-state depth novelty (repo-wide unexploited, built as
§G51), cpuperf precedents, the shapes/structures verdict (no tree, and why),
and the push-vs-pull claim theory that predicted §G50's failure mode before
the regression measured it.

**Claude:** the empirical layer — pricing the scan at 59% (§G48-P probe),
hit-rate counters, the census-dead-at-g45=0 co-gate catch, ring Bug 1 (OR
corruption) and Bug 2 (no byte CAS), the M6 'warm local-line' wording
correction, the F14 two-queues correction, and relentless execution
discipline: byte-identical reverts, pre-registered aborts honored, honest
failure recording (G48 loaded screen, M6 null).

## The error ledger (both sides)

| Error | Caught by | Cost |
|---|---|---|
| F14 'mergeable double-check' overstatement | Claude | none — corrected pre-build |
| 'Warm local-line load' (M6) | Claude | none — wording fix in registration |
| Ring proposal bugs + underpriced miss path | Claude | none — never built |
| Census-claim endorsement (ox-alpha) | **nobody — empirically falsified** | one build cycle, cheaply aborted |
| Idle-smtmask 'allocation cost' fear (F1) | ox-alpha (kernel source) | none |
| M2 'not even written' flail | Claude self-corrected | none |
| Combined-window attribution risk | flagged, unresolved | potential future blur |

The census-claim entry deserves honesty on both sides: ox-alpha proposed it,
Claude endorsed it with better implementation detail than the original, and
reality killed it. The pre-registered abort is what made being wrong cheap —
that is the system working, not either reviewer failing.

## Rating

**Overall: parity, with complementary shapes.**

- **Architecture & novelty:** ox-alpha ahead (M6, F8, C-state, K1, push/pull
  theory — the ideas that survived into the build queue).
- **Empirical iteration:** Claude ahead (faster measure→diagnose→fix loops,
  better instrument design under time pressure).
- **Source grounding:** ox-alpha ahead (kernel-line citations caught F1 and
  grounded §G49/M7 before builds).
- **Execution discipline:** parity — both honored the house laws; the one
  process risk (combined windows) came from Claude's side and was flagged.
- **Error rate per finding:** similar (~1 substantive miss per 6–8 findings
  each); every error was caught by the other stream or by pre-registered
  aborts before it cost a regression.

The genuine result of the session is that adversarial pairing worked: every
wrong idea died cheap, every right idea was stress-tested before it shipped,
and the board (M6, M7, G48-menu-window, G50-R, G51/G52 re-homing, K1) is
stronger than either stream alone would have produced.

— ox-alpha, session close
