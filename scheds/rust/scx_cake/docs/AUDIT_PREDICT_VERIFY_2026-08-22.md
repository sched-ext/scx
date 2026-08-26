# Audit: predict-then-verify sites in cake (MTP / n-gram speculation mapping)

2026-08-22. Source audited at commit `3e2e6afc1` (`cake.bpf.c` 1688 lines, all
eight callbacks). Question: where can cake precompute a decision in a cheap
phase, verify it cheaply on a hot path, and pay full cost only on a miss —
and would it help.

**Verdict: the pattern is already load-bearing in six places. Five new sites
remain. Two are worth building (C1, C3); one is a discriminator for the
aborted §G39 (C2); two need a maintainer call first (C4, C5).**

---

## 1. The mechanism, extracted from MTP and n-gram decoding

Speculative decoding speeds up inference with one economic trick, in three
parts:

| part | requirement | LLM instance |
|---|---|---|
| cheap draft | producing the guess costs near zero | MTP head (one extra layer); n-gram lookup (no model at all) |
| cheap verify | checking beats recomputing | one batched forward pass verifies γ drafts |
| cheap miss | a wrong guess costs one fallback | rejected tokens are discarded, normal path resumes |

Discipline that makes it work:

- **Acceptance rate is measured before the feature ships.** DeepSeek-V3.2
  accepts 2.55 tokens per step, GLM-5 2.76. A draft head with low acceptance
  is deleted, not tuned.
- **Hybrid predictors beat one predictor.** MTP (learned, general) plus
  n-gram (exact-repeat lookup) each cover regimes the other misses:
  mtp-only 80.5 tok/s vs combined 205.9 on edit/echo tasks (llama.cpp
  Qwen3.6 benchmark). Different predictor classes, same verify path.
- **N-gram drafts come from the workload's own history.** No model: match
  the recent pattern against earlier context, propose what followed last
  time. Free where the workload repeats itself.

Scheduler translation: the wake path is the latency-critical "decode step".
`stopping`, the loader run loop, and the going-idle dispatch are the cheap
phases. Kernel scans (`select_cpu_dfl`, `pick_idle_cpu`, cpumask weight,
`dsq_nr_queued` rhashtable lookups) are the expensive "forward pass".

---

## 2. Where cake already runs this pattern

The audit's first finding: this is not a new idea for cake. Six constructs
already have the draft/verify/miss shape.

| construct | draft | verify | miss cost |
|---|---|---|---|
| prev-CPU home claim (§G13, `cake.bpf.c:916`) | last placement predicts next | `test_and_clear_cpu_idle` | fall through to dfl scan |
| §G25 qmask (`:336`) | per-CPU "may hold work" bit | `dsq_move_to_local` | skip one probe |
| §G41 wake mark (`:381`, `:1467`) | one word predicts global work | peek, retire-repeek protocol | one peek |
| §G36 tick predictor (`:443`) | `next_event` predicts handler | compare against hop p99 | one re-pick |
| §G30/§G33 sink gen (`:934`) | generation word predicts staleness | one compare | rebuild mask |
| §R.18 handoff hint (`:1598`) | confidence counter predicts a yield | `cake_handoff_yields` | decline co-location |

The §R.18 hint is the MTP-like predictor: learned, saturating, general.
Cake has **no n-gram-like predictor** — nothing matches "this exact wake
pattern repeated" against history. That gap is §G39's missing discriminator
(section 4, C2).

§G39 Phase B is also the pattern's failure case on record: a draft (chain
successor) whose miss was not cheap — pipe −36.8%, ctx +45.9%, aborted.
Every candidate below inherits that lesson as a pre-registered abort.

---

## 3. New candidate sites

### C1 — going-idle CPU publishes itself; `cake_wake_notify` verifies

**Site:** `cake_wake_notify` (`cake.bpf.c:1064`) runs `cake_pick_idle_clean`
— up to 3 kernel idle-mask scans plus escape re-picks — on every global
wake, and again at `cake_enqueue`'s `kick_idle` tail (`:1355`).

**Draft:** `cake_dispatch` already knows the exact going-idle moment: the
search returned false and prev is not queued (`:1544`). One store publishes
this CPU's id to a BSS slot word. Event-complete — the idle transition
itself writes the word, no polling, no new callback.

**Verify:** read the word, `scx_bpf_test_and_clear_cpu_idle(it)` (the claim
doubles as the verify, same as the prev-CPU arm), then one `cake_cpu_irq_bad`
check. Hit: kick it, done — zero scans. Miss: today's full path, unchanged.

**Expected value:** removes the largest remaining per-wake kernel scans from
the input-pipeline lane §G38–§G42 is chasing. Acceptance should be high in
game regimes (machine mostly idle, wakes frequent).

**Risks:** kick-targeting change — the §R.6/§G39 weld class. Pipe is the
guard workload. Stale word costs one atomic then falls back; two wakers
racing to the same word is resolved by test-and-clear (one wins, one falls
back).

### C2 — n-gram wake-pattern memory (the §G39 Phase B' discriminator)

**Site:** §G39 chain-successor handoff, aborted for want of a wine-RPC vs
data-stream discriminator.

**Draft:** n-gram style — per-CPU run slot remembers the last wake edge
(waker→wakee identity hash in the spare `hint` bits, §R.18's line, owner-
written). The chain draft is admitted only when this wake repeats the
recorded edge AND the waker then blocked within `cake_handoff_max_ns` last
time (the "waker blocks after waking" half that separates RPC from stream).

**Verify:** the recorded outcome of the last identical pattern is the
verify; a stream waker fails the blocked-quickly half every time, so pipe
ping-pong is excluded by measurement, not by flag.

**Expected value:** unknown until Phase A counts pattern-repeat frequency in
game regimes. This is a discriminator for a shelved construct, not a
standalone win.

**Risks:** identity-based policy must respect §R.20 (ALLOW_QUEUED_WAKEUP —
enqueue's current is not the waker; the edge must be recorded where the
waker is trusted, i.e. select_cpu/stopping only).

### C3 — qmask word replaces `dsq_nr_queued` in wake routing

**Site:** `cake_enqueue_wake` empty-home test (`:1197`) and the serial block
(`:894`) pay rhashtable lookups (`scx_bpf_dsq_nr_queued`) per wake. The
qmask bit for that CPU is the same predicate as one word read.

**Draft:** bit clear predicts empty — trust it, skip the lookup (the common
case in game regimes). **Verify:** bit set → run the real `dsq_nr_queued`
(the bit may be stale-set). Miss cost: one lookup, today's price.

**Expected value:** small constant per wake, no new state, no new writes —
the bits already exist and are already maintained.

**Risks:** a stale-clear (insert's mark-in-flight race) claims a home that
holds one queued task. The vtime queue keeps it fair and the owner rescans;
same benignity class the steal ring already accepts (§G25), but here it
flips routing, so it screens as a routing change (game screen required).

### C4 — slice precompute at `stopping`

**Site:** `cake_task_slice` (`:755`) runs two u64 divides plus a clock read
(`cake_burst_ns`, `cake_period_ns`) on **every insert** — five call sites,
all on the wake path.

**Draft:** compute the next slice at `stopping` (the cheap phase; the stats
are already in cache from the vtime charge). The value drifts by one quantum
at most — lifetime means move slowly — so no verify is needed; staleness of
one quantum is inside the estimator's own noise.

**Blocker:** needs per-task storage. Cake's header tenet is "no task-history
model"; options are task-local storage (a per-task map — tenet departure) or
reusing `p->scx.slice` between block and next insert (kernel-field semantics
need verification against tick/dispatch writes). **Maintainer call before
any build.**

### C5 — event-complete idle count for `cake_system_serial`

**Site:** `cake_system_serial` (`:697`) does `get_idle_cpumask` + full
cpumask weight per serial-candidate wake.

**Draft:** an idle-CPU counter maintained by `ops.update_idle` (with
`SCX_OPS_KEEP_BUILTIN_IDLE`) makes it one load — event-complete, matching
the design law. **Cost:** a new callback firing per idle transition with a
shared-line atomic — plausibly worse than the weight it replaces.

**Gate:** Phase A first counts how often the serial path actually executes
`cake_system_serial` per second in game and bench regimes. Below ~10k/s the
weight is noise and C5 is rejected without a build.

---

## 4. Sites audited and cleared (no candidate)

- `cake_dispatch_search` / ring steal — already fully mark-gated (§G25,
  §G41). Nothing left to draft.
- `cake_running` / frontier — test-before-write already (§R.10); frame
  observe already shift-gated.
- `cake_wake_vtime` — recompute-at-use is deliberate (§R.13); inputs are
  plain loads, nothing to precompute.
- Loader (`main.rs` run loop) — sink probe and frame argmax already run the
  cadence model (§R.25); the loader IS the cheap-phase producer for §G30/§G33.
- Occupant-live preempt checks — contended-path only; drafting the
  occupant's live vtime would need cross-CPU writes costing more than the
  clock read it saves.

The original conversation candidate — per-task predicted next CPU computed
at stopping — is **subsumed**: the prev-CPU claim already is that predictor
with prediction = last placement, and C1 covers the miss half (where prev is
busy). A learned per-task CPU adds per-task state for the migration-pattern
case only; value below C1, same blocker as C4. Not carried forward.

---

## 5. Test plan (all candidates)

Phase A is observe-only in every case, per the §G39 lesson: **acceptance
rate is measured before behavior changes.**

| candidate | Phase A counter (probe commit, reverted after read) | accept gate to Phase B | Phase B screen |
|---|---|---|---|
| C1 | hits/misses of the published-idle word at wake_notify | hit rate ≥ 60% in appsim game regime | bench: mutex-handoff, **pipe (weld guard)**, schbench-light; then game rotation (placement change) |
| C2 | pattern-repeat rate + blocked-quickly co-occurrence per CPU | repeat ≥ 50% on a real game, ~0% on pipe | shelved until counters justify reopening §G39 |
| C3 | stale-set and stale-clear rates vs real nr_queued | stale-clear < 1% of wakes | bench screen + game rotation (routing change) |
| C4 | none until the storage call is made | — | A/A + fnspills (cost-only change, no decision change) |
| C5 | serial-path executions/sec, game + bench | ≥ ~10k/s sustained | A/A + stress-ng-futex (serial regimes) |

Standing gates for every build: zero warnings both profiles, `fnspills.py`
per function (wake_notify and enqueue_wake budgets), attach smoke, sealed
A/A null, arms as commits, reverts byte-identical by sha256. C1/C2/C3 are
placement or routing changes: GAME-FIRST applies — game screen before
scoring, severe-frame ratio to screen, 0.1% low and p99.9−median to score.

## 6. Ranking (graph cut)

1. **C1** — highest value, no design-tenet conflict, event-complete, sits
   directly on the §G38–§G42 input-pipeline lane already under test.
2. **C3** — cheapest to build, uses existing state, small steady win.
3. **C5 Phase A counter** — one number decides it; near-zero cost to ask.
4. **C2** — registered against §G39 B'; build only after C1/C3 settle.
5. **C4** — parked on the per-task-storage maintainer call.

Sources: [vLLM MTP](https://docs.vllm.ai/en/latest/features/speculative_decoding/mtp/),
[SGLang speculative decoding](https://sgl-project-sglang-93.mintlify.app/advanced/speculative-decoding),
[prompt-lookup decoding](https://github.com/apoorvumang/prompt-lookup-decoding),
[llama.cpp MTP→ngram pipeline issue](https://github.com/ggml-org/llama.cpp/issues/23184).
