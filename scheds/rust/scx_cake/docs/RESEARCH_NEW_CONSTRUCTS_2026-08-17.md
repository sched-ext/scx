# Three candidate new constructs — 2026-08-17

Goal: new scheduling constructs, not existing patterns. Each candidate names what
is new, which open gap it attacks (STATE.md numbering), why the existing levers
cannot reach it, and a 4-line experiment block ready for STATE.md registration.
None of these touch code today.

Filter applied: gap 3 (schbench-light) and gap 4 (futex-lock-pi) are excluded —
one arc is closed after seven falsifications, the other is a kernel-lane semantic
gap. Gap 6 says enqueue-side work is near-inert in games, so all three candidates
live on the paths that matter: select_cpu, dispatch geometry, and time itself.

---

## Construct A — frame-relative fairness geometry

**Attacks:** gap 1, the easy-scene 0.1%-low loss (highest-value target).

**What exists:** cake already measures the frame (the G11 vote histogram). But
only two consumers use it: the slice cap and the preempt-protect windows. The
entire vtime geometry — SLEEPER_LAG_NS, DEEP_WAKE_HYSTERESIS_NS, the preempt
margins, the ¾ sleeper dose — is still denominated in the fixed 3 ms SLICE_NS.

**What is new:** the fairness window itself breathes with the display. In an easy
scene at 240 Hz the frame is 4.16 ms and native's tail is already tight; cake's
slice-denominated sleeper window (1.5 ms lag, 3 ms hysteresis) is then a fixed
fraction of the wrong clock — sleeper catch-up can overshoot within a frame. The
construct: every scheduling-relative constant becomes a frame fraction, published
by the loader the same way the slice cap already is. No scheduler today ties its
fairness geometry to a measured display; EEVDF cannot follow (it has no frame
clock). This finishes the frame-clock construct instead of adding arithmetic.

**Design-law check:** §S.2 says slice divisors are correct because they measure
turns of service. The claim to test is that in a display-coupled regime the turn
of service IS the frame. That is a re-denomination the laws explicitly allow
("denominate constants in what they physically measure").

**Experiment block:**
- Hypothesis: easy-scene loss comes from slice-denominated sleeper geometry mis-scaled vs a fast frame; frame-denominated clamps close ≥half the −5.6%.
- Steps: loader publishes frame-fraction clamps (rodata-style derivation, compare-only in BPF); A/B by commits.
- Endpoint: HD2 easy scene ABBA, screen severe-frame ratio, score 0.1% low.
- Abort: menu-scene G17 metrics regress on the screen, or any bench in the sealed set moves >2σ.

---

## Construct B — pre-paid idle exit

**Attacks:** gap 5, the renderer wake-tail floor. 28–32% of slow same-CPU wakes
have `swapper` as occupant in BOTH schedulers — an idle-exit cost neither beats.
Locality (G13), preempt (G14/15), notification (G16) all falsified: every
existing lever fires AT the wake, and by then the exit latency is already owed.

**What is new:** act before the event. The frame clock predicts the next wake
window of display-coupled threads to within a bucket. The construct: a BPF timer
armed to kick the predicted home CPU shortly before the predicted wake, so the
C-state exit is paid before the frame needs it, not on it. Schedulers today are
reactive by definition; this uses cake's measured future. EEVDF cannot follow —
no frame clock, no prediction to act on.

**Design-law friction, stated up front:** DESIGN.md lists "no timers" under
deliberately-absent, and the event-completeness law asks which transition failed
to notify. Answer: a FUTURE wake has no notifying transition — there is no event
source for "a wake is about to happen", which is exactly the case the global
rules allow a timer for. This is a maintainer call to amend the absence list; the
experiment is worthless without that call, so it goes first.

**Cost bound before any game time:** one timer per frame period (~4 ms), one
kick; measure timer overhead on an A/A first, same discipline as G26 Phase A.

**Experiment block:**
- Hypothesis: kicking the predicted wake CPU ~50 µs early converts deep idle-exit tails into cheap warm wakes; renderer/input mean wake drops below the shared floor.
- Steps: Phase A — timer + counter only, no kick, A/A overhead screen. Phase B — kick, wake-latency capture on render roles.
- Endpoint: `wake-latency capture --match` render/input roles, mean + p99, vs the G21 numbers.
- Abort: A/A overhead visible in severe-frame ratio, or power/thermal artifacts flagged by `noise_class`.

---

## Construct C — class bits riding the vtime word

**Attacks:** gap 2, ccm-memcpy −14.9%. STATE.md already names the lever —
unlike-type SMT pairing with a per-TASK duty class — and records that the per-CPU
veto version regressed futex +57.2 → +29.3. The blocker is that cake's laws
forbid per-task storage, and a duty class is per-task by definition.

**What is new:** cake already owns one per-task word it writes on every stopping:
`p->scx.dsq_vtime`. Vtime is nanosecond-scaled; its low bits are noise below any
ordering decision (time_before comparisons at µs–ms scale). The construct: encode
the duty class in the low 2–3 bits of the vtime it already writes — classification
travels inside the fairness word, zero new storage, zero new cache lines, and the
steal ring / SMT placement can read it wherever it already reads vtime. The class
itself comes from signals cake already stamps: achieved runtime rate with the
sibling busy vs idle (two existing clocks per CPU, no perf counters).

**Design-law check:** complies with no-per-task-storage by construction; the open
question is whether 2–3 low bits ever flip an ordering decision. Bound it: bit 2
= 4 ns; every comparison in the scheduler operates at ≥ SLEEPER_LAG_NS/2¹⁶ scale.
Static argument first, then an A/A.

**Experiment block:**
- Hypothesis: a per-task duty class readable at placement lets unlike types share an SMT core; ccm-memcpy recovers ≥5 points without the futex regression the per-CPU veto caused.
- Steps: Phase A — encode + decode, no consumer, A/A on the sealed set. Phase B — placement consumer in select_cpu only.
- Endpoint: ccm-memcpy and stress-ng-futex exact-pair, 2-block screen then 8-block seal.
- Abort: any A/A drift on futex (the +57.2% is mode-conditional and fragile), or fnspills shows the encode leaking into hot-path spills.

---

## Order

Graph-cut argument: A is cheapest (constant re-denomination, loader-side), sits
on the highest-value gap, and its null still prunes gap 1's mechanism space. C
has the clearest measured target but risks the most valuable sealed win. B needs
a maintainer ruling on the "no timers" absence before any work. Register A first.
