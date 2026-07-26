# scx_cake hypothesis graph

**The research structure (adopted 2026-07-19).** Nodes are mechanism claims with an
evidence status; edges are dependencies. Rules of use:

- **Before building any mutation, place it on this graph.** If every parent is
  FALSIFIED, do not build it. If a parent is OPEN/UNTESTED, test the parent first
  (cheapest discriminating experiment — usually a census or observed pair, ~4 min).
- **Pick the next experiment by graph cut**: the one that prunes the largest open
  subtree, not the next item in a queue.
- **A falsification propagates**: mark every descendant blocked-by-falsified rather
  than re-testing it. A regime qualifier (like R1 below) re-opens descendants only
  for that regime.
- Statuses: `CONFIRMED(evidence)` / `FALSIFIED(evidence)` / `OPEN` / `REGIME(x)` —
  true only in regime x. Regimes: **Rq** quiet desktop, **Rc** contended (external
  compute ≥1 core).

Legend: `<-` depends on. Evidence = STATE.md gap list + runs/exact_pair + memory.

---

## G1. Wake service under load (the trunk)

- **N1 CONFIRMED(Rq)**: "wakeups global, continuations local" is the winning routing
  law in quiet regimes (+57 futex, +23 pipe, +49 schbench-sat, 2026-07-17/18).
- **N2 CONFIRMED**: sleeper clamp quantizes vtime — erases head identity AND preempt
  deservingness. (Falsified F-vtime-identity; falsified G/H margins.)
- **N3 CONFIRMED(Rq)**: stranded tail wake ≡ storm head — no state signal separates
  them; extra wake service of any form re-splits handoff pairs. (7 falsifications,
  arc 2026-07-19.) *Regime-qualified 2026-07-19: proven in Rq only.*
- **N4 OPEN (TOP TARGET)**: under Rc, wake-global service degrades to slice cadence —
  ALSO audible: benchmark-storm saturation starves the GoXLR Utility audio app under
  BOTH schedulers (overrun bursts in native AND cake windows, 2026-07-19 call) — the
  criticality-protector direction (standing direction 2) attaches here as N4d OPEN:
  protect the active audio/input chain under saturation; a win here is user-audible.
  cake futex 2.05M→0.35M (−82%) while native holds BOTH workloads; kworker p99 17ms;
  schbench-light −1.4→−9.6. `<- N1` (the same routing law is the suspect).
  Discriminator: load-ladder observed pairs (idle→1c→3c external compute), curves for
  cake AND native. Children (all OPEN, blocked on N4 evidence):
  - N4a: bounded wake service is safe in Rc even though falsified in Rq (N3 may not
    transfer — the falsifying regressions were Rq futex storms).
  - N4b: the collapse is occupant-slice waiting (no preempt for globals mid-slice).
  - N4c: the collapse is WAKE_DSQ ordering (herd position), not slice waiting.
- **N5 CONFIRMED**: pinned tasks (user AND kthread) bypass the wake path; unpinned
  service can never reach them. (Census 2026-07-19; basis of K and L.)
  - N5a **CONFIRMED**: pinned-user-wake preempt by raw depth recovers lock-pi
    −86.6→−71.8 (K, kept; 8-block). Residual −72 plateau: **N5b OPEN, narrowed
    2026-07-19** — branch census (tag `archive/lockpi-plateau-diag`): 82% of pinned wakes
    land on IDLE-owned CPUs (core rescheds; healthy), busy targets split ~50/50
    fired(22k)/margin-refused(20k). K2 null ⇒ refusals alone aren't the tail either.
    **RESOLVED 2026-07-19 evening: the plateau WAS the regime.** Under the day's
    contended host, K+L measure lock-pi at −3.8% CI[−6.5,−1.1] — near parity from
    −86.6. (Run exact_pair_20260719T183137Z; UnrealEditor 200-300% during arms.)
    Remaining −3.8 may close in true Rq — measure when actually quiet.
  - N5c **CONFIRMED**: all-kthread local insert fixes watchdog eviction (L, now 5/5
    survival incl. two Rc runs where baseline died in the same session). Futex
    score-neutrality UNMEASURABLE vs baseline under Rc (baseline evicts); the −80.8
    reading is N4's collapse (mutation-independent: J −83.6, L −80.8, L-survival
    −82.x all within noise of each other). Pending: TRUE-Rq score check + game gate.
- **N6 FALSIFIED**: ops.quiescent can be registered casually — costs futex −84% at
  stage 0 via core fast-path loss (J). Any future sleep-marker needs a different hook.
- **N7 OPEN (kernel lane)**: waker-intent signal (handoff vs tail wake) would escape
  N3 in Rq. Blocked on kernel patch; only relevant if N4 work doesn't subsume it.

## G2. The cache/memcpy share trade

- **M1 CONFIRMED**: ccm trade is CPU-share reallocation (sleeper catch-up), equal
  per-usr-s efficiency; zero-sum in share space. (2026-07-18 attribution.)
- **M2 CONFIRMED**: unlike-type SMT pairing raises memcpy efficiency +73% — total
  throughput headroom exists (pinned diagnostic; feasibility 347/480 CPU·s).
- **M3 FALSIFIED**: stochastic drift (v1/v2) can produce segregation — wake remixing
  defeats it. `<- M2`
- **M4 FALSIFIED**: per-CPU class marks + wake-veto — collides with futex homing
  (−28pt). `<- M2`
- **M5 OPEN**: per-TASK duty class with handoff-exempt wakes achieves segregation.
  `<- M2, blocked-by-lessons M3+M4+N6 (no quiescent hook; marker must avoid the
  wake fast path)`. Discriminator: needs a class-bit design that survives N6.
- **M6 OPEN (kernel lane)**: PMU kfunc for true memory-boundness classes. `<- M5`

## G4. Ordering structure (opened 2026-07-19; visual review artifact fb054574)

- **S0 CONFIRMED**: cake is not tree-free — vtime DSQs are kernel rb_root_cached
  (same family as EEVDF); the architectural difference is SHAPE (forest of tiny
  trees + FIFO/direct bypasses + lockless peeks), and position is chosen once at
  enqueue by key computation — "better key" is the cheap lever, in-place reorder
  the expensive one, preemption the structure-bypass.
- **S1 CONFIRMED (2026-07-20, mode-Rq)**: cadence-proportional sleeper depth
  (built 0ce54fb27) recovers futex +65pt in the degraded quiet mode (1.4M→3.3M,
  3× reproduced; 8-block +12.2% vs native) and holds pipe/ccm/sat at sealed
  values; schbench-light cost ~0.8pt (8-block trusted −2.24 vs −1.42 pre-stack).
  Game gate still mandatory before ship (2026-07-10 service-margin WoW caution).
- **S3 OPEN (NEW 2026-07-20): futex host-state MODES** — identical code+boot+
  regime reads 4.7M / 1.4M cake while native is flat; winning mode = high-ctxsw
  handoff churn (283M), losing mode = occupant-stall (84M). The host variable is
  UNKNOWN (not external CPU, not kernel, not boot, not code). Discriminator:
  census wake-queue composition + occupancy at bench start in both modes; find
  and force the 4.7M mode. All historical futex deltas must be read mode-tagged.
- **S2 OPEN (speculative)**: bounded-horizon bucket ring — the clamp bounds live
  keys to a 2-slice window, the textbook calendar-queue case: 64 bucket-DSQs of
  slice/32, ffs-bitmask dispatch, O(1) both ends, 94 µs ordering precision, global
  lock pressure diffused across 64 queues. `<- S1` (buckets are only as good as
  the key; prove S1 on rb-trees first, then the ring is a pure-speed refactor).
  Risks: frontier-rotation bookkeeping, verifier budget, starvation proof rebase.

## G3. Harness/evidence (meta)

- **H1 CONFIRMED**: aggregate scores cannot localize losses; decision-level evidence
  (observatory/census) finds mechanisms in single runs. (schbench, lock-pi, P0.)
- **H2 CONFIRMED**: noise covariates expose scheduler-dependent background treatment
  — arms are only comparable WITH their covariates (UnrealEditor 260% vs 50%).
- **H3 CONFIRMED**: guard verdicts are regime-relative; compare same-day same-regime
  baselines only. (schbench −9.6 baseline shift.)
- **H4 OPEN**: replay simulator would rank policies offline (roadmap #2, unbuilt).
- **H5 ADOPTED (maintainer direction 2026-07-19)**: the master formula exists but is
  CONDITIONED — it must take regime + workload behavior as inputs. Prerequisites:
  (a) machine-readable experiment ledger — BUILT but was EMITTING ZEROS until
  2026-07-24: it read the analysis block off `COMPLETE.json` (which has none)
  and defaulted to `0`, so all 133 sealed rows read as perfect ties. Repaired
  to read `pair_result.json`, numerics default `None`; now 149 transactions
  with real verdicts, validated against the sealed pipe row. Any prior
  ledger-derived conclusion is void.
  (b) behavioral catalog per benchmark/game — decision-stream signatures (wake
  cadence, burst distribution, dependency shape) as formula inputs. OPEN.
- **H6 CONFIRMED (2026-07-24, gear Gate 1)**: offered background load is a real
  exogenous predictor of cake's delta — pooled workload-centred rho = −0.42,
  n = 125, t = −5.15; futex quiet→loaded +10.97 → −82.15 (rho −0.63, n=28).
  This is N4 confirmed at corpus scale rather than from survival runs.
  **Sub-finding H6a:** `ext_cpu_cake_med` is ENDOGENOUS (cake starves
  background work under contention — the covariate is co-produced with the
  delta); regime analysis must use `ext_cpu_native_med`. Sharpens H2.
  **Sub-finding H6b:** mutex-handoff — the Wayland-input shape — is the only
  workload that IMPROVES under load (+0.66 → +7.56, rho +0.48). A single
  global gear is therefore wrong; the gear must be conditional on workload
  shape, not machine-wide regime. → `docs/LEDGER_REPAIR_AND_REGIME_GATE_2026-07-24.md`

## Current graph cut (what to test next, in order)

0. **Gate 2 — `sched.data` retention in the broker `--observe` path.** Blocking
   item for the gear controller and for any per-event N4 attribution; must be
   on BEFORE the next contended capture, or that window yields aggregates only
   (as all ten prior observed transactions did). Harness work, justified by a
   named measurement.
1. **N4 discriminators** — load-ladder observed pairs (blocked until quiet host to
   build the ladder cleanly; can run under any regime since load is controlled).
   *Note (2026-07-24): N4's direction is now CONFIRMED at corpus scale by H6;
   what the ladder still owes is the per-event mechanism, not the existence of
   the effect.*
2. **N5c gates** — Rq futex score check for L + game gate (needs quiet host / game).
3. **N5b** — census the lock-pi −72 plateau.
4. **M5** — design the class bit within N6's constraint.
