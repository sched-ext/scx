# Ledger repair + regime gate (gear Gate 1)

Date: 2026-07-24
Status: completed arc — offline analysis over sealed evidence, no new runs

## Summary

Two results, one enabling the other:

1. **The experiment ledger was recording every sealed transaction as a
   0.000% dead heat.** `bench/scx_cake_ledger.py` read the analysis block off
   `COMPLETE.json`, which does not contain one, and defaulted the miss to `0`.
   All 133 complete rows carried `b_good_median_pct: 0`, `ci_lo: 0`,
   `ci_hi: 0`, `blocks: null`. Fixed; the ledger now holds 149 complete
   transactions with real verdicts.
2. **Gear Gate 1 passes.** With the repaired ledger, offered background load
   predicts cake's delta against native across 125 workload-centred
   transactions: **rho = −0.42, t = −5.15**. The regime is a real, large,
   exogenous covariate — the gear direction has an input worth conditioning on.

No benchmark was run for either result. Everything here is a re-read of
evidence already sealed in `runs/exact_pair/`.

## 1. The ledger bug

`scx_cake_ledger.py` built each row as:

```python
primary = (d.get("analysis") or {}).get("primary") or {}   # d = COMPLETE.json
...
"b_good_median_pct": round(primary.get("observed_median_pct", 0), 3),
"ci_lo": round(primary.get("ci_lower_pct", 0), 3),
"ci_hi": round(primary.get("ci_upper_pct", 0), 3),
```

`COMPLETE.json` carries only the seal — hashes, authorization flags,
`block_count`, `evidence_tier`, `statistical_classification`. The analysis
(`primary.observed_median_pct`, `ci_lower_pct`, `ci_upper_pct`) lives in
`pair_result.json`. So `analysis` was always absent, `primary` was always `{}`,
and the `, 0)` defaults converted "no data" into "a perfect tie with a
zero-width confidence interval."

**Why this mattered more than a normal parsing bug.** The failure was
*plausible*: a consumer reading the ledger saw 133 well-formed rows with valid
run ids, workloads, git heads, tiers, and noise covariates, every one of them
reporting that the mutation changed nothing. HYPOTHESES H5 lists the ledger as
**BUILT** and designates it the AI-steering data source; anything that had
learned from it would have concluded that no mutation in the corpus ever moved
a benchmark. It is the exact shape of the project's own iron rule 12 — evidence
that looks like a result and is not one — occurring inside the tooling meant to
enforce that rule.

**Fix:** read `analysis` from `pair_result.json` (falling back to
`COMPLETE.json`), default every numeric to `None` rather than `0`, take
`blocks` from `primary.block_count or COMPLETE.block_count`, and carry
`statistical_classification` through. Validation: the sealed pipe transaction
`exact_pair_20260717T195140Z_6d5dcf64fbee` now reads **+22.72%,
CI [+21.08, +24.89], 8 blocks**, matching STATE.md's sealed +22.7%
CI [+21.1, +24.9] exactly.

The rebuild also picked up 16 transactions logged since the ledger was last
generated on 07-20.

> The fix is **uncommitted** in `scx_cake_bench_assets`, consistent with that
> repo's existing long-lived working tree.

## 2. External CPU is partly an outcome, not only an input

The first pass regressed delta against the **cake arm's** external CPU and
found that transactions with large inter-arm asymmetry carried a median
|delta| about 5× larger than well-matched ones — which reads like a validity
crisis (16% of sealed transactions "contaminated").

It is not. Inspecting the 22 high-asymmetry rows shows a consistent shape:

| workload | delta | cake-arm ext CPU | native-arm ext CPU |
|---|---|---|---|
| stress-ng-futex | −84.0 | 94.7 | 286.0 |
| stress-ng-futex | −83.6 | 60.6 | 275.6 |
| stress-ng-futex | −82.9 | 55.1 | 274.9 |

Cake's arm is *quieter*, native's is *busier*. That is not the harness handing
cake an easier ride — it is the mechanism STATE.md already documented: under
external compute pressure cake starves the background work (UnrealEditor to
~50%) while native lets it run (260–295%). **The asymmetry is co-produced with
the delta by the scheduler under test.**

Consequence for all future corpus analysis: `ext_cpu_cake_med` is *endogenous*
and must not be used as a regime variable — conditioning on it means
conditioning partly on cake's own behavior. Use **`ext_cpu_native_med`**, the
load the host offered under a fixed reference scheduler. This sharpens
HYPOTHESES H2 from "arms are only comparable with their covariates" into a
usable rule about which covariate is an input.

## 3. Gate 1 — regime predicts outcome

Regressing against the native arm's external CPU (Spearman):

| workload | n | rho | t | quiet half | loaded half |
|---|---:|---:|---:|---|---|
| stress-ng-futex | 28 | **−0.63** | **−4.2** | +10.97 (ext ~4%) | **−82.15** (ext ~275%) |
| perf-sched-pipe | 19 | −0.45 | −2.1 | +21.27 (ext ~7%) | +10.14 (ext ~225%) |
| futex-lock-pi | 19 | −0.35 | −1.5 | −71.82 (ext ~228%) | −71.88 (ext ~233%) |
| schbench-light | 33 | −0.13 | −0.7 | −2.24 (ext ~4%) | −8.95 (ext ~270%) |
| mutex-handoff | 13 | **+0.48** | +1.8 | +0.66 (ext ~4%) | **+7.56** (ext ~232%) |
| ccm-memcpy | 7 | −0.11 | −0.2 | −14.82 | −13.02 |
| ccm-cache | 6 | +0.58 | +1.4 | +45.46 | +56.13 |

**Pooled, workload-centred: rho = −0.421, n = 125, t = −5.15.**

Readings:

- **N4 is confirmed at corpus scale.** The contention collapse was previously
  argued from a handful of mutation-L survival runs. It is now a 28-transaction
  regression on futex with a 93-point swing between regimes, plus a consistent
  pooled effect across seven workloads. N4 stays the top target and is no
  longer an inference from anecdote.
- **schbench-light's weak rho is a distribution artifact, not a null.** Its
  transactions are bimodal (mostly ~4% or ~270%, little in between), so rank
  correlation is weak while the half-split reproduces the documented
  −1.4 → −9.6 deepening almost exactly (−2.24 → −8.95).
- **futex-lock-pi's corpus is almost entirely loaded** (both halves ~230%).
  Its famous −71.8% plateau was therefore measured almost entirely in the bad
  regime — independent confirmation of the 07-19 evening finding that "the
  plateau WAS the regime," now visible at n = 19.
- **mutex-handoff inverts.** It is the only workload that *improves* under
  load (+0.66 → +7.56). It is also the Wayland-input shape — the closest
  registered proxy for the game case. A single global gear would be wrong:
  whatever cake does under contention is already right for input-shaped
  latency and wrong for throughput-shaped work.

## 4. S3 (futex host-state modes) survives, and sharpens

Restricting futex to quiet rows only (native ext CPU < 20%, n = 16, actual
range 3.4–5.2% — flat) still spans **−53.2% to +61.4%**, a 114-point spread
with load held constant. Load does not explain the futex mode.

The structure of that spread is informative:

- the −52/−53 cluster is entirely pre-S1 heads (`f40192df5`, `6c7d05295`,
  `f30cac430`, `6149a4076`) measured on 07-20;
- the +57/+61 cluster is S1/S1d (`992d88bd1`, `afb9994`, `ee9fc1c`);
- and `6f4252f2` — a **pre-S1** head — read **+57.2%** on 07-18 at 3.4%
  external CPU.

So both prior claims reproduce independently from the ledger: S1 is worth
~+65 pt within 07-20, *and* the same pre-S1 code reads +57.2 on 07-18 versus
−52 on 07-20 under identical load. The mode is real, and it is neither code
nor offered load. It remains the open S3 question.

## 5. What this changes

- **Gear direction: Gate 1 answered YES.** There is a large, exogenous,
  measurable regime covariate. Gate 2 (per-event capture retention in the
  broker's `--observe` path) is now the blocking item for building a
  controller, and `sched.data` retention should be turned on before the next
  contended capture rather than after.
- **A gear must not be global.** mutex-handoff's inversion means the correct
  target is a regime-conditional operand whose sign differs by workload
  *shape*, not a single machine-wide "contended mode." That is a materially
  harder design than the 07-24 sketch assumed, and worth knowing before any
  BPF is written.
- **Any past conclusion drawn from the ledger is void** (it was all zeros);
  any past conclusion drawn from `ext_cpu_cake_med` as a regime variable needs
  re-reading against the endogeneity above.
- **Cheap follow-up, still offline:** join the repaired ledger to HYPOTHESES
  node tags by git head, and re-run the per-workload split with
  `statistical_classification` as a filter to separate trusted from
  diagnostic-tier rows.
