# Full internal-arithmetic sweep — 2026-08-03 (follow-on to CENSUS_ARITH)

Whole-file source read of `cake.bpf.c` at `3fb89cf05` (post-R.24), every hot-path
arithmetic site classified. Verdict shorthand: **OPT** = already optimal, mechanism
named; **CAND** = live candidate with an internal test planned; **PARKED** = owned by
another registered hypothesis.

## Already optimal (do not re-derive)

| site | arithmetic | why it is already right |
|---|---|---|
| sleeper clamp (enqueue, wake_vtime, pinned) | `lo + (d & ~((s64)d>>63))` | branchless house template, unpredictable branch avoided |
| vtime charging (stopping, occupant_live) | `used * recip_weight[idx] >> 20` | reciprocal table; overflow split at `FAST_MAX` with `__noinline` slow arm; fast-arm branch perfectly predicted |
| `cake_starved` | `wait·n > run·pc` after `>>RATIO_SHIFT` | cross-multiplied already; pre-scale truncation is accepted by design (§G12 — a definition, not a tuning) |
| `cake_system_serial` | `nr*4 >= span*3` | cross-multiplied; cost is the idle-mask kfuncs, not arithmetic |
| `cake_wake_vtime` cadence divide | div behind the starved test | LLVM sinks it — common path pays nothing (verified in object, insn 341) |
| qmark set/clear/test | test-before-store | §R.10, RFO elision |
| hint machinery (stopping) | shifts+masks, conditional store | cheap; store elided when unchanged |
| steal ring indexing | two constant-start half-loops | no modulo by design (§R.7) |
| ring/probe wrap | `cand++; if(>=span) cand=0` | mask impossible (span not pow2), already branch-cheap |
| R.24a/b divides | cross-multiplied, 2^32 fast/slow | this campaign, measured 2026-08-03 |

## Live candidates (this sweep's output)

**A. `cake_task_slice` clamp-arm pre-check.** `want = (S/n)<<1` then clamp to
[handoff_max≈1.46µs, cap≈2.08ms@240Hz]. Any task whose doubled burst falls outside the
clamp does not need the quotient — `2S < H·n ⟹ floor arm`, `2S > cap·n ⟹ cap arm`
(exact by the §R.24 algebra; wide operands take the divide as before). Mid-arm tasks
pay +2 imul. **Decision needs the arm distribution** — if game/desktop regimes are
floor/cap-dominated, the divide almost never runs; if mid-dominated, this is a loss.
Internal test: DIAG_SLICE_{CALL,FLOOR,CAP} counters.

**B. `cake_frame_observe` call elision.** Post-R.24a the divide is gated, but every
`ops.running` still pays the `__noinline` call (r1–r5 clobber, call+ret) just to take
the early return. Hoist the cross-mul band gate into an `__always_inline
cake_frame_in_band()` used by `cake_running` (single definition — no duplication), call
the `__noinline` body only when in-band or wide-n. Exactness trivial (same gate, same
fallback). Internal test: DIAG_RUNNING vs DIAG_FRAME_INBAND gives the elision rate;
arith_price's `call` row prices the saving.

**C. Stale comment (free fix).** `cake_cadence_depth`'s block comment still says
"Burst estimate is sum_exec >> log2(nvcsw) — no map, no division" — false since §G11
made `cake_burst_ns` an exact divide. Comment-only; verify by disassembly diff.

## Parked territory (not this sweep's to touch)

- **Steal-ring walk** (93–98% of dispatches, ~1% hit) — G25, registered.
- **`cake_pinned_wake_preempt` + sibling kick deletion** — G24 resume item 2 (dead at
  fifth zero dataset); deleting them removes their arithmetic wholesale.
- **Syncgate simplification** — G24 resume item 3.

## The internal test rig

1. **`bench/arith_price.c`** (this commit) — silicon prices for add/imul/div/call and
   the slice_old vs slice_new shapes per arm. Diagnostic, non-ingesting.
2. **Diagnostic counter commit** (G24 pattern `018fbe1d5`: PERCPU_ARRAY + non-atomic
   inc + loader `report_diag` at detach; revert after, verify empty source diff).
   Six slots: RUNNING, FRAME_INBAND, SLICE_CALL, SLICE_FLOOR, SLICE_CAP,
   WIDE_FALLBACK (expect 0 — proves 2^32 fast-arm coverage). Run under
   `helldivers2-mission-fitted.conf` appsim + ambient desktop, ~60 s each.
3. **Decision rule, registered up front:** implement A only if (floor+cap) ≥ 50% of
   slice calls in BOTH regimes (else the +2 imul mid-arm tax loses); implement B if
   the in-band rate is < 20% (expected: only frame threads are in-band). Screen any
   implemented change at `--blocks 2` as R.24; same kills.
