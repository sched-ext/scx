# scx_cake — full codebase review, 2026-08-29

Static review only. No binary was built, no live measurement taken; every
performance figure quoted is copied from its original evidence class (STATE.md
ledger, in-file comments, or the dated docs) with its citation. Basis: tip
`4951242a4` (branch `RitzDaCat/scx_cake-nightly`).

**Method and coverage.** Three independent full read passes — (A) the BPF
object `src/bpf/cake.bpf.c` (2247 lines) + `intf.h`; (B) the loader
(`src/main.rs` + all `src/*.rs` + `build.rs` + `Cargo.toml`); (C) the ledger:
`STATE.md` in full, `DESIGN.md` in full, and the docs layer — plus targeted
verification passes by the synthesizer over `select_cpu`, `dispatch`,
`running`, `stopping`, and the slice/vtime write sites. The 2026-08-27
duplicate/stale review (`REVIEW_DUPE_STALE_2026-08-27.md`) is incorporated;
its Tier-1 correction (§G51/§G52 are registered-with-consumer, NOT dead) is
adopted.

---

## 1. Ops inventory and hot-path classes

Registered ops (`SCX_OPS_DEFINE` cake.bpf.c:2234-2247; flags
`ALLOW_QUEUED_WAKEUP | KEEP_BUILTIN_IDLE` :2244-2245; watchdog 5 s :2246).

| Callback                                        | Line            | Class                                  | Purpose                                                            |
| ----------------------------------------------- | --------------- | -------------------------------------- | ------------------------------------------------------------------ |
| `cake_select_cpu`                               | 1211            | per-wake (99.86% of game dispatches)   | serial handoff → home claim → park → optimistic → ranked/zero-skip |
| `cake_enqueue`                                  | 1702            | per-enqueue (0.14% of game dispatches) | wake-vs-continuation routing, vtime insert, kick                   |
| `cake_dispatch`                                 | 1973            | per-switch                             | search {own, WAKE_DSQ, steal}; re-grant prev; publish idle hint    |
| `cake_running`                                  | 2005            | per-switch                             | stamp run start, frame vote, conditional frontier advance          |
| `cake_stopping`                                 | 2034            | per-switch (hottest per-switch, :2076) | vtime charge (reciprocal, no divide), handoff hint, g46 publish    |
| `cake_update_idle`                              | 2089            | per-idle-transition                    | §G45 census bit+count, §G54 mailbox produce/retract                |
| `cake_enable` / `cake_init` / `cake_exit`       | 2164/2175/2223  | cold                                   | vtime seed; DSQs + census seed; event copy-out                     |
| tp_btf `irq_enter/leave`, `softirq_enter/leave` | 613/620/627/649 | kHz-rate edges                         | live in-handler depth (§G35)                                       |
| tp_btf `cpu_idle`                               | 637             | per-idle-transition                    | §G51-gated cstate write — **never attached** (§4.1)                |

Hot-path cost map (build-attribution receipts, STATE.md unless noted):
select_cpu 426–435 insns / 83 ns @ ~151k calls/s = 12.5k µs/s; dispatch
219→116 ns; spills select_cpu 4/1, enqueue 2/4, stopping 1/1, ring_steal 1/1,
running+dispatch 0/0, TOTAL 16/10/26; `cake_ring_steal` 41 insns 10 branches;
`cake_cpu_tick_soon` 28 insns; `cake_pick_idle_escape` 34 insns; wake-path
floor 80 ns (BPF ~65–70, trampoline 15–20 structural —
AUDIT_COMPONENT_COST_2026-08-23); direct vtime write vs kfunc +28–36% on
stopping (cake.bpf.c:2076-2077, §R.17); 5 static divides at tip (was 11).

## 2. Slice/vtime write-site audit (the kernel deprecation warning)

The kernel emits "Writing directly to p->scx.slice/dsq_vtime is deprecated"
from `bpf_scx_btf_struct_access()` — the BPF **verifier**, i.e. at scheduler
load, once per verifier path exploration containing a direct write; zero
runtime logging cost. Upstream fix (pr_warn_ratelimited + missing newline)
posted 2026-06-24 as v2, Reviewed-by Andrea Righi; pending as of that thread.

| Site                                                              | Verdict                                                                                                                        |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| :129 `cake_set_slice` (direct slice write)                        | OK — §R.17 justification in comment :123-126; sole call site :1979                                                             |
| :2079 `p->scx.dsq_vtime +=` (stopping)                            | OK — justified :2074-2078 (+28–36% kfunc cost, hottest per-switch callback)                                                    |
| :1040 `cake_direct_clamp` (direct dsq_vtime write)                | OK by family, HYGIENE — no § pointer at the site; extend the :1038 comment                                                     |
| :2166 compat `scx_bpf_task_set_dsq_vtime`                         | OK — cold path, correct wrapper choice                                                                                         |
| six `cake_direct_clamp` call sites :1130,1196,1253,1276,1406,1721 | OK — all re-floor the key immediately before a non-vtime insert; :1721 kthread path deliberately flat SLICE_NS (:1724, §G10.4) |

## 3. Findings

Severity: PERF (costs ns on a per-wake/per-switch path), CORRECT,
INVARIANT (CLAUDE.md law), HYGIENE. Each cites file:line.

### 3.1 BPF side

1. `cake.bpf.c:201,641-644` + `main.rs` attach list **[CORRECT]** — §G51's
   `tp_btf/cpu_idle` program is loaded but **never attached** (loader links
   only the four irq/softirq hooks). Consequence (REVIEW_DUPE_STALE §1.1):
   enabling BIOS Global C-State Control will NOT bring §G51 live; the depth
   model stays inert even then. One-line fix in the attach list; do it before
   the BIOS change so the test tests the model.
2. `cake.bpf.c:202,213` **[OK/HYGIENE]** — §G52 `cpu_perf_rank` has no BPF
   reader ("consumer deleted, A/A by construction", STATE.md:79); correctly
   parked per the 8/27 correction (disabled, registered, consumer scheduled).
3. `cake.bpf.c:199,933,2081` **[PERF]** — `cake_tog_g46` measured net
   negative on the new base (sel −9 ns, stopping publish +26 ns; memcpy
   workload win not visible to appsim; STATE.md:224-226). When ON,
   `cake_slice_publish` (:950) recomputes `cake_task_slice` — 2 divides + 2
   clock reads — every stopping. Stays OFF pending its pre-registered seal.
4. `cake.bpf.c:200,541,778,2018,2045` **[PERF, parked]** — m6 occupant mirror:
   NULL on the new base (78 vs 77 ns); maintainer-nominated cleanup
   candidate (STATE.md:227-228; REVIEW_DUPE_STALE §1.5). Same for m7
   (`cake_cpu_curr`/`cake_local_nr`).
5. `cake.bpf.c:1043` **[HYGIENE]** — stale forward declaration of
   `cake_idle_hint_claim` (definition :1354, no earlier caller); residue of
   the select redesign `9254e9cbb`.
6. `intf.h:31` vs `intf.h:78` **[HYGIENE]** — one constant, two names
   (`CAKE_CCD_STEAL_POLICY` exists only to initialise `CCD_STEAL_POLICY`).
7. `cake.bpf.c:1073` **[PERF, scaffolding]** — the DIAGNOSTIC PROBE census
   (per-arm placement counters, commit `4951242a4` "revert before scoring")
   is AT TIP and pays `cake_stat_inc` on every select_cpu path. Must be
   reverted before any scored run; it also feeds the 9-line detach output.
8. Divides: 5 static at tip **CONFIRMED** (source sites `cake_burst_ns` :260,
   `cake_period_ns` :270, `cake_frame_observe` :341; inline expansion accounts
   for the rest). Budget 11, current 5 — compliant.
9. `cake.running` :2026-2027 frontier advance — conditional store on the
   hottest shared line, deliberately branch-shaped (:1999-2003); correct per
   "never re-apply a value already present".
10. `cake.dispatch` :1978-1992 idle-hint publish — test-before-write honored
    (:1990-1991, §G43/§R.10).
11. §G45/§G50-R/§G53/§G54 hardwiring verified against STATE.md:232-234: no
    toggle symbols remain; census :2089-2158 + seed :2200-2214; zero-skip
    :1333-1341; optimistic place :1172-1200; park produce/retract/consume
    :2100-2136/:2143-2156/:1098-1134.
12. `cake_optimistic_place` **[PERF]** — worst spiller in the file
    (4 spill/6 fill, 109 insns; REVIEW_DUPE_STALE §2.1) — it never received
    §G54's `cake_affine` treatment; candidate for the next spill pass.

### 3.2 Loader side

13. `main.rs:214-216` vs `239-244` **[PERF]** — comment claims probe values
    are clamped against host load; `cake_wake_hop_ns = p99` is assigned
    unclamped. A busy-at-launch host (game loading during attach) bakes an
    inflated tick-predictor horizon (cake.bpf.c:564-575) for the whole
    session. Comment/code mismatch + unguarded policy input.
14. `main.rs:990-993` **[CORRECT]** — no restart backoff: a persistent
    kernel restart request loops re-exec → verifier → attach every ≥5 s
    (bounded only by the 5 s watchdog, intf.h:98), re-emitting the verifier
    deprecation warning burst each cycle.
15. `main.rs:190-194` **[CORRECT, latent]** — cpuidle latency table read from
    cpu0 only, applied machine-wide; hybrid E/P hosts would mis-tune §G51.
16. `main.rs:206` **[CORRECT, latent]** — `highest_perf` clamped to u8
    (`.min(255)`); saturating ACPI scales make the §G52 rank silently inert
    (all-equal passes the `perf_seen` guard).
17. `main.rs:435-469` **[HYGIENE]** — exit census prints 9 lines at every
    detach and self-labels "revert before scoring"; stale scaffolding.
18. `main.rs:51-53` vs `:501-509` **[HYGIENE]** — doc contract says
    "identity, attach and exit only"; the first sink-set line fires without
    `--verbose` (contract off by one line; the arms block makes it ten).
19. `main.rs:804-805` **[HYGIENE]** — sink-minority guard degenerates on a
    2-CPU host (never publishes); untested tiny-topology shape.
20. Verified clean: no polling on any BPF hot path; no build-host inputs
    (`build.rs:6-8`; MAX_CPUS the sole refusal, main.rs:148-153); caps
    dropped before the run loop (:393); probe runs pre-attach so it measures
    the stock kernel (:846); stats infrastructure absent — zero cost with no
    client (no scx_stats dependency, Cargo.toml:9-21).

### 3.3 Runtime logging — confirmed silent (closes the 8/29 client question)

- BPF: zero `bpf_printk`/`bpf_trace` calls in the entire scheduler.
- Loader, default run: startup banner, attach line, one possible runtime line
  (first sink set, :501-509), detach lines. Frame clock prints only under
  `--verbose` and only on a >1/16 period change (main.rs:425-432, ≤ ~1/min
  steady). "Nothing in steady state" holds; the literal "zero lines" does not.
- Kernel: the deprecation warning is verifier-time only; every burst
  correlates with a (re)load. Repeated bursts over a day = repeated loads
  (crash loop or restart-request cycles), not runtime spam.

## 4. Invariant compliance

| Law                                         | Status                                                                                                                                                |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Runs on ALL hardware; no build-host input   | PASS (build.rs:6-8; rodata-gated fast paths; MAX_CPUS only refusal)                                                                                   |
| Never sudo; self-elevating helpers          | PASS (caps dropped after attach, main.rs:393)                                                                                                         |
| Event completeness, no polling on hot paths | PASS (userspace sink/frame polls are the only cadence; K1/P2 exist to close them further)                                                             |
| No one-shot startup checks                  | PASS for sinks (§G30 Phase B cadence + Schmitt band) — the one-shot probe falsification is recorded at STATE.md:1079-1087                             |
| Never re-apply state another CPU reads      | PASS (frontier :2026, idle hint :1990, hint field :2070)                                                                                              |
| No divide/modulo on hot paths               | PASS (5 static divides, all in classification/frame math)                                                                                             |
| Spills as proxy; per-function measurement   | PASS (16/10/26; `cake_optimistic_place` flagged above)                                                                                                |
| Comments WHAT-not-HOW, ratio ≤0.7           | PASS (comment_lint 0.69 at §G30 build; no egregious HOW found; two stale comments flagged as HYGIENE)                                                 |
| Cake-ring: no flags, one master algorithm   | PASS with the sanctioned toggle exception (§S.6): g46/g51/g52/m6/m7 remain, each with a recorded reason; m6/m7 are nominated deletions                |
| Docs move with behavior                     | **DRIFT** — STATE.md's board ends 2026-08-23 while docs/ carries 8/25–8/27 material and tip carries the 8/25 census probe; STATE.md needs a sync pass |

## 5. Verified-clean inventory (worth restating)

- No per-task storage; all shared state in 128 B-aligned slots (DESIGN.md).
- Interrupt avoidance is first-class: live in-handler bit, per-line sink
  share, tick look-ahead — no peer scheduler in-tree has an equivalent
  (REVIEW_PANDEMONIUM §2).
- Accounting path below EEVDF (no PELT decay, no cgroup walk, no .tick);
  measured −28% context switches, softirqs halved on both games.
- Zero-warning release+debug, zero spills in running/dispatch.
