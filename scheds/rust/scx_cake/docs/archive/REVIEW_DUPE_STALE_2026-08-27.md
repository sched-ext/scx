# scx_cake — duplicate/stale code review, 2026-08-27

Ground truth: release object `target/release/build/scx_cake-53c56923b961c38a/out/bpf.bpf.o`
(built this session, zero warnings), `bench/fnspills.py`, `llvm-objdump -h/-d`,
kernel `kernel/sched/ext/idle.c`. Nothing here is a performance verdict — static
facts are attribution only.

WARNING for the next session: `target/release/build/` holds FOUR `scx_cake-*` dirs,
three of them from 2026-08-20. Reading the wrong one shows no `cake_update_idle`
and no `tp_btf/cpu_idle` at all. Always pick by mtime.

---

## Tier 1 — CORRECTED 2026-08-27 after maintainer challenge

My first pass filed §G51 and §G52 as "dead, deletable". That was WRONG and the
record says so. Both were measured, and both were kept by explicit maintainer
order four days ago.

STATE.md, TOGGLE AUDIT 2026-08-23: "surviving toggles, each with a reason: ...
g51/g52 (pillar-4 physics inputs, consumers scheduled)". That audit DELETED the
g44/g47/g48 bodies. g51/g52 survived it deliberately.

STATE.md, REMAINING-TOGGLE BENCHMARK 2026-08-23: "g51 unmeasurable (no cpuidle
driver, BIOS decision); g52 unmeasurable (consumer deleted, A/A by construction)."

So they WERE benchmarked. The result is A/A null — which is the argument FOR
keeping them, not against. Pillar 4 names both as the next program: "Physics
inputs feed parking policy at zero wake cost: §G51 depth (needs BIOS Global
C-State Control enabled), §G52 rank, K1 sink self-accounting." §G47 is closed
"revisit only with §G51 depth model live".

Correct classification: **disabled, registered, consumer scheduled.** Not dead.
Do not delete. What follows replaces the deletion proposal.

### 1.1 §G51 — a latent bug in the scaffolding, not dead code
The producer will not work when the blocker is cleared. `main.rs` attaches four
links — `irq_enter`, `irq_leave`, `softirq_enter`, `softirq_leave` — and there is
no `skel.attach()`. `SEC("tp_btf/cpu_idle") cake_cpu_idle` is loaded into the
kernel and never attached, on every host.

The record attributes G51's inertness to one cause: "INERT ON THIS HOST — cpuidle
current_driver is `none`". There is a second, unrecorded cause. Enabling BIOS
Global C-State Control — the action pillar 4 names — will NOT bring §G51 live,
because `cake_irq_live[].cstate` still never gets written. That is a session lost
to a wrong hypothesis, whenever someone flips that BIOS setting.

Fix is one line in the attach list, not a deletion. Worth doing NOW while the
cause is known, so the BIOS change tests the depth model instead of testing the
attach list.

### 1.2 §G52 — correctly parked; one startup cost is toggle-independent
`cpu_perf_rank` having no BPF reader is exactly what "consumer deleted, A/A by
construction" means. Keep.

One real observation survives: the loader fills `cpu_perf_rank` in an unguarded
`for c in 0..*NR_CPU_IDS` loop, outside any toggle test, and the `cake_cstate_exit_us`
loop is unguarded the same way. So a default run with g51=0 and g52=0 still does
`NR_CPU_IDS + 16` sysfs `read_to_string` calls at startup. Startup-only, off every
hot path, and it costs a few hundred microseconds once — note it, do not chase it.

### 1.3 Stale forward declaration (unaffected by the above)
`cake.bpf.c:1043` forward-declares `cake_idle_hint_claim`. Definition is :1354,
first call :1380 (inside `cake_pick_idle_clean`, after the definition). Nothing
between :1043 and :1354 calls it. Residue of the select_cpu redesign (`9254e9cbb`).
Pure syntax, no behaviour, nothing to measure.

### 1.4 One constant, two names (unaffected by the above)
`intf.h:31` `#define CAKE_CCD_STEAL_POLICY 2` exists solely to initialise
`intf.h:78` `CCD_STEAL_POLICY = CAKE_CCD_STEAL_POLICY`. No other reader.
Pure syntax, no behaviour, nothing to measure.

### 1.5 The cleanup the record actually nominates — m6/m7
I missed this. STATE.md, same 2026-08-23 benchmark: "m6+m7 NULL on the new base
(78 vs 77 ns): the mailbox design removed their query sites from the hot path —
**cleanup candidates next audit**." That is a maintainer-nominated deletion with a
measurement behind it, which is more than anything I proposed. m6 spans
`cake_core_contended`, `cake_occupant_live`, `cake_running`, `cake_stopping` and
two `cake_run_slot` fields (`occupant`, `mirror_vtime`); m7 spans `cake_cpu_curr`
and `cake_local_nr`. Removing both also lets `cake_occupant_live` collapse to one
path, which is half of finding 2.3.

## Tier 2 — duplication on the hot paths

### 2.1 `cake_optimistic_place` never got §G54's `cake_affine` — worst spiller in the file
`bench/fnspills.py` on the release object:

    cake_optimistic_place      4 spill   6 fill   10 ops   109 insns   <- worst
    cake_park_take             0 spill   0 fill    0 ops   130 insns

Both are select_cpu subprograms, adjacent in the source, added in the same §G53/§G54
work. `cake_park_take` gates affinity with `cake_affine` (direct `cpus_ptr->bits[0]`
read, rodata-gated on `nr_cpu_span <= 64`). `cake_optimistic_place` still calls
`bpf_cpumask_test_cpu`. Disassembly at `cake_optimistic_place+0x1a4` and `+0x218`:

    819: r2 = *(u64 *)(r3 + 0x598)      ; p->cpus_ptr
    820: call -0x1                      ; bpf_cpumask_test_cpu
    826: r3 = *(u64 *)(r10 - 0x10)      ; reload p  <- fill
    ...
    841: r2 = *(u64 *)(r3 + 0x598)
    842: call -0x1
    843: r3 = *(u64 *)(r10 - 0x10)      ; reload p  <- fill
    853: r3 = *(u64 *)(r10 - 0x10)      ; reload p  <- fill

The two kfunc crossings pin `p` and the candidate cpu to the stack across the loop.
This is precisely the cost §G54 introduced `cake_affine` to remove, and the sibling
that got the helper spills zero.

Fix: swap `bpf_cpumask_test_cpu(ocpu, p->cpus_ptr)` for `cake_affine(p, ocpu)`.
One-line change, same semantics on every host (the helper falls back to the kfunc
above 64 CPUs). Verify with fnspills, then a wallclock screen.

### 2.2 The idle-pick ladder runs twice on the retry path
`cake_pick_idle_clean` (62 insns):
1. `cake_idle_hint_claim`
2. `scx_bpf_pick_idle_cpu(CORE)`
3. if < 0 → `scx_bpf_pick_idle_cpu(0)`
4. if `!cake_cpu_clean(cpu)` → `cake_pick_idle_escape`, which is
   `scx_bpf_pick_idle_cpu(CORE)` then `scx_bpf_pick_idle_cpu(0)` — steps 2 and 3 again
5. then re-evaluates `cake_cpu_clean(alt)`, which `cake_pick_idle_escape` just
   evaluated internally at its own fallback condition

Worst case: four idle-mask scans per wake, and `cake_cpu_clean` — which contains
`cake_cpu_tick_soon`, a `bpf_per_cpu_ptr` plus a `bpf_ktime_get_ns` (28 insns) —
computed twice on the same cpu id.

### 2.3 The same `rq->curr` deref, up to five times per wake
With the default `--toggle m6=0`, one `cake_enqueue_wake(p, tcpu)` can deref
`rq(tcpu)->curr` five times:

| # | site |
|---|---|
| 1 | `cake_enqueue_wake` head: `curr = cake_cpu_curr(tcpu)` |
| 2 | `cake_home_claim` → `cake_occupant_live(tcpu)` |
| 3 | `cake_wake_notify` → `cake_home_notify` → `cake_occupant_live(tcpu)` |
| 4 | `cake_wake_preempt` → `cake_occupant_live(tcpu)` |
| 5 | `cake_wake_preempt` again, directly, for the `cake_starved(curr)` test |

The neighbour probe adds up to three more `cake_wake_preempt` calls, i.e. six more
derefs on other CPUs. `cake_occupant_live`'s own comment says "Five call sites once
computed this identically (§R.11)" — the *arithmetic* was consolidated, the *deref*
was not. #4 and #5 are the cheapest to fix: `cake_wake_preempt` already holds the
slot, and `cake_occupant_live` could return the `curr` it read.

### 2.4 Sleeper clamp spelled three times
Identical branchless max `lo + (d & ~((u64)((s64)d >> 63)))`:
- `cake_wake_vtime` (:991)
- `cake_enqueue` (:1655 `lo`/`d`, :1675 `vt`)
- `cake_pinned_wake_preempt` (:1583 `lo`/`dd`/`pvt`)

### 2.5 `cake_starved` vs `cake_starved_turn`
Byte-identical except `run << 1` on the right-hand side. Both `__always_inline`,
five expansion sites between them (:832 :980 :1195 :1659 :1684). One
`cake_wait_exceeds(p, shift)` covers both.

### 2.6 Smaller repeats
- `cake_qmark_set` / `cake_qmark_clear` differ only in the operator and the mask sense.
- `cake_local_nr` + `cake_cpu_dsq_idle` are called as a pair at :1172-1173 and
  :1341-1342, in opposite order.
- `cake_direct_clamp(p)` + `cake_dsq_insert(LOCAL_ON|cpu, cake_task_slice_cached(p), 0)`
  appears four times in `cake_select_cpu` (serial arm, home claim, `cake_park_take`,
  `cake_optimistic_place`) and once more as `CAKE_DSQ_LOCAL` in the is_idle arm.
- The loader recomputes `cake_sleeper_dose`'s 3/4 shift by hand in
  `publish_frame_clock` (`(f >> 1) + (f >> 2)`), to fill a word nothing reads.

---

## Tier 3 — found while tracing 2.2; a behaviour question, NOT a cleanup

`scx_bpf_pick_idle_cpu` is documented in `kernel/sched/ext/idle.c:1363` as
"Pick and **claim** an idle cpu" — it clears the idle bit. Four sites take a pick
and then discard it without kicking it:

| site | discarded pick |
|---|---|
| `cake_pick_idle_escape` | the CORE pick, when the winner fails `cake_cpu_clean` |
| `cake_pick_idle_clean` | the escape's pick when it loses, or the first pick when it wins |
| `cake_select_cpu` is_idle retry | `alt` when `alt >= 0` but unclean; otherwise the original `cpu` |
| `cake_select_cpu` WAKE_SYNC re-rank | the original `cpu`, replaced by `idle` |

A discarded claim leaves a genuinely idle CPU invisible to every kernel idle scan
until it next *re-enters* idle — and it will not re-enter, because it never left.
Meanwhile `cake_idle_nr` (§G45 census, driven by `ops.update_idle`, which
`pick_idle_cpu` does not call) still counts that CPU idle, so `cake_system_serial`
and `cake_optimistic_place` disagree with `scx_bpf_pick_idle_cpu` about the same CPU.

STATE.md §G38.1 (line ~1366) records the consumption as *intentional* for the CORE
retry ("the pick's test-and-clear consumes the sink's idle bit, which makes the
second CORE try skip it"). It does not address the discard. Kicking the loser with
`SCX_KICK_IDLE` restores the bit; so does reordering the cleanliness test ahead of
the claim. Both change placement, so this needs a screen, not a patch.

---

## Tier 4 — stale documentation contradicting the code

`DESIGN.md` still describes the pre-§R.28 shared-clock geometry:

| DESIGN.md | actual code |
|---|---|
| :49 `cake_frame_slice_ns` "is the geometry unit every patience window shifts from" | zero BPF readers; every window uses `SLICE_NS` |
| :124 wake key on `geom = cake_frame_slice_ns` | `cake_wake_vtime` uses `frontier - SLICE_NS - depth` |
| :121 slice "capped at half a frame" | `cake_task_slice` caps at half the task's OWN cycle, `cake_period_ns >> PERIOD_SLICE_CAP_SHIFT` |
| :133 global wake preempt gate "ran >= frame/16" | `cake_wake_preempt` uses `SLICE_NS >> PREEMPT_PROTECT_SHIFT` |

Also:
- `main.rs:60` `--toggle` help says "(g43, g44, g45, g46)". Accepted names are
  g46, m6, g51, g52, m7.
- `cake.bpf.c:13` and `intf.h:4` point at `HYPOTHESES.md`, merged into STATE.md
  on 2026-08-18.

---

## Already registered, confirmed here

§M2 (STATE.md item 27) — `cake_frame_ns`, `cake_frame_floor_ns`,
`cake_frame_slice_ns` each appear exactly once in the BPF source: their own
declaration. Confirmed decl-only. Worth adding to that item: the producer
`cake_frame_observe` still runs on EVERY `ops.running` (42 insns, 1 spill,
its own `__noinline` frame) and votes into a per-CPU 512-bucket map, to feed
three words that only a `--verbose` log line consumes.
