# Audit: operation cost ladder and site map

2026-09-15. Source `ca4b7218b` (checkpoint tag `cake-checkpoint-20260915b`).
Supersedes `AUDIT_COMPONENT_COST_2026-08-23.md` (now in `archive/`), which priced
kfuncs per callback at `070e0af86`; §G44/§G49/§G86 and today's four commits have
since changed the sites. This file adds the tiers below the kfunc (stack ops,
atomics by line state, cross-core reads, clock sources) and a per-path bill.

Static attribution only. Every ns figure is an estimate for this host (9800X3D,
Zen 5, ~5.2 GHz, kernel 7.2.5) unless it cites a `cake-bpfstats` receipt. Static
counts are build attribution, never a performance verdict (CLAUDE.md).

Method: `fnspills.py` and `llvm-objdump -dr` on the release object with
`cake_tog_probe` folded to 0, so LLVM removes what the verifier removes at attach.
The verifier-pruned program itself was not dumped (`bpftool prog dump xlated`
needs the scoped helper extended); the probe-folded object is the stand-in.

For native instruction costs versus compiler/BPF/JIT expansion on the 9800X3D,
see [§7](#7-native-instructions-versus-bpf-cost-on-the-9800x3d).
Sections 1–6 retain their historical source and estimates; §7 is a separately
dated reference, not a revalidation of those estimates against current Cake.

**October 1 correction from actual current-kernel JIT captures:** folding a
rodata-controlled branch does not guarantee removal of its volatile load or
all weak-symbol address materializations. Four such address moves were removed
from native-bitops select_cpu by moving validation to the loader; flag reads
still remain. See the [assembly review](research/jit-bitops-prototype/ASSEMBLY_PIPELINE_REVIEW_2026-10-01.md).

**Instruction-model qualification:** installed LLVM 22.1.8 maps `znver5` to
`Znver4Model` and assigns ENDBR64 a 100-uop placeholder. Do not treat its cycle
output as calibrated 9800X3D timing. See the
[simulation and model audit](research/jit-bitops-prototype/FASTCALL_SIMULATION_2026-10-01.md).

**October 2 measured update:** [§10](#10-local-hardware-costs-and-further-instruction-passes-2026-10-02)
adds actual 9800X3D PMU measurements, mask costs, and further release experiments.
The dated missing-evidence statements in §§7–9 describe their original snapshots.

## 1. Cost ladder — fastest to slowest

| Tier | Operation | Cost | What moves it between tiers |
|---|---|---|---|
| 0 | rodata conditions, `bpf_ksym_exists`, `barrier_var` | Conditional pruning; surrounding loads/moves can survive | Inspect the actual JIT; do not assign zero cost from C alone |
| 1 | register op, task-struct field load (task line is in cache) | ~0.2 ns | — |
| 1 | BPF stack store | ~0.2 ns (store buffer) | none; frame ≤512 B on the kernel stack, always L1 |
| 1 | BPF stack reload | 4 cycles ≈ 0.8 ns exposed, ~0.3 ns overlapped | exposed when the next branch consumes it |
| 2 | own-line load/store (this CPU's `run[]` slot, own `irq_live` slot) | ~1 ns | — |
| 2 | read-mostly shared line (`cpu_irq_hot_words`, rodata masks, `qmask` when unchanged) | ~1–4 ns (L1/L2 hit) | becomes tier 5 right after another CPU wrote it |
| 3 | BPF-to-BPF call (`__noinline`) | ~2–4 ns + spills of r1–r5 live values | live values across the call |
| 3 | lock-prefixed atomic, line owned | ~20 cycles ≈ 4 ns | tier 6 if another CPU holds the line |
| 4 | kfunc / helper call, no lock: `scx_bpf_now`, `bpf_get_smp_processor_id`, `scx_bpf_get_idle_cpumask`+put, `scx_bpf_cpu_curr`, `scx_bpf_dsq_nr_queued(LOCAL_ON)` | ~10–20 ns (trampoline + body) | `cpu_curr` adds a remote rq line read (tier 5) |
| 4 | `bpf_ktime_get_ns` | ~20–25 ns (clocksource) | — |
| 4 | `bpf_task_storage_get` (exists) | ~20–40 ns | + allocation on first sighting (`F_CREATE`) |
| 5 | cross-core read of a line another CPU writes (`irq_live[c]`, remote `run[c].stamp`, `rq->curr`) | 60–100 ns miss, only if the owner wrote since the last read | frequency of the owner's writes |
| 5 | `bpf_per_cpu_ptr` + remote `evtdev->next_event` | tier-4 call + tier-5 read | — |
| 6 | user-DSQ kfunc: `dsq_nr_queued(id)`, `dsq_peek`, `dsq_insert(_vtime)`, `dsq_move_to_local` | +30–60 ns `rhashtable_lookup` (`ext.c:310`) on top of the body | no cache in the API; only fewer calls help |
| 6 | lock-prefixed atomic, line contended (`qmask` word, multi-LLC `wake_mark`, idle mask `test_and_clear`) | 50–100 ns | contention = other CPUs' write rate on that line |
| 7 | DSQ raw spinlock (inside insert/peek/move) | µs under a wake storm, tens of ns idle | number of CPUs inserting/consuming the same pool |
| 7 | rq-lock switch on a remote move (`unlink_dsq_and_switch_rq_lock`) | ~100s of ns; two rq locks | every pool consume and every steal |
| 8 | `scx_bpf_kick_cpu(IDLE)` | kicker: irq_work, delivered when IRQs re-enable (from a hardirq: after the whole handler, 19–31 µs on the nvidia ISR); kicked CPU polling in MWAIT C1 (this host, no cpuidle driver): a flag store, exit < 1 µs, no IPI; a CPU in a real C-state (`acpi_idle` hosts): IPI + exit latency, µs | whether the target polls (2026-09-18) |
| 8 | `scx_bpf_kick_cpu(PREEMPT)` | kicker as above; the victim is running, so it pays a real IPI (~1–2 µs) and loses the rest of its slice. A `LOCAL_ON` insert with `ENQ_PREEMPT` delivers the same resched under the rq lock the enqueue already holds, with no irq_work | — |
| 9 | attach / detach (bypass mode, all tasks reclassed) | tens of ms system-wide | inherent to sched_ext |
| 9 | watchdog (`WATCHDOG_TIMEOUT_MS` = 5000) | forced unload to EEVDF | a runnable task stalled 5 s |

Recorded anchors (`cake-bpfstats`, 12 s KovaaKs menu, STATE.md `:1700`): 1.1.3
select 58 / dispatch 20 / running 26 ns per run; the §G77b stack select 116 /
dispatch 79 / update_idle 33 / running 58 ns. Dispatch at 78k runs/s measured
111–120 ns/run on the game cores (bpfstats 2026-09-02, source comment `§G76`).

## 2. Site map — where each operation class lives

Lines are `src/bpf/cake.bpf.c` at `ca4b7218b`. Static counts from the probe-folded
object; `insns` is the function's instruction count there.

### 2.1 Per hot function

| Function | insns | stack st/ld | kfuncs (ladder arms collapsed) | helpers | atomics |
|---|---|---|---|---|---|
| `cake_select_cpu` | 467 | 4 / 5 | `cpumask_test_cpu`×3, `get_idle_smtmask`+put ×2, `test_and_clear_cpu_idle`×1, `dsq_nr_queued`×1, `dsq_insert`×1 | `smp_processor_id`×1, `task_storage_get`×1 | 0 |
| `cake_enqueue` | 366 | 3 / 20 | `dsq_insert`×2 sites, `dsq_nr_queued(LOCAL_ON)`×1, `kick_cpu`×1 | — | 3 (qmark, test-before-set) |
| `cake_dispatch_search` | 637 | 5 / 28 | `dsq_nr_queued`×2, `dsq_move_to_local`×2 sites, `get_idle_cpumask/smtmask`+put ×2, `kick_cpu`×2 | — | 1 (seat/offer path) |
| `cake_running` | 149 | 7 / 6 | `scx_bpf_now`×1 | `task_storage_get`×1 (gated), `map_lookup`×2 (seat lock, gated) | 2 (seat, gated) |
| `cake_stopping` | 239 | 18 / 22 | — | `task_storage_get`×1 (stage block only), `map_lookup`×2 (HOLD only) | 2 (HOLD only) |
| `cake_pick_idle_clean` | 344 | 11 / 15 | `get_idle_cpumask/smtmask`+put, `test_and_clear`×2, `pick_idle_cpu`×2 (fallback) | — | 0 |
| `cake_claim_warm` | 265 | 5 / 6 | `get_idle_cpumask/smtmask`+put, `test_and_clear`×2 | — | 0 |
| `cake_ring_steal` | 162 | 1 / 5 | `dsq_move_to_local`×2 sites | — | 0 |
| `cake_offer_remote` | 249 | 4 / 3 | `get_idle_cpumask/smtmask`+put, `test_and_clear`×1, `kick_cpu`×1 | — | 1 (`xchg`) |
| `cake_take_remote` | 71 | 0 / 0 | `dsq_move_to_local`×1 | — | 1 (`xchg`) |
| `cake_occupant_live` | 49 | 0 / 0 | `scx_bpf_now` | (via `cake_cpu_curr`) | 0 |
| `cake_handoff_yields` | 61 | 0 / 0 | `scx_bpf_now` | (via `cake_cpu_curr`) | 0 |
| `cake_task_slice` | 36 | 0 / 0 | — | `ktime`×1 | 0 |
| `cake_cpu_tick_soon` | 22 | 0 / 0 | — | `per_cpu_ptr`×1, `ktime`×1 | 0 |

### 2.2 Per operation class

| Class (tier) | Sites | Function: lines |
|---|---|---|
| user-DSQ kfunc (6) | 19 | `select_cpu` 1607 · `enqueue_wake` 1937, 1953 · `enqueue` 2108, 2129, 2143 · `ring_steal` 2220, 2226, 2246 · `llc_pool_rescue` 2317, 2324 · `take_remote` 2352 · `dispatch_search` 2413, 2419, 2490, 2498, 2511, 2533 · probe 1227 |
| builtin-DSQ kfunc (4) | 8 | `select_cpu` 1608, 1613, 1660, 1718, 1738 · `enqueue` 2041, 2102, 2147 |
| idle-mask `test_and_clear` (6) | 7 | `select_cpu` 1704 · `pick_idle_clean` 1766, 1776 · `offer_remote` 1808, 1852 · `idle_count` 1399, 1406 |
| idle-mask get/put (4) | 16 | `core_contended` 938 · `pick_cold` 1142–1143 · `idle_count` 1353, 1383, 1386 · `pick_idle_clean` 1754–1755, 1785, 1787 · `offer_remote` 1800, 1802 · `dispatch_search` 2423, 2446, 2535, 2543 |
| remote rq read `cpu_curr` (4+5) | 8 | `occupant_live` 884 · `core_contended` 943 · `groove_of` 1313 · `handoff_yields` 1452 · `select_cpu` 1651, 1707 · `enqueue_wake` 1924 · `enqueue` 2093 |
| remote slot read `irq_live` (5) | 8 | `core_irq_bad` 658–659 · `cpu_clean` 695 · `select_cpu` 1604, 1649, 1693 · `pick_idle_clean` 1764 · `offer_remote` 1850 |
| remote per-cpu tick read (5) | 1 | `cpu_clean` 695 (→ `cpu_tick_soon`) |
| clock, rq (4) | 7 | `occupant_live` 898 · `pick_cold` 1134 · `handoff_yields` 1459 · `wake_starved` 2257 · `wake_serve_stamp` 2264 · `wake_idle_stamp` 2276 · `running` 2626 |
| clock, ktime (4) | 2 | `cpu_tick_soon` 688 (vs clockevent `next_event`) · `task_slice` 1503 (vs `p->start_time`) |
| task storage (4) | 7 | `groove_of` 1256 · `select_cpu` 1729 · `running` 2639 (gated on `cake_seat_word`) · `stopping` 2677 (stage block) · `exit_task` 2764 · probe 1130, 1161 |
| spin lock + seat atomics (3/6) | 3 | `running` 2643 · `stopping` 2681 · probe 1215 |
| shared-line atomic (3/6) | 13 | `qmark_set` 550 · `qmark_clear` 565 · `wake_mark_set` 614 · `seat_update` 1005, 1008 · `wake_mark_retire` 1240 · `offer_remote` 1815 · `take_remote` 2345 · `update_idle` 2734–2738 (wide hosts) · probe 1166 |
| kick (8) | 10 | `kick_preempt` 1417 · `select_cpu` 1662 · `groove_of` 1329 · `offer_remote` 1817, 1840, 1853 · `enqueue_wake` 1984 · `enqueue` 2159 · `dispatch_search` 2446, 2543 |
| frontier shared line (2/5) | 10 | reads: `wake_vtime` 1540, `enqueue_wake` 1976, `enqueue` 2056, `ring_steal` 2223, `llc_pool_rescue` 2322, `frontier_candidate` 2587, `enable` 2748 · read+conditional store: `running` 2649–2653 |

## 3. Per-path bill

Ordered operations on the paths a game exercises. Stack ops from the probe-folded
disassembly; kfunc/atomic costs from §1. Δ columns are checkpoint `08763176e` →
`ca4b7218b`.

| Path | Callback | Operations in order | Stack ops | Estimate |
|---|---|---|---|---|
| both queues empty (the idle-bound CPU's dispatch) | `dispatch_search` | `take_remote` (BSS read) → `nr_queued(own)` [6] → `qmark_publish` (test-before-set) → `nr_queued(pool)` [6] → seat test (1 shared read) → `wake_idle_refresh` (own slot) → `ring_steal` (1 word read, return) → `pool_rescue` (gated) | 5 st + 8 ld (was 4 + 4) | ~100 ns; +2–5 ns vs checkpoint, nothing saved on this path |
| own queue only | `dispatch_search` | as above without seat kick → `move_to_local(own)` [6+7] | 5 + 3 (was 4 + 2 **+ `peek(own)` [6]**) | −30–60 ns |
| pool only, no seat | `dispatch_search` | … → `move_to_local(pool)` [6+7, rq-lock switch] | ~5 + 3 (was **+ `peek(pool)`**) | −30–60 ns |
| both non-empty | `dispatch_search` | … → `peek(own)` [6] → `peek(pool)` [6] → vtime compare → (`wake_starved`: rq clock) → move | unchanged | — |
| home wake, claim succeeds | `select_cpu` | `smp_id` → serial gate (own slot, `system_serial`, `cpu_dsq_idle` [6, qmark-gated], `local_nr` [4]) → `stage` (task fields) → retake gate (usually short-circuits) → `core_contended` (`get_idle_smtmask`+put [4]) → `seat_blocks` (shared word) → `starved_turn` → `core_irq_bad` (2 remote slot reads [5]) → `cpumask_test` → `test_and_clear` [6] → `direct_clamp` (frontier read) → `task_slice` (`ktime` [4]) → `dsq_insert(LOCAL_ON)` [4] | 4 / 5 (function total) | ~116 ns recorded for the §G77b stack; no Δ today |
| wake, home declined → claim walk | `select_cpu` → `pick_idle_clean` / `claim_warm` | `groove_of` (task storage [4]) → `get_idle_cpumask`+put, `get_idle_smtmask`+put [4×2] → per try: `pick_cold` (word ops) → `cpu_clean` (`irq_live` [5], `per_cpu_ptr` + `ktime` [4+5]) → `test_and_clear` [6] | 11 / 15 in `pick_idle_clean` | 100–200 ns; ≤4 tries |
| continuation (slice expiry) | `enqueue` | `task_slice` (`ktime` [4]) → `qmark_test` (shared read) → `qmark_set` (test-before-set) → `dsq_insert_vtime(own)` [6] → `local_nr` [4] → return (**was:** `pick_idle_clean`: 4 idle-mask kfuncs + ≤4 `test_and_clear` [6] + `kick` [8]) | 3 st + 20 ld in function (was 5 + 10) | −50 to −150 ns on the enqueuer; −1 IPI + idle exit on the kicked CPU |
| pinned wake (`nr_cpus_allowed == 1`) | `enqueue` | same block + `pinned_wake_preempt` (`occupant_live`: `cpu_curr` [4+5] + rq clock [4]) | shares the +10 ld | +~5 ns for nothing (pays the `alone` spills, never kicks) |
| pool wake | `enqueue` | frontier read → `starved_turn` → `cpu_curr(tcpu)` [4+5] → `pick_idle_clean` (above) → direct `dsq_insert(LOCAL_ON)` [4] **or** `pool_insert` [6+7] + `wake_mark_set` (gated `nr_llcs > 1`) → `offer_remote` (gated) | — | dominated by the claim walk |
| every switch | `running` | own slot stores → `scx_bpf_now` [4] → seat gate (**`cake_seat_word` read; task storage [4] only when a seat is held**) → frontier read → conditional store [2/5] | 0 on the common path | ~26–58 ns recorded; −20–40 ns while no seat is held |
| every switch | `stopping` | task fields → `recip_index` → hint update (own slot) → vtime write; stage block only: `groove_of` [4] + seat lock map lookup + spin lock + atomics | 0–1 on the common path; 18/22 on the HOLD path | ~10–20 ns common |

## 4. Trades ledger — cheap ops added to remove expensive ones

| Change | Added (tier) | Removed (tier) | Path | Net |
|---|---|---|---|---|
| §G44 qmark bits (2026-08) | test-before-set atomic on transitions [3/6] | `dsq_nr_queued` rhashtable per emptiness question [6] | serial gate, dispatch | positive |
| §G45 one idle census word | — | mask walk | claim | positive |
| §G49 sibling via `get_idle_smtmask` | 1 kfunc [4] | `cpu_curr` deref chain [4+5] | home claim | positive |
| §G86 claim walk rewrite | per-try `cpu_clean` [5] | double idle scan, `pick_idle_escape` | claim | positive |
| 2026-09-15 peek gating (`ba1a8912e`) | +5 stack ops on both-empty [1]; +2 on own/pool-only | 1 `dsq_peek` [6] on own-only and pool-only | dispatch | ~−5 ns/dispatch at an 80/20 mix; both-empty path pays ~3 ns for nothing (see §5) |
| 2026-09-15 rq clock (`9722bfcdd`) | `time_delta` clamp [1] | clocksource read → rq clock at 7 sites [4→4, ~20 ns each] | running, occupant, handoff, pool stamps | positive |
| 2026-09-15 seat gate (`a2a8532a4`) | 1 shared read + branch [2] | `task_storage_get` [4] per switch while no seat is held | running | positive |
| 2026-09-15 `kick_alone` (`ca4b7218b`) | `qmark_test` [2] + `local_nr` [4] + ~8 stack ops [1] | `pick_idle_clean` [4×4 + 6×≤4] + `kick` [8] on a lone continuation | enqueue | positive on continuations; pinned wakes pay ~5 ns for nothing |

## 5. Targets — cheap-op accumulations not paying for a removed expensive op

Ranked by (cost × path frequency). All are shape work: same logic, same outputs.

| # | Site | Cost today | Cause | Fix shape | Pass criterion |
|---|---|---|---|---|---|
| 1 | `dispatch_search` both-empty path | +4 reloads (~3 ns) at the most frequent dispatch | `ucpu` spilled in two widths (`r10-0x10` u64, `r10-0x20` u32); `seat` test reloads both | compute `seat` inside the `!own_n` guard as before; peek the pool inside that block | both-empty stack ops ≤ 4 st + 4 ld; own-only still without the peek |
| 2 | `enqueue` continuation block, pinned-wake path | +~8 reloads on a path that never kicks | `alone` live across `task_slice` / `qmark_set` / `dsq_insert_vtime` / `pinned_wake_preempt` | test `nr_cpus_allowed > 1` before computing `alone`; pinned wakes skip the block's `alone` half entirely | pinned path stack ops back to checkpoint |
| 3 | `stopping` HOLD path | 18 st / 22 ld | seat lock map lookup + spin lock + storage in one frame | rare path (stage block); leave unless the census shows HOLD rate matters | — |
| 4 | `pick_idle_clean` | 11 / 15 across ≤4 tries; `ktime` per try inside `cpu_clean` | `cores`, `seats`, `noisy`, `w`, `rejected` all live across kfuncs | pass `now` in once per walk (≤3 clock reads saved on retries — size with `CLAIM_RETRY` first) | `CLAIM_RETRY` share under a game |

Not targets (the cheap op is paying for something): `qmark_publish`'s test-before-set;
the `seat` shared read in dispatch (§G85 leak 3); `cake_seat_word` read in `running`
(replaces a storage lookup); `time_delta` clamps (cross-CPU rq-clock safety).

## 6. What this file does not say

No number here is a performance verdict. The next receipts that would replace
estimates with measurements: `cake-bpfstats` per-callback ns at `ca4b7218b` vs
`08763176e` under the KovaaKs menu (same protocol as STATE.md `:1700`), and
`bpftool prog dump xlated` of the attached program to confirm the probe-folded
stack-op counts on the both-empty path.

## 7. Native instructions versus BPF cost on the 9800X3D

Added 2026-09-29; Cake source `8fc5ec9b1`. Read-only host inspection identified
Ryzen 7 9800X3D, family 26/model 68/stepping 0, microcode `0xb404035`, kernel
`7.2.8-1-cachyos`, and CPU feature flags `abm`, `bmi1`, `bmi2`, `popcnt`.
These describe this inspection, not a portable build requirement.

### 7.1 What “one instruction” establishes

The execution chain is C expression → LLVM BPF instructions → verifier changes
→ x86 JIT instructions → CPU micro-operations (µops). All JIT-generated code is
native machine code, including a long arithmetic sequence implementing a bit
count. “Native” alone does not mean the dedicated hardware instruction is used.

Keep these quantities separate:

- **Instruction count:** x86 instructions emitted for the complete operation,
  including argument/result moves, checks, and spills.
- **µops:** internal work per instruction; one x86 instruction can require
  multiple µops or microcode.
- **Latency:** cycles from an input being ready to its dependent result.
- **Reciprocal throughput:** cycles per instruction for independent operations;
  0.17 cycles/instruction is not a 0.17-cycle dependency latency.
- **Observed cost:** the executed path with cache misses, contention, branches,
  calls, and dependencies. This requires local measurement.

At an assumed 5.2 GHz, one cycle is approximately 0.192 ns. This is a conversion,
not a measured Cake cost; frequency changes and instruction overlap prevent
summing every instruction's latency into callback wall time.

### 7.2 Full instruction references and verified bit-operation examples

There is no verified all-instruction Cake-to-x86 mapping in this document.
Use the full references below for ISA coverage and per-operand-form costs;
do not treat this selected table as a complete x86 catalog.

| Reference | What it establishes | Limit |
|---|---|---|
| [AMD Zen 5 Software Optimization Guide, 58455 rev. 1.00](https://docs.amd.com/v/u/en-US/58455_1.00) | Official Zen 5 optimization reference; distribution includes the instruction-latency material | Architecture reference, not measurements of this Cake binary |
| [AMD64 Programmer's Manual, Volume 3](https://docs.amd.com/v/u/en-US/24594_3.37) | General-purpose/system instruction semantics, encodings, and exceptions | Instruction existence does not establish latency or BPF accessibility; other volumes cover media/vector instructions |
| [uops.info instruction table](https://www.uops.info/table.html) — select Zen 5 | Broad measured instruction/operand-form coverage: latency, throughput, µops | Not every instruction is covered; register and memory forms differ; published Zen 5 measurements are not a local 9800X3D benchmark |
| [BPF ISA specification](https://docs.kernel.org/next/bpf/standardization/instruction-set.html) | BPF operations and semantics | Does not promise a one-to-one x86 mapping |

The following numbers are the **published Zen 5 measurements** on the linked
pages, checked 2026-09-29. They are not measured on this host. Keep both reported
throughput configurations instead of selecting only the better number.

| Exact native form | x86 instructions for the core operation | Executed µops | Input-to-result latency (cycles) | Reciprocal throughput, loop / unrolled (cycles/instruction) |
|---|---:|---:|---:|---:|
| [`LZCNT r64, r64`](https://uops.info/html-instr/LZCNT_R64_R64.html#ZEN5) | 1 | 1 | 1 | 0.17 / 0.31 |
| [`POPCNT r64, r64`](https://uops.info/html-instr/POPCNT_R64_R64.html#ZEN5) | 1 | 1 | 1 | 0.17 / 0.31 |
| `TZCNT r64, r64` | 1 | Not verified in this update | Not verified in this update | Not verified in this update |

`TZCNT` is supported by the host's BMI1 feature. Its timing page could not be
retrieved during this update; do not copy the CLZ/POPCNT timings into that row.
Memory-source forms add memory dependencies and must be looked up separately.

### 7.3 What Cake actually requests, and what remains unverified

| Operation | Cake use at `8fc5ec9b1` | Hardware route | Current Cake machine-code evidence |
|---|---|---|---|
| Trailing-zero count | `__builtin_ctzll()` in `cake_pick_cold()` and irregular-topology `cake_smt_expand()` fallback | `TZCNT`; other bit-scan sequences may implement equivalent nonzero semantics | JIT sequence and surrounding spills not inspected |
| Population count | `__builtin_popcountll()` in `cake_system_serial()` for the one-word LLC idle census | `POPCNT` | JIT sequence and surrounding spills not inspected |
| Leading-zero count | No direct CLZ builtin found in Cake BPF source | `LZCNT` | No current direct Cake site to price |
| Add/subtract/AND/OR/XOR | Bitmap and accounting expressions | Direct scalar arithmetic/logic instructions are available | A C expression can still need multiple instructions; inspect operands and emitted code |
| Shifts, multiply, divide/remainder | Masking and arithmetic | Native instructions exist, but register constraints, checks, and compiler transformations affect the sequence | Do not assign one fixed cost across immediate/variable operands or signed/unsigned forms |
| Atomic RMW | Shared bitmap/counter updates | Locked instructions or retry sequences, depending on the requested operation/result | Even a single locked instruction has cache-ownership and contention costs; use the ladder's distinction |
| Helper/kfunc or BPF-to-BPF call | Kernel services and outlined Cake functions | A native call plus body, unless the verifier/JIT specializes or inlines it | Include argument setup, spills, body, and return; the C function name is not an instruction-cost specification |

The source inspection does **not** establish whether today's bit-count builtins
expand to arithmetic sequences or are optimized to dedicated instructions.
Neither the builtin spelling nor a small BPF instruction count proves that.

### 7.4 Kernel patch opportunity: inline bitops, not just native wrappers

Leon Hwang's [February 2026 bitops proposal](https://www.mail-archive.com/linux-kernel%40vger.kernel.org/msg2612625.html)
provides CLZ/CTZ, first/last-set scans, population count, bit reversal, and
rotations. Its [x86 JIT patch](https://lists.openwall.net/netdev/2026/02/19/110)
proposes direct `LZCNT`, `TZCNT`, and `POPCNT` emission when the CPU features are
available. This is a proposal reference, not confirmation of upstream merge.

| Implementation | Work at the call site |
|---|---|
| Compiler expansion into BPF arithmetic | JIT compiles the resulting sequence; native instructions throughout, but potentially many per bit count |
| Ordinary native kfunc wrapper | Call/return and possible moves/spills around a body containing the hardware operation |
| JIT-inlined bitops kfunc | Dedicated hardware operation replaces the call; argument/result placement and surrounding spills still need inspection |

The running kernel BTF string table contained none of `bpf_clz64`, `bpf_ctz64`,
`bpf_ffs64`, `bpf_fls64`, `bpf_popcnt64`, `bpf_rol64`, or `bpf_ror64` at inspection.
Thus those named kfuncs are not exposed by this vmlinux BTF. This does not rule
out other compiler/JIT optimizations. The local Linux reference checkout
`2709dd5ae32f` also had no matches for the searched bit-count kfunc names in
`kernel/bpf` or `arch/x86/net`; it is not proven to match the running kernel.

For Cake, prioritize CTZ and population count because they have existing sites.
Preserve nonzero-input preconditions: the proposal defines CTZ/CLZ of zero as 64,
whereas the existing C builtins have undefined zero-input behavior. A count of
64 must never become a CPU index accidentally. Verifier return-range knowledge
is a separate potential improvement, not an assumed property of JIT inlining.

To replace the unknowns with evidence, retain the exact Cake binary/BPF pair,
compiler and kernel identities, verifier-translated BPF and JIT disassembly;
count the complete operation including spills, identify exact operand forms,
and compare patched/unpatched callback costs and workload outcomes. A single
hardware instruction does not remove cache-line contention, idle-claim races,
or IPI cost. No kernel patch, activation, or performance test was performed for
this documentation update.

## 8. Recovered Claude rationale and broader fast-path review (2026-09-29)

Follow-up: [JIT investigation and fresh compiler reproductions](research/jit-20260929/README.md).
The reference JIT does not recognize these bit-count sequences; fresh Clang
22.1.8 BPF/native comparisons and matching installed/live kernel build-ID/BTF
evidence are retained there. Current Cake native JIT output remains unavailable.

### 8.1 Original instruction map and evidence

Claude's original document was [BPF to x86-64 Instruction Map](https://claude.ai/code/artifact/75630385-1ea1-42d5-abbb-20a09900b934),
with main-map, Cake-cost-map, and cakesim tabs. This operation-cost ladder is a
different document. The retained local evidence is under the sibling bench repo:

- [ISA benchmark source and raw runs](../../../../../scx_cake_bench/runs/isa_map_20260927/):
  `gen.py`, `run1.txt`, `run2.txt`, `loaded.py`, and `live/`.
- [Simulation methodology](../../../../../scx_cake_bench/bench/cakesim/README.md)
  and [three-run result table](../../../../../scx_cake_bench/bench/cakesim/data/suite.md).
- Original discussion: Claude session `ded5d65a-f0e3-4edc-a586-3264b65c37d9`,
  retained in `/home/ritz/.claude/projects/-home-ritz-Documents-Repo-scx/`.

These artifacts were read again for this review, not rerun. Their September 27
source and workload identities do not establish September 29 performance.

### 8.2 Why Claude wanted LZCNT for Cake

The actual objective was **exact division-free slice arithmetic**, not choosing
the highest CPU bit. Current `cake_slice_from_service()` computes `q = work / n`,
where `n` is derived from voluntary-switch counts; `cake_admit_frame()` can also
need `runtime / n`. Claude investigated finding the divisor's magnitude with
CLZ, normalizing it, then using a reciprocal/table and multiply/refinement to
recover an exact quotient. LZCNT would cheapen the normalization stage.

The retained `kernels/norm.c` implements normalization only. It does not contain
a completed reciprocal quotient algorithm. Its comment that normalization is
the first step of *any* division-free quotient is too broad: bounded-domain,
constant-divisor, or reused-reciprocal approaches need not count leading zeros
on every use. Likewise, the old conclusion that no exact replacement can beat
division is not proved by these experiments.

| September 27 cakesim variant | Independent calls (ns) | Dependent chain (ns) | Scope |
|---|---:|---:|---|
| Hardware quotient `hwdiv` | 0.577 | 1.903 | Complete `a / (n | 1)` primitive |
| BPF `clang_clz` | 1.382 | 4.333 | Normalization only |
| BPF byte-table normalization | 2.152 | 2.716 | Normalization only |
| What-if inline LZCNT | 0.722 | 0.536 | Normalization only; remaining quotient work unpriced |
| CPU picker, original → what-if TZCNT | 2.032 → 1.967 | 3.214 → 1.673 | Simulated picker, not the whole select callback |
| Idle census, original → what-if POPCNT | 1.744 → 1.319 | 1.221 → 0.870 | Simulated census, not the whole select callback |

These are native userspace timings of a custom BPF-to-x86 translator, including
explicit what-if instruction substitutions. They support an experiment; they
do not prove that a kernel patch generates those sequences or improves Cake.
The LZCNT row makes a dependent-chain quotient experiment plausible, but it
does not demonstrate a complete division-free win.

### 8.3 Ranked opportunities and paths already using hardware

| Priority / mechanism | Cake relevance | Missing or expensive path | Review conclusion |
|---|---|---|---|
| Immediate: CTZ and population count | CPU selection / SMT fallback; LLC idle census | Historical loaded BPF contains software bit-count sequences | Strongest direct bitops-patch cases; test JIT inlining plus register handling |
| Enabling: CLZ | Proposed divisor normalization for slice/burst quotients | Software normalization precedes the rest of a reciprocal algorithm | Build an exact complete quotient before claiming a win; preserve rounding and bounds |
| Enabling: unsigned high multiply (`MUL` / `MULX`) | Exact wide cross-product comparisons for `cake_starved()` / `cake_starved_turn()`; possible reciprocal arithmetic | Existing BPF multiply exposes the low product; retained exact prototypes construct high halves from limbs | A portable high-product operation could reduce limb arithmetic. This also supports correctness: current cross-products can wrap; sampled prototype failures are not a measured live failure rate |
| Supporting: carry/borrow (`ADC` / `SBB`) | Multiword products and comparisons | Carry is represented with arithmetic/comparisons rather than a general BPF flags register | Consider with wide arithmetic; no complete Cake win demonstrated |
| Conditional move / min-max | Ranking, caps, comparisons | Branches or masks may replace a native conditional move | Not automatically faster: retained synthetic predictable-branch max beat the CMOV chain. Benchmark unpredictable inputs and dependencies before requesting an ISA extension |
| Rotate (`ROL` / `ROR`) | Potential bitmap traversal designs | Shift/OR sequences can replace rotate | Lower priority: no demonstrated hot Cake rotate site or measured policy-preserving gain |
| Prefetch | Potential remote CPU/queue state reads | No generic Cake prefetch fast path established here | Speculative. Needs verifier-safe pointer semantics and enough lead time; cannot fix ownership contention by itself |
| Atomic bit updates | qmask, idle/seat words, pool/frontier state | Fetch-AND/OR/XOR needs a CMPXCHG retry loop in the reference x86 JIT; non-fetch forms can use locked operations directly | Review whether the old value is genuinely needed. Cake already uses non-fetch-friendly `__atomic` forms at several sites; ordering and return semantics must be preserved |
| Arithmetic and shifts | Accounting, masks, reciprocal-weight scaling | Generally already native; register constraints may add setup | Reference JIT uses IMUL and BMI2 variable shifts when applicable. No need to add a multiply/shift kfunc for operations already available |
| Division | Slice quotient / burst calculations | Native DIV/IDIV plus register save/setup and verifier handling | Already hardware division, not a software divider. Retained tests did not show a cheaper complete exact replacement |
| CPU ID / tick helpers | `bpf_get_smp_processor_id()`, `bpf_jiffies64()` | A helper-shaped source call may already be rewritten inline | Reference `kernel/bpf/fixups.c` has both rewrites. Historical select_cpu xlated dump confirms CPU ID became a per-CPU access; do not price it as a generic 10–20 ns function call |
| DSQ lookup/move, idle claims, clocks | Scheduling hot paths | Lookup, locks, migration/accounting, cache misses, or clock semantics | These are kernel-service costs, not missing ALU instructions. Investigate redundant work and narrowly scoped API fast paths separately from ISA work |

Kernel implementation evidence is the local reference
`/home/ritz/Documents/Repo/linux/arch/x86/net/bpf_jit_comp.c` (arithmetic, shifts,
division, fetch-bitwise retry loops) and `kernel/bpf/fixups.c` (helper rewrites).
That checkout is reference-only, not authenticated source for this boot.

### 8.4 Corrections to evidence strength

- All **16** retained `live/*.jited.json` files contain an error retrieving the
  JIT dump; their existence is not native-disassembly evidence. The translated
  BPF dumps are real instruction lists. The saved select_cpu dump explicitly
  shows the census's shift/mask/subtract population-count sequence.
- `run1.txt` reports CLZ 26.90 versus native 1.98 calibrated cycles, CTZ 8.22
  versus 1.98, POPCNT 13.88 versus 1.99, and high multiply 12.61 versus 4.90.
  `gen.py` adds a dependent ADD to feed the next iteration for these tests.
  These are **whole benchmark-chain costs**, not isolated instruction latency;
  subtracting one nominal ADD cycle is an inference. “Cycles” are normalized
  against the ADD calibration, not directly read from a hardware cycle counter.
- `loaded.py` mixes measured primitive weights with estimated helper/kfunc
  prices. Its critical-path totals are modeled, not per-site kernel timings.
- `suite.md` marks the two-byte census table **NOT EXACT** over the full test
  domain. It needs a proven low-16-bit mask domain and a general fallback;
  “16 CPUs” alone does not prove that CPU IDs occupy bits 0–15.
- Published Zen 5 instruction costs, retained local microbenchmarks, custom
  translation, actual loaded BPF, and whole-scheduler timings are different
  evidence levels. No new performance run or scheduler change was made here.

### 8.5 CTZ instruction-count clarification

Inspection of retained `bench.c` at `ctz_0_0` shows the standalone CTZ block's
12 native instructions: initialize result to 64, compare input with zero,
conditional branch, copy, negate, AND, load constant, multiply, shift, load table
address, add index, byte load. There is no exit jump in this generated block;
the generator's generic “incl. exit jmp” label is misleading for this case.
The dependency-feeding ADD follows separately and is not in the count of 12.

The September 27 loaded select_cpu BPF shows only the nine scan operations
starting at copy, because the Cake path supplies a nonzero candidate bitmap.
The constant is `0x218a392cd3d5dbf`: isolate the lowest set bit with `x & -x`,
multiply by this de Bruijn constant, shift right by 58, and use the resulting
index to load the bit number from a table. A JIT-inlined TZCNT replaces that
scan with one core instruction, subject to surrounding register overhead.
It does not replace candidate filtering, preference ranking, the atomic idle
claim, or retry logic. Nine BPF operations are not a measured count of today's
native instructions; native dump evidence remains missing.

## 9. Experimental JIT patch and test bundle (2026-09-29)

The [scalar-bitops prototype](research/jit-bitops-prototype/README.md) now
contains an apply-ready kernel patch, an optional Cake `--native-bitops` patch,
and a paired wall-clock runner. Explicit CTZ/POPCNT kfunc calls become TZCNT/
POPCNT in the x86 JIT when the CPU supports them, retaining normal call ABI
semantics and portable kernel-call fallbacks. Existing compiler builtins are
unchanged. LZCNT/division replacement is outside this first patch.

Actual VM-loaded primitive programs now have native dumps confirming both
instructions. Native and unsupported-feature VM runs each passed 5,780
differential executions and three kernel-patch selftests. This is TCG correctness
and code-generation evidence, not 9800X3D latency or Cake performance evidence.
Cake native-mode verifier loading/activation and hardware wall-clock measurements
remain pending the patched kernel boot. Earlier missing native-dump statements
above still apply to the running host's Cake program.

## 10. Local hardware costs and further instruction passes (2026-10-02)

### 10.1 Measured scalar instruction chains

These are **userspace machine-code probes on this 9800X3D**, with hardware
`PERF_COUNT_HW_CPU_CYCLES` and retired-instruction counters. They replace no
kernel-service or callback price in §1. The [probe source](research/jit-bitops-prototype/scalar-hardware-cost.c)
retains every tested assembly sequence. Raw samples are in
[`scalar-hardware-cost.jsonl`](../../../../../scx_cake_bench/runs/cake_instruction_pass_20261002T072438Z/scalar-hardware-cost.jsonl).

| Tested sequence | Median core cycles / operation | Min–max across 10 batches | Median wall ns / operation |
|---|---:|---:|---:|
| Dependent ADD calibration | 1.0008 | 1.0005–1.0317 | 0.1830 |
| Dependent TZCNT | 1.0006 | 1.0004–1.0008 | 0.1825 |
| Dependent LZCNT | 1.0005 | 1.0004–1.0009 | 0.1824 |
| Dependent POPCNT | 1.0006 | 1.0005–1.0018 | 0.1825 |
| Dependent TZCNT followed by AND 63 | 2.0012 | 2.0009–2.0016 | 0.3652 |
| Dependent LZCNT followed by AND 63 | 2.0013 | 2.0007–2.0019 | 0.3657 |
| TZCNT, eight independent chains | 0.3362 | 0.3361–0.3367 | 0.0613 |
| LZCNT, eight independent chains | 0.1882 | 0.1880–0.1885 | 0.0344 |
| POPCNT, eight independent chains | 0.1881 | 0.1880–0.1882 | 0.0343 |
| MULHI emitter's 3 instructions + MOV/ADD feedback | 5.0025 | 5.0021–5.0050 | 0.9145 |

Each of 100 batches runs 16 million operations, unrolled 256 operations per
loop; the ten rounds alternate forward/reverse probe order. Only this process
was pinned, to logical CPU 15. No affinity or frequency settings of other
processes were changed. The events counted userspace on this thread, without
multiplexing (`time_running == time_enabled` in every sample). All CPU IDs
remained 15. Retired instruction counts are 1.0078 per unary operation, 2.0078
per count-and-mask pair, and 5.0078 per MULHI-with-feedback step, including loop
overhead. Source, executable and disassembly are retained under
`target/cake_instruction_pass_20261002T072438Z/`.

No counter/loop overhead was subtracted. The 78 context switches across the
100 samples remain included in wall time; PMU cycles exclude time scheduled
out and kernel execution. The ns column is the observed batch wall time divided
by operations, not cycles converted with an assumed GHz. Repeated inputs settle
into short value cycles; this is not a random-input distribution study. The
eight-chain rows measure that particular loop's reciprocal throughput, not a
guaranteed hardware maximum or instruction latency. The MULHI row includes
two feedback instructions and must not be quoted as isolated MUL latency.

**What this suggests:** the explicit count-result mask adds approximately one
cycle to these dependent chains (about 0.183 ns in this run). Removing it from
Cake requires valid verifier bounds: CTZ/CLZ of zero return 64, so `[0,63]` is
only justified for nonzero inputs. Do not remove bounds merely because the
hardware instruction is fast. A kernel return-range mechanism plus a compatible
Cake build is a candidate experiment, not an implemented optimization.

TZCNT's eight-chain result differs from LZCNT/POPCNT despite their similar
dependency latency. Use the operation that shortens the real algorithm; replacing
one count direction with transformations to obtain the other has no demonstrated
benefit here. The results also explain why a former count-plus-ADD benchmark
could report about two cycles when the count itself costs about one.

### 10.2 Release compiler and queue-scan experiments

See the [October 2 investigation](research/jit-bitops-prototype/INSTRUCTION_PASS_2026-10-02.md)
for exact builds, actual VM-loaded JIT, compatibility checks and host callback/frame
measurements. Selective CTZ/POPCNT fastcall keeps the CPU-selection reduction
without the all-unary variant's CLZ histogram growth. Outlining portable
fallbacks increases native instruction counts; no default was changed.

A generic CTZ ring prototype passed 2,487,612 finite differential cases for
attempted-CPU sequence, word-read sequence/value and early success. An empty
1,024-CPU ring visits 16 words instead of testing 1,023 individual CPUs; a full
ring still takes 1,023 iterations and has extra per-iteration work. These are
source-level counts, not timings, and the prototype is not integrated or
verifier-tested in Cake. The current 16-thread host already has a separate
one-word experiment; this wider-host opportunity cannot be credited as a local
game improvement.

### 10.3 Current callback costs, measured and workload-dependent

Both arms below are optimized release builds with native CTZ/POPCNT and probe
off on the current host kernel. BPF runtime accounting is enabled. Each cell is
the mean of ten 15-second slots, five paired blocks. These are whole callback
prices, not isolated kfunc or scalar-instruction prices.

| Callback ns/run | Initial ordinary | Initial selective | Quiet-start ordinary | Quiet-start selective |
|---|---:|---:|---:|---:|
| select_cpu | 141.461 | 142.563 | 85.134 | 84.797 |
| enqueue | 371.554 | 384.322 | 166.779 | 160.520 |
| dispatch | 101.195 | 93.367 | 17.573 | 53.799 |

The first cohort had major Unreal load; the second later overlapped separate
Blender work, reaching 90.4% busy in one slot. Every listed paired delta's 95%
interval includes zero. The quiet-start select_cpu change is **−0.337 ns/call**,
interval **[−4.136, +3.461] ns**. Keep that observed small delta, but do not use
the table as evidence of a confirmed compiler speedup. The −19.41% aggregate
BPF CPU observation in the latter cohort is concentrated in the interfering
block and accompanies worse dispatch/frame averages; it is not an instruction
efficiency result.

The separate accounting-off frame screen has p99 −450 ns and jitter −422.8 ns,
but mixed block effects and unequal background activity. The full
[investigation](research/jit-bitops-prototype/INSTRUCTION_PASS_2026-10-02.md)
retains all 48 slots, 1,496,976 frames, intervals, process samples and limitations.
The current host lacks the later unary KF_FASTCALL patch, so its compiler test
does not measure that patch's spill-removal benefit.

## 11. Verifier bounds and release specialization (2026-10-02)

The [bounds/refactor investigation](research/jit-bitops-prototype/SCALAR_BOUNDS_REFACTOR_2026-10-02.md)
implements the return-range opportunity identified above. The kernel supplies
0–64 for CTZ/CLZ/POPCNT and 0–63 for CTZ/CLZ only on proven nonzero inputs,
with precision tracking. Cake's research wrappers preserve LLVM's range
knowledge without runtime result masks. A separate native specialization
removes surviving mode loads, while retaining loader capability checks.

Actual loaded release JIT, same patched kernel, 8-core/16-thread VM,
`--native-bitops`, probe off:

| Callback | Ordinary → specialized native instructions | Bytes saved | BPF stack accesses removed |
|---|---:|---:|---:|
| select_cpu | 1,444 → 1,418 | 126 | 13 |
| enqueue | 1,963 → 1,956 | 41 | 1 |
| dispatch | 1,177 → 1,173 | 21 | 2 |
| stopping | 306 → 306 | 0 | 0 |

Diagnostic CLZ stopping separately loses two masks: 493 → 491 instructions,
2,044 → 2,038 bytes. That path requires probes and is not normal release work.
Simply deleting masks without preserving LLVM range facts increased select
code by 13 instructions versus the prior selective-fastcall candidate on the
two-CPU VM. Source simplification alone was not sufficient.

These rows are static attribution, **not new latency prices**. Section 10.1's
measured ~1-cycle count / ~2-cycle count-plus-mask dependency chains remain the
hardware evidence. The full callback nanosecond effect requires the new kernel
on hardware; no conversion from these counts to per-wakeup savings is valid.
20,844 differential executions, 56 Cake inspection loads and 8 VM activation/
restoration checks passed; unsafe bounds and incompatible old-kernel loads
remain rejected. No default changed, and the host kernel was not replaced.

## 12. DSQ comparison, register moves, and evidence audit (2026-10-02)

The [deep research report](research/jit-bitops-prototype/DEEP_RESEARCH_2026-10-02.md)
adds an attributed backport of the typed DSQ comparator accepted for Linux 7.4.
The isolated 7.2.8 build and VM checks passed. These are code-generation facts,
not replacements for the measured ns prices above:

| Operation/path | New evidence | Hardware latency delta |
|---|---|---|
| `find_user_dsq` comparison | Generic `bcmp` call becomes inline u64 comparison; hash also inlines | Unmeasured |
| `find_user_dsq` frame | Own stack use 96→32 bytes; body 301→297 bytes, 82→91 instructions because hashing moves into the body | Unmeasured |
| Specialized select CTZ sites | Three sites still have input/output register moves around TZCNT | Unmeasured opportunity; requires liveness-aware lowering |
| Specialized select POPCNT | One result move remains after POPCNT | Unmeasured opportunity |
| Nonzero CTZ/CLZ precision dependency | Removing it lets two unsafe pruning tests pass verification | Load-time analysis; removing it saves no dispatch instruction |

The September 27 perf analyzer included all BPF programs in its purported Cake
denominator. Corrected archived analysis removes unrelated BPF shares of 4.376%
(`h0_release`), 2.138% (`h16_release`), and 0.731% (`appsim_fix`). This is a
denominator correction, not a new performance measurement. The original symbol
resolver remains approximate; old profile percentages cannot establish today's
callback prices or the DSQ patch's expected speedup.

The normal candidate passed 26,248 differential executions, 42 Cake inspection
loads and 9 activation/restoration checks. A separate intentionally weakened
VM kernel confirms that the existing negative tests detect the missing precision
dependency; those negative programs were never executed. No hardware latency
delta, FPS gain, or default promotion is claimed.
