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

## 1. Cost ladder — fastest to slowest

| Tier | Operation | Cost | What moves it between tiers |
|---|---|---|---|
| 0 | rodata load (`const volatile`), `bpf_ksym_exists`, `barrier_var` | 0 — folded by the verifier | — |
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
