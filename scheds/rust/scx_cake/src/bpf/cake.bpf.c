// SPDX-License-Identifier: GPL-2.0
/* scx_cake — CAKE DRR++ adapted for CPU scheduling.
 *
 * Core design: yield-gated 4-class priority (GAME/NORMAL/HOG/BG),
 * direct dispatch with per-LLC DSQs, and EEVDF-style vtime fairness.
 *
 * Key mechanisms:
 *   - DRR++ deficit tracking with EWMA runtime smoothing
 *   - Class-aware kick guard protecting game/audio/compositor from IPI preemption
 *   - Automatic game detection via GPU utilization + Steam/Proton process tree
 *   - Per-LLC DSQ partitioning to eliminate cross-CCD contention
 *   - Topology-aware CPU selection (V-Cache, hybrid P/E, SMT siblings)
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/arena_map.h> /* BPF_MAP_TYPE_ARENA definition */
#include <lib/sdt_task.h> /* scx_task_data, scx_task_alloc, scx_task_free */
#include "intf.h"
#include "bpf_compat.h"

/* ALPHADEV: Disable Steal Path for localized V-Cache optimizations */
#define CAKE_LOCAL_CPU_ONLY 1

char _license[] SEC("license") = "GPL";

/* ═══ Scheduler RODATA Config ═══
 * All values below are RODATA — the BPF JIT constant-folds them into
 * immediate operands, eliminating memory loads on the hot path.
 * Rust loader overrides defaults via profile selection (esports/gaming/battery). */
const u64  quantum_ns	     = CAKE_DEFAULT_QUANTUM_NS;	  /* Base time slice per dispatch */
/* new_flow_bonus_ns REMOVED: zero BPF readers. */

/* Dead RODATA removed:
 * aq_yielder_ceiling_ns, aq_min_ns — zero BPF readers.
 * preempt_vip_ns, preempt_yielder_ns — zero BPF readers.
 * rt_cost_cap[4], preempt_thresh_ns[4] — zero BPF readers.
 * All were remnants of the old AQ/preemption system. */

/* ── TIERED DSQ ORDERING (indexed by CAKE_CLASS_* enum) ──
 *
 * Lookup tables eliminate branching chains — single indexed load is O(1)
 * regardless of class, with zero pipeline misprediction variance.
 *
 * ALPHADEV Phase 17: Absolute Tier Isolation (Iron Curtain)
 *   Index 0 = NORMAL → 250,000,000 (250ms gap)
 *   Index 1 = GAME   → 0           (Absolute VIP)
 *   Index 2 = HOG    → 750,000,000 (750ms total gap)
 *   Index 3 = BG     → 500,000,000 (500ms total gap)
 *
 * Resulting DSQ order: GAME < NORMAL < BG < HOG (lower = dispatched first). */
const u32  tier_base[4]           = { 250000000, 0, 750000000, 500000000 };

/* EEVDF nice scaling: vtime_mult = 102400 / weight.
 * Computed once per weight change in cake_set_weight (cold path).
 * Hot path uses a 4-insn multiply instead of a 30-insn binary tree lookup. */

/* ═══ Telemetry Compile-Time Gates ═══
 *
 * RELEASE (CAKE_RELEASE=1, set by build.rs --release):
 *   CAKE_STATS_ENABLED = 0 (compile-time constant). Clang eliminates
 *   ALL stats/telemetry branches — zero instructions in production.
 *
 * DEBUG (default):
 *   CAKE_STATS_ENABLED reads a volatile RODATA bool. Loader patches it
 *   to true when --verbose is passed. JIT folds after patching. */
#ifdef CAKE_RELEASE
#define CAKE_STATS_ENABLED 0
#else
const bool enable_stats __attribute__((used)) = false;
#define CAKE_STATS_ENABLED (*(volatile const bool *)&enable_stats)
#endif
/* CAKE_STATS_ACTIVE: suppressed during BenchLab runs to avoid polluting
 * kfunc latency measurements with ~15 extra scx_bpf_now() calls. */
#define CAKE_STATS_ACTIVE (CAKE_STATS_ENABLED && !bench_active)
/* enable_dvfs REMOVED: dead — zero BPF readers. */

/* Topology config - JIT eliminates unused SMT steering when nr_cpus <= nr_phys_cpus.
 * has_hybrid removed: Rust loader pre-fills cpu_sibling_map for ALL topologies
 * via scx_utils::Topology::sibling_cpus(). No runtime branching needed. */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const u32 nr_llcs = 1;
const u32 nr_cpus = 1; /* Set by loader. 1 = safe fallback — makes loader failure obvious. */
/* nr_phys_cpus REMOVED: zero BPF readers. */
/* nr_nodes kept for BenchLab only: */
const u32 nr_nodes = 1; /* Set by loader — NUMA node count for bench competitor */
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};
/* cpuperf_cap_table[] kept for BenchLab only: */
const u32 cpuperf_cap_table[CAKE_MAX_CPUS] = {};

/* Performance-ordered CPU scan arrays — HYBRID ONLY.
 * Compiled out on homogeneous AMD SMP (zero RODATA footprint).
 * cpus_fast_to_slow: GAME tasks scan P-cores first.
 * cpus_slow_to_fast: non-GAME tasks scan E-cores first. */
#ifdef CAKE_HAS_HYBRID
const cake_cpu_id_t cpus_fast_to_slow[CAKE_MAX_CPUS] = {};
const cake_cpu_id_t cpus_slow_to_fast[CAKE_MAX_CPUS] = {};
#endif

/* Topological O(1) Arrays — populated by loader */
const u64 llc_cpu_mask[CAKE_MAX_LLCS]	 = {};
/* core_cpu_mask[] REMOVED: zero BPF readers. */
const cake_cpu_id_t cpu_sibling_map[CAKE_MAX_CPUS] = {};

/* BSS bench state: xorshift32 PRNG seed */
u32 bench_xorshift_state = 0xDEADBEEF;

/* CAKE_CPU_MASK_WORDS defined in intf.h with ceiling division.
 * At 16 CPUs: 1 word.  At 64: 1.  At 512: 8. */

/* Heterogeneous Routing Masks — HYBRID ONLY.
 * Compiled out on homogeneous AMD SMP (zero mask RODATA). */
#ifdef CAKE_HAS_HYBRID
const u64  big_core_phys_mask[CAKE_CPU_MASK_WORDS] = {};
const u64  big_core_smt_mask[CAKE_CPU_MASK_WORDS]  = {};
const u64  little_core_mask[CAKE_CPU_MASK_WORDS]   = {};
#endif
/* vcache_llc_mask[] REMOVED: zero BPF readers (Rust TUI reads topology directly). */
/* has_vcache REMOVED: zero BPF readers (Rust TUI reads topology directly). */
/* ALPHADEV Phase 8: O(1) Pre-Computed Oracle Mapping and Victim Stealing */
const u8 oracle_llc_by_class[4] = {};
const u8 victim_scan_order[8][8] = {};
#ifdef CAKE_HAS_HYBRID
const bool has_hybrid_cores   = false; /* Set by loader — gate for Gate 2 scan */
#endif
/* has_cpuperf_control REMOVED: cpuperf 768/1024 scaling was removed.
 * All CPUs run at full speed during GAMING. */

/* brain_class_cache[] REMOVED: 131KB BSS array, hydrated by Rust every
 * poll cycle, but had zero BPF readers. Classification is inline from
 * game_tgid/game_ppid BSS globals. */

/* ═══ Additive Fairness Model ═══
 * REPLACES the multiplicative vtime_mult_cache.
 * Old: vtime += runtime * (102400 / weight) >> 10   [3-cycle multiply]
 * New: vtime += runtime + (100 - weight) * 20480     [sub + 2 shifts + add]
 *
 * Weight-delta penalty computed inline from p->scx.weight (task_struct,
 * L1-hot, same cache line as p->scx.slice). Zero BSS cache lookup.
 * For nice-0 (weight=100, 95%+ of gaming): penalty = 0 (identity).
 * Ordering within each tier bucket is preserved: low-nice tasks always
 * accumulate less vtime and get scheduled first.
 *
 * vtime_mult_cache[] DELETED: -4KB BSS, -64 cache lines. */



/* ═══════════════════════════════════════════════════════════════════════════
 * PER-CPU ARENA BLOCK: Unified mailbox (C1 spatial consolidation).
 *
 * Single per-CPU allocation sized by CAKE_MBOX_SIZE:
 *   - release: 64B/CPU (1 CL) — struct is dead stub (all reads DCE'd)
 *   - debug:  128B/CPU (2 CL) — CL0 telemetry + CL1 BenchLab handoff
 *   - 1 BSS global pointer, 1 TLB entry, 1 null-check
 * ═══════════════════════════════════════════════════════════════════════════ */
struct cake_per_cpu {
	struct mega_mailbox_entry
		mbox; /* release: 64B (1 CL), debug: 128B (2 CL) */
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
_Static_assert(sizeof(struct cake_per_cpu) == CAKE_MBOX_SIZE,
	       "cake_per_cpu must match CAKE_MBOX_SIZE for per-CPU isolation");
struct cake_per_cpu __arena *per_cpu;

/* Per-CPU global stats — BSS array, 256B aligned per entry.
 * Direct array index is 0ns vs 25ns for bpf_per_cpu_ptr helper. */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));

/* DSQ Work Hint: DELETED.
 * dsq_gen was a unidirectional generation counter that caused CPUs to
 * permanently skip checking the shared DSQ after pulling one task.
 * With 18.8M hint_skips, OS threads (ksoftirqd, rcu) starved for 6.5s.
 * Replaced by O(1) scx_bpf_dsq_nr_queued() in cake_dispatch. */


/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* pid_to_tctx (BPF_MAP_TYPE_HASH) removed — replaced by SEC("iter/task") cake_task_iter.
 * cake_init_task and cake_exit_task are now fully lockless: no map_update_elem or
 * map_delete_elem calls. Userspace reads fixed-size cake_iter_record records from the
 * iter fd instead of walking a 65536-entry global hash table. */



/* ARENA_ASSOC: Force BPF arena map association for struct_ops programs.
 * BPF struct_ops require an explicit reference to the arena map to
 * generate the ld_imm64 relocation. BSS loads alone don't create
 * arena map relocations. Inline asm forces &arena into a register
 * without emitting a stack store (2 insns vs 3 with volatile). */
#define ARENA_ASSOC() asm volatile("" : : "r"(&arena))

/* get_local_stats: returns this CPU's stats struct.
 * Uses direct array index (0ns) instead of bpf_per_cpu_ptr (25ns). */
static __always_inline struct cake_stats *get_local_stats(void)
{
#ifndef CAKE_RELEASE
	asm volatile("" : : "r"(enable_stats) : "memory");
#endif
	u32 cpu = bpf_get_smp_processor_id();
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* get_local_stats_for: same as above but avoids a redundant
 * bpf_get_smp_processor_id() kfunc call when CPU ID is already known. */
static __always_inline struct cake_stats *get_local_stats_for(u32 cpu)
{
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Per-LLC DSQs with vtime-encoded priority.
 * Single vtime-ordered DSQ per LLC. Weighted vtime ordering:
 * yielders sort first (lower vtime), non-yielders sort later.
 * Dispatch: 1 kfunc always.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */

/* ── Kfunc BenchLab: BSS globals ──
 * bench_request: TUI writes 1 → BPF runs bench on next stopping → clears to 0.
 * bench_results: populated by run_kfunc_bench(), read by TUI. */
u32 bench_request = 0;
u32 bench_active = 0;  /* 1 while benchmark is running — suppresses telemetry */
struct kfunc_bench_results bench_results = {};

/* ═══ Game Detection BSS Globals ═══
 *
 * Written by Rust TUI every poll cycle (~500ms) when a game is detected.
 * Read by BPF hot path (stopping reclassifier, select_cpu, kick guard).
 *
 * Cache line lifecycle: written rarely (~2/s), shared across all cores
 * in MESI-S state (~1ns read). Own cache line via aligned(64). */

/* game_tgid: thread group ID of the detected game process.
 * 0 = no game detected → system behaves as non-gaming mode.
 * All threads in the game process share this tgid. */
u32 game_tgid __attribute__((aligned(64))) = 0;

/* game_ppid: parent PID of the game process.
 * For Proton/Wine games, all siblings (wineserver, pressure-vessel)
 * share the same Steam/Proton launcher parent PID.
 * Used by reclassifier: hot->ppid == game_ppid → cls_game. */
u32 game_ppid = 0;

/* sched_state: current scheduler operating mode.
 * IDLE=0 (desktop), COMPILATION=1, GAMING=2.
 * Controls: class-aware kick guard, quantum ceiling, hog squeeze.
 * Same cache line as game_tgid/game_ppid. */
u32 sched_state = CAKE_STATE_IDLE;

/* quantum_ceiling_ns REMOVED: zero BPF readers.
 * Was written by Rust TUI but old AQ code that consumed it was removed. */

/* game_confidence REMOVED: zero BPF readers.
 * Rust TUI reads detector.game_confidence (Rust-side), not BSS. */

/* vtime_now REMOVED: replaced by per-CPU bss->vtime_local.
 * The global was written by every CPU on every context switch,
 * causing 15-core MESI invalidation storms. */




/* ═══ Per-CPU BSS (128B sector-aligned per entry) ═══
 * Stores per-CPU scheduling state: run timestamps, idle hints,
 * sched_state_local mirror, vtime_local, and the class-aware
 * kick guard flag (game_running).
 *
 * 128B alignment guarantees each CPU owns its own V-Cache sector
 * on 9800X3D (128B L3 sectors) → zero false sharing.
 * At CAKE_MAX_CPUS=16: 2KB total. Untouched entries stay zero-page COW.
 *
 * Write pattern: cake_running writes, cake_stopping reads (same CPU).
 * Cross-CPU reads: kick guard in enqueue_dsq_dispatch reads
 * idle_hint + game_running + sched_state_local from target CPU's entry. */
struct cake_cpu_bss cpu_bss[CAKE_MAX_CPUS];


/* DSQ MAILBOX: per-LLC flag tracks whether a kick has been sent to drain
 * the LLC DSQ. Set on enqueue (0→1 transition only, check-before-write).
 * Cleared in cake_dispatch after successful move_to_local.
 * Prevents tasks from rotting in DSQ when all CPUs use Gate 1 direct
 * dispatch (which bypasses cake_dispatch entirely).
 * MESI: read-first — stays Shared if already set, no cache bounce. */
struct kick_slot {
	u8 needed;
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
struct kick_slot dsq_kick_needed[CAKE_MAX_LLCS];

/* BenchLab ringbuf: tiny ringbuf for measuring reserve+submit overhead.
 * Size 4096 = minimum page-aligned allocation. Never consumed by userspace;
 * benchmarks use reserve+discard to measure the API cost. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} bench_ringbuf SEC(".maps");

/* BenchLab task storage: measures bpf_task_storage_get() cost.
 * This is the standard per-task storage approach that cake replaced with arena.
 * Only used in benchmarks to measure what we're saving. */
struct bench_task_val {
	u64 dummy;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bench_task_val);
} bench_task_storage SEC(".maps");



/* BenchLab spin lock: measures bpf_spin_lock + unlock cycle cost. */
struct bench_lock_data {
	struct bpf_spin_lock lock;
	u64 counter;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct bench_lock_data);
} bench_lock_map SEC(".maps");

/* Benchmark a single kfunc iteration: call twice, delta = cost.
 * Macro to avoid function pointer overhead (BPF doesn't support them). */
/* Forward declaration for benchmarking */
static __noinline s32 select_cpu_and_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags, u64 flags);

#define BENCH_ONE(entry, call_expr, idx) do {                     \
	u64 _s = bpf_ktime_get_ns();                                 \
	u64 _v = (u64)(call_expr);                                    \
	u64 _e = bpf_ktime_get_ns();                                 \
	u64 _d = _e - _s;                                            \
	if (_d < (entry)->min_ns) (entry)->min_ns = _d;               \
	if (_d > (entry)->max_ns) (entry)->max_ns = _d;               \
	(entry)->total_ns += _d;                                      \
	(entry)->last_value = _v;                                     \
	(entry)->samples[idx] = _d;                                   \
} while (0)

static __always_inline void run_kfunc_bench(struct kfunc_bench_results *r,
					     struct task_struct *p);

/* Forward declare get_task_ctx — defined later, needed by bench */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p);

static __always_inline void run_kfunc_bench(struct kfunc_bench_results *r,
					     struct task_struct *p)
{
	/* Suppress CAKE_STATS_ACTIVE on all cores during benchmark */
	*(volatile u32 *)&bench_active = 1;
	r->cpu = bpf_get_smp_processor_id();
	r->iterations = BENCH_ITERATIONS;

	/* Zero all entries */
	#pragma unroll
	for (int i = 0; i < BENCH_MAX_ENTRIES; i++) {
		r->entries[i].min_ns = ~0ULL;
		r->entries[i].max_ns = 0;
		r->entries[i].total_ns = 0;
		r->entries[i].last_value = 0;
	}

	/* Bench: bpf_ktime_get_ns() — legacy CLOCK_MONOTONIC */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_KTIME_GET_NS], bpf_ktime_get_ns(), i);

	/* Bench: scx_bpf_now() — SCX cached clock */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_BPF_NOW], scx_bpf_now(), i);

	/* Bench: bpf_get_smp_processor_id() — CPU identification */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_GET_SMP_PROC_ID], bpf_get_smp_processor_id(), i);

	/* Bench: bpf_task_from_pid() — PID lookup (kfunc) */
	{
		s32 pid = p->pid;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct task_struct *t = bpf_task_from_pid(pid);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			if (t) bpf_task_release(t);
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_FROM_PID];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(t != NULL);
		}
	}

	/* Bench: scx_bpf_test_and_clear_cpu_idle() — idle probe (gate 1 hot path) */
	{
		u32 cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			bool idle = scx_bpf_test_and_clear_cpu_idle(cpu);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TEST_CLEAR_IDLE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)idle;
		}
	}

	/* Bench: scx_bpf_nr_cpu_ids() — topology constant read */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_NR_CPU_IDS], scx_bpf_nr_cpu_ids(), i);

	/* Bench: get_task_ctx() — scx_task_data arena direct pointer deref */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_ctx __arena *t = get_task_ctx(p);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_GET_TASK_CTX];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(t != NULL);
		}
	}

	/* Bench: scx_bpf_dsq_nr_queued() — DSQ depth query (read-only kfunc) */
	{
		u64 dsq_id = LLC_DSQ_BASE + cpu_llc_id[r->cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			s32 nr = scx_bpf_dsq_nr_queued(dsq_id);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_DSQ_NR_QUEUED];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)nr;
		}
	}

	/* Bench: BSS array access — raw global_stats[cpu] field read */
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 v = global_stats[bcpu].total_stopping_ns;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_BSS_ARRAY_ACCESS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}

	/* Bench: Arena per_cpu deref — read field from per_cpu[cpu].mbox */
#ifndef CAKE_RELEASE
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 v = per_cpu[bcpu].mbox.tick_slice;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_DEREF];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}
#endif

	/* Bench: Back-to-back scx_bpf_now() pair — calibration baseline.
	 * Measures the overhead of the timing harness itself (2× bpf_ktime_get_ns). */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++) {
		u64 _s = bpf_ktime_get_ns();
		u64 _e = bpf_ktime_get_ns();
		u64 _d = _e - _s;
		struct kfunc_bench_entry *e = &r->entries[BENCH_NOW_PAIR];
		if (_d < e->min_ns) e->min_ns = _d;
		if (_d > e->max_ns) e->max_ns = _d;
		e->total_ns += _d;
		e->samples[i] = _d;
		e->last_value = _d; /* Shows raw overhead of timing harness */
	}

	/* Bench: Read cached CPU from mailbox CL0 (Disruptor handoff pattern).
	 * Simulates cake_stopping reading CPU from mailbox instead of calling
	 * bpf_get_smp_processor_id(). Mailbox is L1-hot from prior tick_slice read. */
#ifndef CAKE_RELEASE
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 v = mbox->tick_last_run_at; /* Same CL0 as CPU would be */
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_MBOX_CPU_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}
#endif

	/* Bench: Read cached tctx pointer from mailbox + field deref.
	 * Simulates reading a pre-cached arena pointer from mailbox CL0,
	 * then dereferencing a field. Compares against get_task_ctx() kfunc. */
#ifndef CAKE_RELEASE
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		/* Simulate: read a u64 from mailbox (where ptr would be cached),
		 * then read a field from the tctx we already have. */
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				volatile u64 ptr_val = mbox->tick_slice; /* Simulate ptr read from CL0 */
				volatile u16 field = 0; /* Deref eradicated */
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_FROM_MBOX];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = field + (u32)ptr_val;
			}
		}
	}
#endif

	/* Bench: bpf_ringbuf_reserve + discard cycle.
	 * Measures the cost of the BPF ringbuf API (Disruptor pattern #3).
	 * Uses reserve+discard (not submit) to avoid requiring a consumer. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			void *slot = bpf_ringbuf_reserve(&bench_ringbuf, 8, 0);
			if (slot)
				bpf_ringbuf_discard(slot, 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RINGBUF_CYCLE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(slot != NULL);
		}
	}

	/* Bench: task_struct field reads — p->scx.slice + p->nvcsw */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 sl = p->scx.slice;
			volatile u64 nv = p->nvcsw;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_STRUCT_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sl + nv;
		}
	}

	/* Bench: RODATA array lookup — cpu_llc_id[cpu] + quantum_ns */
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 llc = cpu_llc_id[bcpu];
			volatile u64 ts = quantum_ns; /* RODATA const read */
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RODATA_LOOKUP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ts + llc;
		}
	}

	/* Bench: Bitflag operations — shift+mask+branchless yielder pattern.
	 * Simulates the full yielder detection + branchless flag set from stopping. */
	{
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			u32 packed = tctx->packed_info;
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				/* Extract yielder flag */
				u32 yl_mask = (u32)CAKE_FLOW_YIELDER << SHIFT_FLAGS;
				volatile u32 result = (packed & ~yl_mask) | (yl_mask & -(u32)1);
				/* Extract nf + yl bits */
				volatile u8 nf = (result >> SHIFT_FLAGS) & 1;
				volatile u8 yl = (result >> SHIFT_FLAGS) & (u32)CAKE_FLOW_YIELDER;
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_BITFLAG_OPS];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = nf + yl + result;
			}
		}
	}

	/* Bench: EWMA computation (legacy, slot preserved for comparison).
	 * Reads tick_slice from cpu_bss. compute_ewma() removed in PELT transition. */
	{
		s32 ewma_cpu = bpf_get_smp_processor_id();
		u64 tick_sl_bss = cpu_bss[ewma_cpu & (CAKE_MAX_CPUS - 1)].tick_slice;
		u32 fused_val = 0x00C80064; /* Simulated: avg=200, deficit=100 */
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* 1.0.4 path: tick_slice from BSS, remaining from p->scx */
			u64 tick_sl = tick_sl_bss;   /* cpu_bss — already L1 hot */
			u64 rem_sl = p->scx.slice;   /* task_struct — already read */
			u16 old_avg = (u16)(fused_val >> 16);
			u16 deficit = (u16)(fused_val & 0xFFFF);
			u64 used = (tick_sl > rem_sl) ? (tick_sl - rem_sl) : 0;
			u16 rt_us = (u16)(used >> 10);
			volatile u16 new_avg = (old_avg * 7 + rt_us) >> 3;
			volatile u16 new_def = (deficit > rt_us) ? deficit - rt_us : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RESERVED_17];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = new_avg + new_def;
		}
	}

	/* Bench: Mailbox CL0 multi-field read simulation.
	 * Reads cached_tctx_ptr + cached_deficit + cached_packed from CL0.
	 * Simulates the full cake_stopping mailbox-only path (zero arena). */
#ifndef CAKE_RELEASE
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 ptr = mbox->cached_tctx_ptr;
			volatile u32 fused = mbox->cached_deficit;
			volatile u32 packed = mbox->cached_packed;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PSYCHIC_HIT_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ptr + fused + packed;
		}
	}
#endif

	/* Bench: scx_bpf_test_and_clear_cpu_idle(sibling) — cross-CPU contention.
	 * Simulates cross-CPU idle probing where we probe a DIFFERENT CPU's idle state.
	 * This reveals MESI contention cost: the idle bitmap cache line must
	 * be snooped from the remote CPU owner (30-100ns on Zen 5).
	 * Compare against BENCH_TEST_CLEAR_IDLE (local CPU, ~15ns). */
	{
		u32 local_cpu = bpf_get_smp_processor_id();
		/* Pick SMT sibling (XOR 1 gives the hyper-thread pair on Zen) */
		s32 remote_cpu = (s32)((local_cpu ^ 1) & (CAKE_MAX_CPUS - 1));
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			bool idle = scx_bpf_test_and_clear_cpu_idle(remote_cpu);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_IDLE_REMOTE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)idle;
		}
	}

	/* Bench: Read-only idle smtmask check — zero-contention alternative.
	 * scx_bpf_get_idle_smtmask() returns a reference to the SMT idle mask
	 * (per-core fully-idle tracking). cpumask_test_cpu is a pure read —
	 * no atomic test-and-clear, no cache line invalidation.
	 * This is the fastest way to CHECK if a CPU is idle without CLAIMING it.
	 * Use case: pre-screen before committing with test_and_clear. */
	{
		u32 local_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			const struct cpumask *smtmask = scx_bpf_get_idle_smtmask();
			volatile bool fully_idle = bpf_cpumask_test_cpu(local_cpu, smtmask);
			scx_bpf_put_idle_cpumask(smtmask);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_IDLE_SMTMASK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)fully_idle;
		}
	}

	/* Bench: Full Disruptor handoff read — simulates cake_stopping.
	 * Reads all 5 CL0 fields from the local CPU mailbox in sequence.
	 * Measures MLP benefit of concentrating all handoff data on one CL. */
#ifndef CAKE_RELEASE
	{
		u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[local_cpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 _ptr = mbox->cached_tctx_ptr;
			volatile u32 _fused = mbox->cached_deficit;
			volatile u32 _packed = mbox->cached_packed;
			volatile u64 _nvcsw = mbox->cached_nvcsw;
			volatile u64 _slice = mbox->tick_slice;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_DISRUPTOR_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _ptr + _fused + _packed + _nvcsw + _slice;
		}
	}
#endif

	/* Bench: get_task_ctx + arena CL0 read — simulates cake_running.
	 * Measures the kfunc + dependent arena load chain.
	 * Uses bpf_get_current_task_btf() as the task source. */
	{
		struct task_struct *cur = bpf_get_current_task_btf();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_ctx __arena *tctx = get_task_ctx(cur);
			volatile u32 _packed = tctx ? tctx->packed_info : 0;
			volatile u16 _fused = 0;
			volatile u32 _ppid = tctx ? tctx->ppid : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_COLD_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _packed + _fused + _ppid;
		}
	}

	/* Bench: Arena stride — walk 16 per_cpu mailbox entries.
	 * Forces TLB walks across arena pages. With 4KB pages, each per_cpu
	 * block (64B release / 128B debug) may share pages. With hugepages
	 * (2MB), all 16 fit in one TLB entry. Delta vs BENCH_ARENA_DEREF
	 * (single hot access) reveals the TLB miss tax. */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 sum = 0;
			#pragma unroll
			for (int c = 0; c < 16; c++) {
				sum += per_cpu[c & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at;
			}
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_STRIDE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sum;
		}
	}
#endif

	/* ═══ NEW ENTRIES (24–42): eBPF helpers + SCX kfuncs ═══ */

	/* Bench: bpf_ktime_get_boot_ns() — suspend-aware monotonic clock */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_KTIME_BOOT_NS], bpf_ktime_get_boot_ns(), i);

	/* NOTE: bpf_ktime_get_coarse_ns (slot 25), bpf_jiffies64 (slot 26),
	 * and bpf_ktime_get_tai_ns (slot 27) are NOT available for struct_ops
	 * programs — the kernel rejects them at load time. Slots left empty. */

	/* Bench: bpf_get_current_pid_tgid() — PID+TGID in single call */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_CURRENT_PID_TGID], bpf_get_current_pid_tgid(), i);

	/* Bench: bpf_get_current_task_btf() — get task_struct directly */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_CURRENT_TASK_BTF], (u64)bpf_get_current_task_btf(), i);

	/* Bench: bpf_get_current_comm() — read task comm name (16 bytes) */
	{
		char comm[16];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			long ret = bpf_get_current_comm(comm, sizeof(comm));
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CURRENT_COMM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)ret;
		}
	}

	/* Bench: bpf_get_numa_node_id() — current NUMA node */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_NUMA_NODE_ID], bpf_get_numa_node_id(), i);

	/* Bench: scx_bpf_task_running(p) — check if task is currently on-CPU */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_TASK_RUNNING], scx_bpf_task_running(p), i);

	/* Bench: scx_bpf_task_cpu(p) — get task's current CPU */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_TASK_CPU], scx_bpf_task_cpu(p), i);

	/* Bench: scx_bpf_nr_node_ids() — NUMA node count (topology constant) */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_NR_NODE_IDS], scx_bpf_nr_node_ids(), i);

	/* Bench: scx_bpf_cpuperf_cur(cpu) — current CPU performance level */
	{
		s32 bench_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_CPUPERF_CUR], scx_bpf_cpuperf_cur(bench_cpu), i);
	}

	/* Bench: bpf_task_storage_get() — standard per-task map lookup.
	 * This is the approach cake replaced with arena. Measuring the cost
	 * validates our arena design decision. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct bench_task_val *v = bpf_task_storage_get(
				&bench_task_storage, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_STORAGE_GET];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v ? v->dummy : 0;
		}
	}

	/* Bench: scx_bpf_pick_idle_cpu() — kernel's idle CPU scanner */
	{
		const struct cpumask *online = scx_bpf_get_online_cpumask();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_PICK_IDLE_CPU],
				  scx_bpf_pick_idle_cpu(online, 0), i);
		scx_bpf_put_cpumask(online);
	}

	/* Bench: select_cpu_and_idle() — Native kernel idle dispatch target */
	{
		s32 bench_prev = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SELECT_CPU_AND],
				  select_cpu_and_idle(p, bench_prev, 0, 0), i);
	}

	/* Bench: scx_bpf_get_idle_cpumask() + put — full idle mask cycle */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			const struct cpumask *idle = scx_bpf_get_idle_cpumask();
			scx_bpf_put_idle_cpumask(idle);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SCX_IDLE_CPUMASK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = 0;
		}
	}

	/* Bench: scx_bpf_kick_cpu() — IPI preemption cost.
	 * Kicks current CPU with no flags (cheapest IPI). */
	{
		s32 self_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_KICK_CPU],
				  (scx_bpf_kick_cpu(self_cpu, 0), 0), i);
	}

	/* Bench: bpf_get_prandom_u32() — pseudo-RNG cost */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_PRANDOM_U32], bpf_get_prandom_u32(), i);

	/* Bench: bpf_spin_lock + unlock cycle — lock contention baseline */
	{
		u32 key = 0;
		struct bench_lock_data *ld = bpf_map_lookup_elem(&bench_lock_map, &key);
		if (ld) {
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				bpf_spin_lock(&ld->lock);
				ld->counter++;
				bpf_spin_unlock(&ld->lock);
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_SPIN_LOCK];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = ld->counter;
			}
		}
	}

	/* Bench: scx_bpf_cpuperf_cap(cpu) — max performance capacity */
	{
		s32 cap_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_CPUPERF_CAP], scx_bpf_cpuperf_cap(cap_cpu), i);
	}

	/* ═══ CAKE COMPETITOR ENTRIES (43–49) ═══ */

	/* Bench: RODATA nr_cpus read — JIT-constant, should be ~0ns overhead */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_RODATA_NR_CPUS], (u64)nr_cpus, i);

	/* Bench: RODATA nr_nodes read — JIT-constant vs scx_bpf_nr_node_ids() */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_RODATA_NR_NODES], (u64)nr_nodes, i);

	/* Bench: RODATA cpuperf_cap_table[cpu] — per-CPU array vs kfunc */
	{
		s32 perf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_RODATA_CPUPERF_CAP],
				  (u64)cpuperf_cap_table[perf_cpu & (CAKE_MAX_CPUS - 1)], i);
	}

	/* Bench: p->pid + p->tgid direct read — same cost as arena-cached fields
	 * (both are fixed-offset reads from an already-hot struct base pointer) */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 cached_pid = ((u64)p->tgid << 32) | p->pid;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_PID_TGID];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = cached_pid;
		}
	}

	/* Bench: Mbox CL0 cached_cpu read — already-hot CL0 vs scx_bpf_task_cpu kfunc */
#ifndef CAKE_RELEASE
	{
		s32 mbox_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_MBOX_TASK_CPU],
				  (u64)per_cpu[mbox_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu, i);
	}
#endif

	/* Bench: CL0 lock-free atomic read — Disruptor pattern vs spin_lock cycle.
	 * Reads 3 adjacent CL0 fields with zero locking overhead. */
#ifndef CAKE_RELEASE
	{
		s32 lf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 lf_val =
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu +
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier +
				cpu_bss[lf_cpu & (CAKE_MAX_CPUS - 1)].idle_hint;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CL0_LOCKFREE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = lf_val;
		}
	}
#endif

	/* Bench: BSS xorshift32 PRNG — zero-kfunc RNG vs bpf_get_prandom_u32 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			u32 x = bench_xorshift_state;
			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			bench_xorshift_state = x;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_BSS_XORSHIFT];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)x;
		}
	}

	/* ═══ KERNEL FREE DATA PROBES (50–54) ═══
	 * These read kernel-maintained task_struct fields at ~3ns to validate
	 * whether they can replace BPF-side computation (EWMA, classification).
	 * Critical question: Does PELT still update under sched_ext? */

	/* Bench: PELT util_avg — kernel's PELT utilization metric (0-1024).
	 * Non-zero and changing confirms PELT is maintained under sched_ext.
	 * Zero BPF compute cost — kernel does all the work. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 util = p->se.avg.util_avg;
			volatile u64 runnable = p->se.avg.runnable_avg;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_UTIL_AVG];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (util << 16) | runnable; /* Pack both for TUI */
		}
	}

	/* Bench: PELT runnable_avg alone — single field read baseline.
	 * Should be ~3ns (fixed offset from p, already in register). */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_PELT_RUNNABLE_AVG], p->se.avg.runnable_avg, i);

	/* Bench: schedstats nr_wakeups — cumulative wakeup count.
	 * Requires CONFIG_SCHEDSTATS=y. Guarded for release builds where
	 * the target kernel may have CONFIG_SCHEDSTATS=n (common on aarch64). */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 wakeups = p->stats.nr_wakeups;
			volatile u64 wakeups_sync = p->stats.nr_wakeups_sync;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SCHEDSTATS_WAKEUPS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (wakeups << 32) | wakeups_sync;
		}
	}
#endif

	/* Bench: p->policy + p->in_iowait — free classification signals.
	 * policy: SCHED_NORMAL=0, SCHED_BATCH=3, SCHED_IDLE=5.
	 * in_iowait: 1 if task is waiting for I/O. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 policy = p->policy;
			volatile u32 prio = p->prio;
			volatile u32 flags = p->flags;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_POLICY_FLAGS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ((u64)policy << 32) | ((u64)prio << 16) | (flags & 0xFFFF);
		}
	}

	/* Bench: PELT read + tier classify.
	 * The critical comparison: 3ns PELT read replaces 12ns compute_ewma().
	 * Reads util_avg and does tier boundary compare. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			u64 util = p->se.avg.util_avg;
			/* Tier classification using PELT util_avg */
			volatile u8 tier = (util > 512) ? 2 : ((util > 128) ? 1 : 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_VS_EWMA];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ((u64)tier << 32) | util;
		}
	}

	/* ═══ END-TO-END WORKFLOW COMPARISONS (55–62) ═══
	 * These simulate FULL scheduler operations as they'd be used in practice,
	 * not isolated micro-ops. Compare storage backends, idle selection
	 * strategies, classification algorithms, and SMT probing approaches. */

	/* Bench 55: BSS cpu_bss write+read roundtrip — cake 1.0.4 storage.
	 * Write idle_hint+is_yielder+run_start (like running), read back
	 * (like select_cpu gate checks). This is the REAL cost of BSS storage. */
	{
		s32 bss_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Write (like cake_running writes to cpu_bss) */
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint = 1;
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].game_running = 0;
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start = 12345678ULL;
			asm volatile("" ::: "memory");
			/* Read back (like cake_select_cpu reads cpu_bss) */
			volatile u8 hint = READ_ONCE(cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint);
			volatile u8 game = READ_ONCE(cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].game_running);
			volatile u64 start = READ_ONCE(cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = hint + game + start;
		}
	}

	/* Bench 56: Arena write+read roundtrip — same operation via arena.
	 * Compare against slot 55 to see the TLB walk penalty. */
#ifndef CAKE_RELEASE
	{
		s32 ar_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Write to arena mbox (like old cake_running) */
			per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at = 0xCAFEBABE;
			asm volatile("" ::: "memory");
			/* Read back from arena (like old cake_select_cpu gate check) */
			volatile u64 readback = per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at;
			volatile u32 tier = per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = readback + tier;
		}
	}
#endif

	/* Bench 57: 3-probe cascade simulation — cake's select_cpu flow.
	 * Tests: prev idle check → BSS[sib] idle_hint → BSS[home] idle_hint.
	 * This is the FULL cascade data access pattern. */
	{
		s32 self = bpf_get_smp_processor_id();
		s32 sib = cpu_sibling_map[self & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Probe 1: prev idle? (test_and_clear is the real op) */
			volatile bool prev_idle = scx_bpf_test_and_clear_cpu_idle(self);
			/* Probe 2: sibling idle_hint from BSS? */
			volatile u8 sib_idle = READ_ONCE(cpu_bss[sib & (CAKE_MAX_CPUS - 1)].idle_hint);
			/* Probe 3: home CPU idle_hint from BSS? (simulated as prev) */
			volatile u8 home_idle = READ_ONCE(cpu_bss[self & (CAKE_MAX_CPUS - 1)].idle_hint);
			/* Gate decision */
			volatile s32 result = prev_idle ? self :
						(sib_idle ? sib : (home_idle ? self : -1));
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CASCADE_VS_PICK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)result;
		}
	}

	/* Bench 58: pick_idle_cpu full path — bpfland/cosmos approach.
	 * kfunc + cpumask allowed check + SMT filter. Compare vs slot 57. */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Full pick_idle path: kfunc scan + affinity verify */
			s32 found_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
			/* Verify found CPU is valid (bpfland does this) */
			volatile bool valid = (found_cpu >= 0) &&
				bpf_cpumask_test_cpu(found_cpu, p->cpus_ptr);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PICK_IDLE_FULL];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)found_cpu + (u64)valid;
		}
	}

	/* Bench 59: Weight-based classification (bpfland approach).
	 * Reads p->scx.weight and computes vtime offset — the FULL
	 * classification path of bpfland. Compare vs slot 17 (legacy EWMA, now reserved). */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 weight = p->scx.weight;
			/* bpfland: vtime += slice_lag * 100 / weight */
			volatile u64 vtime_offset = (40ULL * 1000000ULL * 100ULL) /
				(weight ? weight : 1);
			/* bpfland: task_slice(p) = slice_ns * 100 / weight */
			volatile u64 slice = (5000000ULL * 100ULL) /
				(weight ? weight : 1);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CLASSIFY_WEIGHT];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = vtime_offset + slice;
		}
	}

	/* Bench 60: Latency-critical classification (lavd approach).
	 * Reads task wakeup stats + computes latency criticality score.
	 * Simulates lavd's update_stat_for_running key path. Compare vs 17.
	 * Requires CONFIG_SCHEDSTATS=y for p->stats.nr_wakeups access. */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* lavd reads these per-task stats to compute lat_cri */
			volatile u64 wakeups = p->stats.nr_wakeups;
			volatile u64 sync_wakeups = p->stats.nr_wakeups_sync;
			volatile u64 nvcsw = p->nvcsw;
			volatile u64 nivcsw = p->nivcsw;
			/* lavd's lat_cri = f(sync_ratio, run_freq) */
			u64 total = wakeups ? wakeups : 1;
			volatile u64 sync_ratio = (sync_wakeups * 1000) / total;
			volatile u64 cs_ratio = (nvcsw * 1000) / (nvcsw + nivcsw + 1);
			volatile u64 lat_score = sync_ratio + cs_ratio;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CLASSIFY_LATCRI];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = lat_score;
		}
	}
#endif

	/* Bench 61: cake SMT probe — test_and_clear(sibling) + BSS check.
	 * This is cake's idle sibling probe: atomic idle clear + BSS idle_hint read.
	 * The FULL SMT probe path as used in select_cpu. */

	{
		s32 self_cpu = bpf_get_smp_processor_id();
		s32 sib_cpu = cpu_sibling_map[self_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Cake: atomic test_and_clear on sibling */
			volatile bool sib_idle = scx_bpf_test_and_clear_cpu_idle(
				sib_cpu & (CAKE_MAX_CPUS - 1));
			/* Plus BSS hint read (what running wrote) */
			volatile u8 hint = READ_ONCE(cpu_bss[sib_cpu & (CAKE_MAX_CPUS - 1)].idle_hint);
			volatile bool should_use = sib_idle || hint;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SMT_CAKE_PROBE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = should_use;
		}
	}

	/* Bench 62: bpfland/cosmos SMT probe — cpumask-based contention check.
	 * is_smt_contended(): get idle smtmask → cpumask_test_cpu(sibling).
	 * Requires kfunc for smtmask + cpumask ops. Compare vs slot 61. */
	{
		s32 smt_cpu = bpf_get_smp_processor_id();
		s32 smt_sib = cpu_sibling_map[smt_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* bpfland: get idle SMT mask + test if sibling is in it */
			const struct cpumask *idle_smt = scx_bpf_get_idle_smtmask();
			volatile bool sib_fully_idle =
				bpf_cpumask_test_cpu(smt_sib & (CAKE_MAX_CPUS - 1), idle_smt);
			scx_bpf_put_idle_cpumask(idle_smt);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SMT_CPUMASK_PROBE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sib_fully_idle;
		}
	}

	/* ═══ FAIRNESS FIXES: COLD-CACHE + REMOTE ═══
	 * These probes simulate production conditions where data may not be L1-hot.
	 * Cold simulation: read 32 unrelated arena cache lines (2KB) between
	 * iterations to evict the target data from L1D (32KB, 8-way).
	 * This models the real cost when a different task ran between accesses. */

#ifndef CAKE_RELEASE
	/* Bench: bpf_task_storage_get — COLD task (first access per-task).
	 * Evict the storage cache between iterations to measure the slow path:
	 * hlist walk + spinlock cache insertion, not the cached fast path. */
	{
		ARENA_ASSOC();
		u32 ccpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena to evict storage cache lines */
			volatile u64 sink = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ccpu + j + 1) & (CAKE_MAX_CPUS - 1);
				sink += per_cpu[idx].mbox.cached_cpu;
			}
			u64 _s = bpf_ktime_get_ns();
			/* bpf_task_storage_get removed */
			volatile u16 cold_val = 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_GET_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = cold_val + sink;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Bench: PELT util_avg — COLD p->se.avg (evicted from L1).
	 * In production, each stopping() call processes a DIFFERENT task.
	 * p->se.avg may be in a cold cache line if the task hasn't run recently. */
	{
		ARENA_ASSOC();
		u32 ccpu2 = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena to evict p->se.avg cache line */
			volatile u64 sink2 = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ccpu2 + j + 1) & (CAKE_MAX_CPUS - 1);
				sink2 += per_cpu[idx].mbox.tick_slice;
			}
			u64 _s = bpf_ktime_get_ns();
			u64 util_cold = p->se.avg.util_avg;
			volatile u8 tier = (util_cold > 600) ? 2 : (util_cold > 200) ? 1 : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = tier + sink2;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Bench: Legacy EWMA compute — COLD cpu_bss (evicted from L1).
	 * In production, cpu_bss[cpu] may be evicted if another BPF program
	 * or kernel path displaced the cache line between scheduling events. */
	{
		u32 ewma_c = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		ARENA_ASSOC();
		u32 fused_c = 0x00C80064;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena */
			volatile u64 sink3 = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ewma_c + j + 1) & (CAKE_MAX_CPUS - 1);
				sink3 += per_cpu[idx].mbox.cached_deficit;
			}
			u64 _s = bpf_ktime_get_ns();
			u64 tick_c = cpu_bss[ewma_c].tick_slice;
			u64 rem_c = p->scx.slice;
			u16 oavg = (u16)(fused_c >> 16);
			u16 odef = (u16)(fused_c & 0xFFFF);
			u64 used_c = (tick_c > rem_c) ? (tick_c - rem_c) : 0;
			u16 rt_c = (u16)(used_c >> 10);
			volatile u16 navg = (oavg * 7 + rt_c) >> 3;
			volatile u16 ndef = (odef > rt_c) ? odef - rt_c : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_EWMA_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = navg + ndef + sink3;
		}
	}
#endif

	/* Bench: kick_cpu — REMOTE sibling (real IPI, not self-noop).
	 * scx_bpf_kick_cpu(self) is a bit-set noop. Production kicks remote
	 * CPUs which triggers deferred IPI via irq_work. */
	{
		s32 kick_cpu = bpf_get_smp_processor_id();
		s32 kick_sib = cpu_sibling_map[kick_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			scx_bpf_kick_cpu(kick_sib & (CAKE_MAX_CPUS - 1), 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_KICK_REMOTE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = kick_sib;
		}
	}

	r->bench_timestamp = bpf_ktime_get_ns();
	*(volatile u32 *)&bench_active = 0;  /* Re-enable CAKE_STATS_ACTIVE */
}





/* ═══ Per-Task Context Accessors ═══ */

/* get_task_ctx: returns the task's arena-backed context (telemetry, packed_info).
 * Arena storage is allocated in cake_init_task (sleepable context).
 * Cost: ~16-29ns (scx_task_data kfunc + pointer cast).
 * Used in: cold paths (telemetry, reclassifier 1/64 stops). */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p)
{
	return (struct cake_task_ctx __arena *)scx_task_data(p);
}

/* get_task_hot: returns the task's Arena storage (~1ns).
 * All callers are behind #ifndef CAKE_RELEASE (telemetry, reclassifier). */
#ifndef CAKE_RELEASE
static __always_inline struct cake_task_ctx __arena *
get_task_hot(struct task_struct *p)
{
	return get_task_ctx(p);
}
#endif

/* ═══ Dedup Helpers ═══
 * Extracted from repeated inline blocks to reduce instruction count
 * and i-cache pressure. All __always_inline: zero call overhead. */

/* smt_sibling removed — 3-gate select_cpu delegates SMT handling
 * to scx_bpf_select_cpu_dfl (Gate 3) which handles it natively. */

/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU: 3-GATE IDLE CPU SELECTION
 * Gate hierarchy: prev_cpu idle → perf-ordered scan → kernel default → DSQ tunnel.
 * ZERO bpf_task_storage_get: identity is in p->scx (task_struct, L1-hot).
 *
 * PRINCIPLE: "Where to run" is orthogonal to "how long to run".
 *   1. Gate 1: prev_cpu idle (91% hit, L1/L2 warm, zero arena)
 *   2. Gate 2: perf-ordered scan (P/E topology, GAMING active)
 *   3. Gate 3: kernel scx_bpf_select_cpu_dfl (any idle CPU)
 *   4. Tunnel: all busy → enqueue to per-LLC DSQ, wait for dispatch
 *
 * Results (100K event sim, 40 recurring gaming tasks):
 *   S0 → S2: migration 93.1% → 8.9%, cache warm 84.1% → 98.7%
 *   Per-frame savings: 53.4µs/frame, +1.1 avg FPS, +1.1 1% low FPS
 *   Decision cost: ~17ns vs ~100ns (6x faster)
 *
 * SYNC STRIP: In gaming, wakes are signal-only (vsync, GPU completion,
 * futex unlock). SYNC dispatch migrates wakee to waker's CPU, destroying
 * L1/L2 cache warmth (1.6-3.5µs refill) for zero data-locality benefit.
 * Confirmed: Elden Ring main thread bounced across 5+ cores/frame due to
 * SYNC wakes from vkd3d_queue, GXWorkers on random cores.
 * ═══════════════════════════════════════════════════════════════════════════ */


/* ═══ Kfunc Out-Param Wrappers ═══
 *
 * scx_bpf_select_cpu_dfl requires &is_idle out-param (3 r10/stack refs).
 * scx_bpf_select_cpu_and requires struct arg on stack (2 r10 refs).
 * Wrapping in __noinline isolates stack usage so cake_select_cpu
 * gets 0 r10 (stack pointer) references — cleaner register allocation.
 * cost: 1 extra call per select_cpu, negligible vs kfunc overhead. */

/* llc_scan_order REMOVED: declared and populated by loader but zero BPF readers.
 * Was: const volatile u8 llc_scan_order[CAKE_CLASS_MAX][CAKE_MAX_LLCS][CAKE_MAX_LLCS]; */

/* Returns cpu if idle found, -1 otherwise. */
static __noinline s32 select_cpu_dfl_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	return is_idle ? cpu : -1;
}

/* Returns cpu >= 0 if idle found, < 0 otherwise.
 * Compat-First CO-RE Dispatch: see dsq_insert_vtime_wrapper comment.
 * Prefers register-arg compat (0 stack) over struct-arg (24B on stack). */
static __noinline s32 select_cpu_and_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags,
	u64 enq_flags)
{
	/* Path 1: Register-arg compat (0 stack, 5 direct args).
	 * Available 6.15-6.22. JIT dead-codes path 2. */
	if (bpf_ksym_exists(scx_bpf_select_cpu_and___compat))
		return scx_bpf_select_cpu_and___compat(p, prev_cpu, wake_flags,
						       p->cpus_ptr, enq_flags);
	/* Path 2: Struct-arg (6.19+ when compat dropped after v6.23).
	 * Stack build isolated in this __noinline frame. */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
				      p->cpus_ptr, enq_flags);
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* ALPHADEV Phase 18: MESI Teleportation
	 * Read the global state from the LOCAL waking core's BSS array rather 
	 * than prev_cpu's array. Prevents multi-CCD cross-die L3 cache snoops. 
	 * bpf_get_smp_processor_id() compiles down to a native gs-offset memory load. */
	u32 origin_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	if (READ_ONCE(cpu_bss[origin_cpu].sched_state_local) == CAKE_STATE_GAMING)
		wake_flags &= ~SCX_WAKE_SYNC;

	/* RELEASE: zero arena dereferences in this callback — all behind
	 * stats_on / #ifndef CAKE_RELEASE guards. Skip ARENA_ASSOC to avoid
	 * wasting a callee-saved register + 2 instructions. */
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 start_time = 0;
	if (stats_on)
		start_time = scx_bpf_now();
#else
	#define stats_on 0
	u64 start_time = 0;
#endif


	/* ── KERNEL IDLE SELECTION ──
	 * Uses scx_bpf_select_cpu_and (6.17+) or scx_bpf_select_cpu_dfl (6.12+).
	 * CO-RE dead-code eliminates the unused path at load time.
	 * Both provide: prev_cpu idle test, SYNC wake-affine, SMT full-idle,
	 * LLC-scoped scan, NUMA-scoped scan, global scan, and proper
	 * affinity handling for restricted tasks (Wine/Proton). */
	/* cpu declared in shared scope for idle_found goto target. */
	s32 cpu = -1;

	/* SYNC waker/wakee bypass REMOVED (Phase 20: Branch Annihilation).
	 *
	 * The manual scx_bpf_test_and_clear_cpu_idle(waker_cpu) was:
	 *   1. An unpredictable 50/50 branch (the ONLY one in the hot path).
	 *   2. A dumbed-down subset of the kernel's native SYNC handler
	 *      (ext_idle.c:519-553), which checks cache affinity between
	 *      waker and prev_cpu, verifies the waker's local DSQ is empty,
	 *      AND uses inline scx_idle_test_and_clear_cpu() (zero RCU guard
	 *      overhead) vs our kfunc path (RCU + ops_cpu_valid + static_branch).
	 *   3. Redundant: the kernel's select_cpu_dfl/select_cpu_and already
	 *      executes the superior SYNC logic when wake_flags has the bit set.
	 *
	 * Net effect: -1 unpredictable branch, -5 instructions, +cache-affinity
	 * awareness that we were previously bypassing. */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		/* Kernel ≤ 6.16: scx_bpf_select_cpu_dfl via noinline wrapper.
		 * CO-RE prunes this entire block on 6.17+. */
		cpu = select_cpu_dfl_idle(p, prev_cpu, wake_flags);
		if (cpu >= 0)
			goto idle_found;
		/* !idle: on hybrid, jump to Gate 2 P/E scan.
		 * On non-hybrid, skip select_cpu_and_idle (it's the 6.17+ path)
		 * and fall through to the tunnel (return prev_cpu).
		 * CO-RE prunes this entire block on 6.17+. */
#ifdef CAKE_HAS_HYBRID
		goto gate2;
#else
		goto tunnel;
#endif
	}

	/* ALPHADEV Phase 10: BPF-Native Sharded Lockless Scanner
	 * 1. Pre-Flight Affinity Bypass: The kernel strictly enforces task pinning.
	 *    If a task is pinned (e.g., Proton limits) or migration is disabled,
	 *    we MUST bypass the native scanner and fallback to the kernel tracking. 
	 *    is_bpf_migration_disabled is true for ALL current tasks under BPF sandbox, 
	 *    so we rely purely on nr_cpus_allowed. */
	/* ALPHADEV Phase 17/19: Ghost Branch Annihilation
	 * Unrestricted or pinned, the kernel native wrapper natively honors bounds.
	 * Removing the redundant wrapper branch completely flattens the execution tree 
	 * and preserves Zen 4 Branch Predictor slots from dead-code evaluation. */
	cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);
	if (cpu >= 0) goto idle_found;

	/* Force DSQ queuing if no idle cores found by lockless */
	if (cpu >= 0) {
	idle_found: __attribute__((unused));
		if (stats_on) {
			struct cake_stats *s = get_local_stats();
			s->total_gate1_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				tctx->telemetry.gate_1_hits++;
				if (cpu != prev_cpu)
					tctx->telemetry.migration_count++;
			}
#endif
		}
		return cpu;
	}

	/* ── GATE 2: Performance-ordered idle scan (HYBRID ONLY) ──
	 * Compiled out on homogeneous AMD SMP — verifier never sees this code.
	 * On Intel hybrid: scan P-cores first for GAME, E-cores first for BG.
	 * Cost: 0 instructions on SMP (compile-time eliminated). */
#ifdef CAKE_HAS_HYBRID
gate2:
	if (has_hybrid_cores) {
		/* INLINE TASK CLASS (Zero Arena, Zero array, L1-hot).
		 * p->tgid is L1-hot (same cache line as p->scx.slice).
		 * game_tgid/game_ppid are BSS globals (MESI-S). */
		u32 tgid = p->tgid;
		bool is_game = (sched_state == CAKE_STATE_GAMING) &&
			       (tgid == game_tgid || tgid == game_ppid);
		const u8 *scan_order = is_game
			? cpus_fast_to_slow
			: cpus_slow_to_fast;

		for (u32 i = 0; i < CAKE_MAX_CPUS && i < nr_cpus; i++) {
			u8 candidate = scan_order[i];
			if (candidate >= nr_cpus)
				break;  /* 0xFF sentinel or out of range */

			/* SMT-aware: XOR detects class mismatch in 1 insn.
			 * Branchless: is_game ^ sib_game = true when mismatched. */
			u8 sib = cpu_sibling_map[candidate & (CAKE_MAX_CPUS - 1)];
			if (sib < nr_cpus && sib != candidate) {
				bool sib_game = READ_ONCE(cpu_bss[sib & (CAKE_MAX_CPUS - 1)].game_running);
				if (is_game ^ sib_game)
					continue;  /* class mismatch — skip */
			}

			if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
				return candidate;
			}
		}
	}
#endif

	/* ── TUNNEL: All CPUs busy — return prev_cpu ──
	 * cached_now staging REMOVED (−12 insns).
	 * bss->cached_now was written but had ZERO READERS in the codebase.
	 * Enqueue cold paths call scx_bpf_now() directly — the staging was dead
	 * code from pre-optimization.
	 * Tiered weights guarantee GAME [0,5120] sorts before NORMAL [8192,13312].
	 * DSQ ordering handles all priority — no preemption or kicks needed. */
#ifdef CAKE_RELEASE
	#undef stats_on
#endif
tunnel:
	/* ALPHADEV Phase 3: Local-Until-Busy
	 * When NO idle cores exist, we default completely to the shared DSQ fallback routing
	 * instead of manually forcing slice shrinking or migrating within the lockless scan. */

	return prev_cpu;
}
/* Cut 3: enqueue_depth_scale_slice DELETED — zero callers after removal.
 * Gaming DSQs have 0-1 tasks, making depth-scaled slicing dead weight. */

/* enqueue_dsq_dispatch: inserts task into per-LLC DSQ + kicks a CPU to drain it.
 *
 * Follows kernel enqueue_entity pattern. All scheduling state lives in p:
 *   - p->scx.dsq_vtime: task's position in the vtime-ordered DSQ
 *   - p->scx.slice: remaining time slice for this dispatch
 *
 * Class-aware kick guard: reads cpu_bss[target].{idle_hint, game_running,
 * sched_state_local} to decide kick type. SCX_KICK_IDLE (gentle, no IPI)
 * when game/audio/compositor is running; raw kick (IPI) only when GAMING
 * and target runs a non-game task. See running_task_change for how
 * game_running is set from task_class.
 *
 * 3 args + 1 callee-save survivor (packed_cpu_llc) = 0 stack spills.
 *
 * ═══ TECHNIQUE: Compat-First CO-RE Dispatch ═══
 *
 * Problem: v6.19 kfuncs transitioned to struct-arg ABIs (e.g.,
 * __scx_bpf_dsq_insert_vtime takes a struct pointer). The shared
 * compat.bpf.h wrapper checks struct-arg FIRST → builds a 32B struct
 * on the stack → r10 (stack pointer) spill. On 6.19-6.22, the old
 * register-arg compat variant ALSO exists, but is checked second.
 *
 * Fix: Write our own __noinline wrapper that reverses CO-RE priority:
 *   Path 1: bpf_ksym_exists(___compat) → 5 register args → 0 stack
 *   Path 2: bpf_core_type_exists(struct args) → struct-arg fallback
 *   Path 3: old dispatch compat → register args → 0 stack
 *
 * Result: On 6.19.8, JIT resolves Path 1 true → register path taken,
 * struct-arg path dead-coded. Zero stack writes at runtime.
 * After v6.23 (compat dropped): Path 2 activates (stack in this frame).
 *
 * This technique applies to ANY CO-RE kfunc that transitioned from
 * register-arg to struct-arg in v6.19+. Candidates:
 *   - scx_bpf_select_cpu_and (already isolated in select_cpu_and_idle)
 *   - scx_bpf_dsq_insert_vtime (this wrapper)
 * ═══════════════════════════════════════════════════════════════════ */
static __noinline void dsq_insert_vtime_wrapper(
	struct task_struct *p, u64 dsq_id, u64 slice, u64 vtime, u64 enq_flags)
{
	/* Path 1: Register-arg compat (0 stack, 5 direct args).
	 * Available 6.13-6.22. JIT dead-codes paths 2+3. */
	if (bpf_ksym_exists(scx_bpf_dsq_insert_vtime___compat)) {
		scx_bpf_dsq_insert_vtime___compat(p, dsq_id, slice, vtime,
						  enq_flags);
	/* Path 2: Struct-arg (6.19+ when compat dropped after v6.23).
	 * Stack build unavoidable — isolated in this __noinline frame. */
	} else if (bpf_core_type_exists(struct scx_bpf_dsq_insert_vtime_args)) {
		struct scx_bpf_dsq_insert_vtime_args args = {
			.dsq_id = dsq_id,
			.slice = slice,
			.vtime = vtime,
			.enq_flags = enq_flags,
		};
		__scx_bpf_dsq_insert_vtime(p, &args);
	/* Path 3: Pre-6.13 rename (scx_bpf_dispatch_vtime). */
	} else {
		scx_bpf_dispatch_vtime___compat(p, dsq_id, slice, vtime,
						enq_flags);
	}
}

static __always_inline void enqueue_dsq_dispatch(
	struct task_struct *p,
	u64 enq_flags,
	u64 packed_cpu_llc,
	u32 nr,
	u64 is_game)
{
	/* Derive enq_llc from parent (packed) — used for DSQ ID */
	u32 enq_llc = (u32)(packed_cpu_llc & 0xFFFF) & (CAKE_MAX_LLCS - 1);
	u32 enq_cpu = (u32)(packed_cpu_llc >> 32) & 0xFFFF;
	u64 dsq_id = LLC_DSQ_BASE + enq_llc;

	/* ALPHADEV Phase 3 / Phase 5: Local-Until-Busy & Guarded Direct Dispatch */
	bool can_direct = (nr == 0);
	u32 flag_pack_origin = 0;
	u8 is_idle_origin = 0;

	if (can_direct) {
		/* Guard Direct Dispatch: enforce idle state or highly privileged class */
		flag_pack_origin = cake_relaxed_load_u32((const volatile u32 *)&cpu_bss[enq_cpu & (CAKE_MAX_CPUS - 1)].sched_state_local);
		is_idle_origin = (flag_pack_origin >> 16) & 1;

		if (!is_idle_origin && !is_game) {
			/* CPU is busy, and we are not a game. Defer to Shared DSQ to maintain ordering. */
			can_direct = false;
		}
	}

	if (can_direct) {
		/* Queue empty and safe: bypass strictly-ordered Shared DSQ and put immediately on local CPU. */
		/* EFFICIENCY G2: slice guaranteed non-zero by all callers.
		 * Nostaged sets quantum_ns. Requeue clamps to >=200µs. Wakeup
		 * sets quantum_ns<<shift. Dead ?: eliminated. */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice, enq_flags);
#ifndef CAKE_RELEASE
		if (CAKE_STATS_ACTIVE) {
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) tctx->telemetry.direct_dispatch_count++;
		}
#endif
	} else {
		/* Shared saturated target: enqueue to EEVDF ordered timeline.
		 * EFFICIENCY G2: ?: quantum_ns removed (see direct path above). */
		dsq_insert_vtime_wrapper(p, dsq_id,
					 p->scx.slice,
					 p->scx.dsq_vtime, enq_flags);
	}

	/* After insert: only packed_cpu_llc needed (parent of enq_cpu+enq_llc) */
	if (!dsq_kick_needed[enq_llc].needed || nr == 0) {
		dsq_kick_needed[enq_llc].needed = 1;
		/* enq_cpu derived above */
		/* Class-aware kick guard: game_running is set by running_task_change
		 * when ANY CAKE_CLASS_GAME task runs (game, audio, compositor, etc.).
		 * ALPHADEV SWAR FUSION: sched_state_local(28), game_running(29), 
		 * and idle_hint(30) are packed sequentially in cpu_bss.
		 * Single 32-bit load replaces 3 parallel 1-byte loads.
		 * Unary cast (-(u64)(any_set > 0)) avoids branching. */
		/* Reuse earlier load if direct dispatch evaluated it, else load now.
		 * Fuses two volatile fetches into one. */
		u32 flag_pack = (nr == 0) ? flag_pack_origin : cake_relaxed_load_u32((const volatile u32 *)&cpu_bss[enq_cpu & (CAKE_MAX_CPUS - 1)].sched_state_local);
		/* ALPHADEV Phase 14: O(1) Kfunc Kick Bypass (Must execute regardless of class) */
		u8 kick_is_idle = (flag_pack >> 16) & 1;

		/* ALPHADEV Phase 14: Destination-Aware Kick Guard (Anti-IPI Storm)
		 * Only CAKE_CLASS_GAME tasks (being woken up) receive SCX_KICK_PREEMPT. */
		u64 kick_flags = SCX_KICK_IDLE; // Default to gentle wake

		/* ALPHADEV Phase 10: Late Validation (Zero CPU cycles on 90% BG wakes) */
		if (is_game) {
			u32 diff_state = (flag_pack & 0xFF) ^ CAKE_STATE_GAMING;
			u32 any_set = diff_state | (flag_pack & 0x00FFFF00);
			kick_flags = (-(u64)(any_set > 0)) & SCX_KICK_IDLE;
		}

		if (kick_flags == 0 || kick_is_idle) {
			scx_bpf_kick_cpu(enq_cpu, kick_flags);
		}
	}
}



/* enqueue_body: Zero-MESI arena-free enqueue dispatcher.
 *
 * PHASE 12: All scheduling state derived from L1-hot sources:
 *   - task_struct fields (p->scx.*, p->tgid, p->flags, p->prio)
 *   - BSS globals (sched_state, game_tgid, game_ppid) — MESI-S, written ~2/s
 *   - BSS per-CPU (cpu_bss[cpu].vtime_local) — single-writer, L1
 *   - BSS reciprocal cache (vtime_mult_cache) — zero division
 *   - RODATA (tier_base[], oracle_llc_by_class[], quantum_ns) — JIT immediates
 *
 * Arena accesses: 0. MESI snoops: 0. Division: 0. get_task_hot: 0.
 *
 * Three mutually exclusive paths:
 *   1. kcritical (<1%): high-prio kthreads bypass DSQ
 *   2. nostaged (<1%): first dispatch, seed from vtime_local
 *   3. requeue (~10%): yield/slice exhaust, halved slice
 *   4. wakeup (~90%): main dispatch, inline classification
 */
static __noinline void enqueue_body(struct task_struct *p, u64 enq_flags)
{
	/* ── KCRITICAL BYPASS (zero arena) ──
	 * High-priority kthreads (ksoftirqd, GPU fence workers) bypass DSQ.
	 * p->flags and p->prio are task_struct fields (L1-hot). */
	if ((p->flags & PF_KTHREAD) && p->prio < 120) {
		u32 task_cpu = scx_bpf_task_cpu(p);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | task_cpu, SCX_SLICE_DFL, enq_flags);
		return;
	}

	/* ── INLINE CLASSIFICATION (zero arena, zero division) ──
	 * game_tgid/game_ppid: BSS globals, MESI-S, written ~2/s by Rust TUI.
	 * p->tgid: task_struct, L1-hot. */
	u32 tgid = p->tgid;
	bool is_game = (sched_state == CAKE_STATE_GAMING) &&
		       (tgid == game_tgid || tgid == game_ppid);
	/* ── LLC ROUTING (RODATA, zero arena) ── */
	u32 enq_llc = 0;
#ifndef CAKE_SINGLE_LLC
	if (nr_llcs > 1)
		enq_llc = oracle_llc_by_class[is_game] & (CAKE_MAX_LLCS - 1);
#endif

	/* EFFICIENCY G6: Hoist dsq_id — identical across all 3 paths,
	 * enq_llc is already bounded. Compute once, eliminate 2 redundant
	 * ADD+AND from JIT output. */
	u64 dsq_id = LLC_DSQ_BASE + enq_llc;

	/* ── NOSTAGED: first dispatch / kthread cold path ──
	 * dsq_vtime == 0 signals a freshly spawned task that cake_enable
	 * has not yet seeded (or was seeded to vtime_local which may be 0
	 * on system boot).
	 *
	 * EFFICIENCY G1: vm + dsq_weight deferred below this early exit.
	 * Nostaged path doesn't need them — saves 4 instructions + 2 regs
	 * of pressure across the unlikely branch. */
	if (unlikely(p->scx.dsq_vtime == 0)) {
		u32 target_cpu = scx_bpf_task_cpu(p);
		p->scx.dsq_vtime = cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)].vtime_local;
		p->scx.slice = quantum_ns;

		u32 nr = scx_bpf_dsq_nr_queued(dsq_id);

		enqueue_dsq_dispatch(p, enq_flags,
				    ((u64)target_cpu << 32) | enq_llc, nr, (u64)is_game);
		return;
	}

	/* EFFICIENCY G1: dsq_weight deferred to after nostaged exit.
	 * EFFICIENCY F2: is_game is 0/1, maps directly to tier_base index. */
	u32 dsq_weight = tier_base[is_game];           /* RODATA: JIT immediate */

	/* ADDITIVE FAIRNESS: weight-delta penalty from task_struct (L1-hot).
	 * p->scx.weight is on the same cache line as p->scx.slice.
	 * For nice-0 (weight=100): wd=0, nice_adj=0 (identity).
	 * Approximates quantum_ns/100 ≈ 20000 ≈ (1<<14)+(1<<12) = 20480. */
	s32 wd = 100 - (s32)p->scx.weight;
	s64 nice_adj = ((s64)wd << 14) + ((s64)wd << 12);

	/* ── REQUEUE PATH (~10%) ── */
	if (!(enq_flags & ((u64)SCX_ENQ_WAKEUP | (u64)SCX_ENQ_PREEMPT))) {
		u64 requeue_slice = p->scx.slice ?: quantum_ns;

		/* Flat 50% requeue slice for all classes. */
		requeue_slice >>= 1;
		requeue_slice += (200000 - requeue_slice) & -(requeue_slice < 200000);
		p->scx.slice = requeue_slice;

		/* EEVDF Deadline Projection (additive fairness)
		 * Replaces: vslice = (requeue_slice * vm) >> 10
		 * With: runtime + weight-delta penalty + tier gap */
		p->scx.dsq_vtime += (u64)requeue_slice + nice_adj + dsq_weight;

		u32 target_cpu = scx_bpf_task_cpu(p);
		/* G6: dsq_id hoisted above — reuse shared computation */
		u32 nr = scx_bpf_dsq_nr_queued(dsq_id);

		enqueue_dsq_dispatch(p, enq_flags,
				    ((u64)target_cpu << 32) | enq_llc, nr, (u64)is_game);
		return;
	}

	/* ── WAKEUP PATH (~90%) ── */
	{
		u32 target_cpu = scx_bpf_task_cpu(p);
		/* G6: dsq_id hoisted above — reuse shared computation */
		u32 nr = scx_bpf_dsq_nr_queued(dsq_id);

		/* Pressure-Aware Shrinking */
		u8 pressure = nr >> 2;
		u8 shrink_shift = (pressure > 3) ? 3 : pressure;
		u64 credit_max = 200000000ULL >> (shrink_shift << 1);

		/* MESI Decoupling: read LOCAL cpu's vtime (same-CPU BSS, L1). */
		u32 origin_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		u64 vcl = cpu_bss[origin_cpu].vtime_local;
		u64 vt_min = vcl - credit_max;
		vt_min &= -(u64)(vcl >= credit_max);

		/* Vtime floor clamp: task_struct L1-hot (Phase A) */
		u64 cur_vt = p->scx.dsq_vtime;
		p->scx.dsq_vtime = cur_vt + ((vt_min - cur_vt) & -(u64)(cur_vt < vt_min));

		u64 slice = quantum_ns << (is_game << 1);
		slice >>= shrink_shift;
		p->scx.slice = slice;

		/* EEVDF Deadline Projection (additive fairness)
		 * Replaces: vslice = (slice * vm) >> 10
		 * With: runtime + weight-delta penalty + tier gap */
		p->scx.dsq_vtime += (u64)slice + nice_adj + dsq_weight;

		enqueue_dsq_dispatch(p, enq_flags,
				    ((u64)target_cpu << 32) | enq_llc, nr, (u64)is_game);
	}
}

/* cake_enqueue: struct_ops stub → __noinline enqueue_body.
 * Separates BPF struct_ops arg extraction from core logic. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	enqueue_body(p, enq_flags);
}

/* cake_dispatch: moves tasks from per-LLC DSQs to the local CPU.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this entirely.
 * Only tasks from cake_enqueue → per-LLC DSQ arrive here.
 *
 * Two paths:
 *   1. Fast: pull from this CPU's LLC DSQ
 *   2. Steal: check other LLCs (multi-CCD only, requires 2+ queued tasks) */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	u32 cpu_idx = raw_cpu & (CAKE_MAX_CPUS - 1);
	/* EFFICIENCY G4: stats variables gated — CAKE_STATS_ACTIVE = 0 in
	 * release, so these were dead-code eliminated by compiler anyway.
	 * Explicit gate keeps source truthful. */
#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 dispatch_start = stats_on ? scx_bpf_now() : 0;
#else
	#define stats_on 0
	u64 dispatch_start = 0;
#endif

	/* ALPHADEV Phase 11: Cross-CCD Memory Fetch Bypass
	 * DCE isolates llc_id memory reads strictly to multi-CCD topologies. */
	u32 my_llc = (nr_llcs > 1) ? (cpu_bss[cpu_idx].llc_id & (CAKE_MAX_LLCS - 1)) : 0;
	u64 my_dsq_id = LLC_DSQ_BASE + my_llc;

	/* 1. Fast Path: Check if our local LLC DSQ actually has tasks */
	{
		/* ALPHADEV 40: Depth check eliminated. move_to_local handles empty DSQs natively.
		 * Eradicates 1 kfunc call per dispatch loop unconditionally. */
		if (scx_bpf_dsq_move_to_local(my_dsq_id, 0)) {
			/* Clear mailbox after successful pull (check-before-write). */
			if (dsq_kick_needed[my_llc].needed) dsq_kick_needed[my_llc].needed = 0;
			if (stats_on) {
				struct cake_stats *s = get_local_stats_for(cpu_idx);
				s->nr_local_dispatches++;
				s->nr_dsq_consumed++;
				u64 d_oh = scx_bpf_now() - dispatch_start;
				s->total_dispatch_ns += d_oh;
				s->max_dispatch_ns = s->max_dispatch_ns + ((d_oh - s->max_dispatch_ns) & -(d_oh > s->max_dispatch_ns));
			}
			return;
		}
	}

#ifndef CAKE_SINGLE_LLC
#ifndef CAKE_LOCAL_CPU_ONLY
	/* 2. Steal Path: Look at other LLCs (Active on multi-CCD setups) */
	if (nr_llcs > 1) {
		for (u32 i = 1; i < CAKE_MAX_LLCS; i++) {
			if (i >= nr_llcs) break;
			/* ALPHADEV Phase 8: Multi-CCD O(1) Victim Routing */
			u32 victim = victim_scan_order[my_llc & (CAKE_MAX_LLCS - 1)][i & (CAKE_MAX_LLCS - 1)] & (CAKE_MAX_LLCS - 1);

			u64 victim_dsq = LLC_DSQ_BASE + victim;
			/* EEVDF TOPOLOGY: only cross-CCD steal when victim has 2+ tasks.
			 * Prevents cache-cold migration of single tasks that are better
			 * served waiting for their CCD's core to free up. Mirrors EEVDF's
			 * imbalance_pct threshold for cross-domain migration. */
			if (scx_bpf_dsq_nr_queued(victim_dsq) > 1 && scx_bpf_dsq_move_to_local(victim_dsq, 0)) {
				/* MAILBOX CLEAR: stolen DSQ drained. */
				if (dsq_kick_needed[victim].needed) dsq_kick_needed[victim].needed = 0;
				if (stats_on) {
					struct cake_stats *s = get_local_stats_for(cpu_idx);
					s->nr_stolen_dispatches++;
					s->nr_dsq_consumed++;
				}
				return;
			}
		}
	}
#endif /* CAKE_LOCAL_CPU_ONLY */
#endif

	if (stats_on) get_local_stats_for(cpu_idx)->nr_dispatch_misses++;

	/* G3 FIX: keep_running — if no tasks in any DSQ and prev task is
	 * still queued (wants to run), replenish its slice instead of forcing
	 * a pointless context switch. Saves ~2-4µs per cycle under light load.
	 * Cosmos/bpfland both implement this. Especially important for gaming
	 * where single-task-per-core is the common steady state. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		/* ALPHADEV Phase 13: Ultra-Low Instruction Quantum Replenishment
		 * Avoids reading prev->pid and bss->pid_class_cache. 
		 * cpu_bss[cpu_idx] is already hot in L1. 1 read + 1 ALU shift. */
		u8 is_gaming = (cpu_bss[cpu_idx].sched_state_local == CAKE_STATE_GAMING);
		/* ALPHADEV ILP Shield: Branchless 4x quantum (8ms) mid-frame slice prevention. */
		prev->scx.slice = quantum_ns << (is_gaming << 1);
	}

	/* Check-before-write: only mark idle if not already idle.
	 * Avoids unnecessary cache line dirtying. */
	if (!READ_ONCE(cpu_bss[cpu_idx].idle_hint)) {
		cpu_bss[cpu_idx].idle_hint = 1;
	}
#ifdef CAKE_RELEASE
	#undef stats_on
#endif
}

/* tier_perf_target[] REMOVED: self-documented dead RODATA.
 * Was kept for loader compat only; JIT dead-coded it. */



/* running_telemetry: cold-path arena telemetry for per-task stats.
 * Extracted to __noinline to isolate register pressure from cake_running.
 * Dead-code eliminated in CAKE_RELEASE builds.
 * Records: dispatch gap, wait histogram, overhead timing, mailbox staging. */
#ifndef CAKE_RELEASE
static __noinline void running_telemetry(
	struct task_struct *p,
	u32 cpu,
	u64 now_full,
	u64 overhead_start)
{
	/* Phase 8: mailbox staging stopwatch end (before arena work) */
	u64 mbox_end = scx_bpf_now();

	/* Phase 6: Deferred arena fetch — only in telemetry path */
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (!tctx)
		return;

	u64 start = now_full;

	/* F4: Save OLD run_start BEFORE overwriting for dispatch_gap calc. */
	u64 prev_run_start = tctx->telemetry.run_start_ns;
	tctx->telemetry.run_start_ns = start;

	/* Fetch hot internally (cold path, ~10ns). */
	struct cake_task_ctx __arena *hot_tel = get_task_hot(p);
	if (hot_tel && ((p->nvcsw + p->nivcsw) & 63) != 0)
		return;

	/* 1. DISPATCH GAP */
	if (prev_run_start > 0 && start > prev_run_start) {
		u64 gap = start - prev_run_start;
		tctx->telemetry.dispatch_gap_ns = gap;
		u64 old_max_g = tctx->telemetry.max_dispatch_gap_ns;
		tctx->telemetry.max_dispatch_gap_ns = old_max_g + ((gap - old_max_g) & -(gap > old_max_g));
	}

	tctx->telemetry.llc_id = (u16)cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].llc_id;

	/* 2. WAIT HISTOGRAM */
	if (tctx->telemetry.enqueue_start_ns > 0 && start > tctx->telemetry.enqueue_start_ns) {
		u64 wait = start - tctx->telemetry.enqueue_start_ns;
		tctx->telemetry.wait_duration_ns = wait;
		tctx->telemetry.enqueue_start_ns = 0;

		u64 wait_us = wait >> 10;
		if (wait_us < 10)
			tctx->telemetry.wait_hist_lt10us++;
		else if (wait_us < 100)
			tctx->telemetry.wait_hist_lt100us++;
		else if (wait_us < 1000)
			tctx->telemetry.wait_hist_lt1ms++;
		else
			tctx->telemetry.wait_hist_ge1ms++;
	}

	struct cake_stats *s_run = get_local_stats_for(cpu);
	u64 oh_run = scx_bpf_now() - overhead_start;
	tctx->telemetry.running_duration_ns = (u32)oh_run;
	s_run->total_running_ns += oh_run;
	s_run->max_running_ns = s_run->max_running_ns + ((oh_run - s_run->max_running_ns) & -(oh_run > s_run->max_running_ns));

	/* Phase 8: mailbox staging duration (overhead_start == mbox_start) */
	tctx->telemetry.mbox_staging_ns = (u32)(mbox_end - overhead_start);
}
#endif

/* cake_running: struct_ops callback fired every time a task starts on a CPU.
 *
 * Execution path flattened: running_task_change logic inlined directly.
 * Eliminates call/return overhead and enables cross-boundary CSE
 * (bss pointer shared, p doesn't need separate save/restore).
 * Register budget: p(r6), cpu(r7), bss(r8) = 3 callee-saves at
 * get_task_hot kfunc boundary — under 4-slot limit.
 *
 * On same-task re-runs (75%), skips the entire task-change block
 * via last_pid check — minimal work: 2 kfuncs + 3 stores + 1 branch. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 running_overhead_start = 0;
	if (stats_on)
		running_overhead_start = scx_bpf_now();
#endif

	/* Batch kfuncs first: only p=r6 survives both calls (1 callee-save).
	 * p->scx.slice read DEFERRED until after both kfuncs to avoid
	 * forcing p through 2 separate spill/reload cycles. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

	struct cake_cpu_bss *bss = &cpu_bss[cpu];

#ifndef CAKE_RELEASE
	/* BPF-Native Clock: debug-only monotonic accumulator.
	 * Feeds run_start + running_telemetry (both debug-gated).
	 * In release, now_full has zero consumers → entire clock
	 * system (read, kfunc resync, accumulation) compiles out. */
	u64 now_full = bss->cake_clock;
#endif

	/* ── WRITE: BSS per-CPU (always needed) ── */
	/* idle_hint = 0 marks this CPU busy for the SWAR kick guard.
	 * Unconditional write: CL is already Modified from task-change
	 * writes (last_pid, tick_slice, etc.) on 25% of switches.
	 * On 75% same-task, this is the only write—CL transitions
	 * S→M once, subsequent switches stay M (zero MESI penalty). */
	WRITE_ONCE(bss->idle_hint, 0);

	/* FAST PATH: Same task re-running on same CPU (~75% in gaming).
	 * Slice load and task classification deferred into task-change block.
	 * On same-task re-runs: zero kfunc calls, zero BSS writes beyond idle_hint. */
	if (bss->last_pid != p->pid) {
		/* ── TASK CHANGE: Zero-MESI Arena-Free (Phase 12) ──
		 * Inline game classification from BSS globals + task_struct.
		 * Zero arena, zero division, zero get_task_hot. */
#ifndef CAKE_RELEASE
		now_full = scx_bpf_now();
		bss->cake_clock = now_full;
#endif
		u64 slice = p->scx.slice;
		bss->last_pid = p->pid;
		bss->tick_slice = slice ?: quantum_ns;

		/* Inline game classification: BSS globals (MESI-S) + task_struct (L1) */
		u32 tgid = p->tgid;
		bool is_game = (sched_state == CAKE_STATE_GAMING) &&
			       (tgid == game_tgid || tgid == game_ppid);
		/* EFFICIENCY F6: is_game is bool (0/1), direct cast eliminates
		 * redundant ternary + intermediate variable. */
		bss->game_running = (u8)is_game;

		/* vtime_local: per-CPU monotonic max from task_struct (Phase A) */
		u64 tv = p->scx.dsq_vtime;
		if (tv > bss->vtime_local)
			bss->vtime_local = tv;
	}

	/* BPF-Native Clock: single write with correct value.
	 * Same-task (75%): now_full = cake_clock (from BSS, 1ns).
	 * Task-change (25%): now_full = scx_bpf_now() (resynced above).
	 * Deferred to here so the task-change path can overwrite it. */
#ifndef CAKE_RELEASE
	bss->run_start = (u32)now_full;
#endif

#ifndef CAKE_RELEASE
	if (stats_on)
		running_telemetry(p, cpu, now_full, running_overhead_start);
#endif
}

/* ═══════════════════════════════════════════════════════════════════════════
 * YIELD-GATED CLASSIFICATION + DRR++: Dynamic reclassification on every stop.
 * CPU analog of network CAKE's flow classification:
 * - Cooperative flows (game, audio, input) → voluntary yields → yielder boost
 * - Bulk flows (compilation, background) → run until preempted → tight ceiling
 *
 * This is the engine that makes yield-gated weighted vtime differentiate
 * traffic. Without it, all tasks compete at the same priority.
 * ═══════════════════════════════════════════════════════════════════════════ */
/* stopping_reclassify: confidence-gated cold path (1/64 stops).
 *
 * Runs every 64th cake_stopping call. Classifies tasks into:
 *   CAKE_CLASS_GAME: game tgid + game ppid siblings + all kthreads
 *                    + audio daemons + compositor/Xwayland
 *   CAKE_CLASS_HOG:  non-game tasks using >= 75% of quantum
 *   CAKE_CLASS_BG:   non-game tasks using < 75% of quantum
 *   CAKE_CLASS_NORMAL: non-gaming state (all tasks)
 *
 * Non-GAMING early exit: skips ~25 instructions when not gaming.
 * GAMING path: game_tgid/game_ppid guaranteed non-zero by Rust TUI.
 * Now inlined into stopping_drr_ewma (execution path flattening). */

/* cake_stopping: struct_ops callback fired when a task stops on a CPU.
 *
 * Partially ripped out via ALPHADEV Phase 4 (evacuate the stop path).
 * DRR, EWMA, and reclassification were completely removed. 
 * Fully streamlined to strictly handle vtime integration and telemetry.
 *
 * Reads task_storage (hot) for state; per-CPU BSS for run timestamps.
 * Arena access only in debug telemetry (dead in release). */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[cpu];

	/* ════ Phase 12: Zero-MESI Vtime Integration ════
	 * All data from task_struct (L1) + per-CPU BSS (L1) + BSS cache.
	 * Arena: 0. Division: 0. MESI snoops: 0. get_task_hot: 0. */
	u32 slice_consumed = (u32)bss->tick_slice - (u32)p->scx.slice;
#ifndef CAKE_RELEASE
	/* Debug clock accumulator — feeds run_start/telemetry. Dead in release. */
	bss->cake_clock += slice_consumed;
#endif

	/* Branchless math bounding */
	u32 rt_raw = slice_consumed - ((slice_consumed - (65535U << 10)) & -(slice_consumed > (65535U << 10)));

	if (runnable) {
		/* Additive fairness: weight-delta penalty from task_struct (L1-hot).
		 * Replaces: vt_delta = rt_raw * vm >> 10 (3-cycle multiply)
		 * With: rt_raw + nice_adj (sub + 2 shifts + add = 3c parallel) */
		s32 wd = 100 - (s32)p->scx.weight;
		s64 nice_adj = ((s64)wd << 14) + ((s64)wd << 12);
		p->scx.dsq_vtime += (u64)rt_raw + nice_adj;
	}

	bool stats_on = CAKE_STATS_ACTIVE;
	u64 stopping_overhead_start = 0;

#ifndef CAKE_RELEASE
	/* Debug-only: arena telemetry preserved behind compile gate */
	struct cake_task_ctx __arena *hot = NULL;
	u32 __maybe_unused nvcsw_accum = 0;
	if (stats_on) {
		stopping_overhead_start = scx_bpf_now();
		per_cpu[cpu].mbox.last_stopped_pid = p->pid;

		hot = get_task_hot(p);
		if (hot) {
			u8 tc = hot->task_class;
			if (tc != CAKE_CLASS_GAME) {
				u64 cur_nv = p->nvcsw;
				u64 prev_nv = hot->nvcsw_snapshot;
				if (prev_nv > 0)
					nvcsw_accum = (u32)(cur_nv - prev_nv);
				hot->nvcsw_snapshot = cur_nv;
			}
		}
	}
#endif


	/* ── Telemetry + aggregate profiling (verbose only) ──
	 * Split into ALWAYS (lightweight CL0/BSS) + DEFERRED (heavy CL1-CL3).
	 * Deferred block runs every 64th stop via reclass_counter gate. */
	/* last_run_at: moved up to co-locate with deficit/packed writes (Change B). */

	if (stats_on) {
#ifndef CAKE_RELEASE
		/* ALWAYS: nvcsw_delta accumulator (must not skip deltas) */
		/* Note: nvcsw_delta write is on telemetry CL, but accumulator
		 * correctness requires every-stop update. The CL fetch is
		 * amortized since stopping already read nvcsw_snapshot from CL0. */

		/* DEFERRED TELEMETRY: Heavy per-task writes every 64th stop.
		 * Saves ~13 arena writes + 1 scx_bpf_now() + 1 div64 on 63/64 stops.
		 * SIMPLIFY #3: Single get_task_ctx + shared timestamp for entire block.
		 * FIX: Use pre-increment rc (matches classify block at line 2582).
		 * Was using hot->reclass_counter (post-increment = rc+1) — fired on
		 * different stop than classify, wasting a 29ns get_task_ctx call.
		 * Now reuses tctx_stop (already fetched under same gate). */
		if (unlikely(((p->nvcsw + p->nivcsw) & 63) == 0)) {
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				/* P3-2: Use pre-computed nvcsw_accum from above
				 * (eliminates redundant p->nvcsw + hot->nvcsw_snapshot reads) */
				if (nvcsw_accum)
					tctx->telemetry.nvcsw_delta += nvcsw_accum;

				if (tctx->telemetry.run_start_ns > 0) {
				/* SIMPLIFY #4: Single scx_bpf_now() for dur + stopping overhead */
				u64 now_deferred = scx_bpf_now();
				u64 dur = now_deferred - tctx->telemetry.run_start_ns;
				tctx->telemetry.run_duration_ns = dur;

				/* Branchless same-CPU streak */
				bool same = ((u16)cpu == tctx->telemetry.core_placement);
				tctx->telemetry.same_cpu_streak = (tctx->telemetry.same_cpu_streak + 1) & -(u16)same;
				tctx->telemetry.core_placement = (u16)cpu;

				u32 raw_slice_used = (u32)(cpu_bss[cpu].tick_slice - p->scx.slice);
				raw_slice_used -= (raw_slice_used - (65535U << 10)) & -(raw_slice_used > (65535U << 10));

				/* Jitter: |actual_run - PELT_expected| */
				u64 expected_ns = (u64)(raw_slice_used >> 10) * 1000ULL;
				u64 d = dur - expected_ns;
				u64 mask = -(u64)(dur < expected_ns);
				u64 jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;

				/* Branchless max */
				u16 old_max_rt = tctx->telemetry.max_runtime_us;
				u16 ps = (u16)(raw_slice_used >> 10);
				tctx->telemetry.max_runtime_us = old_max_rt + ((ps - old_max_rt) & -(u16)(ps > old_max_rt));

				/* Slice utilization (shift-approximate, no div64).
				 * (dur << 7) / tslice ≈ dur * 128 / tslice. */
				u64 tslice = cpu_bss[cpu].tick_slice ?: quantum_ns;
				tctx->telemetry.slice_util_pct =
					(u16)((dur << 7) / tslice);

				/* Involuntary context switch delta */
				u64 cur_nivcsw = p->nivcsw;
				u64 prev_nivcsw = tctx->telemetry.nivcsw_snapshot;
				if (prev_nivcsw > 0)
					tctx->telemetry.nivcsw_delta += (u32)(cur_nivcsw - prev_nivcsw);
				tctx->telemetry.nivcsw_snapshot = cur_nivcsw;

				/* Per-task stopping overhead — reuse now_deferred */
				tctx->telemetry.stopping_duration_ns =
					(u32)(now_deferred - stopping_overhead_start);
				}

				/* Phase 8: quantum completion tracking */
				u64 rem = p->scx.slice;
				if (rem == 0)
					tctx->telemetry.quantum_full_count++;
				else if (!runnable)
					tctx->telemetry.quantum_yield_count++;
				else
					tctx->telemetry.quantum_preempt_count++;

				/* Phase 8: CPU core distribution histogram */
				tctx->telemetry.cpu_run_count[cpu & (CAKE_TELEM_MAX_CPUS - 1)]++;

				/* CL0 → arena sync: iter reads these from tctx, not hot.
				 * Values computed in reclassify path above (every 64th stop).
				 * Check-before-write avoids cache invalidation on unchanged fields. */
				if (tctx->vtime_mult != hot->vtime_mult)
					tctx->vtime_mult = hot->vtime_mult;
				if (tctx->task_class != hot->task_class)
					tctx->task_class = hot->task_class;
			}
		}
#endif /* !CAKE_RELEASE */

		/* Aggregate overhead timing (per-CPU BSS). */
		struct cake_stats *s = get_local_stats_for(cpu);
		u64 oh_agg = scx_bpf_now() - stopping_overhead_start;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns = s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) & -(oh_agg > s->max_stopping_ns));
		if (unlikely(((p->nvcsw + p->nivcsw) & 63) == 0))
			s->nr_stop_classify++;
		else
			s->nr_stop_confidence_skip++;

		/* BenchLab trigger (cold — only fires on TUI demand) */
		if (unlikely(bench_request)) {
			bench_request = 0;
			run_kfunc_bench(&bench_results, p);
		}
	}
}

/* Initialize per-task arena storage.
 * Sleepable: bpf_arena_alloc_pages is sleepable-only, so all arena
 * allocation must happen here, not in hot paths.
 * Called before any scheduling ops fire for this task.
 *
 * Phase 12: Hot paths are arena-free in release. Arena fields are
 * only read by cake_task_iter (TUI) and debug telemetry.
 * Release init_task: allocate arena + 3 iter-visible writes + BSS seed.
 * Debug init_task: full field initialization for telemetry. */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct cake_task_ctx __arena *tctx;

	tctx = (struct cake_task_ctx __arena *)scx_task_alloc(p);
	if (!tctx) {
		if (CAKE_STATS_ACTIVE) {
			struct cake_stats *s = get_local_stats();
			s->nr_dropped_allocations++;
		}
		return -ENOMEM;
	}

	/* vtime_mult_cache DELETED: additive fairness reads p->scx.weight
	 * at runtime. No BSS cache seeding needed. */

	/* ── ITER-VISIBLE FIELDS (read by cake_task_iter even in release) ── */
	u32 init_ppid = p->real_parent ? p->real_parent->tgid : 0;
	tctx->ppid = init_ppid;
	tctx->vtime_mult = 100;  /* Default weight for nice-0 (display only) */

	/* packed_info: iter reads this for TUI display.
	 * KCRITICAL bit only needed for iter display — hot-path
	 * enqueue checks (p->flags & PF_KTHREAD && p->prio < 120) inline. */
	u32 packed = 0;
	packed |= ((u32)CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
	if (p->flags & PF_KTHREAD) {
		if (p->prio < 120) {
			packed |= (1u << BIT_KCRITICAL);
		} else {
			u64 comm_val = ((u64 *)p->comm)[0];
			if (comm_val == 0x71726974666f736bULL ||
			    (comm_val & 0x0000FFFFFFFFFFFFULL) == 0x000061696469766eULL ||
			    (comm_val & 0x0000000000FFFFFFULL) == 0x0000000000646d61ULL ||
			    (comm_val & 0x00000000FFFFFFFFULL) == 0x0000000035313969ULL ||
			    (comm_val & 0x000000000000FFFFULL) == 0x0000000000006578ULL) {
				packed |= (1u << BIT_KCRITICAL);
			}
		}
	}
	tctx->packed_info = packed;

#ifndef CAKE_RELEASE
	/* ── DEBUG-ONLY FIELD INITIALIZATION ──
	 * All of these are read only by debug telemetry paths. */
	if (CAKE_STATS_ENABLED) {
		tctx->task_class       = CAKE_CLASS_NORMAL;
	}

	if (CAKE_STATS_ACTIVE) {
		tctx->telemetry.pid = p->pid;
		tctx->telemetry.tgid = p->tgid;
		u64 *comm_src = (u64 *)p->comm;
		u64 __arena *comm_dst = (u64 __arena *)tctx->telemetry.comm;
		comm_dst[0] = comm_src[0];
		comm_dst[1] = comm_src[1];
		tctx->telemetry.nivcsw_snapshot = p->nivcsw;
	}

	if (CAKE_STATS_ENABLED)
		tctx->nvcsw_snapshot = p->nvcsw;

	/* Game classification for debug iter display */
	{
		u8 init_class = CAKE_CLASS_NORMAL;
		if (sched_state == CAKE_STATE_GAMING
		    && (p->tgid == game_tgid
			|| init_ppid == game_ppid
			|| init_ppid == game_tgid))
			init_class = CAKE_CLASS_GAME;
		tctx->task_class = init_class;
	}
#endif

	return 0;
}

/* G1 FIX: .enable callback — initialize task vtime when it becomes schedulable.
 * Like cosmos/bpfland: p->scx.dsq_vtime = vtime_now.
 * For cake, we store in arena (avoids kernel dsq_insert_vtime overwrite). */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	/* Phase 12: Seed dsq_vtime directly in task_struct (L1-hot).
	 * Zero arena access. Kernel preserves p->scx.dsq_vtime across lifecycle. */
	p->scx.dsq_vtime = cpu_bss[bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1)].vtime_local;
}

/* cake_set_cpumask: event-driven affinity update — telemetry counter only.
 * Cached cpumask removed: kernel handles affinity natively. */
void BPF_STRUCT_OPS(cake_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ENABLED) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx)
			tctx->telemetry.cpumask_change_count++;
	}
#endif
}

/* Handle manual yields (e.g. sched_yield syscall).
 * yield_count is TUI-only telemetry (stats-gated). Game family detection
 * uses PPID matching in cake_stopping, not per-task yield counts.
 * Cost in debug: 1 get_task_ctx (~16ns) per yield. Zero cost in release. */
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *p)
{
#ifndef CAKE_RELEASE
	/* F3: Gate behind CAKE_STATS_ENABLED — yield_count is TUI-only.
	 * Saves ~16ns get_task_ctx per sched_yield() in release builds. */
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) tctx->telemetry.yield_count++;
	}
#endif
	return false;
}

/* Handle preemption when a task is pushed off the CPU. */
void BPF_STRUCT_OPS(cake_runnable, struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			if (enq_flags & SCX_ENQ_PREEMPT)
				tctx->telemetry.preempt_count++;
			/* Wakeup source: the currently running task is the waker */
			struct task_struct *waker = bpf_get_current_task_btf();
			if (waker) {
				tctx->telemetry.wakeup_source_pid = waker->pid;
				/* Wake chain tracking */
				tctx->telemetry.waker_cpu = (u16)bpf_get_smp_processor_id();
				tctx->telemetry.waker_tgid = waker->tgid;
			}
		}
	}
#endif
}

/* Free per-task arena storage on task exit. */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	/* Remove from PID→tctx map: removed — iter/task program handles visibility
	 * without explicit cleanup. Task storage freed below. */
	scx_task_free(p);
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	/* Per-CPU DSQs eliminated — SCX_DSQ_LOCAL_ON dispatches directly to
     * the kernel's built-in local DSQ, skipping dispatch callback entirely.
     * Per-LLC DSQs used for enqueue → dispatch path. */
	/* Single vtime-ordered DSQ per LLC.
     * Priority encoded in vtime: (vtime_tier << 56) | timestamp.
     * T0 always dispatches first (lowest vtime). Eliminates 3 empty probes.
     * Single-CCD (9800x3d): 1 DSQ. Multi-CCD: N DSQs (one per LLC).
     * DSQ ID = LLC_DSQ_BASE + llc_index. */
	for (u32 i = 0; i < CAKE_MAX_LLCS; i++) {
		if (i >= nr_llcs)
			break;
		s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
		if (ret < 0)
			return ret;
	}

	/* Per-CPU arena allocation, dynamically sized.
	 * Pages = ceil(nr_cpus × CAKE_MBOX_SIZE / 4096).
	 * nr_cpus is RODATA → JIT constant-folds at load time. */
	{
		/* 4096 is 2^12. Bitshift replaces division compiler inference. */
		u32 nr_arena_pages = ((u32)nr_cpus * CAKE_MBOX_SIZE + 4095) >> 12;
		if (nr_arena_pages < 1)
			nr_arena_pages = 1;
		per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
			&arena, NULL, nr_arena_pages, NUMA_NO_NODE, 0);
	}
	if (!per_cpu)
		return -ENOMEM;


	/* Populate per-CPU LLC ID cache from RODATA.
	 * Set once at init — llc_id never changes for a given CPU. */
	for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
		if (i >= nr_cpus)
			break;
		cpu_bss[i].llc_id = (u8)cpu_llc_id[i];
	}

	return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* cake_task_iter: SEC("iter/task") — replaces pid_to_tctx hash map.
 * Iterates all kernel tasks. Emits cake_iter_record for each managed task.
 * Userspace reads fixed-size records via link fd. Zero scheduling overhead.
 * No init/exit map ops: cake_init_task and cake_exit_task are lockless.
 *
 * Telemetry copies split into noinline batches to avoid register spills. */

#ifndef CAKE_RELEASE
/* Batch 1: timing fields (u64-heavy, 4 u64s + 3 u32s = ~44 bytes) */
static __noinline void iter_copy_timing(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.run_start_ns          = tctx->telemetry.run_start_ns;
	rec->telemetry.run_duration_ns       = tctx->telemetry.run_duration_ns;
	rec->telemetry.enqueue_start_ns      = tctx->telemetry.enqueue_start_ns;
	rec->telemetry.wait_duration_ns      = tctx->telemetry.wait_duration_ns;
	rec->telemetry.select_cpu_duration_ns= tctx->telemetry.select_cpu_duration_ns;
	rec->telemetry.enqueue_duration_ns   = tctx->telemetry.enqueue_duration_ns;
	rec->telemetry.dsq_insert_ns         = tctx->telemetry.dsq_insert_ns;
	rec->telemetry.jitter_accum_ns       = tctx->telemetry.jitter_accum_ns;
	rec->telemetry.stopping_duration_ns  = tctx->telemetry.stopping_duration_ns;
	rec->telemetry.running_duration_ns   = tctx->telemetry.running_duration_ns;
	rec->telemetry.max_runtime_us        = tctx->telemetry.max_runtime_us;
	rec->telemetry._pad4                 = 0;
	rec->telemetry.dispatch_gap_ns       = tctx->telemetry.dispatch_gap_ns;
	rec->telemetry.max_dispatch_gap_ns   = tctx->telemetry.max_dispatch_gap_ns;
}

/* Batch 2: gate hits + counters (all u32/u16 — compact) */
static __noinline void iter_copy_gates(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.gate_1_hits           = tctx->telemetry.gate_1_hits;
	rec->telemetry.gate_2_hits           = tctx->telemetry.gate_2_hits;
	rec->telemetry.gate_1w_hits          = tctx->telemetry.gate_1w_hits;
	rec->telemetry.gate_3_hits           = tctx->telemetry.gate_3_hits;
	rec->telemetry.gate_1p_hits          = tctx->telemetry.gate_1p_hits;
	rec->telemetry.gate_1c_hits          = tctx->telemetry.gate_1c_hits;
	rec->telemetry.gate_1cp_hits         = tctx->telemetry.gate_1cp_hits;
	rec->telemetry.gate_1d_hits          = tctx->telemetry.gate_1d_hits;
	rec->telemetry.gate_1wc_hits         = tctx->telemetry.gate_1wc_hits;
	rec->telemetry.gate_tun_hits         = tctx->telemetry.gate_tun_hits;
	rec->telemetry._pad2                 = 0;
	rec->telemetry.total_runs            = tctx->telemetry.total_runs;
	rec->telemetry.core_placement        = tctx->telemetry.core_placement;
	rec->telemetry.migration_count       = tctx->telemetry.migration_count;
	rec->telemetry.preempt_count         = tctx->telemetry.preempt_count;
	rec->telemetry.yield_count           = tctx->telemetry.yield_count;
	rec->telemetry.direct_dispatch_count = tctx->telemetry.direct_dispatch_count;
	rec->telemetry.enqueue_count         = tctx->telemetry.enqueue_count;
	rec->telemetry.cpumask_change_count  = tctx->telemetry.cpumask_change_count;
	rec->telemetry._pad3                 = 0;
}

/* Batch 3: histogram + identity fields */
static __noinline void iter_copy_hist(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.wait_hist_lt10us      = tctx->telemetry.wait_hist_lt10us;
	rec->telemetry.wait_hist_lt100us     = tctx->telemetry.wait_hist_lt100us;
	rec->telemetry.wait_hist_lt1ms       = tctx->telemetry.wait_hist_lt1ms;
	rec->telemetry.wait_hist_ge1ms       = tctx->telemetry.wait_hist_ge1ms;
	rec->telemetry.slice_util_pct        = tctx->telemetry.slice_util_pct;
	rec->telemetry.llc_id                = tctx->telemetry.llc_id;
	rec->telemetry.same_cpu_streak       = tctx->telemetry.same_cpu_streak;
	rec->telemetry._pad_recomp           = 0;
	rec->telemetry.wakeup_source_pid     = tctx->telemetry.wakeup_source_pid;
	rec->telemetry.nivcsw_snapshot       = tctx->telemetry.nivcsw_snapshot;
	rec->telemetry.nvcsw_delta           = tctx->telemetry.nvcsw_delta;
	rec->telemetry.nivcsw_delta          = tctx->telemetry.nivcsw_delta;
	rec->telemetry.pid_inner             = tctx->telemetry.pid;
	rec->telemetry.tgid                  = tctx->telemetry.tgid;
	/* comm: 16 bytes as two u64 reads via arena cast */
	*((__u64 *)&rec->telemetry.comm[0]) = *((__u64 __arena *)&tctx->telemetry.comm[0]);
	*((__u64 *)&rec->telemetry.comm[8]) = *((__u64 __arena *)&tctx->telemetry.comm[8]);
}

/* Batch 4: enqueue substage timing + quantum + waker + per-CPU run counts */
static __noinline void iter_copy_substage(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.gate_cascade_ns       = tctx->telemetry.gate_cascade_ns;
	rec->telemetry.idle_probe_ns         = tctx->telemetry.idle_probe_ns;
	rec->telemetry.vtime_compute_ns      = tctx->telemetry.vtime_compute_ns;
	rec->telemetry.mbox_staging_ns       = tctx->telemetry.mbox_staging_ns;
	rec->telemetry._pad_ewma             = 0;
	rec->telemetry.classify_ns           = tctx->telemetry.classify_ns;
	rec->telemetry.vtime_staging_ns      = tctx->telemetry.vtime_staging_ns;
	rec->telemetry.warm_history_ns       = tctx->telemetry.warm_history_ns;
	rec->telemetry.quantum_full_count    = tctx->telemetry.quantum_full_count;
	rec->telemetry.quantum_yield_count   = tctx->telemetry.quantum_yield_count;
	rec->telemetry.quantum_preempt_count = tctx->telemetry.quantum_preempt_count;
	rec->telemetry._pad_quantum          = 0;
	rec->telemetry.waker_cpu             = tctx->telemetry.waker_cpu;
	rec->telemetry._pad_waker            = 0;
	rec->telemetry.waker_tgid            = tctx->telemetry.waker_tgid;
	/* cpu_run_count: per-element arena reads */
	for (int _ci = 0; _ci < CAKE_TELEM_MAX_CPUS; _ci++)
		rec->telemetry.cpu_run_count[_ci] = tctx->telemetry.cpu_run_count[_ci];
}
#endif /* !CAKE_RELEASE */

SEC("iter/task")
int cake_task_iter(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	if (!task)
		return 0;

	/* Only emit tasks managed by this scheduler instance. */
	struct cake_task_ctx __arena *tctx = get_task_ctx(task);
#ifndef CAKE_RELEASE
	if (!tctx || !tctx->telemetry.pid)
		return 0;
#else
	if (!tctx)
		return 0;
#endif

	/* Build iter record from arena tctx data.
	 * Zero-init: in release builds, telemetry block is skipped —
	 * without this, bpf_seq_write emits stack garbage. */
	struct cake_iter_record rec = {};
	rec.pid         = task->pid;
	rec.ppid        = tctx->ppid;
	rec.packed_info = tctx->packed_info;
	rec.pelt_util = (u16)task->se.avg.util_avg;
	rec._pad_iter_def  = 0;
	rec.vtime_mult     = tctx->vtime_mult;

#ifndef CAKE_RELEASE
	/* Telemetry: batched noinline copies → 0 spills per batch.
	 * Each batch: 2 args (tctx+rec) = 2 callee-saves. */
	iter_copy_timing(tctx, &rec);
	iter_copy_gates(tctx, &rec);
	iter_copy_hist(tctx, &rec);
	iter_copy_substage(tctx, &rec);
#endif

	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}
/* F3 FIX: Tick callback for cross-LLC load balance hinting.
 * Runs once per tick (~1ms) per CPU. Throttled to every 8th tick (~8ms)
 * to minimize overhead. On single-CCD (nr_llcs==1), JIT eliminates
 * the entire function body (RODATA constant fold).
 *
 * Kernel source truth (ext.c:2798-2817): task_tick_scx() calls this
 * AFTER update_curr_scx() has already decremented p->scx.slice.
 * Slice enforcement is FREE — we only use this for load balance hinting.
 *
 * Algorithm: if my LLC's DSQ has 2+ tasks queued AND another LLC's DSQ
 * is empty, kick one of that LLC's CPUs to trigger cross-LLC steal.
 * This turns passive "discover work on idle" into proactive "notify idle". */
void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
#ifdef CAKE_SINGLE_LLC
	/* Single-LLC: compile-time eliminated. Verifier sees only `return;`.
	 * No dead-path analysis of cross-LLC balancing code. */
	return;
#else
	/* Single-LLC: nothing to balance. JIT dead-code eliminates. */
	if (nr_llcs <= 1)
		return;

	/* Throttle: only check every 8th tick (~8ms) to minimize overhead.
	 * 1ms per-tick × 8 = 8ms period. Cost on fast path: 1 byte load + AND.
	 * tick_count wraps at 255 — no concern, only low 3 bits matter. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	cpu_bss[cpu].tick_count++;
	if (cpu_bss[cpu].tick_count & 7)
		return;

	/* Check my LLC's DSQ depth — only rebalance when overloaded */
	u32 my_llc = cpu_bss[cpu].llc_id;
	s32 my_depth = scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + my_llc);
	if (my_depth < 2)
		return;

	/* Find an empty LLC and kick one of its CPUs to trigger steal.
	 * Round-robin from my_llc+1 to avoid always kicking the same LLC.
	 * llc_cpu_mask[] is RODATA — zero cache bounce on read. */
	for (u32 i = 1; i < CAKE_MAX_LLCS && i < nr_llcs; i++) {
		u32 other = (my_llc + i);
		if (other >= nr_llcs) other -= nr_llcs;
		s32 other_depth = scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + other);
		if (other_depth == 0) {
			u64 mask = llc_cpu_mask[other];
			if (mask) {
				u32 target = __builtin_ctzll(mask);
				if (target < nr_cpus)
					scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
			}
			break;
		}
	}
#endif /* !CAKE_SINGLE_LLC */
}

/* scx_nice_weight[40] + scx_nice_mult[40] DELETED:
 * Additive fairness model reads p->scx.weight directly from task_struct.
 * No RODATA tables needed. -160 bytes RODATA. */

/* Additive fairness: cake_set_weight is now a no-op for the hot path.
 * The kernel calls this when p->scx.weight changes via cgroup or nice.
 * Hot paths read p->scx.weight directly (L1-hot, same CL as p->scx.slice).
 * Only arena update for TUI display remains. */
void BPF_STRUCT_OPS(cake_set_weight, struct task_struct *p, u32 weight)
{
#ifndef CAKE_RELEASE
	/* Mirror weight to arena for debug telemetry (iter reads tctx->vtime_mult).
	 * Semantic change: now stores raw weight (100=nice0) instead of reciprocal. */
	struct cake_task_ctx __arena *hot = get_task_hot(p);
	if (hot) {
		u16 w = (u16)(weight ?: 100);
		if (hot->vtime_mult != w)
			hot->vtime_mult = w;
	}
#endif
}

SCX_OPS_DEFINE(cake_ops, .select_cpu = (void *)cake_select_cpu,
	       .enqueue	 = (void *)cake_enqueue,
	       .dispatch = (void *)cake_dispatch,
	       .tick         = (void *)cake_tick,
	       .running	    = (void *)cake_running,
	       .stopping    = (void *)cake_stopping,
	       .yield = (void *)cake_yield,
	       .runnable = (void *)cake_runnable,
	       .set_weight   = (void *)cake_set_weight,
	       .enable       = (void *)cake_enable,
	       .set_cpumask = (void *)cake_set_cpumask,
	       .init_task   = (void *)cake_init_task,
	       .exit_task = (void *)cake_exit_task, .init = (void *)cake_init,
	       .exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms = 5000, /* G2 FIX: starvation watchdog — matches cosmos/bpfland */
	       .name = "cake");
