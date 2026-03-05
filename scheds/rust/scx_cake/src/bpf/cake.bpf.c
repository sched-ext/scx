// SPDX-License-Identifier: GPL-2.0
/* scx_cake - CAKE DRR++ adapted for CPU scheduling: yield-gated priority, direct dispatch, per-LLC DSQ */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/arena_map.h> /* BPF_MAP_TYPE_ARENA definition */
#include <lib/sdt_task.h> /* scx_task_data, scx_task_alloc, scx_task_free */
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
const u64  quantum_ns	     = CAKE_DEFAULT_QUANTUM_NS;
const u64  new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;

/* Hog Squeeze RODATA — self-regulating triple-gate deprioritization.
 * Vtime penalties only matter under contention (zero contention = zero impact).
 * Set by loader, derivable from hardware config. */
const u32  hog_vtime_shift    = 2;           /* 4× slower vtime (1<<2) */
const u32  hog_quantum_cap_ns = 250 * 1000;  /* 250µs max slice for hogs */
const u32  bg_vtime_shift     = 1;           /* 2× slower vtime for bg noise */
const u32  bg_quantum_cap_ns  = 500 * 1000;  /* 500µs max slice for bg noise */

/* RODATA BAKING: hot-path constants promoted from #define for JIT folding
 * + per-profile tunability. JIT treats these identically to immediates.
 * Rust loader can override for esports/battery profiles. */
const u64  aq_yielder_ceiling_ns = AQ_YIELDER_CEILING_NS; /* 50ms ceiling for yielders */
const u64  aq_min_ns             = AQ_MIN_NS;             /* 50µs quantum floor */
const u32  pelt_hog_threshold    = CAKE_PELT_HOG_THRESHOLD; /* 800 PELT util → HOG */
const u32  preempt_vip_ns        = CAKE_PREEMPT_VIP_THRESHOLD_NS;     /* 50µs VIP preempt */
const u32  preempt_yielder_ns    = CAKE_PREEMPT_YIELDER_THRESHOLD_NS; /* 100µs normal preempt */

/* JITTER REDUCTION: RODATA lookup tables indexed by task_class (0-3).
 * Eliminates branching chains — single indexed load is constant-time
 * regardless of class, zero pipeline misprediction variance.
 * Populated by Rust loader from hog/bg RODATA values. */
const u32  quantum_cap_ns[4]     = { 0, 0, 250000, 500000 };  /* NORMAL/GAME=0(no cap), HOG=250µs, BG=500µs */
const u32  vtime_penalty_shift[4] = { 0, 0, 2, 1 };           /* NORMAL/GAME=0, HOG=2(4×), BG=1(2×) */
const u32  preempt_thresh_ns[4]  = { 100000, 50000, 100000, 100000 }; /* NORMAL=100µs, GAME=50µs(VIP), HOG/BG=100µs */
/* CAKE_STATS_ENABLED: compile-time elimination for release builds.
 *
 * RELEASE (CAKE_RELEASE=1, set by build.rs in --release):
 *   CAKE_STATS_ENABLED is a compile-time constant 0. Clang eliminates ALL
 *   stats/telemetry branches entirely — zero instructions, zero overhead.
 *   The --verbose flag is unavailable in release builds.
 *
 * DEBUG (CAKE_RELEASE not defined):
 *   volatile RODATA toggle — loader patches enable_stats to true when
 *   --verbose is passed. Volatile prevents Clang DCE while the initial
 *   value is still 'false'. JIT replaces the volatile load with an
 *   immediate compare after loader patching — negligible cost. */
#ifdef CAKE_RELEASE
#define CAKE_STATS_ENABLED 0
#else
const bool enable_stats __attribute__((used)) = false;
#define CAKE_STATS_ENABLED (*(volatile const bool *)&enable_stats)
#endif
/* CAKE_STATS_ACTIVE: runtime-suppressible telemetry.
 * False during BenchLab runs (bench_active=1) so kfunc measurements
 * aren't polluted by ~15 extra scx_bpf_now() + arena writes per event. */
#define CAKE_STATS_ACTIVE (CAKE_STATS_ENABLED && !bench_active)
const bool enable_dvfs =
	false; /* RODATA — loader-compat only (tick removed, DVFS dead) */

/* Topology config - JIT eliminates unused SMT steering when nr_cpus <= nr_phys_cpus.
 * has_hybrid removed: Rust loader pre-fills cpu_sibling_map for ALL topologies
 * via scx_utils::Topology::sibling_cpus(). No runtime branching needed. */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const u32 nr_llcs = 1;
const u32 nr_cpus = 8; /* Set by loader — bounds kick scan loop (Rule 39) */
const u32 nr_phys_cpus =
	8; /* Set by loader — physical core count for PHYS_FIRST */
const u32 nr_nodes = 1; /* Set by loader — NUMA node count for bench competitor */
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};
const u32 cpuperf_cap_table[CAKE_MAX_CPUS] = {}; /* Set by loader — per-CPU max perf */

/* Topological O(1) Arrays — populated by loader */
const u64 llc_cpu_mask[CAKE_MAX_LLCS]	 = {};
const u64 core_cpu_mask[32]		 = {};
const u8  cpu_sibling_map[CAKE_MAX_CPUS] = {};

/* BSS bench state: xorshift32 PRNG seed */
u32 bench_xorshift_state = 0xDEADBEEF;

/* Heterogeneous Routing Masks */
const u64  big_core_phys_mask = 0;
const u64  big_core_smt_mask  = 0;
const u64  little_core_mask   = 0;
const u64  vcache_llc_mask    = 0;
const bool has_vcache	      = false;

/* Legacy 16-bit physical wrapper */

/* ═══════════════════════════════════════════════════════════════════════════
 * PER-CPU ARENA BLOCK: Unified mailbox + scratch (C1 spatial consolidation).
 *
 * Merges arena_mailbox (128B) + arena_scratch (128B) into a single 256B
 * per-CPU allocation. Benefits:
 *   - 1 BSS global pointer, 1 TLB entry, 1 null-check
 *   - release: 64B/CPU (1 CL, 1 page total), debug: 128B/CPU (2 CL, 2 pages)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct cake_per_cpu {
	struct mega_mailbox_entry
		mbox; /* release: 64B (1 CL), debug: 128B (2 CL) */
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
_Static_assert(sizeof(struct cake_per_cpu) == CAKE_MBOX_SIZE,
	       "cake_per_cpu must match CAKE_MBOX_SIZE for per-CPU isolation");
struct cake_per_cpu __arena *per_cpu;

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
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



/* ARENA_ASSOC: Force arena map association for struct_ops programs.
 * BSS loads don't create arena map relocations — only direct &arena references do.
 * Inline asm constraint forces &arena into a register (ld_imm64 relocation)
 * without emitting a stack store. 2 insns vs 3 with volatile. */
#define ARENA_ASSOC() asm volatile("" : : "r"(&arena))

static __always_inline struct cake_stats *get_local_stats(void)
{
#ifndef CAKE_RELEASE
	asm volatile("" : : "r"(enable_stats) : "memory");
#endif
	u32 cpu = bpf_get_smp_processor_id();
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* Rule 30: Avoid redundant bpf_get_smp_processor_id() kfunc trampoline (~15ns)
 * when caller already has CPU ID in a register. */
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

/* ── Game Family Boost: PPID-based process-level yielder promotion ──
 * Written by Rust TUI every poll (~500ms) with detected game tgid + ppid.
 * Read in cake_stopping and select_cpu to identify game family members.
 * game_tgid == 0 means no game detected (system behaves as before).
 * Own cache line: written rarely (~2/s), read on every dispatch (~6K/s).
 * After settling, lives in shared-S state across all cores (~1ns read). */
u32 game_tgid __attribute__((aligned(64))) = 0;
/* Parent PID of game process — all Proton/Wine siblings share the same
 * pv-adverb container PPID.  Written by Rust TUI alongside game_tgid.
 * Same cache-line lifecycle: written rarely (~2/s), read in cake_stopping. */
u32 game_ppid = 0;
/* Scheduler operating state: IDLE=0, COMPILATION=1, GAMING=2.
 * Written by Rust TUI every poll (~500ms). Read by BPF hot path to select
 * the appropriate policy profile (squeeze, Gate 1P, quantum ceiling).
 * Lives on the same cache line as game_tgid/game_ppid — written rarely,
 * read-shared across cores in MESI-S state at ~1ns cost. */
u32 sched_state = CAKE_STATE_IDLE;
/* Precomputed quantum ceiling — set by userspace when sched_state changes.
 * Eliminates sched_state == COMPILATION branch from stopping hot path.
 * COMPILATION → 8ms, else → 2ms. Zero-init for BSS placement; Rust sets
 * initial value (AQ_BULK_CEILING_NS) at startup. Written at ~2Hz by TUI. */
u64 quantum_ceiling_ns = 0;
/* Confidence score for game detection: 100=Steam-confirmed, 90=Wine .exe,
 * 50=native/unknown, 0=none. Written by Rust TUI alongside sched_state.
 * Same cache line — available for future BPF hot-path policy scaling. */
u8 game_confidence = 0;

/* Phase 5: Per-CPU BSS — arena-free running.
 * Each entry is 64B aligned (one cache line per CPU).
 * running writes, stopping reads (same CPU) + Gate 1P reads (remote CPU). */
struct cake_cpu_bss cpu_bss[CAKE_MAX_CPUS];

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

/* Phase 6: Per-task hot fields in kernel task_storage (~10ns lookup).
 * Replaces Arena CL0 reads in running+stopping (saves 2× 19ns = 38ns).
 * Arena CL0 still exists for telemetry but is dead in release builds. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_task_hot);
} task_hot_stor SEC(".maps");

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

	/* Bench: get_task_ctx() — bpf_task_storage_get + arena deref */
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
				volatile u16 field = tctx->deficit_u16; /* Deref cached ptr */
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

	/* Bench: RODATA array lookup — cpu_llc_id[cpu] + tier_slice_ns[tier] */
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
	 * Simulates Gate 1b/1W where we probe a DIFFERENT CPU's idle state.
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
			volatile u16 _fused = tctx ? tctx->deficit_u16 : 0;
			volatile u64 _nvcsw = tctx ? tctx->nvcsw_snapshot : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_COLD_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _packed + _fused + _nvcsw;
		}
	}

	/* Bench: Arena stride — walk 16 per_cpu mailbox entries.
	 * Forces TLB walks across arena pages. With 4KB pages, each per_cpu
	 * block (256B) shares pages, but 16 blocks span ~4KB. With hugepages
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
				cpu_bss[lf_cpu & (CAKE_MAX_CPUS - 1)].is_yielder;
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
	 * CONFIG_SCHEDSTATS=y verified. Wakeup frequency = interactivity signal. */
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
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].is_yielder = 0;
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start = 12345678ULL;
			asm volatile("" ::: "memory");
			/* Read back (like cake_select_cpu reads cpu_bss) */
			volatile u8 hint = cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint;
			volatile u8 yielder = cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].is_yielder;
			volatile u64 start = cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = hint + yielder + start;
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

	/* Bench 57: 6-gate cascade simulation — cake's select_cpu flow.
	 * Tests: prev idle check → BSS[sib] idle_hint → BSS[home] idle_hint.
	 * This is the FULL cascade data access pattern. */
	{
		s32 self = bpf_get_smp_processor_id();
		s32 sib = cpu_sibling_map[self & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Gate 1: prev idle? (test_and_clear is the real op) */
			volatile bool prev_idle = scx_bpf_test_and_clear_cpu_idle(self);
			/* Gate 1b: sibling idle_hint from BSS? */
			volatile u8 sib_idle = cpu_bss[sib & (CAKE_MAX_CPUS - 1)].idle_hint;
			/* Gate 1C: home CPU idle_hint from BSS? (simulated as prev) */
			volatile u8 home_idle = cpu_bss[self & (CAKE_MAX_CPUS - 1)].idle_hint;
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
	 * Simulates lavd's update_stat_for_running key path. Compare vs 17. */
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

	/* Bench 61: cake SMT probe — test_and_clear(sibling) + BSS check.
	 * This is cake's Gate 1b: atomic idle clear + BSS idle_hint read.
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
			volatile u8 hint = cpu_bss[sib_cpu & (CAKE_MAX_CPUS - 1)].idle_hint;
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
			struct cake_task_hot *hot_cold = bpf_task_storage_get(
				&task_hot_stor, p, 0, 0);
			volatile u16 cold_val = hot_cold ? hot_cold->deficit_u16 : 0;
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




/* ═══ YIELD-GATED ADAPTIVE QUANTUM (Phase 5.0) ═══
 * Yielders get the full ceiling — they cooperate (voluntarily yield)
 * and will never approach 50ms in practice. The slice is NOT a fairness
 * mechanism (vtime handles that); it only sets the preemption deadline.
 * Trusting yielders with a generous deadline eliminates all ICSW.
 *
 * Non-yielders: clamp(PELT × BULK_HEADROOM, 50µs, ceiling) — tight leash.
 * ceiling_ns selects the cap: 2ms for gaming/idle, 8ms for COMPILATION. */
static __always_inline u64 yield_gated_quantum_ns(u16 pelt_runtime_us,
						  bool yielder, u64 ceiling_ns)
{
	if (yielder)
		return aq_yielder_ceiling_ns;

	/* Bulk path: PELT × 1000 (µs→ns), clamped [floor, ceiling].
	 * AQ_BULK_HEADROOM (1) eliminated — multiply by 1 is dead work. */
	u64 q = (u64)pelt_runtime_us * 1000;
	u64 lo = aq_min_ns;
	q = q + ((lo - q) & -(q < lo));
	q = q - ((q - ceiling_ns) & -(q > ceiling_ns));
	return q;
}



/* Per-task context: arena-backed direct pointer dereference.
 * Replaces BPF_MAP_TYPE_TASK_STORAGE (hash lookup, ~25-40ns cold)
 * Fast, direct lookups utilizing Arena pointers rather than BPF task storage.
 * Storage allocated in cake_init_task (sleepable), freed in cake_exit_task. */

/* Get task context — arena direct pointer dereference.
 * Arena storage allocated upfront in cake_init_task (sleepable).
 * No null check needed in hot paths: init_task guarantees allocation
 * before any scheduling callbacks fire for this task.
 * __arena qualifier: verifier knows this pointer is arena-backed. */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p)
{
	return (struct cake_task_ctx __arena *)scx_task_data(p);
}

/* Phase 6: Fast per-task hot field lookup (~10ns vs 29ns arena).
 * Used by running + stopping + select_cpu + enqueue for CL0 fields.
 * Returns NULL if task_storage not yet allocated (init_task not called). */
static __always_inline struct cake_task_hot *
get_task_hot(struct task_struct *p)
{
	return bpf_task_storage_get(&task_hot_stor, p, 0, 0);
}

/* ═══ DEDUP HELPERS (F1/F2/F3) ═══
 * Extracted from repeated inline blocks to reduce BPF insn footprint,
 * i-cache pressure, and source maintenance burden.
 * All __always_inline: zero call overhead, compiler CSE applies. */

/* F1: Direct-dispatch helper — shared by all gates in cake_select_cpu.
 * Loads slice, inserts to SCX_DSQ_LOCAL_ON, records per-task telemetry.
 * gate_id selects which gate counter to increment (0=none). */
enum gate_id {
	GATE_NONE = 0,
	GATE_1    = 1, /* prev_cpu idle */
	GATE_1B   = 2, /* SMT sibling */
	GATE_1W   = 3, /* Waker affinity */
	GATE_1P   = 4, /* Yielder preempts bulk */
	GATE_3    = 5, /* Kernel fallback */
	GATE_1C   = 6, /* Home CPU warm set */
	GATE_1D   = 7, /* Domestic: same-process cache affinity */
	GATE_1WC  = 8, /* Waker-chain: producer-consumer locality */
	GATE_1CP  = 9, /* Home CPU preempt-hog (migration dampening) */
};

static __always_inline s32
direct_dispatch(struct task_struct *p, s32 cpu, u64 wake_flags,
		u64 start_time, enum gate_id gid, bool stats_on,
		struct cake_task_ctx __arena *tctx, s32 caller_cpu)
{
	u64 slice = p->scx.slice ?: quantum_ns;
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);

	/* IPI SAFETY NET: After scx_bpf_test_and_clear_cpu_idle() cleared the
	 * idle bit, the kernel may skip sending an IPI to wake that CPU from
	 * deep C-states (C1/C6). If the target CPU != our current CPU, we must
	 * explicitly kick it to ensure it wakes up and processes the task.
	 * Without this, tasks get stranded on sleeping cores — observed as
	 * 86M dispatch thrash + 31s kworker starvation during Alt-Tab.
	 * THROUGHPUT: caller_cpu passed from caller (Rule 30: avoid redundant
	 * bpf_get_smp_processor_id kfunc trampoline ~15ns). */
	if (cpu != caller_cpu)
		scx_bpf_kick_cpu(cpu, 0);

#ifndef CAKE_RELEASE
	if (stats_on && tctx) {
		/* Guard against clock-skew underflow (Rule F5) */
		u64 sel_end = scx_bpf_now();
		u32 sel_dur = sel_end > start_time ? (u32)(sel_end - start_time) : 0;
		tctx->telemetry.select_cpu_duration_ns = sel_dur;
		/* Phase 8: gate cascade = full select_cpu time (same metric, explicit name) */
		tctx->telemetry.gate_cascade_ns = sel_dur;
		switch (gid) {
		case GATE_1:  tctx->telemetry.gate_1_hits++;  break;
		case GATE_1B: tctx->telemetry.gate_2_hits++;  break;
		case GATE_1W: tctx->telemetry.gate_1w_hits++; break;
		case GATE_1P: tctx->telemetry.gate_1p_hits++; break;
		case GATE_3:  tctx->telemetry.gate_3_hits++;  break;
		case GATE_1C: tctx->telemetry.gate_1c_hits++; break;
		case GATE_1CP: tctx->telemetry.gate_1cp_hits++; break;
		case GATE_1D: tctx->telemetry.gate_1d_hits++; break;
		case GATE_1WC: tctx->telemetry.gate_1wc_hits++; break;
		default: break;
		}
		tctx->telemetry.direct_dispatch_count++;
	}
#endif
	return cpu;
}

/* F2: Enqueue telemetry helper — shared by 3 enqueue paths.
 * Records aggregate + per-task enqueue timing after DSQ insert.
 * tctx + enq_cpu passed from caller — zero redundant get_task_ctx/get_smp calls. */
static __always_inline void
enqueue_telemetry(struct task_struct *p, u64 start_time, u64 pre_kfunc,
		  u64 now_cached, bool stats_on,
		  struct cake_task_ctx __arena *tctx, u32 enq_cpu)
{
	u64 post_kfunc = scx_bpf_now();
	struct cake_stats *s = get_local_stats_for(enq_cpu);
	/* Per-CPU stats: single-writer, no atomic needed (Rule 22) */
	s->total_enqueue_latency_ns += post_kfunc - start_time;
#ifndef CAKE_RELEASE
	if (tctx) {
		tctx->telemetry.enqueue_start_ns = now_cached;
		/* Guard against clock-skew underflow (negative delta → u32 wrap) */
		tctx->telemetry.enqueue_duration_ns =
			post_kfunc > start_time ? (u32)(post_kfunc - start_time) : 0;
		tctx->telemetry.dsq_insert_ns =
			post_kfunc > pre_kfunc ? (u32)(post_kfunc - pre_kfunc) : 0;
		/* Phase 8: vtime compute = enqueue overhead minus DSQ insert kfunc cost */
		u32 total_enq = post_kfunc > start_time ? (u32)(post_kfunc - start_time) : 0;
		u32 insert_cost = post_kfunc > pre_kfunc ? (u32)(post_kfunc - pre_kfunc) : 0;
		tctx->telemetry.vtime_compute_ns = total_enq > insert_cost ? total_enq - insert_cost : 0;
	}
#endif
}

/* F3: Build cached cpumask from kernel cpumask — shared by init_task + set_cpumask.
 * Converts bpf_cpumask_test_cpu kfunc calls to a u64 bitmask.
 * First 16 CPUs unrolled for BPF verifier; remainder in bounded loop. */
static __always_inline u64
build_cached_cpumask(const struct cpumask *mask)
{
	u64 result = 0;
#pragma unroll
	for (u32 i = 0; i < 16 && i < CAKE_MAX_CPUS; i++) {
		if (bpf_cpumask_test_cpu(i, mask))
			result |= (1ULL << i);
	}
	if (nr_cpus > 16) {
		for (u32 i = 16; i < 64 && i < nr_cpus; i++) {
			if (bpf_cpumask_test_cpu(i, mask))
				result |= (1ULL << i);
		}
	}
	return result;
}

/* SIMPLIFIED: Pure RODATA lookup — Rust loader pre-fills cpu_sibling_map
 * for both hybrid (Intel sysfs) and symmetric (AMD scx_utils) topologies.
 * Eliminates has_hybrid branch. Dead-coded when nr_cpus <= nr_phys_cpus. */
static __always_inline s32
smt_sibling(s32 cpu)
{
	return cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];
}

/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU: PREV-CPU GATE + IDLE FALLBACK
 * Gate hierarchy: prev_cpu idle → SMT sibling → kernel default → DSQ tunnel.
 * ZERO bpf_task_storage_get: identity is in p->scx (task_struct, L1-hot).
 *
 * PRINCIPLE: "Where to run" is orthogonal to "how long to run".
 *   1. If prev_cpu idle: direct dispatch (91% hit, L1/L2 warm)
 *   2. If SMT sibling idle: L2 still warm (3% hit)
 *   3. Kernel idle scan: any idle CPU (4% hit)
 *   4. All busy: enqueue to per-LLC DSQ, wait for dispatch
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


s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* RELEASE: zero arena dereferences in this callback — all behind
	 * stats_on / #ifndef CAKE_RELEASE. Skip ARENA_ASSOC to free a
	 * callee-saved register + 2 insns (Rule 36). */
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	/* Snapshot once — eliminates TOCTOU race when bench_active
	 * transitions mid-callback (Rule 45: oscillation avoidance). */
	bool stats_on = CAKE_STATS_ACTIVE;

	u64 start_time = 0;
	if (stats_on)
		start_time = scx_bpf_now();

	/* SYNC STRIP: prevent kernel from migrating wakee to waker's CPU.
	 * Gaming wakes are signal-only — no data locality benefit from SYNC. */
	wake_flags &= ~SCX_WAKE_SYNC;

	/* ── GATE 1: Try prev_cpu — task's L1/L2 cache is hot there ──
	 * PHASE 1 OPTIMIZATION: Arena fetch (29ns) and smt_sibling (2ns)
	 * DEFERRED past Gate 1. The fast path (91% hit) needs ZERO arena.
	 *
	 * AFFINITY FAST-CHECK: nr_cpus_allowed == nr_cpus is a RODATA-const
	 * comparison. JIT folds to a single register cmp. For the 95%+ of
	 * tasks with full affinity, this is always true → skip arena lookup.
	 * Wine/Proton restricted tasks (5%) fall through to Gate 1 miss
	 * where arena is fetched for the real cpumask check.
	 *
	 * Cost: ~19ns (test_and_clear_cpu_idle) vs old ~48ns (arena+idle). */
	u32 prev_idx = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);

	if (likely(p->nr_cpus_allowed == nr_cpus) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		/* Gate 1 FAST PATH: full affinity + prev_cpu idle.
		 * ZERO arena, ZERO smt_sibling, ZERO classification.
		 * ~19ns: single kfunc + dispatch. */
		u64 slice = p->scx.slice ?: quantum_ns;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
				    slice, wake_flags);

		if (stats_on) {
			struct cake_stats *s = get_local_stats();
			s->total_gate1_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx_g1 = get_task_ctx(p);
			if (tctx_g1) {
				tctx_g1->telemetry.gate_1_hits++;
				tctx_g1->telemetry.direct_dispatch_count++;
			}
#endif
		}
		return prev_cpu;
	}

	/* ── GATE 1 MISS PATH (9%): task_hot lookup + affinity ──
	 * Only reached when prev_cpu was busy or task has restricted affinity.
	 * Consolidation: 10ns task_hot lookup replaces 29ns arena for cpumask.
	 * Arena get_task_ctx deferred to stats_on telemetry (dead in release). */
	struct cake_task_hot *hot = get_task_hot(p);
	struct cake_task_ctx __arena *tctx = stats_on ? get_task_ctx(p) : NULL;

	/* Affinity mask: full mask for unrestricted tasks, task_hot for restricted. */
	u64 aff_mask = ~0ULL;
	if (unlikely(p->nr_cpus_allowed != nr_cpus) && hot)
		aff_mask = hot->cached_cpumask;

	/* Restricted affinity tasks that landed here because nr_cpus_allowed != nr_cpus
	 * but prev_cpu IS in their mask AND was idle — try Gate 1 again with real mask. */
	if (unlikely(p->nr_cpus_allowed != nr_cpus) &&
	    (aff_mask & (1ULL << prev_idx)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		u64 slice = p->scx.slice ?: quantum_ns;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
				    slice, wake_flags);
		if (stats_on) {
			struct cake_stats *s = get_local_stats();
			s->total_gate1_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
			if (tctx) {
				tctx->telemetry.gate_1_hits++;
				tctx->telemetry.direct_dispatch_count++;
			}
#endif
		}
		return prev_cpu;
	}

	/* SMT sibling: deferred past Gate 1. Computed once, shared by
	 * Gate 1b, Gate 1c skip, Gate 1D skip. Dead-coded on non-SMT. */
	s32 prev_sib = smt_sibling(prev_cpu);

	u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

	/* ── FUSED SMT BLOCK: Gate 1b + Gate 1W-SMT (AP-2) ──
	 * Single nr_cpus > nr_phys_cpus guard covers both sibling probes.
	 * Eliminates redundant branch (Rule 16: flatter branch tree).
	 *
	 * Gate 1b: prev_cpu's SMT sibling → L2 shared (same physical core)
	 * Gate 1W-SMT: waker's SMT sibling → L2 shared (producer-consumer)
	 *
	 * Skip duplicate: if waker_sib == prev_sib, already checked. */
	if (nr_cpus > nr_phys_cpus) {
		/* Gate 1b: prev_cpu's SMT sibling */
		s32 sib = prev_sib;

		if (sib != prev_cpu && (u32)sib < nr_cpus &&
		    (aff_mask & (1ULL << (u32)sib)) &&
		    cpu_bss[(u32)sib & (CAKE_MAX_CPUS - 1)].idle_hint &&
		    scx_bpf_test_and_clear_cpu_idle(sib)) {
			if (stats_on) {
				struct cake_stats *s = get_local_stats();
				s->total_gate1_latency_ns += scx_bpf_now() - start_time;
			}
			return direct_dispatch(p, sib, wake_flags, start_time, GATE_1B, stats_on, tctx, tc_id);
		}

		/* Gate 1W-SMT: waker's SMT sibling — producer-consumer L2 sharing */
		s32 waker_sib = smt_sibling(tc_id);

		if (waker_sib != prev_cpu && waker_sib != sib &&
		    (u32)waker_sib < nr_cpus &&
		    (aff_mask & (1ULL << (u32)waker_sib)) &&
		    cpu_bss[(u32)waker_sib & (CAKE_MAX_CPUS - 1)].idle_hint &&
		    scx_bpf_test_and_clear_cpu_idle(waker_sib)) {
			return direct_dispatch(p, waker_sib, wake_flags, start_time, GATE_1W, stats_on, tctx, tc_id);
		}
	}

	/* ── HOISTED staged_vtime_bits READ (AP-3, Fix: dsq_vtime corruption) ──
	 * Reads from hot->staged_vtime_bits (task_storage, ~10ns) instead of
	 * p->scx.dsq_vtime (kernel-overwritable by scx_bpf_dsq_insert_vtime).
	 * SIMPLIFY P2-1: was reading from arena tctx (NULL in release → staged
	 * always 0 → Gates 1c, 1C-P, 1P all dead in release builds).
	 * Single load shared by Gate 1c (home_cpu) and Gate 1P (yielder check). */
	u64 staged = hot ? hot->staged_vtime_bits : 0;
	u32 home = (staged >> STAGED_SHIFT_HOME) & 0xFF; /* Home CPU: shared by G1c, G1WC, G1D */

	/* LAZY TIMESTAMP (Win #3): shared by Gate 1C-P, Gate 1P, and Tunnel.
	 * Initialized to start_time if stats_on (already fetched at function top),
	 * otherwise 0. First consumer calls scx_bpf_now() if still 0.
	 * Eliminates up to 2 redundant kfunc trampolines (~22ns each). */
	u64 now_lazy = start_time;

	/* ── GATE 1c: Home CPU — warm cache fallback ──
	 * When prev_cpu and all siblings are busy, try the CPU where this
	 * task last ran before prev_cpu. L1/L2 may still be partially warm
	 * if the task ran there within ~100µs (typical for game thread loops).
	 *
	 * home_cpu is staged in dsq_vtime bits [62:55] by cake_stopping.
	 * Zero kfunc: L1 read (p->scx already cached) + 1 idle check (~19ns).
	 *
	 * Edge case guards:
	 *   - 0xFF sentinel: uninitialized/invalid → skip
	 *   - >= nr_cpus: CPU hotplug/offline → skip
	 *   - == prev_cpu or == sibling: already checked by Gate 1/1b → skip
	 *   - Affinity mask: Wine/Proton restriction → skip if outside mask
	 *   - LLC mismatch: on multi-LLC, wrong LLC → skip (L3 cold > L3 warm) */
	{
		if (home < nr_cpus && home != prev_idx) {
			/* ILP: BSS read — cpu_bss is L3 for remote CPU.
			 * OoO overlaps fetch with skip_sib + aff_mask ALU below. */
			u32 home_idx = home & (CAKE_MAX_CPUS - 1);
			u32 home_idle = cpu_bss[home_idx].idle_hint;

			/* Skip if home == SMT sibling (already tried in Gate 1b).
			 * A→C: prev_sib == prev_idx on non-SMT (RODATA maps to self),
			 * so prev_sib always works — eliminates ternary. */
			u32 skip_sib = (u32)prev_sib;

			if (home != skip_sib &&
			    (aff_mask & (1ULL << home)) &&
			    cpu_llc_id[home] == cpu_llc_id[prev_idx]) {
				/* Fast path: home_cpu idle — claim it */
				if (home_idle &&
				    scx_bpf_test_and_clear_cpu_idle((s32)home)) {
					return direct_dispatch(p, (s32)home, wake_flags,
							       start_time, GATE_1C, stats_on, tctx, tc_id);
				}

				/* ── GATE 1c-P: Home CPU preempt-hog (migration dampening) ──
				 * Home CPU busy but occupied by a HOG (is_yielder == 0).
				 * Instead of migrating to a random CPU (Gate 3), preempt
				 * the hog to keep THIS task on its warm cache line.
				 *
				 * Semantics: "cache-sensitive reclaims home from cache-
				 * insensitive." Hogs are CPU-bound → perform equally on
				 * any core. Non-hogs (wineserver, audio, GPU, game
				 * threads) benefit from L1/L2 warmth.
				 *
				 * Guards:
				 *   - Incoming must NOT be a hog (STAGED_BIT_HOG == 0)
				 *   - Incumbent must be hog (!is_yielder == 0)
				 *   - Incumbent ran ≥ 100µs (Rule 9: no micro-slicing)
				 *   - Conditional scx_bpf_now(): only ~3% of wakeups
				 *     reach here; avoids 22ns penalty on fast path */
				if ((staged & (1ULL << STAGED_BIT_VALID)) &&
				    (hot && hot->task_class != CAKE_CLASS_HOG) &&
				    !cpu_bss[home_idx].is_yielder) {
					u64 now_lazy_1cp = now_lazy ? now_lazy : scx_bpf_now();
					if (!now_lazy) now_lazy = now_lazy_1cp;
					u32 elapsed = (u32)now_lazy_1cp - cpu_bss[home_idx].run_start;
					/* JITTER: RODATA indexed lookup replaces ternary.
					 * preempt_thresh_ns[GAME]=50µs(VIP), others=100µs. */
					u32 preempt_thresh = preempt_thresh_ns[hot->task_class & 3];
					if (elapsed > preempt_thresh) {
						direct_dispatch(p, (s32)home, 0,
								start_time, GATE_1CP, stats_on, tctx, tc_id);
						scx_bpf_kick_cpu((s32)home,
								 SCX_KICK_PREEMPT);
						return (s32)home;
					}
				}
			}
		}
	}

	/* SIMPLIFY P2-2: tctx_shared alias removed — tctx is already in scope.
	 * Uses 'hot' pointer (from get_task_hot) for task fields already in task_storage. */

	/* Phase 4: game family from task_class.
	 * SIMPLIFY #9: Read from task_hot (always fetched on miss path) instead
	 * of arena tctx (NULL in release builds → Gate 1WC was dead in release). */
	/* R6: is_game_family inlined — hot + task_class both L1-hot (Rule 36). */

	/* ── GATE 1W-chain: Waker's CPU — chain producer-consumer locality ──
	 * For game family: try the CPU where our waker last ran. In a
	 * sequential chain (A→B→C), A's stopping released its CPU. B's
	 * next wakeup finds A's core idle with L1/L2 holding A's output.
	 *
	 * For game family members (TGID match or PPID sibling match).
	 * waker_cpu == 0xFFFF sentinel (init) or >= nr_cpus skips cleanly.
	 *
	 * Skip guards: already tried as prev (Gate 1), home (Gate 1c). */
	{
		if (hot && hot->task_class == CAKE_CLASS_GAME) {
			u32 wcpu = (u32)hot->waker_cpu;
			if (wcpu < nr_cpus &&
			    wcpu != prev_idx &&
			    wcpu != home &&
			    (aff_mask & (1ULL << wcpu)) &&
			    cpu_llc_id[wcpu] == cpu_llc_id[prev_idx] &&
			    cpu_bss[wcpu & (CAKE_MAX_CPUS - 1)].idle_hint &&
			    scx_bpf_test_and_clear_cpu_idle((s32)wcpu)) {
				return direct_dispatch(p, (s32)wcpu,
					wake_flags, start_time,
					GATE_1WC, stats_on, tctx, tc_id);
			}
		}
	}

	/* ── GATE 1D: Domestic — process-local cache affinity ──
	 * When prev_cpu, sibling, and home_cpu are all busy, search for an
	 * idle core that recently ran a thread from the SAME process (tgid).
	 * L2 may still hold shared heap/globals from the sibling thread.
	 *
	 * COMPILATION-ONLY: WoW data shows 0% Gate 1D hits during gaming.
	 * On single-CCD (9800X3D), all cores share L3 — tgid-local placement
	 * adds zero cache benefit. The 3× remote mbox reads are pure waste.
	 * During COMPILATION, sibling compiler threads DO share heap/globals
	 * across cores, so tgid affinity provides real L2 warmth (Rule 53).
	 *
	 * Only probes the warm_cpus ring (3 candidates) — bounded O(1),
	 * no full-system scan. Falls through to Gate 1W-LLC/Gate 3 if no match.
	 *
	 * Skip guards:
	 *   - wcpu == prev_idx → already tried at Gate 1
	 *   - wcpu == smt_sibling(prev_cpu) → already tried at Gate 1b
	 *   - wcpu == home → already tried at Gate 1c
	 *   - idle_hint gating → skip known-busy cores (Rule 11: MESI)
	 *
	 * Cost: 3× CL1 arena reads (~0ns each). get_task_ctx shared above.
	 * Only reached on Gate 1+1b+1W+1c all miss (~2-5% of wakeups). */
	/* SIMPLIFY P2-3: volatile removed — sched_state changes at ~2Hz (TUI poll).
	 * Stale read harmless: at worst 1 extra/missed Gate 1D probe cycle. */
	if (sched_state == CAKE_STATE_COMPILATION) {
		u32 my_tgid = p->tgid;

		if (hot) {
			int i;
			bpf_for(i, 0, 3) {
				u32 wcpu = (u32)hot->warm_cpus[i];
				if (wcpu >= nr_cpus || wcpu == prev_idx)
					continue;
				/* Verifier fix: compiler proves wcpu < nr_cpus < CAKE_MAX_CPUS
				 * and dead-code-eliminates the & mask. Barrier breaks the
				 * compiler's range proof so the mask survives as a real
				 * BPF instruction, giving verifier the BSS bound it needs. */
				asm volatile("" : "+r"(wcpu));
				wcpu &= (CAKE_MAX_CPUS - 1);
				/* Skip if already tried as SMT sibling (Gate 1b).
				 * A→C: prev_sib == prev_idx on non-SMT. */
				if (wcpu == (u32)prev_sib)
					continue;
				/* Skip if already tried as home_cpu (Gate 1c) */
				if (wcpu == home)
					continue;
				if (!(aff_mask & (1ULL << wcpu)))
					continue;
				/* Idle gate first (u8 test, short-circuits 90% of iterations)
				 * before tgid comparison (u32). Same CL, zero extra fetch cost. */
				if (cpu_bss[wcpu & (CAKE_MAX_CPUS - 1)].idle_hint &&
				    cpu_bss[wcpu & (CAKE_MAX_CPUS - 1)].last_tgid == my_tgid &&
				    scx_bpf_test_and_clear_cpu_idle((s32)wcpu)) {
					return direct_dispatch(p, (s32)wcpu,
						wake_flags, start_time,
						GATE_1D, stats_on, tctx, tc_id);
				}
			}
		}
	}

	/* ── GATE 1W-Step2: Waker LLC affinity — multi-LLC only ──
	 * If waker and prev are on different LLCs, search for idle CPU
	 * near waker. No-op on single-LLC (9800X3D): RODATA comparison
	 * folds to dead code. Active on multi-LLC (7950X3D, Intel).
	 *
	 * Win #1: If this O(N) scan proves zero idle CPUs, set system_full
	 * to skip the redundant Gate 3 scan (~100ns saved under full load). */
	bool system_full = false;
	{
		u32 waker_llc = cpu_llc_id[tc_id];
		u32 prev_llc = cpu_llc_id[prev_idx];

		if (waker_llc != prev_llc) {
			bool is_idle_1w = false;
			s32 waker_near = scx_bpf_select_cpu_dfl(p, tc_id, 0,
								&is_idle_1w);

			if (is_idle_1w &&
			    (aff_mask & (1ULL << (u32)waker_near))) {
#ifndef CAKE_RELEASE
				if (stats_on) {
				if (tctx && waker_near != prev_cpu)
					tctx->telemetry.migration_count++;
				}
#endif
				return direct_dispatch(p, waker_near, wake_flags, start_time, GATE_1W, stats_on, tctx, tc_id);
			}
			if (!is_idle_1w) system_full = true;
		}
	}

	/* ── GATE 1P: Game/boosted preempts bulk (GAMING state only) ──
	 * Gate 1P fires ONLY when GAMING. In IDLE/COMPILATION there is no
	 * high-priority tenant to protect, so preemption adds pure overhead.
	 * The sched_state BSS read is L1-hot (same cache line as game_tgid) —
	 * ~1ns cost, JIT-cached across the callback. */
	if (sched_state == CAKE_STATE_GAMING) {
		if ((staged & (1ULL << STAGED_BIT_VALID)) &&
		    ((staged & (1ULL << STAGED_BIT_WB_DUP)) || (hot && hot->task_class == CAKE_CLASS_GAME))) {
			/* Incoming IS game/boosted — check if prev_cpu incumbent is preemptable.
			 * Gate 1P checks !is_yielder (both bits == 0 → HOG).
			 * Phase 4: Amnesty now works via task_class — running reads task_class
			 * to derive is_yielder, so HOG tasks that received Amnesty just need
			 * their task_class reclassified (happens within 64 stops). */
			struct cake_cpu_bss *bss_prev = &cpu_bss[prev_idx];
			/* INTERFERENCE REDUCTION: preempt any non-game incumbent.
			 * bit 0 of is_yielder = game/boosted flag.
			 * HOG (0) and NORMAL yielder (2) both have bit 0=0 → preempt.
			 * GAME/boosted (1,3) have bit 0=1 → respect (same priority). */
			if (!(bss_prev->is_yielder & 1)) {
				/* Lazy timestamp: first consumer triggers fetch */
				if (!now_lazy) now_lazy = scx_bpf_now();
				u32 elapsed = (u32)now_lazy - bss_prev->run_start;
				/* JITTER: RODATA indexed lookup replaces ternary.
				 * preempt_thresh_ns[GAME]=50µs(VIP), others=100µs. */
				u32 preempt_thresh = preempt_thresh_ns[
					(hot ? hot->task_class : CAKE_CLASS_NORMAL) & 3];
				if (elapsed > preempt_thresh) {
					direct_dispatch(p, prev_cpu, 0, start_time, GATE_1P, stats_on, tctx, tc_id);
					scx_bpf_kick_cpu(prev_cpu, SCX_KICK_PREEMPT);
					return prev_cpu;
				}
			}
		}
	}

	/* ── GATE 3: Kernel fallback — let kernel find any idle CPU ──
	 * Win #1: Skip if Gate 1W-Step2 already proved zero idle CPUs.
	 * The ~100ns between the two scans is too short for a CPU to
	 * transition from busy→idle, so the result would be identical.
	 *
	 * MIGRATION REDUCTION: GAME tasks during GAMING skip Gate 3.
	 * Random idle CPU = cold L1/L2 cache = 3-5µs refill = jitter.
	 * Let GAME fall through to Tunnel → DSQ → prev_cpu dispatch:
	 *   - prev_cpu's cache still warm with GAME data
	 *   - 8× boost + perpetual NEW_FLOW → sorts first in DSQ
	 *   - game threads have short runs → prev_cpu free quickly
	 *   - other LLC cores can still pull from shared DSQ (no starvation) */
	if (!system_full &&
	    !(sched_state == CAKE_STATE_GAMING &&
	      hot && hot->task_class == CAKE_CLASS_GAME)) {
		bool is_idle_g3 = false;
		s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle_g3);

		if (is_idle_g3 && (aff_mask & (1ULL << (u32)cpu))) {
			if (stats_on) {
				struct cake_stats *s = get_local_stats();
				s->total_gate2_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
				if (tctx && cpu != prev_cpu)
					tctx->telemetry.migration_count++;
#endif
			}
			return direct_dispatch(p, cpu, wake_flags, start_time, GATE_3, stats_on, tctx, tc_id);
		}
	}

	/* ── TUNNEL: All CPUs busy — fall through to enqueue → DSQ ──
	 * Phase 1C: enqueue_llc_hint and waker_yielder moved to enqueue
	 * where they're consumed. Eliminates 2 writes from tunnel path.
	 * enqueue computes LLC from cpu_llc_id[scx_bpf_task_cpu(p)] and
	 * reads waker's mbox is_yielder directly. */
	/* A→C: eliminated tunnel_now intermediate → write cached_now directly. */
	if (!now_lazy) now_lazy = scx_bpf_now();
	cpu_bss[tc_id].cached_now = now_lazy;

	/* CHAIN LOCALITY: Stage waker's CPU into wakee's task context.
	 * tc_id = waker's CPU (still running). On wakee's NEXT wakeup,
	 * Gate 1W-chain tries this CPU — by then the waker has stopped
	 * and its L1/L2 holds the producer's output. Chain members
	 * converge onto the same core over 2-3 frames.
	 * Reuses tctx_shared — no extra get_task_ctx call. */
	/* MESI: skip store when waker CPU unchanged (~70% for render loops). */
	if (hot && hot->task_class == CAKE_CLASS_GAME && hot->waker_cpu != (u16)tc_id)
		hot->waker_cpu = (u16)tc_id;

	if (stats_on) {
		struct cake_stats *s = get_local_stats();
		s->total_gate2_latency_ns += now_lazy - start_time;
#ifndef CAKE_RELEASE
		if (tctx) {
			tctx->telemetry.select_cpu_duration_ns = (u32)(now_lazy - start_time);
			tctx->telemetry.gate_tun_hits++;
		}
#endif
	}

	if (unlikely(!(aff_mask & (1ULL << prev_idx)))) {
		s32 fallback_cpu = aff_mask ? __builtin_ctzll(aff_mask) : 0;
		if ((u32)fallback_cpu >= nr_cpus)
			fallback_cpu = 0;
		return fallback_cpu;
	}
	return prev_cpu;
}

/* ENQUEUE-TIME KICK: DISABLED.
 * A/B testing confirmed kicks cause 16fps 1% low regression in Arc Raiders
 * (252fps without kick, 236fps with T3-only kick). Even T3-only kicks create
 * cache pollution and GPU pipeline bubbles. Tick-based starvation detection
 * is sufficient for gaming workloads. */

/* Enqueue - per-LLC DSQ with yield-gated weighted vtime.
 *
 * ZERO bpf_task_storage_get: yield flag + CAKE_FLOW_NEW are pre-staged in
 * tctx->staged_vtime_bits by cake_stopping (Rule 41: locality promotion).
 * Slice is pre-staged in p->scx.slice. staged_vtime_bits is a direct arena
 * field read (~4ns) vs the 30-80ns cold-memory lookup under heavy load.
 * Unlike p->scx.dsq_vtime, the arena field is never overwritten by the
 * kernel's scx_bpf_dsq_insert_vtime() Red-Black tree sorting. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	register struct task_struct *p_reg asm("r6") = p;
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	/* Phase 6: task_storage replaces arena for CL0 hot fields.
	 * 10ns lookup vs 29ns arena TLB walk.
	 * Arena get_task_ctx deferred to telemetry (dead in release). */
	struct cake_task_hot *hot = get_task_hot(p_reg);

	/* Snapshot once — eliminates TOCTOU race when bench_active
	 * transitions mid-callback (Rule 45: oscillation avoidance). */
	bool stats_on = CAKE_STATS_ACTIVE;

	u64 start_time = 0;
	/* SIMPLIFY #6: Hoist single get_task_ctx for all enqueue telemetry paths.
	 * Saves 2 kfunc calls (~32ns) across the 3 enqueue_telemetry call sites. */
	struct cake_task_ctx __arena *tctx_enq = NULL;
	if (stats_on) {
		start_time = scx_bpf_now();
		tctx_enq = get_task_ctx(p_reg);
#ifndef CAKE_RELEASE
		if (tctx_enq) tctx_enq->telemetry.enqueue_count++;
#endif
	}

	/* staged_vtime_bits from task_storage (Phase 6). */
	u64 staged = hot ? hot->staged_vtime_bits : 0;

	/* Phase 1C: LLC computed directly — no select_cpu dependency.
	 * On WAKEUP: use task's prev_cpu LLC (from the return value of select_cpu).
	 * On PREEMPT/YIELD: use current CPU's LLC (enq_cpu).
	 * scx_bpf_task_cpu(p) returns the CPU select_cpu chose (prev_cpu). */
	u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	u64 now_cached = cpu_bss[enq_cpu].cached_now;
	/* THROUGHPUT: scx_bpf_task_cpu (~15ns kfunc) dead-coded on single-LLC.
	 * nr_llcs is RODATA — JIT constant-folds "1 > 1" → false → enq_llc = 0.
	 * 9800X3D: saves 15ns on every enqueue. Multi-CCD: normal path. */
	u32 enq_llc = 0;
	if (nr_llcs > 1) {
		u32 task_cpu = scx_bpf_task_cpu(p_reg);
		enq_llc = cpu_llc_id[task_cpu < nr_cpus ? task_cpu : enq_cpu];
	}

	/* Stale scratch guard: select_cpu is only called on WAKEUP (~90%).
	 * On PREEMPT or YIELD, the scratch cache contains ancient data from the last wakeup.
	 * We MUST refresh now_cached, or preempted tasks will get a stale timestamp and
	 * steal the queue (breaking DRR++ fairness).
	 * Branch hint: wakeup is the hot path (~90% of enqueues). */
	if (unlikely(!(enq_flags & SCX_ENQ_WAKEUP))) {
		now_cached = scx_bpf_now();
	}

	if (unlikely(!(staged & (1ULL << STAGED_BIT_VALID)))) {
		/* No staged context: first dispatch or kthread without alloc.
         * task_flags read deferred here — only needed on this cold path.
         * Avoids stealing a callee-saved register from the hot path,
         * eliminating spill of p across bpf_get_smp_processor_id. */
		/* Cold path: pure timestamp, no priority encoding.
		 * Full 64-bit range — no mask. */
		u64 vtime = now_cached;
		u64 pre_kfunc = 0;
		if (stats_on) pre_kfunc = scx_bpf_now();

		/* Per-LLC DSQ with vtime ordering — priority system applies
		 * to ALL tasks regardless of LLC count. */
		scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
					 quantum_ns, vtime, enq_flags);

		if (stats_on)
			enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached, stats_on, tctx_enq, enq_cpu);
		return;
	}

	/* Handle Yields/Background — preserve staged priority from stopping.
     * Re-enqueues (slice exhaust, yield) don't go through select_cpu.
     * now_cached and enq_llc are already fresh (fetched in the non-wakeup
     * branch above). Use staged weight/slice from cake_stopping. */
	if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
		u64 requeue_slice = p_reg->scx.slice ?: quantum_ns;
		/* Weighted vtime: heavier tasks sort later.
		 * weight_ns pre-computed in cake_stopping (zero MUL here). */
		u32 weight_ns = (u32)(staged & 0xFFFFFFFF);
		u64 vtime = now_cached + weight_ns;
		/* ASYMMETRIC STOLEN SLICE (Phase 4.0):
		 * Yielders keep 75% — cooperative tasks shouldn't be punished.
		 * Non-yielders keep 50% — forces faster CPU release for game wakeups.
		 * 200µs floor prevents micro-slicing (Rule 9). */
		/* THROUGHPUT FIX: GAME tasks get yl_flag=0 from STAGED_BIT_WB_DUP
		 * (chain propagation never fires for GAME → wb=0 always).
		 * Without this fix, GAME requeues get 50% stolen slice instead of 75%.
		 * hot is L1-warm from top of enqueue. */
		u8 yl_flag = ((staged >> STAGED_BIT_WB_DUP) & 1)
		           | (u8)(hot && hot->task_class == CAKE_CLASS_GAME);
		/* P4-1: Branchless slice select: yl=1→75%, yl=0→50% (Rule 16) */
		u64 lo = requeue_slice >> 1;
		u64 hi = (requeue_slice * 3) >> 2;
		requeue_slice = lo + ((hi - lo) & -(u64)yl_flag);
		requeue_slice += (200000 - requeue_slice) & -(requeue_slice < 200000);
		u64 pre_kfunc = 0;
		if (stats_on) pre_kfunc = scx_bpf_now();

		/* Per-LLC DSQ with vtime — re-enqueued tasks get priority
		 * ordering (yielders sort before bulk). */
		scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
					 requeue_slice, vtime, enq_flags);

		if (stats_on)
			enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached, stats_on, tctx_enq, enq_cpu);
		return;
	}

	/* Phase 4: game/hog/bg from task_class (no longer in staged_vtime_bits) */
	u8 new_flow    = (staged >> STAGED_BIT_NEW_FLOW) & 1;
	u8 waker_boost = (staged >> STAGED_BIT_WB_DUP) & 1; /* was yielder, now wb */
	u8 tc_enq      = hot ? hot->task_class : CAKE_CLASS_NORMAL;
	/* R5: is_hog/is_bg/game_member inlined — tc_enq already in register (Rule 36). */
	u32 weight_ns  = (u32)(staged & 0xFFFFFFFF);
	u64 slice = p_reg->scx.slice ?: quantum_ns;

	/* ═══ GAME FAST PATH: skip dead work (unfair GAME priority) ═══
	 * LOGIC FLOW SHORTCUT: weight_ns already pre-shifted in stopping
	 * (pelt_runtime_us * 125 = fused *1000>>3). Direct read, zero ALU.
	 * Also skips: waker_yl BSS read, yl_shift/penalty chain,
	 * anti-starvation, chain propagation — all dead for GAME. */
#define CAKE_ANTI_STARVE_NS (250U * 1000U * 1000U) /* 250ms as u32 */
	u32 effective_weight;
	if (tc_enq == CAKE_CLASS_GAME) {
		effective_weight = weight_ns;  /* pre-shifted in stopping */
	} else {
		/* Full weight computation for NORMAL/HOG/BG */
		/* A→C: waker_yl already &1, skip dead !! + effective_yl register. */
		u8 waker_yl = (enq_flags & SCX_ENQ_WAKEUP)
			     ? (cpu_bss[enq_cpu].is_yielder & 1)
			     : 0;
		u32 yl_shift = (u32)(waker_boost | waker_yl) * 3;
		u32 penalty_shift = vtime_penalty_shift[tc_enq & 3];
		/* GAMING UNFAIRNESS: double vtime penalty for HOG/BG.
		 * HOG: 4×→8×, BG: 2×→4×. Pushes them further back in DSQ
		 * so GAME always dispatches first. NORMAL unaffected (shift=0). */
		if (sched_state == CAKE_STATE_GAMING && penalty_shift)
			penalty_shift += 1;
		effective_weight = (weight_ns >> yl_shift) << penalty_shift;

		/* Anti-starvation: only during GAMING (prevent HOG/BG starvation
		 * vs GAME priority). During COMPILATION: no GAME → no starvation
		 * risk → skip entire check. Saves ~3-5ns per HOG enqueue. */
		if (sched_state == CAKE_STATE_GAMING &&
		    ((tc_enq == CAKE_CLASS_HOG) | (tc_enq == CAKE_CLASS_BG)) &&
		    effective_weight > 0) {
			if (hot) {
				u32 last_run_32 = hot->last_run_at;
				u32 now_32 = (u32)now_cached;
				if (last_run_32 == 0 ||
				    (now_32 - last_run_32) > CAKE_ANTI_STARVE_NS) {
					effective_weight = 0;
				}
			}
		}

		/* Chain propagation: boost non-game wakees from game wakers */
		if (waker_yl && !waker_boost) {
			if (hot)
				hot->packed_info |= ((u32)CAKE_FLOW_WAKER_BOOST << SHIFT_FLAGS);
		}
	}

	u64 vtime = now_cached + effective_weight;

	/* Anti-starvation vtime adjustment (moved outside GAME guard
	 * since effective_weight=0 for clamped tasks triggers this). */
	if (unlikely(effective_weight == 0 && tc_enq != CAKE_CLASS_GAME)) {
		if (vtime >= (1ULL << 30))
			vtime -= (1ULL << 30);
		else
			vtime = 1;
	}

	/* P4-5: Branchless new_flow vtime subtraction (Rule 16) */
	vtime -= new_flow_bonus_ns & -(u64)new_flow;

	if (stats_on) {
		struct cake_stats *s = get_local_stats_for(enq_cpu);
		/* P4-3: Reuse new_flow (identical to nf_stat, saves 1 reg + 2 insns) */
		if (new_flow)
			s->nr_new_flow_dispatches++;
		else
			s->nr_old_flow_dispatches++;

		s->nr_dsq_queued++;
	}

	u64 pre_kfunc = 0;
	if (stats_on) pre_kfunc = scx_bpf_now();

	/* Per-LLC DSQ with vtime — game/boosted tasks sort before bulk. */
	scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
				 slice, vtime, enq_flags);

	if (stats_on)
		enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached, stats_on, tctx_enq, enq_cpu);
}

/* Dispatch: single DSQ per LLC + cross-LLC steal.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here.
 *
 * FIX: dsq_gen blindfold REMOVED. The generation counter caused CPUs to
 * permanently skip checking the shared DSQ after pulling one task, because
 * all CPUs synced to the same global gen after consuming a single task.
 * Result: 18.8M hint_skips, OS threads (ksoftirqd, rcu) starved for 6.5s.
 * Replaced with O(1) scx_bpf_dsq_nr_queued() — true queue depth, no drift. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	u32 cpu_idx = raw_cpu & (CAKE_MAX_CPUS - 1);
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 dispatch_start = stats_on ? scx_bpf_now() : 0;

	u32 my_llc = cpu_llc_id[cpu_idx];
	u64 my_dsq_id = LLC_DSQ_BASE + my_llc;

	/* 1. Fast Path: Check if our local LLC DSQ actually has tasks */
	if (scx_bpf_dsq_nr_queued(my_dsq_id) > 0) {
		if (scx_bpf_dsq_move_to_local(my_dsq_id)) {
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

	/* 2. Steal Path: Look at other LLCs (Active on multi-CCD setups) */
	if (nr_llcs > 1) {
		for (u32 i = 1; i < CAKE_MAX_LLCS; i++) {
			if (i >= nr_llcs) break;
			u32 victim = my_llc + i;
			if (victim >= nr_llcs) victim -= nr_llcs;

			u64 victim_dsq = LLC_DSQ_BASE + victim;
			if (scx_bpf_dsq_nr_queued(victim_dsq) > 0 && scx_bpf_dsq_move_to_local(victim_dsq)) {
				if (stats_on) {
					struct cake_stats *s = get_local_stats_for(cpu_idx);
					s->nr_stolen_dispatches++;
					s->nr_dsq_consumed++;
				}
				return;
			}
		}
	}

	if (stats_on) get_local_stats_for(cpu_idx)->nr_dispatch_misses++;
	/* Check-before-write: if CPU is already marked idle from a previous
	 * dispatch miss, skip the store (Rule 11: MESI optimization). */
	if (!cpu_bss[cpu_idx].idle_hint) cpu_bss[cpu_idx].idle_hint = 1;
}

/* DVFS RODATA: unused by BPF (tick removed) but written by Rust loader.
 * Kept to prevent loader panic on missing RODATA symbol. JIT dead-code eliminates. */
const u32 tier_perf_target[8] = {
	1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
};

/* cake_running — stamp per-CPU mailbox with run start + slice.
 * cake_stopping reads from the same cache line. Per-task telemetry
 * tracked via arena for zero cross-CPU cache invalidation. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	/* CONSOLIDATION: BSS-only running. Arena mbox eliminated.
	 * All per-CPU data written to cpu_bss (L1 cached, 0ns).
	 * Remote readers (Gate 1P/1C-P) read cpu_bss directly.
	 * ARENA_ASSOC kept for stats_on telemetry path. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

	u64 slice = p->scx.slice;

	/* CLOCK DOMAIN FIX: tick_last_run_at MUST come from scx_bpf_now(),
	 * NOT p->se.exec_start. exec_start is rq_clock_task() which subtracts
	 * IRQ + steal time. Consumers (anti-starvation clamp in cake_enqueue,
	 * Gate 1C-P + Gate 1P in cake_select_cpu) compare against scx_bpf_now().
	 * After ~22 min of gaming, accumulated IRQ time drift exceeds the u32
	 * wrap boundary (4.295s), corrupting elapsed-time checks → unconditional
	 * anti-starvation firing (priority inversion) + constant preemption. */
	u64 now_full = scx_bpf_now();
	u32 now = (u32)now_full;

	/* Snapshot once — eliminates TOCTOU race when bench_active
	 * transitions mid-callback (Rule 45: oscillation avoidance). */
	bool stats_on = CAKE_STATS_ACTIVE;

	u64 __maybe_unused running_overhead_start = stats_on ? now_full : 0;

	/* Phase 8: mailbox staging stopwatch start */
	u64 __maybe_unused mbox_start = stats_on ? now_full : 0;

	/* ── WRITE: BSS per-CPU (always needed) ── */
	struct cake_cpu_bss *bss = &cpu_bss[cpu];
	bss->run_start   = now;
	/* Check-before-write: ~75% of calls (same-task re-run), idle_hint
	 * is already 0. Skip the store to avoid unnecessary L1 dirty-mark
	 * and store buffer pressure (Rule 11: MESI optimization). */
	if (bss->idle_hint) bss->idle_hint = 0;

	/* FAST PATH: Same task re-running on same CPU (~75% in gaming).
	 * is_yielder unchanged — skip 10ns get_task_hot + 2ns decode.
	 * Gate 1C-P/1P consumers tolerate 1-frame staleness on waker_boost
	 * (existing design already has 1-cycle delay).
	 * hot hoisted to function scope for reuse in stats_on telemetry.
	 *
	 * JITTER FIX: tick_slice write + sched_state check moved inside
	 * this block. On 75% same-task re-runs:
	 *   - tick_slice unchanged (same task, same slice) → skip write
	 *   - sched_state read + COMPILATION branch → skip entirely
	 * For GAME: tick_slice is dead work (stopping skips deficit drain). */
	struct cake_task_hot *hot = NULL;
	if (bss->last_pid != p->pid) {
		bss->last_pid = p->pid;
		/* tick_slice: consumed by deficit drain in stopping.
		 * Dead for GAME tasks (deficit skip), but needed for others. */
		bss->tick_slice = slice ?: quantum_ns;
		hot = get_task_hot(p);
		u64 staged = hot ? hot->staged_vtime_bits : 0;
		u8 wb49 = (staged >> STAGED_BIT_WB_DUP) & 1;
		u8 tc = hot ? hot->task_class : CAKE_CLASS_NORMAL;
		bss->is_yielder = ((tc == CAKE_CLASS_GAME) | wb49) | ((tc != CAKE_CLASS_HOG) << 1);

		/* Cluster hint: stamp tgid for Gate 1D (COMPILATION only).
		 * Gated behind last_pid — saves BSS read + branch on 75% fast path. */
		if (unlikely(sched_state == CAKE_STATE_COMPILATION))
			bss->last_tgid = p->tgid;
	}

	/* ARENA TELEMETRY: Record run start time for task-level tracking.
     * Stored directly in BPF Arena for 0-syscall user-space sweeping.
     * Phase 6: Arena access ONLY in stats_on (dead in release). */
#ifndef CAKE_RELEASE
	if (stats_on) {
		/* Phase 8: mailbox staging stopwatch end (before arena work) */
		u64 mbox_end = scx_bpf_now();

		/* Phase 6: Deferred arena fetch — only in telemetry path */
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			/* P4-4: Reuse now_full instead of extra scx_bpf_now() (~15ns saved) */
			u64 start = now_full;

			/* F4: Save OLD run_start BEFORE overwriting for dispatch_gap calc.
			 * Previous bug: gap = start - start = 0 always (self-comparison). */
			u64 prev_run_start = tctx->telemetry.run_start_ns;
			tctx->telemetry.run_start_ns = start;

			/* DEFERRED TELEMETRY: Heavy CL1-CL3 writes every 64th stop.
			 * Reduces verbose overhead by 98.4%, making profiling less intrusive.
			 * TUI refreshes at 1-4Hz so 64x decimation is invisible. */
		/* Reuse hoisted hot if available, otherwise fetch.
		 * Saves 10ns kfunc trampoline on ~25% of calls. */
		struct cake_task_hot *hot_tel = hot ? hot : get_task_hot(p);
			u32 rc = hot_tel ? hot_tel->reclass_counter : 0;
			if ((rc & 63) == 0) {
				/* 1. DISPATCH GAP */
				if (prev_run_start > 0 && start > prev_run_start) {
					u64 gap = start - prev_run_start;
					tctx->telemetry.dispatch_gap_ns = gap;
					u64 old_max_g = tctx->telemetry.max_dispatch_gap_ns;
					tctx->telemetry.max_dispatch_gap_ns = old_max_g + ((gap - old_max_g) & -(gap > old_max_g));
				}

				tctx->telemetry.llc_id = (u16)cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)];

				/* 2. WAIT HISTOGRAM */
				if (tctx->telemetry.enqueue_start_ns > 0 && start > tctx->telemetry.enqueue_start_ns) {
					u64 wait = start - tctx->telemetry.enqueue_start_ns;
					tctx->telemetry.wait_duration_ns = wait;

					/* FIX: Clear timestamp after reading. LOCAL_ON dispatches
					 * bypass cake_enqueue, so enqueue_start_ns never updates.
					 * Without this reset, the next telemetry sample subtracts
					 * a minute-old timestamp → ghost 1.2s wait. */
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
				u64 oh_run = scx_bpf_now() - running_overhead_start;
				tctx->telemetry.running_duration_ns = (u32)oh_run;
				s_run->total_running_ns += oh_run;
				s_run->max_running_ns = s_run->max_running_ns + ((oh_run - s_run->max_running_ns) & -(oh_run > s_run->max_running_ns));

				/* Phase 8: mailbox staging duration */
				tctx->telemetry.mbox_staging_ns = (u32)(mbox_end - mbox_start);
			}
		}
	}
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
/* NOTE: reclassify_task_cold removed — classification now uses per-stop
 * PELT + binary yield detection inline in cake_stopping. */

/* cake_stopping — direct arena access + confidence-gated PELT
 *
 * Inputs read directly from task_storage via get_task_hot:
 *   deficit_u16 = DRR deficit (standalone)
 *   packed_info = yield/flow flags
 *   nvcsw_snapshot = yield detection baseline
 *
 * Per-CPU BSS (cpu_bss) provides run_start and tick_slice
 * (staged by cake_running from task_struct fields).
 *
 * Cost: get_task_ctx (~29ns) + arena CL0 reads (~4ns) + work (~15ns). */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	/* p->cpu not BTF-accessible — bpf_get_smp_processor_id is required. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[cpu];
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	/* Snapshot once — eliminates TOCTOU race when bench_active
	 * transitions mid-callback (Rule 45: oscillation avoidance).
	 * This was the ROOT CAUSE of ~85T ns callback profile corruption:
	 * bench_active transition 1→0 between start-timestamp (line A)
	 * and accumulation (line B) left stopping_overhead_start=0,
	 * making scx_bpf_now()-0 = raw system clock leaking into total. */
	bool stats_on = CAKE_STATS_ACTIVE;

	/* R3: snap_sched_state moved into reclassification block (Rule 36).
	 * Quantum ceiling reads sched_state BSS directly (same CL, L1-hot). */

	u64 stopping_overhead_start = 0;
	if (stats_on) {
		stopping_overhead_start = scx_bpf_now();
		/* SIMPLIFY #5: mbox arena dereference moved inside stats_on.
		 * Saves ~19ns arena TLB walk on every release-mode stopping call.
		 * Only used for last_stopped_pid telemetry. */
		per_cpu[cpu].mbox.last_stopped_pid = p->pid;
	}

	/* Phase 6: task_storage replaces arena for CL0 hot fields.
	 * 10ns lookup vs 29ns arena TLB walk. Arena deferred to telemetry. */
	struct cake_task_hot *hot = get_task_hot(p);
	if (unlikely(!hot))
		return;

	/* LOCALITY BURST: Read all hot-> CL0 fields while cache line is L1-warm
	 * from get_task_hot(). Groups 4 reads before touching p->se / bss (different
	 * cache lines) to avoid L2 re-fetch (~4-8ns) after eviction. */
	u8 tc = hot->task_class;
	u32 packed = hot->packed_info;
	u32 rc = hot->reclass_counter++;
	u16 old_deficit = hot->deficit_u16;

	/* DEFERRED: pelt_util read moved into consuming blocks (reclassify + runnable).
	 * On ~49% of stops (non-runnable, non-reclassify), this eliminates a
	 * wasted p->se.avg cache line fetch (~4-8ns L2 / ~30ns L3).
	 * pelt_runtime_us declared here with = 0 for deferred telemetry. */
	u16 pelt_runtime_us = 0;

	/* Standalone deficit drain (DRR fairness, independent of PELT).
	 * Drains based on actual runtime delta.
	 * GAME ADVANTAGE: skip drain entirely for GAME tasks.
	 * Preserves NEW_FLOW flag → perpetual 8ms vtime head start.
	 * DRR fairness is irrelevant for GAME (unfair = desired).
	 * Saves 4 ALU ops per GAME stop + deficit write-back is MESI no-op. */
	u16 new_deficit;
	if (tc == CAKE_CLASS_GAME) {
		new_deficit = old_deficit;  /* preserve — skip drain */
	} else {
		u32 rt_raw = (u32)(bss->tick_slice - p->scx.slice);
		rt_raw -= (rt_raw - (65535U << 10)) & -(rt_raw > (65535U << 10));
		u16 rt_us = (u16)(rt_raw >> 10);
		new_deficit = old_deficit - rt_us;
		new_deficit &= -(u16)(old_deficit > rt_us); /* branchless clamp to 0 */
	}

	/* ── CONFIDENCE-GATED RECLASSIFICATION ──
	 * Full classification (PELT check + game detection) runs every 64th stop.
	 * 63/64 stops reuse task_class from task_storage CL0.
	 * HOG detection uses PELT util_avg >= 800 (~78% CPU utilization). */
	if (unlikely((rc & 63) == 0)) {
		u32 snap_sched_state = sched_state;
		u32 snap_game_tgid  = game_tgid;
		u32 snap_game_ppid  = game_ppid;
		u8 is_kthread = (packed >> BIT_KTHREAD) & 1;
		bool cls_game = (snap_game_tgid && p->tgid == snap_game_tgid)
			     || (snap_game_ppid && hot->ppid == snap_game_ppid)
			     || (is_kthread && snap_sched_state == CAKE_STATE_GAMING);
		/* SIMPLIFY: cls_squeeze + cls_gaming + !is_kthread fused into cls_penalty.
		 * 3 booleans instead of 5, 2 fewer register temporaries (Rule 36). */
		bool cls_penalty = !cls_game
			&& !(((packed >> SHIFT_FLAGS) & CAKE_FLOW_WAKER_BOOST))
			&& snap_sched_state == CAKE_STATE_GAMING
			&& !is_kthread;
		/* DEFERRED: Read pelt_util only when reclassifying (1/64 stops).
		 * Avoids pulling in p->se.avg cache line on 63/64 fast-path stops. */
		u64 pelt_util_rc = p->se.avg.util_avg;
		bool cls_hog = cls_penalty && (pelt_util_rc >= pelt_hog_threshold);
		bool cls_bg  = cls_penalty && !cls_hog;

		u8 new_tc = cls_game ? CAKE_CLASS_GAME
			  : cls_hog  ? CAKE_CLASS_HOG
			  : cls_bg   ? CAKE_CLASS_BG
			  : CAKE_CLASS_NORMAL;
		/* MESI: skip store if class unchanged (~95% stable).
		 * tc already loaded from hot->task_class — register compare. */
		if (hot->task_class != new_tc)
			hot->task_class = new_tc;
		tc = new_tc;  /* Use fresh classification for this stop */
	}

	/* Phase 2: Derive is_game/is_hog/bg_noise from task_class.
	 * Single byte read replaces 3 BSS reads + 6 comparisons. */
	/* R2: is_game inlined — tc already in register, 1-cycle compare (Rule 36). */

	/* P3-2: nvcsw_snapshot update (always, for yield detection).
	 * Arena nvcsw_delta write batched into deferred block below —
	 * eliminates get_task_ctx (~29ns) on 62/64 verbose stops. */
	u64 cur_nv = 0;
	u32 __maybe_unused nvcsw_accum = 0;
	if (stats_on && tc != CAKE_CLASS_GAME) {
		cur_nv = p->nvcsw;
		u64 prev_nv = hot->nvcsw_snapshot;
		if (prev_nv > 0)
			nvcsw_accum = (u32)(cur_nv - prev_nv);
		hot->nvcsw_snapshot = cur_nv;
	}

	/* Phase 8: classify/warm/vtime stopwatch — hoisted for scope. */
	u64 deferred_ts_start = 0;

	/* GAME STOPPING FAST PATH: For GAME, the entire DRR/flag block is
	 * provably constant — skip it entirely.
	 *   wb = 0 (chain propagation gated by tc!=GAME)
	 *   mask clear = no-op (WB=0, NF never clears: deficit preserved)
	 *   packed unchanged → write-back is MESI no-op
	 *   deficit unchanged → write-back is MESI no-op
	 *   nf = 1 (deficit never zeroes → NF persists forever)
	 * Saves ~8 ops per GAME stop (~250K/sec during gaming). */
	u32 wb;
	u8 nf;
	if (tc == CAKE_CLASS_GAME) {
		wb = 0;
		nf = 1;
	} else {
		if (stats_on && (rc & 63) == 0)
			deferred_ts_start = scx_bpf_now();

		/* R4: Extract wb before clearing, then fuse clear_mask inline. */
		wb = (packed >> SHIFT_FLAGS) & CAKE_FLOW_WAKER_BOOST;
		packed &= ~(((u32)CAKE_FLOW_WAKER_BOOST |
			     ((new_deficit == 0) & ((packed >> SHIFT_FLAGS) & 1)))
			    << SHIFT_FLAGS);

		/* hog/bg flag updates only on reclassification (63/64 skip). */
		if ((rc & 63) == 0) {
			u32 hog_mask = (u32)CAKE_FLOW_HOG << SHIFT_FLAGS;
			packed = (packed & ~hog_mask) | (hog_mask & -(u32)(tc == CAKE_CLASS_HOG));
			packed = (packed & ~(1u << BIT_BG_NOISE))
			       | (((u32)(tc == CAKE_CLASS_BG)) << BIT_BG_NOISE);
		}

		nf = (packed >> SHIFT_FLAGS) & 1;

		/* Write back to task_storage */
		if (hot->deficit_u16 != new_deficit)
			hot->deficit_u16 = new_deficit;
		if (hot->packed_info != packed)
			hot->packed_info = packed;
	}

	/* LOCALITY: Write last_run_at while hot CL0 is still dirty from
	 * deficit/packed writes above. At original position (70 lines later),
	 * arena telemetry may have evicted this CL → wasted L2 re-fetch.
	 * Anti-starvation clamp in cake_enqueue reads this field. */
	hot->last_run_at = bss->run_start;

	/* Phase 8: classify stopwatch end — reuses deferred_ts_start */
	u64 classify_end = 0;
	if (stats_on && deferred_ts_start) {
		classify_end = scx_bpf_now();
	}

	/* ═══ 5. WARM CPU HISTORY — migration-gated ring shift ═══
	 * Only fires on migration (cpu != warm_cpus[0]), ~9% of stops.
	 * 91% fast path: single comparison, zero writes.
	 * Feeds Gate 1c warm cache probes in cake_select_cpu. */

	/* Phase 8: warm history stopwatch — reuses classify_end as start */

	/* CHECK-BEFORE-WORK: Hoist get_task_ctx before runnable block.
	 * Eliminates duplicate 29ns arena TLB walk (was called at both
	 * line A inside runnable and line B outside it). */
	struct cake_task_ctx __arena * __maybe_unused tctx_stop = NULL;
	if (stats_on && classify_end)
		tctx_stop = get_task_ctx(p);

	/* RUNNABLE GATE: Only pack staged + warm_cpus + slice if task stays
	 * runnable. Sleeping tasks won't be enqueued — skip ~5ns of work.
	 * (~50% of stops are non-runnable in gaming.) */
	if (runnable) {
		/* DEFERRED: Read pelt_util inline — only on runnable stops (50%).
		 * Eliminates wasted cache line fetch on sleeping task stops. */
		u64 pelt_util = p->se.avg.util_avg;
		pelt_runtime_us = (u16)((pelt_util * bss->tick_slice) >> 20);

		if (hot->warm_cpus[0] != (u16)cpu) {
			hot->warm_cpus[2] = hot->warm_cpus[1];
			hot->warm_cpus[1] = hot->warm_cpus[0];
			hot->warm_cpus[0] = (u16)cpu;
		}

#ifndef CAKE_RELEASE
		/* P3-3: Merged classify_ns + warm_history_ns into hoisted tctx_stop. */
		if (tctx_stop) {
			u64 warm_end = scx_bpf_now();
			tctx_stop->telemetry.classify_ns = (u32)(classify_end - deferred_ts_start);
			tctx_stop->telemetry.warm_history_ns = (u32)(warm_end - classify_end);
		}
#endif

		/* pelt_runtime_us already computed above */
		u32 home_cpu_staged = (u32)(hot->warm_cpus[1] & 0xFF);

		if (tc == CAKE_CLASS_GAME) {
			/* LOGIC FLOW SHORTCUT (a→c): Pre-shift weight, skip dead ops.
			 *   1. weight = pelt_runtime_us * 125 (fused *1000>>3)
			 *      → enqueue reads effective_weight directly (zero ALU)
			 *   2. wb_val packing: dead (wb=0 always, 0<<49 = 0)
			 *   3. cap_raw lookup: dead (quantum_cap_ns[GAME]=0, no cap)
			 * Saves ~5 ops here + 1 shift per GAME enqueue. */
			u32 weight_ns = pelt_runtime_us * 125;
			u64 ceiling = quantum_ceiling_ns;
			u64 slice = yield_gated_quantum_ns(pelt_runtime_us,
				true, ceiling);
			p->scx.slice = slice;
			hot->staged_vtime_bits = (1ULL << STAGED_BIT_VALID) |
					    ((u64)home_cpu_staged << STAGED_SHIFT_HOME) |
					    ((u64)nf << STAGED_BIT_NEW_FLOW) |
					    (u64)weight_ns;
		} else {
			u32 weight_ns = (u32)pelt_runtime_us * 1000;
			u64 ceiling = quantum_ceiling_ns;
			bool yielder = !!wb;
			u64 base_slice = yield_gated_quantum_ns(pelt_runtime_us,
				yielder, ceiling);
			u32 cap_raw = quantum_cap_ns[tc & 3];
			/* GAMING UNFAIRNESS: halve HOG/BG cap during GAMING.
			 * HOG: 250µs→125µs, BG: 500µs→250µs.
			 * Shorter slices = more preemption points for GAME. */
			if (sched_state == CAKE_STATE_GAMING && cap_raw)
				cap_raw >>= 1;
			u64 slice = base_slice;
			if (cap_raw) {
				u64 cap = (u64)cap_raw;
				slice = base_slice - ((base_slice - cap) & -(base_slice > cap));
			}
			p->scx.slice = slice;
			u64 wb_val = (u64)!!wb;
			hot->staged_vtime_bits = (1ULL << STAGED_BIT_VALID) |
					    ((u64)home_cpu_staged << STAGED_SHIFT_HOME) |
					    (wb_val << STAGED_BIT_WB_DUP) |
					    ((u64)nf << STAGED_BIT_NEW_FLOW) |
					    (u64)weight_ns;
		}
	}

	/* Phase 8: vtime staging stopwatch — reuses hoisted tctx_stop. */
#ifndef CAKE_RELEASE
	if (tctx_stop) {
		u64 vtime_end = scx_bpf_now();
		u32 warm_dur = tctx_stop->telemetry.warm_history_ns;
		tctx_stop->telemetry.vtime_staging_ns = (u32)(vtime_end - classify_end - warm_dur);
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
		if ((rc & 63) == 0) {
			struct cake_task_ctx __arena *tctx = tctx_stop;
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

				/* Jitter: |actual_run - PELT_expected| */
				u64 expected_ns = (u64)pelt_runtime_us * 1000ULL;
				u64 d = dur - expected_ns;
				u64 mask = -(u64)(dur < expected_ns);
				u64 jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;

				/* Branchless max */
				u16 old_max_rt = tctx->telemetry.max_runtime_us;
				tctx->telemetry.max_runtime_us = old_max_rt + ((pelt_runtime_us - old_max_rt) & -(u16)(pelt_runtime_us > old_max_rt));

				/* Slice utilization — shift-approximate, no div64 (Rule 5)
				 * (dur << 7) / tslice ≈ dur * 128 / tslice.
				 * Rescaled by 100/128 = 0.78, close enough for TUI display. */
				u64 tslice = bss->tick_slice ?: quantum_ns;
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
				tctx->telemetry.cpu_run_count[cpu & (CAKE_MAX_CPUS - 1)]++;
			}
		}
#endif /* !CAKE_RELEASE */

		/* ALWAYS: Aggregate overhead timing (per-CPU BSS, cheap)
		 * Rule 30: reuse cpu from top of function, skip kfunc trampoline.
		 * Rule 7: single scx_bpf_now() for both deferred + always paths. */
		struct cake_stats *s = get_local_stats_for(cpu);
		u64 oh_agg = scx_bpf_now() - stopping_overhead_start;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns = s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) & -(oh_agg > s->max_stopping_ns));
		/* Track confidence-skip vs full classify accurately.
		 * rc was read pre-increment, so (rc & 63) == 0 matches classify path. */
		if ((rc & 63) == 0)
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
 * Called before any scheduling ops fire for this task. */
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

	/* NOTE: pid_to_tctx registration removed — iter/task program provides
	 * full task visibility without any map update. Fully lockless. */

	/* MULTI-SIGNAL INITIAL CLASSIFICATION (moved from alloc_task_ctx_cold)
     *
     * Signal 1: Nice value (u32 field read, ~2 cycles)
     *   - nice < 0 (prio < 120): OS/user explicitly prioritized → T0
     *   - nice > 10 (prio > 130): explicitly deprioritized → T3
     *   - nice 0-10: default → T1, avg_runtime adjusts naturally
     *
     * R1 sum-of-cmp: branchless non-monotonic mapping.
     * (prio >= 120) = 0 for negative nice (→ CRITICAL=0), 1 for default (→ INTERACT=1)
     * (prio > 130) * 2 = 0 for normal, 2 for high nice (1+2 = BULK=3) */
	/* init_deficit: shared by arena init (stats-gated) and task_hot init. */
	u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);

	/* SIMPLIFY #1: Arena CL0 fields are only read by cake_task_iter (telemetry).
	 * Hot-path readers (running, stopping, select_cpu, enqueue) use task_hot.
	 * Gate arena CL0 init behind CAKE_STATS_ENABLED to save ~10 arena writes. */
	if (CAKE_STATS_ENABLED) {
		tctx->deficit_u16      = init_deficit;
		tctx->last_run_at      = 0;
		tctx->reclass_counter  = 0;
		tctx->warm_cpus[0]     = 0xFFFF;
		tctx->warm_cpus[1]     = 0xFFFF;
		tctx->warm_cpus[2]     = 0xFFFF;
		tctx->waker_cpu        = 0xFFFF;
		tctx->task_class       = CAKE_CLASS_NORMAL;
	}

	/* PPID: ALWAYS populated — game family detection (cake_stopping line 2031,
	 * Gate 1WC, tunnel) reads tctx->ppid unconditionally. Must be outside
	 * CAKE_STATS_ACTIVE or PPID-based Wine/Proton sibling detection is
	 * dead in release builds.
	 * SIMPLIFY: Derive into local — avoids arena readback on line 2895. */
	u32 init_ppid = p->real_parent ? p->real_parent->tgid : 0;
	tctx->ppid = init_ppid;

	/* TUI telemetry: identity fields only needed with --verbose.
	 * Gated to avoid unnecessary arena writes on task creation. */
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE) {
		tctx->telemetry.pid = p->pid;
		tctx->telemetry.tgid = p->tgid;
		u64 *comm_src = (u64 *)p->comm;
		u64 __arena *comm_dst = (u64 __arena *)tctx->telemetry.comm;
		comm_dst[0] = comm_src[0];
		comm_dst[1] = comm_src[1];
		/* nivcsw_snapshot: TUI delta only (nvcsw gated separately below) */
		tctx->telemetry.nivcsw_snapshot = p->nivcsw;
	}
#endif

	/* nvcsw_snapshot: ALWAYS — yield detection in cake_stopping reads this.
	 * Must be seeded here so first delta is zero, not task's lifetime count. */
	tctx->nvcsw_snapshot = p->nvcsw;


	u32 packed		= 0;
	/* Fused FLAGS: bits [27:24] = [flags:4], FLOW_NEW set on creation */
	packed |= ((u32)CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
	/* Cache PF_KTHREAD once (Rule 41: relocate cold read to init).
	 * Kernel threads are immune to bg_noise squeeze. */
	if (p->flags & PF_KTHREAD)
		packed |= (1u << BIT_KTHREAD);
	tctx->packed_info = packed;

	/* CACHED AFFINITY: Build mask from p->cpus_ptr at init time.
     * p->cpus_ptr is RCU-protected — must hold bpf_rcu_read_lock.
     * Updated event-driven by cake_set_cpumask (zero polling).
     * SIMPLIFY: Derive into local — avoids arena readback on line 2905. */
	bpf_rcu_read_lock();
	u64 init_cpumask = build_cached_cpumask(p->cpus_ptr);
	tctx->cached_cpumask = init_cpumask;
	bpf_rcu_read_unlock();

	/* Phase 6: Allocate task_storage and mirror CL0 hot fields.
	 * BPF_LOCAL_STORAGE_GET_F_CREATE allocates on first call. */
	struct cake_task_hot *hot = bpf_task_storage_get(
		&task_hot_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (hot) {
		hot->deficit_u16 = init_deficit;
		hot->packed_info       = packed;
		hot->ppid              = init_ppid;
		hot->last_run_at       = 0;
		hot->reclass_counter   = 0;
		hot->warm_cpus[0]      = 0xFFFF;
		hot->warm_cpus[1]      = 0xFFFF;
		hot->warm_cpus[2]      = 0xFFFF;
		hot->waker_cpu         = 0xFFFF;
		hot->nvcsw_snapshot    = p->nvcsw;
		hot->task_class        = CAKE_CLASS_NORMAL;
		hot->staged_vtime_bits = 0;
		hot->cached_cpumask    = init_cpumask;
	}

	return 0;
}

/* EVENT-DRIVEN AFFINITY UPDATE (Rule 41: Locality Promotion)
 * Kernel calls this when sched_setaffinity() changes a task's cpumask.
 * Replaces polling — zero hot-path cost.
 * Cost: 16 kfuncs × 15ns = 240ns per call — amortized to ~0ns/cycle. */
void BPF_STRUCT_OPS(cake_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
	u64 new_mask = build_cached_cpumask(cpumask);

	/* Write to task_hot (release hot path) */
	struct cake_task_hot *hot = get_task_hot(p);
	if (hot) hot->cached_cpumask = new_mask;

#ifndef CAKE_RELEASE
	/* Write to arena (telemetry + backward compat)
	 * SIMPLIFY #2: Gated — arena tctx only read by cake_task_iter (stats-only). */
	if (CAKE_STATS_ENABLED) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			tctx->telemetry.cpumask_change_count++;
			tctx->cached_cpumask = new_mask;
		}
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
				/* Phase 8: wake chain enhancement */
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

	/* Unified per-CPU arena block — conditional sizing.
	 * RELEASE: 64B/CPU × 64 = 4KB = 1 page (CL0 only, all DCE'd)
	 * DEBUG:  128B/CPU × 64 = 8KB = 2 pages (CL0 telemetry + CL1 BenchLab)
	 * Pages rounded up: (CAKE_MBOX_SIZE * CAKE_MAX_CPUS + 4095) / 4096 */
#ifdef CAKE_RELEASE
	per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
		&arena, NULL, 1, NUMA_NO_NODE, 0);
#else
	per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
		&arena, NULL, 2, NUMA_NO_NODE, 0);
#endif
	if (!per_cpu)
		return -ENOMEM;


	return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* ── cake_task_iter: SEC("iter/task") — replaces pid_to_tctx hash map ──
 * Iterates all kernel tasks. For each task managed by cake (tctx != NULL,
 * telemetry.pid != 0), emits a cake_iter_record via bpf_seq_write.
 * Userspace opens the link fd and reads fixed-size records synchronously.
 * Zero overhead in scheduling hot path: never called during scheduling.
 * No init/exit map ops: cake_init_task and cake_exit_task are now lockless. */
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

	/* Build iter record from arena tctx data (zero-copy field assignment).
	 * Zero-init: in release builds, telemetry block is skipped (#ifndef
	 * CAKE_RELEASE) — without this, bpf_seq_write emits stack garbage. */
	struct cake_iter_record rec = {};
	rec.pid         = task->pid;
	rec.ppid        = tctx->ppid;
	rec.packed_info = tctx->packed_info;
	rec.pelt_util = (u16)task->se.avg.util_avg;  /* PELT util from kernel */
	rec.deficit_us     = tctx->deficit_u16;

#ifndef CAKE_RELEASE
	/* Telemetry block: copy all fields from arena-resident tctx.telemetry. */
	rec.telemetry.run_start_ns          = tctx->telemetry.run_start_ns;
	rec.telemetry.run_duration_ns       = tctx->telemetry.run_duration_ns;
	rec.telemetry.enqueue_start_ns      = tctx->telemetry.enqueue_start_ns;
	rec.telemetry.wait_duration_ns      = tctx->telemetry.wait_duration_ns;
	rec.telemetry.select_cpu_duration_ns= tctx->telemetry.select_cpu_duration_ns;
	rec.telemetry.enqueue_duration_ns   = tctx->telemetry.enqueue_duration_ns;
	rec.telemetry.dsq_insert_ns         = tctx->telemetry.dsq_insert_ns;
	rec.telemetry.gate_1_hits           = tctx->telemetry.gate_1_hits;
	rec.telemetry.gate_2_hits           = tctx->telemetry.gate_2_hits;
	rec.telemetry.gate_1w_hits          = tctx->telemetry.gate_1w_hits;
	rec.telemetry.gate_3_hits           = tctx->telemetry.gate_3_hits;
	rec.telemetry.gate_1p_hits          = tctx->telemetry.gate_1p_hits;
	rec.telemetry.gate_1c_hits          = tctx->telemetry.gate_1c_hits;
	rec.telemetry.gate_1cp_hits         = tctx->telemetry.gate_1cp_hits;
	rec.telemetry.gate_1d_hits          = tctx->telemetry.gate_1d_hits;
	rec.telemetry.gate_1wc_hits         = tctx->telemetry.gate_1wc_hits;
	rec.telemetry.gate_tun_hits         = tctx->telemetry.gate_tun_hits;
	rec.telemetry._pad2                 = 0;
	rec.telemetry.jitter_accum_ns       = tctx->telemetry.jitter_accum_ns;
	rec.telemetry.total_runs            = tctx->telemetry.total_runs;
	rec.telemetry.core_placement        = tctx->telemetry.core_placement;
	rec.telemetry.migration_count       = tctx->telemetry.migration_count;
	rec.telemetry.preempt_count         = tctx->telemetry.preempt_count;
	rec.telemetry.yield_count           = tctx->telemetry.yield_count;
	rec.telemetry.direct_dispatch_count = tctx->telemetry.direct_dispatch_count;
	rec.telemetry.enqueue_count         = tctx->telemetry.enqueue_count;
	rec.telemetry.cpumask_change_count  = tctx->telemetry.cpumask_change_count;
	rec.telemetry._pad3                 = 0;
	rec.telemetry.stopping_duration_ns  = tctx->telemetry.stopping_duration_ns;
	rec.telemetry.running_duration_ns   = tctx->telemetry.running_duration_ns;
	rec.telemetry.max_runtime_us        = tctx->telemetry.max_runtime_us;
	rec.telemetry._pad4                 = 0;
	rec.telemetry.dispatch_gap_ns       = tctx->telemetry.dispatch_gap_ns;
	rec.telemetry.max_dispatch_gap_ns   = tctx->telemetry.max_dispatch_gap_ns;
	rec.telemetry.wait_hist_lt10us      = tctx->telemetry.wait_hist_lt10us;
	rec.telemetry.wait_hist_lt100us     = tctx->telemetry.wait_hist_lt100us;
	rec.telemetry.wait_hist_lt1ms       = tctx->telemetry.wait_hist_lt1ms;
	rec.telemetry.wait_hist_ge1ms       = tctx->telemetry.wait_hist_ge1ms;
	rec.telemetry.slice_util_pct        = tctx->telemetry.slice_util_pct;
	rec.telemetry.llc_id                = tctx->telemetry.llc_id;
	rec.telemetry.same_cpu_streak       = tctx->telemetry.same_cpu_streak;
	rec.telemetry._pad_recomp           = 0;  /* was _deprecated_recomp — padding only */
	rec.telemetry.wakeup_source_pid     = tctx->telemetry.wakeup_source_pid;
	rec.telemetry.nivcsw_snapshot       = tctx->telemetry.nivcsw_snapshot;
	rec.telemetry.nvcsw_delta           = tctx->telemetry.nvcsw_delta;
	rec.telemetry.nivcsw_delta          = tctx->telemetry.nivcsw_delta;
	rec.telemetry.pid_inner             = tctx->telemetry.pid;
	rec.telemetry.tgid                  = tctx->telemetry.tgid;
	/* comm is 16 bytes: copy as two u64 reads via arena cast (not __builtin_memcpy).
	 * __builtin_memcpy uses r0 (raw scalar) instead of r1 (arena), rejected by verifier. */
	*((__u64 *)&rec.telemetry.comm[0]) = *((__u64 __arena *)&tctx->telemetry.comm[0]);
	*((__u64 *)&rec.telemetry.comm[8]) = *((__u64 __arena *)&tctx->telemetry.comm[8]);
	rec.telemetry.gate_cascade_ns       = tctx->telemetry.gate_cascade_ns;
	rec.telemetry.idle_probe_ns         = tctx->telemetry.idle_probe_ns;
	rec.telemetry.vtime_compute_ns      = tctx->telemetry.vtime_compute_ns;
	rec.telemetry.mbox_staging_ns       = tctx->telemetry.mbox_staging_ns;
	rec.telemetry._pad_ewma             = 0;  /* was _deprecated_ewma_ns — padding only */
	rec.telemetry.classify_ns           = tctx->telemetry.classify_ns;
	rec.telemetry.vtime_staging_ns      = tctx->telemetry.vtime_staging_ns;
	rec.telemetry.warm_history_ns       = tctx->telemetry.warm_history_ns;
	rec.telemetry.quantum_full_count    = tctx->telemetry.quantum_full_count;
	rec.telemetry.quantum_yield_count   = tctx->telemetry.quantum_yield_count;
	rec.telemetry.quantum_preempt_count = tctx->telemetry.quantum_preempt_count;
	rec.telemetry._pad_quantum          = 0;
	rec.telemetry.waker_cpu             = tctx->telemetry.waker_cpu;
	rec.telemetry._pad_waker            = 0;
	rec.telemetry.waker_tgid            = tctx->telemetry.waker_tgid;
	/* cpu_run_count: copy via per-element arena reads. __builtin_memcpy bypasses arena cast. */
	for (int _ci = 0; _ci < CAKE_MAX_CPUS; _ci++)
		rec.telemetry.cpu_run_count[_ci] = tctx->telemetry.cpu_run_count[_ci];
#endif /* !CAKE_RELEASE */

	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}

SCX_OPS_DEFINE(cake_ops, .select_cpu = (void *)cake_select_cpu,
	       .enqueue	 = (void *)cake_enqueue,
	       .dispatch = (void *)cake_dispatch,
	       /* .tick removed: tick-less architecture (see cake_running) */
	       .running	    = (void *)cake_running,
	       .stopping    = (void *)cake_stopping,
	       .yield = (void *)cake_yield,
	       .runnable = (void *)cake_runnable,
	       .set_cpumask = (void *)cake_set_cpumask,
	       .init_task   = (void *)cake_init_task,
	       .exit_task = (void *)cake_exit_task, .init = (void *)cake_init,
	       .exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name = "cake");
