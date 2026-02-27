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
const bool enable_dvfs =
	false; /* RODATA — loader-compat only (tick removed, DVFS dead) */

/* Topology config - JIT eliminates unused P/E-core steering when has_hybrid=false */
const bool has_hybrid = false;

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
 *   - 1 BSS global pointer instead of 2 (~1.3ns saved per dual-access)
 *   - 1 TLB entry instead of 2 (arena uses 4KB demand-faulted pages)
 *   - Scratch offset derived from mailbox ptr via ADD 128 (no separate MUL)
 *   - 1 allocation in init instead of 2
 *
 * Mailbox (CL0-CL1): Disruptor handoff, tick staging, cross-CPU fields.
 * Scratch (CL2-CL3): select_cpu → enqueue tunnel (LLC ID, timestamp).
 * ═══════════════════════════════════════════════════════════════════════════ */
struct cake_scratch {
	/* P5-1: u64 first avoids 4B implicit alignment gap (Rule 10) */
	u64 cached_now; /* scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
	u32 cached_llc; /* LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
	u8  waker_yielder; /* Waker Priority Inheritance: was waker a yielder? (L1-hot mailbox read) */
	u8 _pad[115]; /* Pad to 128 bytes: 8(u64) + 4(u32) + 1(u8) + 115 = 128 */
};
_Static_assert(sizeof(struct cake_scratch) <= 128,
	       "cake_scratch exceeds 128B -- adjacent CPUs will false-share");

struct cake_per_cpu {
	struct mega_mailbox_entry
		mbox; /* bytes 0-255: CL0 (local hot) + CL2 (cross-CPU warm) */
	struct cake_scratch
		scr; /* bytes 256-383: select→enqueue tunnel */
	/* bytes 384-511: Compiler padding to maintain 256B alignment */
} __attribute__((aligned(256)));
_Static_assert(sizeof(struct cake_per_cpu) == 512,
	       "cake_per_cpu must be exactly 512B for per-CPU isolation");
struct cake_per_cpu __arena *per_cpu;

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));

/* DSQ Work Hint v2 — unidirectional generation counter.
 * Raised (++) by enqueue only. Dispatch NEVER writes here.
 * Each CPU reads this and compares to its own local last_dsq_gen
 * (in per-CPU mbox). If equal → nothing new → skip 26ns kfunc.
 * Monotonic: no drift, no recalibration needed.
 * One-directional flow: global → local (pull only). */
u32 dsq_gen[CAKE_MAX_LLCS] SEC(".bss") __attribute__((aligned(64)));


/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* PID → arena tctx pointer map.
 * Populated in cake_init_task, deleted in cake_exit_task.
 * The TUI iterates this map to get 100% visibility of all managed tasks.
 * Replaces the unreliable flat slab scan that missed radix-tree overflow entries. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, u32);   /* PID */
	__type(value, u64);  /* arena tctx pointer cast to u64 */
} pid_to_tctx SEC(".maps");



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

	/* Bench: Read cached tctx pointer from mailbox + field deref.
	 * Simulates reading a pre-cached arena pointer from mailbox CL0,
	 * then dereferencing a field. Compares against get_task_ctx() kfunc. */
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
				volatile u32 field = tctx->deficit_avg_fused; /* Deref cached ptr */
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

	/* Bench: EWMA computation — inline EWMA math (same as compute_ewma) */
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			u32 fused = tctx->deficit_avg_fused;
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				/* Inline EWMA math: same computation as compute_ewma */
				u64 tick_sl = mbox->tick_slice;
				u64 rem_sl = p->scx.slice;
				u16 old_avg = (u16)(fused >> 16);
				u16 deficit = (u16)(fused & 0xFFFF);
				u64 used = (tick_sl > rem_sl) ? (tick_sl - rem_sl) : 0;
				u16 rt_us = (u16)(used >> 10);
				volatile u16 new_avg = (old_avg * 7 + rt_us) >> 3;
				volatile u16 new_def = (deficit > rt_us) ? deficit - rt_us : 0;
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_EWMA_COMPUTE];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = new_avg + new_def;
			}
		}
	}

	/* Bench: Mailbox CL0 multi-field read simulation.
	 * Reads cached_tctx_ptr + cached_fused + cached_packed from CL0.
	 * Simulates the full cake_stopping mailbox-only path (zero arena). */
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 ptr = mbox->cached_tctx_ptr;
			volatile u32 fused = mbox->cached_fused;
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
	{
		u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[local_cpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 _ptr = mbox->cached_tctx_ptr;
			volatile u32 _fused = mbox->cached_fused;
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
			volatile u32 _fused = tctx ? tctx->deficit_avg_fused : 0;
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
	{
		s32 mbox_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_MBOX_TASK_CPU],
				  (u64)per_cpu[mbox_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu, i);
	}

	/* Bench: CL0 lock-free atomic read — Disruptor pattern vs spin_lock cycle.
	 * Reads 3 adjacent CL0 fields with zero locking overhead. */
	{
		s32 lf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 lf_val =
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu +
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier +
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.is_yielder;
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

	r->bench_timestamp = bpf_ktime_get_ns();
}




/* ═══ EWMA HELPER ═══
 * Computes EWMA avg_runtime and deficit drain from slice delta.
 * Used by cake_stopping for adaptive quantum sizing. */
struct ewma_result {
	u16 rt_us;
	u16 new_avg;
	u16 deficit;
};

static __always_inline struct ewma_result
compute_ewma(u64 tick_slice, u64 remaining_slice, u16 old_avg,
	     u16 old_deficit)
{
	struct ewma_result r;
	/* slice-delta runtime (zero kfuncs) */
	u32 rt_raw  = (u32)(tick_slice - remaining_slice);
	u32 _max_rt = 65535U << 10;
	rt_raw -= (rt_raw - _max_rt) & -(rt_raw > _max_rt);
	r.rt_us = (u16)(rt_raw >> 10);
	/* EWMA: 7/8 old + 1/8 new */
	r.new_avg = old_avg - (old_avg >> 3) + (r.rt_us >> 3);
	/* Deficit drain (branchless — Rule 16) */
	u16 _d	  = old_deficit - r.rt_us;
	r.deficit = _d & -(u16)(old_deficit > r.rt_us);
	return r;
}

/* ═══ YIELD-GATED ADAPTIVE QUANTUM (Phase 5.0) ═══
 * Yielders get the full ceiling — they cooperate (voluntarily yield)
 * and will never approach 50ms in practice. The slice is NOT a fairness
 * mechanism (vtime handles that); it only sets the preemption deadline.
 * Trusting yielders with a generous deadline eliminates all ICSW.
 *
 * Non-yielders: clamp(EWMA × BULK_HEADROOM, 50µs, 2ms) — tight leash. */
static __always_inline u64 yield_gated_quantum_ns(u16 avg_runtime_us,
						  bool yielder)
{
	if (yielder)
		return AQ_YIELDER_CEILING_NS;

	/* Bulk path: EWMA × 1, clamped [50µs, 2ms] */
	u64 q = (u64)avg_runtime_us * AQ_BULK_HEADROOM * 1000;
	u64 lo = AQ_MIN_NS;
	q = q + ((lo - q) & -(q < lo));
	q = q - ((q - AQ_BULK_CEILING_NS) & -(q > AQ_BULK_CEILING_NS));
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
		u64 start_time, enum gate_id gid)
{
	u64 slice = p->scx.slice ?: quantum_ns;
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);
	if (CAKE_STATS_ENABLED) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			/* Guard against clock-skew underflow (Rule F5) */
			u64 sel_end = scx_bpf_now();
			tctx->telemetry.select_cpu_duration_ns =
				sel_end > start_time ? (u32)(sel_end - start_time) : 0;
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
	}
	return cpu;
}

/* F2: Enqueue telemetry helper — shared by 3 enqueue paths.
 * Records aggregate + per-task enqueue timing after DSQ insert. */
static __always_inline void
enqueue_telemetry(struct task_struct *p, u64 start_time, u64 pre_kfunc,
		  u64 now_cached)
{
	u64 post_kfunc = scx_bpf_now();
	struct cake_stats *s = get_local_stats();
	/* Per-CPU stats: single-writer, no atomic needed (Rule 22) */
	s->total_enqueue_latency_ns += post_kfunc - start_time;
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (tctx) {
		tctx->telemetry.enqueue_start_ns = now_cached;
		/* Guard against clock-skew underflow (negative delta → u32 wrap) */
		tctx->telemetry.enqueue_duration_ns =
			post_kfunc > start_time ? (u32)(post_kfunc - start_time) : 0;
		tctx->telemetry.dsq_insert_ns =
			post_kfunc > pre_kfunc ? (u32)(post_kfunc - pre_kfunc) : 0;
	}
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

/* P2-5: SMT sibling lookup — shared by Gate 1b and Gate 1W.
 * Returns the SMT sibling of the given CPU. Supports both hybrid
 * (Intel P/E-core map) and symmetric (AMD XOR) topologies.
 * Dead-code eliminated when nr_cpus <= nr_phys_cpus (no SMT). */
static __always_inline s32
smt_sibling(s32 cpu)
{
	if (has_hybrid)
		return cpu_sibling_map[cpu];
	return cpu ^ nr_phys_cpus;
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
	ARENA_ASSOC();

	u64 start_time = 0;
	if (CAKE_STATS_ENABLED)
		start_time = scx_bpf_now();

	/* ── SYNC STRIP: prevent waker-core migration ──
     * Without this, scx_bpf_select_cpu_dfl prefers waker CPU over prev_cpu
     * when WF_SYNC is set, destroying cache warmth. */
	wake_flags &= ~SCX_WAKE_SYNC;

	/* LAZY AFFINITY LOAD: Moved before Gate 1 to bypass slow kernel execution.
     * get_task_ctx → BPF Arena direct pointer dereference (~4ns).
     * By moving this above Gate 1, we convert a ~15ns `bpf_cpumask_test_cpu`
     * into a ~0.5ns bitwise AND `(aff_mask & (1ULL << cpu))`.
     * If unallocated (cold path), fallback to full ~0ULL mask. */
	u64 aff_mask = ~0ULL;
	if (unlikely(p->nr_cpus_allowed != nr_cpus)) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx)
			aff_mask = tctx->cached_cpumask;
	}

	/* ── GATE 1: Try prev_cpu — task's L1/L2 cache is hot there ──
     * Atomically claims the idle CPU. If idle, we get direct dispatch.
     * This is the fast path (~91% hit rate in gaming workloads).
     * Cost: ~19ns (single kfunc: test_and_clear_cpu_idle).
     *
     * AP-1 FAST DISPATCH: Zero per-task telemetry on this path.
     * Gate 1 hit (91%) skips get_task_ctx (28ns) + scx_bpf_now (22ns)
     * by inlining scx_bpf_dsq_insert directly. Per-task G1% is computed
     * as remainder = 100% - sum(other gates) on the Rust side.
     * Rule 5: No work > less work > some work.
     *
     * KFUNC DEFERRAL: bpf_get_smp_processor_id() deferred to after Gate 1.
     * Gate 1 hit (91%) never uses tc_id/scr — saves 15ns kfunc trampoline.
     *
     * AFFINITY GATE: Wine/Proton tasks may dynamically restrict cpumask.
     * Fast path: nr_cpus_allowed == nr_cpus is RODATA-const, JIT folds
     * to single register cmp — zero kfunc cost for full-affinity tasks. */
	u32 prev_idx = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);

	/* HOISTED SMT SIBLING (Rule 5: no duplicate work)
	 * Computed once, shared by Gate 1b, Gate 1c skip, and Gate 1D skip.
	 * On non-SMT (nr_cpus == nr_phys_cpus), all consumers are dead-coded
	 * by JIT — this computation is eliminated entirely. */
	s32 prev_sib = smt_sibling(prev_cpu);

	if ((aff_mask & (1ULL << prev_idx)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		u64 slice = p->scx.slice ?: quantum_ns;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu,
				    slice, wake_flags);
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->total_gate1_latency_ns += scx_bpf_now() - start_time;
			/* Per-task gate hit — lightweight: just counter increment,
			 * no select_cpu_duration_ns (Gate 1 cost is constant ~19ns,
			 * not worth a second scx_bpf_now). Saves 22ns vs full
			 * direct_dispatch telemetry. */
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				tctx->telemetry.gate_1_hits++;
				tctx->telemetry.direct_dispatch_count++;
			}
		}
		return prev_cpu;
	}

	/* ── DEFERRED KFUNC: bpf_get_smp_processor_id() ──
	 * Only reached on Gate 1 miss (~9%). Gate 1b, 1W, 1P, and tunnel
	 * all need tc_id. scx_bpf_now() is deferred further — see below. */
	u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_scratch __arena *scr = &per_cpu[tc_id].scr;

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
		    per_cpu[(u32)sib].mbox.idle_hint &&
		    scx_bpf_test_and_clear_cpu_idle(sib)) {
			if (CAKE_STATS_ENABLED) {
				struct cake_stats *s = get_local_stats();
				s->total_gate1_latency_ns += scx_bpf_now() - start_time;
			}
			return direct_dispatch(p, sib, wake_flags, start_time, GATE_1B);
		}

		/* Gate 1W-SMT: waker's SMT sibling — producer-consumer L2 sharing */
		s32 waker_sib = smt_sibling(tc_id);

		if (waker_sib != prev_cpu && waker_sib != sib &&
		    (u32)waker_sib < nr_cpus &&
		    (aff_mask & (1ULL << (u32)waker_sib)) &&
		    per_cpu[(u32)waker_sib].mbox.idle_hint &&
		    scx_bpf_test_and_clear_cpu_idle(waker_sib)) {
			return direct_dispatch(p, waker_sib, wake_flags, start_time, GATE_1W);
		}
	}

	/* ── HOISTED dsq_vtime READ (AP-3) ──
	 * Single load shared by Gate 1c (home_cpu in bits [62:55]) and
	 * Gate 1P (yielder check in bits 63,49). In-register after load,
	 * both gates use it at zero additional cost. */
	u64 staged = p->scx.dsq_vtime;
	u32 home = (staged >> STAGED_SHIFT_HOME) & 0xFF; /* Home CPU: shared by G1c, G1WC, G1D */

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
			/* ILP: Issue arena load EARLY — OoO overlaps 14ns fetch
			 * with skip_sib + aff_mask + LLC ALU work below.
			 * By the time we reach 'home_idle &&', value is in register.
			 * Eliminates the 14ns sequential penalty on success path. */
			struct mega_mailbox_entry __arena *mbox_home = &per_cpu[home].mbox;
			u32 home_idle = mbox_home->idle_hint;

			/* Skip if home == SMT sibling (already tried in Gate 1b) */
			u32 skip_sib = (nr_cpus > nr_phys_cpus) ?
				(u32)prev_sib : prev_idx;

			if (home != skip_sib &&
			    (aff_mask & (1ULL << home)) &&
			    cpu_llc_id[home] == cpu_llc_id[prev_idx]) {
				/* Fast path: home_cpu idle — claim it */
				if (home_idle &&
				    scx_bpf_test_and_clear_cpu_idle((s32)home)) {
					return direct_dispatch(p, (s32)home, wake_flags,
							       start_time, GATE_1C);
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
				    !(staged & (1ULL << STAGED_BIT_HOG)) &&
				    !mbox_home->is_yielder) {
					u64 now_1cp = scx_bpf_now();
					u32 elapsed = (u32)now_1cp - mbox_home->tick_last_run_at;
					if (elapsed > CAKE_PREEMPT_YIELDER_THRESHOLD_NS) {
						direct_dispatch(p, (s32)home, 0,
								start_time, GATE_1CP);
						scx_bpf_kick_cpu((s32)home,
								 SCX_KICK_PREEMPT);
						return (s32)home;
					}
				}
			}
		}
	}

	/* ── SHARED tctx: Single get_task_ctx for G1WC + G1D + tunnel ──
	 * Eliminates 2 redundant arena lookups (~16ns each) on miss path. */
	struct cake_task_ctx __arena *tctx_shared = get_task_ctx(p);

	/* GAME FAMILY PREDICATE (Rule 24: operation fusion)
	 * Evaluated once, shared by Gate 1WC and tunnel waker_cpu staging.
	 * Keeps game_tgid/game_ppid/tctx->ppid in registers for both consumers. */
	bool is_game_family = game_tgid && tctx_shared &&
		(p->tgid == game_tgid ||
		 (game_ppid && tctx_shared->ppid == game_ppid));

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
		if (is_game_family) {
			u32 wcpu = (u32)tctx_shared->waker_cpu;
			if (wcpu < nr_cpus &&
			    wcpu != prev_idx &&
			    wcpu != home &&
			    (aff_mask & (1ULL << wcpu)) &&
			    cpu_llc_id[wcpu] == cpu_llc_id[prev_idx] &&
			    per_cpu[wcpu].mbox.idle_hint &&
			    scx_bpf_test_and_clear_cpu_idle((s32)wcpu)) {
				return direct_dispatch(p, (s32)wcpu,
					wake_flags, start_time,
					GATE_1WC);
			}
		}
	}

	/* ── GATE 1D: Domestic — process-local cache affinity ──
	 * When prev_cpu, sibling, and home_cpu are all busy, search for an
	 * idle core that recently ran a thread from the SAME process (tgid).
	 * L2 may still hold shared heap/globals from the sibling thread.
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
	{
		u32 my_tgid = p->tgid;

		if (tctx_shared) {
			int i;
			bpf_for(i, 0, 3) {
				u32 wcpu = (u32)tctx_shared->warm_cpus[i];
				if (wcpu >= nr_cpus || wcpu == prev_idx)
					continue;
				/* Skip if already tried as SMT sibling (Gate 1b) */
				if (nr_cpus > nr_phys_cpus &&
				    wcpu == (u32)prev_sib)
					continue;
				/* Skip if already tried as home_cpu (Gate 1c) */
				if (wcpu == home)
					continue;
				if (!(aff_mask & (1ULL << wcpu)))
					continue;
				/* Cluster match + idle gate + atomic probe */
				if (per_cpu[wcpu].mbox.last_tgid == my_tgid &&
				    per_cpu[wcpu].mbox.idle_hint &&
				    scx_bpf_test_and_clear_cpu_idle((s32)wcpu)) {
					return direct_dispatch(p, (s32)wcpu,
						wake_flags, start_time,
						GATE_1D);
				}
			}
		}
	}

	/* ── GATE 1W-Step2: Waker LLC affinity — multi-LLC only ──
	 * If waker and prev are on different LLCs, search for idle CPU
	 * near waker. No-op on single-LLC (9800X3D): RODATA comparison
	 * folds to dead code. Active on multi-LLC (7950X3D, Intel). */
	{
		u32 waker_llc = cpu_llc_id[tc_id];
		u32 prev_llc = cpu_llc_id[prev_idx];

		if (waker_llc != prev_llc) {
			bool is_idle_1w = false;
			s32 waker_near = scx_bpf_select_cpu_dfl(p, tc_id, 0,
								&is_idle_1w);

			if (is_idle_1w &&
			    (aff_mask & (1ULL << (u32)waker_near))) {
				if (CAKE_STATS_ENABLED) {
					if (tctx_shared && waker_near != prev_cpu)
						tctx_shared->telemetry.migration_count++;
				}
				return direct_dispatch(p, waker_near, wake_flags, start_time, GATE_1W);
			}
		}
	}

	/* ── DEFERRED TIMESTAMP: scx_bpf_now() ──
	 * Deferred past fused SMT block, Gate 1c, and Gate 1W-LLC —
	 * none use the timestamp. Only Gate 1P (elapsed check) and
	 * tunnel (vtime base) need it. Saves 22ns on ~5% of wakeups. */
	u64 now_post_g1 = scx_bpf_now();

	/* ── GATE 1P: Game/boosted preempts bulk ──
	 * If incoming task is a game_member or waker-boosted and prev_cpu
	 * runs a non-boosted task that has consumed ≥ threshold, preempt it.
	 *
	 * TGID-BASED: STAGED_BIT_WB_DUP = waker_boost (was VCSW yielder).
	 * Combined with STAGED_BIT_GAME_MEMBER, only game ecosystem threads
	 * trigger preemption. Brave/Discord never fire Gate 1P.
	 *
	 * Threshold = 100µs (not 1ms): hog_quantum_cap is 500µs, so 1ms was
	 * structurally unreachable — Gate 1P could NEVER preempt hogs.
	 * At 100µs the incumbent has done meaningful work; preemption cost
	 * (~1.5µs cache refill) is a 133:1 benefit trade for audio/input/game.
	 *
	 * STAGED CHECK: Reuses hoisted dsq_vtime (AP-3).
	 * STAGED_BIT_WB_DUP = waker_boost, STAGED_BIT_GAME_MEMBER, STAGED_BIT_VALID.
	 * Brand-new tasks have VALID=0 and are correctly skipped. */
	{
		if ((staged & (1ULL << STAGED_BIT_VALID)) && (staged & ((1ULL << STAGED_BIT_WB_DUP) | (1ULL << STAGED_BIT_GAME_MEMBER)))) {
			/* Incoming IS game/boosted — now check if prev_cpu incumbent is preemptable */
			struct mega_mailbox_entry __arena *mbox_prev = &per_cpu[prev_idx].mbox;
			if (!mbox_prev->is_yielder) {
				u32 elapsed = (u32)now_post_g1 - mbox_prev->tick_last_run_at;
				if (elapsed > CAKE_PREEMPT_YIELDER_THRESHOLD_NS) {
					direct_dispatch(p, prev_cpu, 0, start_time, GATE_1P);
					scx_bpf_kick_cpu(prev_cpu, SCX_KICK_PREEMPT);
					return prev_cpu;
				}
			}
		}
	}

	/* ── GATE 3: Kernel fallback — let kernel find any idle CPU ── */
	bool is_idle_g3 = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle_g3);

	if (is_idle_g3 && (aff_mask & (1ULL << (u32)cpu))) {
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->total_gate2_latency_ns += scx_bpf_now() - start_time;
			if (tctx_shared && cpu != prev_cpu)
				tctx_shared->telemetry.migration_count++;
		}
		return direct_dispatch(p, cpu, wake_flags, start_time, GATE_3);
	}

	/* ── TUNNEL: All CPUs busy — fall through to enqueue → DSQ ──
	 * No preemption, no kicks. Task goes to DSQ, gets picked up
	 * when a CPU naturally becomes idle and calls cake_dispatch. */
	u64 tunnel_now = now_post_g1;
	scr->cached_llc = cpu_llc_id[tc_id];
	scr->cached_now = tunnel_now;
	/* WAKER PRIORITY INHERITANCE: Stash waker's yielder status.
	 * Reads LOCAL CPU mailbox CL0 (L1-hot, ~0ns). Consumed by
	 * cake_enqueue to boost non-yielding render pipeline threads
	 * woken by yielding UE5 task workers.
	 *
	 * NARROW MASK (& 1): Only bit 0 (game_member | waker_boost)
	 * seeds the waker chain. The broad !hog bit (bit 1) is for
	 * Gate 1P protection only — must NOT propagate through chains
	 * or it re-enables system-wide priority inflation. */
	scr->waker_yielder = per_cpu[tc_id].mbox.is_yielder & 1;

	/* CHAIN LOCALITY: Stage waker's CPU into wakee's task context.
	 * tc_id = waker's CPU (still running). On wakee's NEXT wakeup,
	 * Gate 1W-chain tries this CPU — by then the waker has stopped
	 * and its L1/L2 holds the producer's output. Chain members
	 * converge onto the same core over 2-3 frames.
	 * Reuses tctx_shared — no extra get_task_ctx call. */
	if (is_game_family)
		tctx_shared->waker_cpu = (u16)tc_id;

	if (CAKE_STATS_ENABLED) {
		struct cake_stats *s = get_local_stats();
		s->total_gate2_latency_ns += tunnel_now - start_time;
		if (tctx_shared) {
			tctx_shared->telemetry.select_cpu_duration_ns = (u32)(tunnel_now - start_time);
			tctx_shared->telemetry.gate_tun_hits++;
		}
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
 * p->scx.dsq_vtime by cake_stopping (Rule 41: locality promotion). Slice is
 * pre-staged in p->scx.slice. Both are direct task_struct field reads (~3ns)
 * vs the 30-80ns cold-memory lookup under heavy load. The kernel does not
 * read p->scx.dsq_vtime for sleeping tasks (not on any DSQ), so the staging
 * bits are inert until we consume them here. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
	register struct task_struct *p_reg asm("r6") = p;
	ARENA_ASSOC();

	u64 start_time = 0;
	if (CAKE_STATS_ENABLED) {
		start_time = scx_bpf_now();
		struct cake_task_ctx __arena *tctx = get_task_ctx(p_reg);
		if (tctx)
			tctx->telemetry.enqueue_count++;
	}

	/* PRE-LOAD: staged context before kfunc trampoline.
     * p_reg->scx.dsq_vtime doesn't depend on enq_cpu — load executes
     * in parallel with the ~15ns bpf_get_smp_processor_id trampoline.
     * Saves ~3ns dependent load on the hot path. */
	u64 staged = p_reg->scx.dsq_vtime;

	/* KFUNC TUNNELING: Reuse LLC ID + timestamp cached by select_cpu in scratch.
     * Eliminates 2 kfunc trampolines (~40-60ns) — select_cpu always runs on
     * the same CPU immediately before enqueue, so values are fresh for WAKEUP.
     *
     * PREEMPT PATH (multi-LLC only): select_cpu was NOT called — scratch may
     * contain stale cached_llc from a different task's wakeup on this CPU.
     * On single-LLC (9800x3d), LLC is always 0 regardless of staleness, so
     * the branch is dead-code-eliminated by BPF JIT (Rule 5: no work < some work).
     * On multi-LLC (9950X, EPYC), fetch fresh LLC + timestamp to prevent
     * cross-LLC DSQ insertion. Yield/weight staging is correct (from p->scx.dsq_vtime,
     * staged by cake_stopping on the task itself). */
	u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_scratch __arena *scr	= &per_cpu[enq_cpu].scr;
	u64			     now_cached = scr->cached_now;
	u32			     enq_llc	= scr->cached_llc;

	/* Stale scratch guard: select_cpu is only called on WAKEUP.
     * On PREEMPT or YIELD, the scratch cache contains ancient data from the last wakeup. 
     * We MUST refresh now_cached, or preempted tasks will get a stale timestamp and
     * steal the queue (breaking DRR++ fairness). */
	if (!(enq_flags & SCX_ENQ_WAKEUP)) {
		now_cached = scx_bpf_now();
		if (nr_llcs > 1) {
			enq_llc = cpu_llc_id[enq_cpu];
		}
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
		if (CAKE_STATS_ENABLED) pre_kfunc = scx_bpf_now();

		/* Per-LLC DSQ with vtime ordering — priority system applies
		 * to ALL tasks regardless of LLC count. dsq_gen bumped so
		 * cake_dispatch knows new work arrived. */
		scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
					 quantum_ns, vtime, enq_flags);
		dsq_gen[enq_llc & (CAKE_MAX_LLCS - 1)]++;

		if (CAKE_STATS_ENABLED)
			enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached);
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
		u8 yl_flag = (staged >> STAGED_BIT_WB_DUP) & 1;
		/* P4-1: Branchless slice select: yl=1→75%, yl=0→50% (Rule 16) */
		u64 lo = requeue_slice >> 1;
		u64 hi = (requeue_slice * 3) >> 2;
		requeue_slice = lo + ((hi - lo) & -(u64)yl_flag);
		requeue_slice += (200000 - requeue_slice) & -(requeue_slice < 200000);
		u64 pre_kfunc = 0;
		if (CAKE_STATS_ENABLED) pre_kfunc = scx_bpf_now();

		/* Per-LLC DSQ with vtime — re-enqueued tasks get priority
		 * ordering (yielders sort before bulk). */
		scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
					 requeue_slice, vtime, enq_flags);
		dsq_gen[enq_llc & (CAKE_MAX_LLCS - 1)]++;

		if (CAKE_STATS_ENABLED)
			enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached);
		return;
	}

	/* Extract staged fields — zero bpf_task_storage_get */
	u64 slice = p_reg->scx.slice ?: quantum_ns;

	/* TGID-BASED PRIORITY (Phase 7.0):
	 * weight_ns pre-computed in cake_stopping (zero MUL).
	 * game_member + waker_boost advance vtime at 8× priority (>> 3).
	 * VCSW (yielder) removed — it leaked priority to browser/Discord.
	 * Self-scaling: heavier tasks get proportionally more boost.
	 * No magic constants — priority is relative to the task's own EWMA. */
	u8 new_flow    = (staged >> STAGED_BIT_NEW_FLOW) & 1;
	u8 waker_boost = (staged >> STAGED_BIT_WB_DUP) & 1; /* was yielder, now wb */
	u8 is_hog      = (staged >> STAGED_BIT_HOG) & 1;
	u8 is_bg       = (staged >> STAGED_BIT_BG_NOISE) & 1;
	u8 game_member = (staged >> STAGED_BIT_GAME_MEMBER) & 1; /* staged by cake_stopping */
	u32 weight_ns  = (u32)(staged & 0xFFFFFFFF);

	/* WAKER PRIORITY INHERITANCE: boost non-game wakees when waker
	 * is game/boosted. Covers cross-process chains
	 * (game thread wakes wineserver/pipewire with different tgid).
	 * Cost: 1 scratch read (same CL as cached_llc, ~0ns). */
	u8 waker_yl = scr->waker_yielder;
	/* F2: Branchless normalization — waker_yl may be 0/1/2/3 (Rule 16) */
	u8 effective_yl = game_member | waker_boost | !!waker_yl;

	/* P4-2: Branchless effective_weight (Rule 16)
	 * Yielder boost: >> 3 = 8× priority (from 0 to 3 shift)
	 * Hog squeeze: << hog_vtime_shift = 4× slower (RODATA, default 2)
	 * Both are self-regulating: penalties only matter under contention. */
	u32 yl_shift = (u32)effective_yl * 3; /* 0 or 3 */
	/* Fused penalty: HOG(4×) and BG(2×) mutually exclusive (Rule 36) */
	u32 penalty_shift = (u32)is_hog * hog_vtime_shift
			  + (u32)is_bg  * bg_vtime_shift;
	u32 effective_weight = (weight_ns >> yl_shift) << penalty_shift;
	u64 vtime = now_cached + effective_weight;

	/* CHAIN PROPAGATION: Set WAKER_BOOST in tctx packed_info so
	 * cake_running reflects the boost in mbox->is_yielder.
	 * Guards:
	 *   !game_member — already boosted by tgid, skip 16ns arena overhead.
	 *   !waker_boost — already boosted from previous cycle, don't re-propagate.
	 *     Without this guard, the chain cascades transitively through the
	 *     entire wakeup graph (game→wine→dbus→everything), inflating
	 *     priority for most threads and causing dispatch starvation.
	 * Still fires for 1st-hop cross-process chains (wineserver, pipewire). */
	if (waker_yl && !waker_boost && !game_member) {
		struct cake_task_ctx __arena *tctx_boost = get_task_ctx(p_reg);
		if (tctx_boost)
			tctx_boost->packed_info |= ((u32)CAKE_FLOW_WAKER_BOOST << SHIFT_FLAGS);
	}
	/* P4-5: Branchless new_flow vtime subtraction (Rule 16) */
	vtime -= new_flow_bonus_ns & -(u64)new_flow;

	if (CAKE_STATS_ENABLED) {
		struct cake_stats *s = get_local_stats();
		/* P4-3: Reuse new_flow (identical to nf_stat, saves 1 reg + 2 insns) */
		if (new_flow)
			s->nr_new_flow_dispatches++;
		else
			s->nr_old_flow_dispatches++;

		s->nr_dsq_queued++;
	}

	u64 pre_kfunc = 0;
	if (CAKE_STATS_ENABLED) pre_kfunc = scx_bpf_now();

	/* Per-LLC DSQ with vtime — game/boosted tasks sort before bulk.
	 * dsq_gen bumped so cake_dispatch picks up new work. */
	scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
				 slice, vtime, enq_flags);
	dsq_gen[enq_llc & (CAKE_MAX_LLCS - 1)]++;

	if (CAKE_STATS_ENABLED)
		enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached);
}

/* Dispatch: single DSQ per LLC + cross-LLC steal.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here.
 *
 * Single vtime-ordered DSQ per LLC. 1 kfunc call always.
 * Yield-gated weighted vtime ensures cooperative tasks (game, audio, input)
 * sort before bulk tasks. Eliminates 3 wasted empty-DSQ probes. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
	ARENA_ASSOC();
	u32 cpu_idx = raw_cpu & (CAKE_MAX_CPUS - 1);

	/* All LLC counts use per-LLC DSQ with vtime ordering.
	 * No early return — cake_dispatch always checks the DSQ. */

	/* MULTI-LLC: Per-LLC DSQ with dsq_gen hint-skip optimization. */
	u32 my_llc = cpu_llc_id[cpu_idx];
	u32 llc_idx = my_llc & (CAKE_MAX_LLCS - 1);

	/* DSQ generation check: unidirectional flow.
	 * Read local last_dsq_gen (L1 hot, ~0ns) and shared dsq_gen
	 * (Shared MESI state, ~1-3ns). If equal → nothing new since
	 * last miss → skip 26ns kfunc. Dispatch NEVER writes to
	 * shared state — only reads global + writes local. */
	u32 cur_gen = dsq_gen[llc_idx];
	u32 my_gen = per_cpu[cpu_idx].mbox.last_dsq_gen;
	if (cur_gen == my_gen) {
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->nr_dispatch_hint_skip++;
		}
		/* Idle shadow hint (local write only) */
		per_cpu[cpu_idx].mbox.idle_hint = 1;
		return;
	}

	/* Generation changed — new work was enqueued. Check the DSQ. */
	if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc)) {
		/* Consumed — no shared write needed! */
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->nr_local_dispatches++;
			s->nr_dsq_consumed++;
		}
		return;
	}

	/* DSQ empty despite gen change — another CPU consumed it.
	 * Sync local gen to current (per-CPU write, zero sharing). */
	per_cpu[cpu_idx].mbox.last_dsq_gen = cur_gen;

	/* Steal from other LLCs (only when local DSQ empty). */
	for (u32 i = 1; i < CAKE_MAX_LLCS; i++) {
		if (i >= nr_llcs)
			break;
		u32 victim = my_llc + i;
		if (victim >= nr_llcs)
			victim -= nr_llcs;
		if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + victim)) {
			if (CAKE_STATS_ENABLED) {
				struct cake_stats *s = get_local_stats();
				s->nr_stolen_dispatches++;
				s->nr_dsq_consumed++;
			}
			return;
		}
	}

	if (CAKE_STATS_ENABLED) {
		struct cake_stats *s = get_local_stats();
		s->nr_dispatch_misses++;
	}

	/* Idle shadow hint: CPU has no work — going idle. */
	per_cpu[cpu_idx].mbox.idle_hint = 1;
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
	ARENA_ASSOC();

	/* ZERO-ARENA RUNNING: All data sourced from task_struct fields.
	 * Eliminated get_task_ctx (29ns) from production path.
	 *
	 * is_yielder: extracted from dsq_vtime staged bits (STAGED_BIT_WB_DUP,
	 *   STAGED_BIT_WAKER_BOOST — set by cake_stopping).
	 * tick_last_run_at: from p->se.exec_start (kernel-maintained).
	 * tick_slice: from p->scx.slice (kernel-maintained).
	 *
	 * Disruptor staging (cached_fused/packed/nvcsw/tctx_ptr) removed —
	 * cake_stopping reads directly from arena via get_task_ctx.
	 * Net: running saves 29ns, stopping costs 15ns more → 14ns/cycle win. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct mega_mailbox_entry __arena *mbox = &per_cpu[cpu].mbox;

	/* All reads from task_struct — L1-hot, zero kfuncs */
	u64 staged = p->scx.dsq_vtime;
	u64 slice = p->scx.slice;
	u32 now = (u32)p->se.exec_start;

	/* STATS-ONLY: scx_bpf_now + get_task_ctx for telemetry timing. */
	u64 now_full = CAKE_STATS_ENABLED ? scx_bpf_now() : (u64)now;
	u64 running_overhead_start = CAKE_STATS_ENABLED ? now_full : 0;

	/* ── COMPUTE: final slice from staged data ── */
	u64 final_slice = slice ?: quantum_ns;

	/* Extract game_member + waker_boost + hog from dsq_vtime staging.
	 * All bits set by cake_stopping's dsq_vtime write, already in register.
	 * STAGED_BIT_WB_DUP = waker_boost, STAGED_BIT_HOG, STAGED_BIT_GAME_MEMBER.
	 * VCSW yielder removed from priority path (Phase 7.0). */
	u8 wb49 = (staged >> STAGED_BIT_WB_DUP) & 1; /* waker_boost (was yielder) */
	u8 hog_bit = (staged >> STAGED_BIT_HOG) & 1; /* hog squeeze flag */
	u8 gm = (staged >> STAGED_BIT_GAME_MEMBER) & 1;

	/* ── WRITE: per-CPU mailbox (minimal — no Disruptor staging) ── */
	mbox->tick_last_run_at = now;
	mbox->tick_slice       = final_slice;
	/* 2-bit is_yielder encoding (Rule 14/37 — bitfield coalescing):
	 *   bit 0 = game_member | waker_boost  (NARROW: waker chain seed only)
	 *   bit 1 = !hog                       (BROAD: Gate 1P protection)
	 *
	 * Gate 1P checks !is_yielder: only hogs have both bits == 0.
	 * Waker chain reads (is_yielder & 1): only game/boosted seeds.
	 *
	 * Phase 7.0 fix: VCSW removal left ALL non-game tasks unprotected
	 * from Gate 1P preemption. CPU-pinned kworkers starved (34s stall).
	 * Using hog_bit eliminates magic thresholds (Rule 54) — protection
	 * boundary is the well-tested 8ms EWMA hog classification.
	 * Zero extra cost: hog_bit already in staged register (Rule 41). */
	mbox->is_yielder       = (gm | wb49) | ((!hog_bit) << 1);
	mbox->cached_cpu       = (u16)cpu;

	/* Idle shadow hint: CPU is busy (task running).
	 * CL1 write — separate cache line from CL0 hot path.
	 * Zero false sharing: each CPU writes only its own mbox. */
	mbox->idle_hint = 0;

	/* Cluster hint: stamp tgid for Gate 1D cache-affinity routing.
	 * Same CL1 as idle_hint — ALP-prefetched on Zen5 as 128B pair with CL0.
	 * Local-only write, zero cross-CPU contention. */
	mbox->last_tgid = p->tgid;

	/* ARENA TELEMETRY: Record run start time for task-level tracking.
     * Stored directly in BPF Arena for 0-syscall user-space sweeping. */
	if (CAKE_STATS_ENABLED) {
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
			if ((tctx->reclass_counter & 63) == 0) {
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
			}
		}
	}
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
 * EWMA + binary yield detection inline in cake_stopping. */

/* cake_stopping — direct arena access + confidence-gated EWMA
 *
 * Inputs read directly from arena via get_task_ctx:
 *   deficit_avg_fused = EWMA state
 *   packed_info = yield/flow flags
 *   nvcsw_snapshot = yield detection baseline
 *
 * Mailbox used only for tick_last_run_at and tick_slice
 * (staged by cake_running from task_struct fields).
 *
 * Cost: get_task_ctx (~29ns) + arena CL0 reads (~4ns) + work (~15ns). */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	/* p->cpu not BTF-accessible — bpf_get_smp_processor_id is required. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	ARENA_ASSOC();
	struct mega_mailbox_entry __arena *mbox = &per_cpu[cpu].mbox;

	u64 stopping_overhead_start = 0;
	if (CAKE_STATS_ENABLED) {
		stopping_overhead_start = scx_bpf_now();
		mbox->last_stopped_pid = p->pid;
	}

	/* Direct arena access: get_task_ctx replaces Disruptor handoff.
	 * Running no longer stages fused/packed/nvcsw/tctx_ptr to mailbox.
	 * Trade: stopping pays get_task_ctx (29ns) but running saved 29ns+.
	 * Net: 14ns/cycle win (running eliminated arena entirely). */
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (!tctx)
		return;

	/* Read fused + packed directly from arena CL0. */
	u32 fused  = tctx->deficit_avg_fused;
	u32 packed = tctx->packed_info;

	/* ── 1. CONFIDENCE-GATED EWMA (Rule 40) ──
	 * EWMA recomputation only fires every 64th stop (~15ns bench).
	 * On skipped stops (98.4%), previous deficit/avg values are reused.
	 * Gaming threads have stable runtimes — EWMA converges within 10-20
	 * stops and barely changes. Skipping 63/64 recomputations uses a value
	 * that differs by <0.1% from the fresh computation.
	 *
	 * reclass_counter is always incremented (needed for deferred telemetry).
	 * The & 63 gate is the same one used by deferred STATS — zero extra cost.
	 *
	 * CRITICAL: counter MUST be incremented BEFORE the gate check and
	 * OUTSIDE CAKE_STATS_ENABLED. Previous bug: counter only incremented
	 * inside stats block → stayed 0 in release → EWMA ran every stop. */
	u32 rc = tctx->reclass_counter++;
	struct ewma_result er;
	if ((rc & 63) == 0) {
		/* Full EWMA recomputation (every 64th stop) */
		er = compute_ewma(
			mbox->tick_slice, p->scx.slice,
			EXTRACT_AVG_RT(fused), EXTRACT_DEFICIT(fused));
		if (CAKE_STATS_ENABLED)
			tctx->telemetry.ewma_recomp_count++;
	} else {
		/* Confidence skip: reuse previous values (98.4% of stops) */
		er.new_avg = EXTRACT_AVG_RT(fused);
		er.deficit = EXTRACT_DEFICIT(fused);
	}

	/* ── 2. Game family priority (PPID-based, Phase 7.0+) ──
	 * VCSW (nvcsw) removed from priority path — it leaked 8× boost
	 * to browser/Discord threads (any epoll_wait increments nvcsw).
	 * Priority now uses ONLY game_member + waker_boost.
	 * Game family = TGID match (game threads) OR PPID match (Wine siblings).
	 *
	 * nvcsw_delta kept for TUI telemetry under CAKE_STATS_ENABLED. */
	bool is_game = (game_tgid && p->tgid == game_tgid)
		    || (game_ppid && tctx->ppid == game_ppid);
	if (CAKE_STATS_ENABLED && !is_game) {
		u64 cur_nv = p->nvcsw;
		u64 prev_nv = tctx->nvcsw_snapshot;
		if (prev_nv > 0)
			tctx->telemetry.nvcsw_delta += (u32)(cur_nv - prev_nv);
		tctx->nvcsw_snapshot = cur_nv;
	}

	/* ── 3. DRR++ deficit exhaustion + WAKER_BOOST extraction ──
	 * FUSED MASK CLEAR (Rule 24): unconditional WAKER_BOOST clear +
	 * conditional NEW clear combined into single AND operation.
	 * Must extract wb BEFORE clearing — one-shot flag set by cake_enqueue.
	 * Pre-Phase-7.0 bug: wb was read AFTER clear → always 0. */
	u32 wb = (packed >> SHIFT_FLAGS) & CAKE_FLOW_WAKER_BOOST;
	u32 clear_mask = (u32)CAKE_FLOW_WAKER_BOOST << SHIFT_FLAGS;
	/* Branchless: conditionally add NEW to clear mask (Rule 16) */
	u32 nf_expired = (er.deficit == 0) & ((packed >> SHIFT_FLAGS) & 1);
	clear_mask |= nf_expired << SHIFT_FLAGS;
	packed &= ~clear_mask;

	/* ── SQUEEZE PREDICATE FUSION (Rule 24) ──
	 * Shared gate: !is_game && !wb used by both hog and bg_noise.
	 * Single evaluation eliminates redundant branch. */
	bool can_squeeze = !is_game && !wb;

	/* HOG: BULK tier (EWMA ≥ 8ms) + not game + not boosted */
	bool is_hog = can_squeeze && (er.new_avg >= 8000);

	/* Branchless hog flag set/clear (Rule 16/37) */
	u32 hog_mask = (u32)CAKE_FLOW_HOG << SHIFT_FLAGS;
	packed = (packed & ~hog_mask) | (hog_mask & -(u32)is_hog);

	/* BG NOISE: game active + can_squeeze + not already HOG + not kthread */
	u8 is_kthread = (packed >> BIT_KTHREAD) & 1;
	bool bg_noise = can_squeeze && game_tgid && !is_hog && !is_kthread;

	/* Branchless bg_noise flag set/clear (Rule 16/37) */
	packed = (packed & ~(1u << BIT_BG_NOISE))
	       | (((u32)bg_noise) << BIT_BG_NOISE);

	u8 nf = (packed >> SHIFT_FLAGS) & 1;

	/* ── 4. Write back to per-task arena ── */
	tctx->deficit_avg_fused = PACK_DEFICIT_AVG(er.deficit, er.new_avg);
	tctx->packed_info = packed;

	/* ── 5. WARM CPU HISTORY — migration-gated ring shift ──
	 * Only fires on migration (cpu != warm_cpus[0]), ~9% of stops.
	 * 91% fast path: single comparison, zero writes.
	 * Feeds Gate 1c warm cache probes in cake_select_cpu. */
	if (tctx->warm_cpus[0] != (u16)cpu) {
		tctx->warm_cpus[2] = tctx->warm_cpus[1];
		tctx->warm_cpus[1] = tctx->warm_cpus[0];
		tctx->warm_cpus[0] = (u16)cpu;
	}

	/* ── 6. YIELD-GATED QUANTUM + WEIGHTED VTIME (Phase 5.0) ──
	 * Slice = runtime-proportional, modulated by yield signal.
	 * Yielders: ceiling (50ms) — cooperators get generous preemption deadline.
	 *   The slice is NOT a fairness mechanism (vtime handles that).
	 *   Yielders voluntarily yield after 1-22ms; ceiling is never reached.
	 *   This eliminates ALL ICSW — no spike tracking needed.
	 * Non-yielders: EWMA × 1, capped at 2ms (forces release).
	 * Hogs: capped at hog_quantum_cap_ns (500µs) — releases core quickly.
	 *
	 * dsq_vtime layout (see STAGED_BIT_* constants in intf.h):
	 *   [STAGED_BIT_VALID]=valid | [STAGED_SHIFT_HOME:+7]=home_cpu |
	 *   [STAGED_BIT_WAKER_BOOST]=wb | [STAGED_BIT_GAME_MEMBER]=game |
	 *   [STAGED_BIT_HOG]=hog | [STAGED_BIT_WB_DUP]=wb(dup) |
	 *   [STAGED_BIT_NEW_FLOW]=nf | [31:0]=weight_ns
	 * home_cpu = warm_cpus[1] (the CPU before current, i.e. prev home).
	 * 0xFF sentinel for uninitialized tasks (warm_cpus init to 0xFFFF).
	 * STAGED_BIT_WB_DUP was yielder (VCSW), now duplicates waker_boost for Gate 1P.
	 * game_member staged so cake_running can reflect it in mbox.is_yielder
	 * without re-reading game_tgid/game_ppid or accessing tgid again. */
	u32 weight_ns = (u32)er.new_avg * 1000; /* µs→ns */
	u32 home_cpu_staged = (u32)(tctx->warm_cpus[1] & 0xFF);
	/* wb already extracted above before clear — reuse here */

	/* Hog quantum cap: force short slices so hogs release cores quickly.
	 * Game members + waker-boosted get yielder path (50ms ceiling). */
	u64 base_slice = yield_gated_quantum_ns(er.new_avg, is_game || !!wb);
	/* Tiered quantum cap: HOG(250µs) > BG(500µs) > normal(uncapped).
	 * HOG and BG are mutually exclusive — at most one cap applies. */
	u64 cap = is_hog  ? (u64)hog_quantum_cap_ns
	        : bg_noise ? (u64)bg_quantum_cap_ns
	        : base_slice;  /* no cap — identity */
	p->scx.slice     = base_slice < cap ? base_slice : cap;
	/* wb precomputed once — used at two bit positions (Rule 24: mask fusion) */
	u64 wb_val = (u64)!!wb;
	p->scx.dsq_vtime = (1ULL << STAGED_BIT_VALID) |
			    ((u64)home_cpu_staged << STAGED_SHIFT_HOME) |
			    (wb_val << STAGED_BIT_WAKER_BOOST) |
			    ((u64)is_game << STAGED_BIT_GAME_MEMBER) |
			    ((u64)is_hog << STAGED_BIT_HOG) |
			    ((u64)bg_noise << STAGED_BIT_BG_NOISE) |
			    (wb_val << STAGED_BIT_WB_DUP) |
			    ((u64)nf << STAGED_BIT_NEW_FLOW) |
			    (u64)weight_ns;

	/* ── Telemetry + aggregate profiling (verbose only) ──
	 * Split into ALWAYS (lightweight CL0/BSS) + DEFERRED (heavy CL1-CL3).
	 * Deferred block runs every 64th stop via reclass_counter gate. */
	if (CAKE_STATS_ENABLED) {
		/* ALWAYS: lightweight counters (CL0 — same line as fused/packed) */
		/* reclass_counter moved to pre-EWMA gate (line ~1920) — must
		 * increment in release builds too for confidence skip to work. */
		tctx->last_run_at = mbox->tick_last_run_at;

		/* ALWAYS: nvcsw_delta accumulator (must not skip deltas) */
		/* Note: nvcsw_delta write is on telemetry CL, but accumulator
		 * correctness requires every-stop update. The CL fetch is
		 * amortized since stopping already read nvcsw_snapshot from CL0. */

		/* DEFERRED TELEMETRY: Heavy per-task writes every 64th stop.
		 * Saves ~13 arena writes + 1 scx_bpf_now() + 1 div64 on 63/64 stops. */
		if ((tctx->reclass_counter & 63) == 0) {
			if (tctx->telemetry.run_start_ns > 0) {
				u64 dur = scx_bpf_now() - tctx->telemetry.run_start_ns;
				tctx->telemetry.run_duration_ns = dur;

				/* Branchless same-CPU streak */
				bool same = ((u16)cpu == tctx->telemetry.core_placement);
				tctx->telemetry.same_cpu_streak = (tctx->telemetry.same_cpu_streak + 1) & -(u16)same;
				tctx->telemetry.core_placement = (u16)cpu;

				/* Jitter: |actual_run - EWMA_expected| */
				u64 expected_ns = (u64)er.new_avg * 1000ULL;
				u64 d = dur - expected_ns;
				u64 mask = -(u64)(dur < expected_ns);
				u64 jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;

				/* Branchless max */
				u16 old_max_rt = tctx->telemetry.max_runtime_us;
				tctx->telemetry.max_runtime_us = old_max_rt + ((er.new_avg - old_max_rt) & -(u16)(er.new_avg > old_max_rt));

				/* Slice utilization — shift-approximate, no div64 (Rule 5)
				 * (dur << 7) / tslice ≈ dur * 128 / tslice.
				 * Rescaled by 100/128 = 0.78, close enough for TUI display. */
				u64 tslice = mbox->tick_slice ?: quantum_ns;
				tctx->telemetry.slice_util_pct =
					(u16)((dur << 7) / tslice);

				/* Involuntary context switch delta */
				u64 cur_nivcsw = p->nivcsw;
				u64 prev_nivcsw = tctx->telemetry.nivcsw_snapshot;
				if (prev_nivcsw > 0)
					tctx->telemetry.nivcsw_delta += (u32)(cur_nivcsw - prev_nivcsw);
				tctx->telemetry.nivcsw_snapshot = cur_nivcsw;
			}

			/* Per-task stopping overhead (deferred — TUI display only) */
			u64 oh = scx_bpf_now() - stopping_overhead_start;
			tctx->telemetry.stopping_duration_ns = (u32)oh;
		}

		/* ALWAYS: Aggregate overhead timing (per-CPU BSS, cheap)
		 * Rule 30: reuse cpu from top of function, skip kfunc trampoline.
		 * Rule 7: single scx_bpf_now() for both deferred + always paths. */
		struct cake_stats *s = get_local_stats_for(cpu);
		u64 oh_agg = scx_bpf_now() - stopping_overhead_start;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns = s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) & -(oh_agg > s->max_stopping_ns));
		/* Track confidence-skip vs full-EWMA accurately.
		 * rc was read pre-increment, so (rc & 63) == 0 matches EWMA path. */
		if ((rc & 63) == 0)
			s->nr_stop_ewma++;
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
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->nr_dropped_allocations++;
		}
		return -ENOMEM;
	}

	/* Register in PID→tctx map for TUI visibility (100% task coverage) */
	if (CAKE_STATS_ENABLED) {
		u32 pid_key = p->pid;
		u64 tctx_val = (u64)tctx;
		bpf_map_update_elem(&pid_to_tctx, &pid_key, &tctx_val, BPF_ANY);
	}

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
	u16 init_deficit	= (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
	tctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, 0);
	tctx->last_run_at	= 0;
	tctx->reclass_counter	= 0;

	/* Gate 1c warm CPU history: initialize to invalid sentinel.
	 * 0xFFFF → dsq_vtime home_cpu byte = 0xFF → fails (home >= nr_cpus)
	 * check, correctly skipping Gate 1c until task runs on 2+ CPUs. */
	tctx->warm_cpus[0] = 0xFFFF;
	tctx->warm_cpus[1] = 0xFFFF;
	tctx->warm_cpus[2] = 0xFFFF;
	tctx->waker_cpu    = 0xFFFF;  /* Invalid until first wakeup-from-waker */

	/* PPID: ALWAYS populated — game family detection (cake_stopping line 2031,
	 * Gate 1WC, tunnel) reads tctx->ppid unconditionally. Must be outside
	 * CAKE_STATS_ENABLED or PPID-based Wine/Proton sibling detection is
	 * dead in release builds. */
	tctx->ppid = p->real_parent ? p->real_parent->tgid : 0;

	/* TUI telemetry: identity fields only needed with --verbose.
	 * Gated to avoid unnecessary arena writes on task creation. */
	if (CAKE_STATS_ENABLED) {
		tctx->telemetry.pid = p->pid;
		tctx->telemetry.tgid = p->tgid;
		u64 *comm_src = (u64 *)p->comm;
		u64 __arena *comm_dst = (u64 __arena *)tctx->telemetry.comm;
		comm_dst[0] = comm_src[0];
		comm_dst[1] = comm_src[1];
		/* nivcsw_snapshot: TUI delta only (nvcsw gated separately below) */
		tctx->telemetry.nivcsw_snapshot = p->nivcsw;
	}

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
     * Updated event-driven by cake_set_cpumask (zero polling). */
	bpf_rcu_read_lock();
	tctx->cached_cpumask = build_cached_cpumask(p->cpus_ptr);
	bpf_rcu_read_unlock();

	return 0;
}

/* EVENT-DRIVEN AFFINITY UPDATE (Rule 41: Locality Promotion)
 * Kernel calls this when sched_setaffinity() changes a task's cpumask.
 * Replaces polling — zero hot-path cost.
 * Cost: 16 kfuncs × 15ns = 240ns per call — amortized to ~0ns/cycle. */
void BPF_STRUCT_OPS(cake_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (!tctx)
		return;

	if (CAKE_STATS_ENABLED)
		tctx->telemetry.cpumask_change_count++;

	tctx->cached_cpumask = build_cached_cpumask(cpumask);
}

/* Handle manual yields (e.g. sched_yield syscall).
 * yield_count is TUI-only telemetry (stats-gated). Game family detection
 * uses PPID matching in cake_stopping, not per-task yield counts.
 * Cost in debug: 1 get_task_ctx (~16ns) per yield. Zero cost in release. */
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *p)
{
	/* F3: Gate behind CAKE_STATS_ENABLED — yield_count is TUI-only.
	 * Saves ~16ns get_task_ctx per sched_yield() in release builds. */
	if (CAKE_STATS_ENABLED) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) tctx->telemetry.yield_count++;
	}
	return false;
}

/* Handle preemption when a task is pushed off the CPU. */
void BPF_STRUCT_OPS(cake_runnable, struct task_struct *p, u64 enq_flags)
{
	if (CAKE_STATS_ENABLED) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			if (enq_flags & SCX_ENQ_PREEMPT)
				tctx->telemetry.preempt_count++;
			/* Wakeup source: the currently running task is the waker */
			struct task_struct *waker = bpf_get_current_task_btf();
			if (waker)
				tctx->telemetry.wakeup_source_pid = waker->pid;
		}
	}
}

/* Free per-task arena storage on task exit. */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	/* Remove from PID→tctx map before freeing arena storage */
	if (CAKE_STATS_ENABLED) {
		u32 pid_key = p->pid;
		bpf_map_delete_elem(&pid_to_tctx, &pid_key);
	}
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

	/* Unified per-CPU arena block.
     * Merges mailbox (128B) + scratch (128B) into 256B per CPU.
     * 256B × 64 CPUs = 16KB = 4 pages.
     * Single allocation: 1 TLB entry, 1 global pointer, 1 null-check. */
	per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
		&arena, NULL, 4, NUMA_NO_NODE, 0);
	if (!per_cpu)
		return -ENOMEM;


	return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
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
