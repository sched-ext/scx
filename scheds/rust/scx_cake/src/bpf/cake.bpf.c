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
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};

/* Topological O(1) Arrays — populated by loader */
const u64 llc_cpu_mask[CAKE_MAX_LLCS]	 = {};
const u64 core_cpu_mask[32]		 = {};
const u8  cpu_sibling_map[CAKE_MAX_CPUS] = {};

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

/* BenchLab ringbuf: tiny ringbuf for measuring reserve+submit overhead.
 * Size 4096 = minimum page-aligned allocation. Never consumed by userspace;
 * benchmarks use reserve+discard to measure the API cost. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} bench_ringbuf SEC(".maps");

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
			tctx->telemetry.select_cpu_duration_ns =
				(u32)(scx_bpf_now() - start_time);
			switch (gid) {
			case GATE_1:  tctx->telemetry.gate_1_hits++;  break;
			case GATE_1B: tctx->telemetry.gate_2_hits++;  break;
			case GATE_1W: tctx->telemetry.gate_1w_hits++; break;
			case GATE_1P: tctx->telemetry.gate_1p_hits++; break;
			case GATE_3:  tctx->telemetry.gate_3_hits++;  break;
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
		tctx->telemetry.enqueue_duration_ns =
			(u32)(post_kfunc - start_time);
		tctx->telemetry.dsq_insert_ns =
			(u32)(post_kfunc - pre_kfunc);
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

/* Gate recording macro removed — no more cross-CPU gate prediction state. */

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
     * Cost: ~15ns (single kfunc).
     *
     * KFUNC DEFERRAL: bpf_get_smp_processor_id() deferred to after Gate 1.
     * Gate 1 hit (91%) never uses tc_id/scr — saves 15ns kfunc trampoline
     * on the hottest path. ~1,365µs/s returned to game threads.
     *
     * AFFINITY GATE: Wine/Proton tasks may dynamically restrict cpumask.
     * prev_cpu could be outside the allowed set after affinity change.
     * Fast path: nr_cpus_allowed == nr_cpus is RODATA-const, JIT folds
     * to single register cmp — zero kfunc cost for full-affinity tasks.
     *
     */
	u32 prev_idx = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);
	if ((aff_mask & (1ULL << prev_idx)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->total_gate1_latency_ns += scx_bpf_now() - start_time;
		}
		return direct_dispatch(p, prev_cpu, wake_flags, start_time, GATE_1);
	}

	/* ── DEFERRED KFUNC: bpf_get_smp_processor_id() ──
	 * Only reached on Gate 1 miss (~9%). Gate 1b, 1W, 1P, and tunnel
	 * all need tc_id. scx_bpf_now() is deferred further — see below. */
	u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_scratch __arena *scr = &per_cpu[tc_id].scr;

	/* ── GATE 1b: SMT sibling fallback — L2 still warm ──
     * When prev_cpu is busy, try its SMT sibling.
     * Same physical core → L2 cache shared. */
	if (nr_cpus > nr_phys_cpus) {
		s32 sib = smt_sibling(prev_cpu);

		if (sib != prev_cpu && (u32)sib < nr_cpus &&
		    (aff_mask & (1ULL << (u32)sib)) &&
		    scx_bpf_test_and_clear_cpu_idle(sib)) {
			if (CAKE_STATS_ENABLED) {
				struct cake_stats *s = get_local_stats();
				s->total_gate1_latency_ns += scx_bpf_now() - start_time;
			}
			return direct_dispatch(p, sib, wake_flags, start_time, GATE_1B);
		}
	}

	/* ── GATE 1W: Waker-aware placement ──
	 * Waker is running on tc_id. Place wakee near waker for
	 * L2/LLC cache sharing in producer-consumer pairs (e.g.,
	 * GPU submit → fence → render pipeline).
	 *
	 * Step 1: Try waker's SMT sibling (same core = L2 shared).
	 *         Works on ALL topologies. ~15ns (1 kfunc).
	 * Step 2: If waker and prev are on different LLCs, search
	 *         for idle CPU near waker instead of prev_cpu.
	 *         No-op on single-LLC (9800X3D): ~2ns comparison.
	 *         Active on multi-LLC (7950X3D, Intel): ~40ns kfunc. */
	{
		/* Step 1: Waker's SMT sibling — L2 cache sharing */
		if (nr_cpus > nr_phys_cpus) {
			s32 waker_sib = smt_sibling(tc_id);

			if (waker_sib != prev_cpu && (u32)waker_sib < nr_cpus &&
			    (aff_mask & (1ULL << (u32)waker_sib)) &&
			    scx_bpf_test_and_clear_cpu_idle(waker_sib)) {
				return direct_dispatch(p, waker_sib, wake_flags, start_time, GATE_1W);
			}
		}

		/* Step 2: Waker LLC affinity — multi-LLC only */
		u32 waker_llc = cpu_llc_id[tc_id];
		u32 prev_llc = cpu_llc_id[prev_idx];

		if (waker_llc != prev_llc) {
			bool is_idle_1w = false;
			s32 waker_near = scx_bpf_select_cpu_dfl(p, tc_id, 0,
								&is_idle_1w);

			if (is_idle_1w &&
			    (aff_mask & (1ULL << (u32)waker_near))) {
				if (CAKE_STATS_ENABLED) {
					struct cake_task_ctx __arena *tctx = get_task_ctx(p);
					if (tctx && waker_near != prev_cpu)
						tctx->telemetry.migration_count++;
				}
				return direct_dispatch(p, waker_near, wake_flags, start_time, GATE_1W);
			}
		}
	}

	/* ── DEFERRED TIMESTAMP: scx_bpf_now() ──
	 * Deferred past Gate 1b/1W — neither uses the timestamp.
	 * Only Gate 1P (elapsed check) and tunnel (vtime base) need it.
	 * Saves 23ns kfunc trampoline on ~5% of wakeups that hit 1b/1W.
	 * Negligible staleness: <100ns later than before, irrelevant
	 * against 1ms Gate 1P threshold and 2ms quantum vtime base. */
	u64 now_post_g1 = scx_bpf_now();

	/* ── GATE 1P: Yielder-preempts-bulk ──
	 * If incoming task is a yielder and prev_cpu runs a non-yielder
	 * that has consumed ≥1ms, preempt it.
	 *
	 * STAGED YIELDER CHECK: p->scx.dsq_vtime bit 49 = yielder,
	 * bit 63 = validity (set after first cake_stopping). Eliminates
	 * get_task_ctx kfunc (32ns → 3ns). Brand-new tasks have bit63=0
	 * and are correctly skipped. */
	{
		u64 staged_1p = p->scx.dsq_vtime;
		if ((staged_1p & (1ULL << 63)) && (staged_1p & (1ULL << 49))) {
			/* Incoming IS a yielder — now check if prev_cpu incumbent is preemptable */
			struct mega_mailbox_entry __arena *mbox_prev = &per_cpu[prev_idx].mbox;
			if (!mbox_prev->is_yielder) {
				u32 elapsed = (u32)now_post_g1 - mbox_prev->tick_last_run_at;
				if (elapsed > 1000000) {
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
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx && cpu != prev_cpu)
				tctx->telemetry.migration_count++;
		}
		return direct_dispatch(p, cpu, wake_flags, start_time, GATE_3);
	}

	/* ── TUNNEL: All CPUs busy — fall through to enqueue → DSQ ──
     * No preemption, no kicks. Task goes to DSQ, gets picked up
     * when a CPU naturally becomes idle and calls cake_dispatch. */
	/* Fix 2: Reuse now_post_g1 — no extra scx_bpf_now() (saves 23ns). */
	u64 tunnel_now = now_post_g1;
	scr->cached_llc = cpu_llc_id[tc_id];
	scr->cached_now = tunnel_now;
	/* WAKER PRIORITY INHERITANCE: Stash waker's yielder status.
	 * Reads LOCAL CPU mailbox CL0 (L1-hot, ~0ns). Consumed by
	 * cake_enqueue to boost non-yielding render pipeline threads
	 * woken by yielding UE5 task workers. */
	scr->waker_yielder = per_cpu[tc_id].mbox.is_yielder;

	if (CAKE_STATS_ENABLED) {
		struct cake_stats *s = get_local_stats();
		s->total_gate2_latency_ns += tunnel_now - start_time;
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			tctx->telemetry.select_cpu_duration_ns = (u32)(tunnel_now - start_time);
			tctx->telemetry.gate_tun_hits++;
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

	if (unlikely(!(staged & (1ULL << 63)))) {
		/* No staged context: first dispatch or kthread without alloc.
         * task_flags read deferred here — only needed on this cold path.
         * Avoids stealing a callee-saved register from the hot path,
         * eliminating spill of p across bpf_get_smp_processor_id. */
		/* Cold path: pure timestamp, no priority encoding.
		 * Full 64-bit range — no mask. */
		u64 vtime = now_cached;
		u64 pre_kfunc = 0;
		if (CAKE_STATS_ENABLED) pre_kfunc = scx_bpf_now();

		/* Single DSQ per LLC — vtime ordering handles priority */
		scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
					 quantum_ns, vtime, enq_flags);

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
		u8 yl_flag = (staged >> 49) & 1;
		/* P4-1: Branchless slice select: yl=1→75%, yl=0→50% (Rule 16) */
		u64 lo = requeue_slice >> 1;
		u64 hi = (requeue_slice * 3) >> 2;
		requeue_slice = lo + ((hi - lo) & -(u64)yl_flag);
		requeue_slice += (200000 - requeue_slice) & -(requeue_slice < 200000);
		u64 pre_kfunc = 0;
		if (CAKE_STATS_ENABLED) pre_kfunc = scx_bpf_now();

		/* Single DSQ per LLC */
		scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
					 requeue_slice, vtime, enq_flags);

		if (CAKE_STATS_ENABLED)
			enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached);
		return;
	}

	/* Extract staged fields — zero bpf_task_storage_get */
	u64 slice = p_reg->scx.slice ?: quantum_ns;

	/* PROPORTIONAL YIELDER PRIORITY (Phase 6.0):
	 * weight_ns pre-computed in cake_stopping (zero MUL).
	 * Yielders advance vtime at half rate (>> 1 = 2× priority).
	 * Self-scaling: heavier tasks get proportionally more boost.
	 * No magic constants — priority is relative to the task's own EWMA. */
	u8 new_flow = (staged >> 48) & 1;
	u8 yielder  = (staged >> 49) & 1;
	u32 weight_ns = (u32)(staged & 0xFFFFFFFF);

	/* WAKER PRIORITY INHERITANCE: If waker is a yielder, boost wakee.
	 * Covers non-yielding render pipeline threads (RHIThread, vkd3d-swapchain)
	 * woken by yielding UE5 Foreground/Background Workers.
	 * Cost: 1 scratch read (same CL as cached_llc, ~0ns). */
	u8 waker_yl = scr->waker_yielder;
	u8 effective_yl = yielder | (waker_yl ? 1 : 0);

	/* P4-2: Branchless effective_weight (Rule 16) */
	u32 shift = (u32)effective_yl * 3; /* 0 or 3 */
	u32 effective_weight = weight_ns >> shift;
	u64 vtime = now_cached + effective_weight;

	/* CHAIN PROPAGATION: Set WAKER_BOOST in tctx packed_info so
	 * cake_running reflects the boost in mbox->is_yielder. This enables
	 * depth-N chains (yielder→RHIThread→RHISubmissionTh) to propagate
	 * naturally through successive wakeup cycles.
	 * Cost: 16ns get_task_ctx, ~1-2% of wakeups (tunnel + waker yielder + wakee non-yielder). */
	if (waker_yl && !yielder) {
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

	scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, slice, vtime,
				 enq_flags);

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
	u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];

	/* Single DSQ probe — 1 kfunc, always. 26ns on 9800X3D.
     * Vtime ordering handles priority: lowest vtime pops first.
     * Zero MESI bouncing, zero atomics, zero arena allocation.
     * -75% cache line footprint vs old 4-DSQ design. */
	if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc)) {
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->nr_local_dispatches++;
			s->nr_dsq_consumed++;
		}
		return;
	}

	/* Steal from other LLCs (only when local DSQ empty).
     * RODATA gate: single-LLC systems skip this entirely. (Rule 5) */
	if (nr_llcs <= 1) {
		if (CAKE_STATS_ENABLED) {
			struct cake_stats *s = get_local_stats();
			s->nr_dispatch_misses++;
		}
		return;
	}

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

	/* ILP REORDER: kfuncs arranged to maximize OoO latency hiding.
	 *
	 * bpf_get_smp_processor_id → get_task_ctx → scx_bpf_now
	 *
	 * After get_task_ctx returns the arena pointer, x86 OoO issues the
	 * dependent arena CL0 loads (packed_info, fused, nvcsw_snapshot)
	 * immediately. These loads execute IN PARALLEL with scx_bpf_now's
	 * kfunc trampoline (23ns). In the cold-tctx case (task slept >100ms,
	 * arena page evicted), this hides ~23ns of L3/DRAM latency.
	 * In the hot case (task ran recently), arena CL0 is L1 (~4ns) and
	 * the reorder has zero cost — kfunc order doesn't affect hot latency.
	 *
	 * Critical: p->scx.slice load is placed between get_task_ctx and
	 * scx_bpf_now — it's independent of both and the CPU can issue it
	 * in the same cycle as the arena loads (MLP). */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct mega_mailbox_entry __arena *mbox = &per_cpu[cpu].mbox;

	/* KFUNC #2: get_task_ctx — arena pointer fetch.
	 * Placed BEFORE scx_bpf_now to start arena page walk early.
	 * Dependent loads issued immediately after return — OoO overlaps
	 * them with kfunc #3 below. */
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	u32 raw_packed = tctx ? tctx->packed_info : 0;
	u32 raw_fused  = tctx ? tctx->deficit_avg_fused : 0;
	u64 raw_nvcsw  = tctx ? tctx->nvcsw_snapshot : 0;

	/* Independent load — can execute in parallel with arena CL0 fetch */
	u64 slice = p->scx.slice;

	/* KFUNC #3: scx_bpf_now — 23ns trampoline overlaps arena fetch */
	u64 now_full = scx_bpf_now();
	u32 now = (u32)now_full;
	u64 running_overhead_start = CAKE_STATS_ENABLED ? now_full : 0;

	/* ── COMPUTE: final slice from staged data ── */
	u64 final_slice = slice ?: quantum_ns;

	/* ── WRITE: per-CPU mailbox (local CPU only, zero cross-CPU traffic) ──
	 * All stores to CL0 — single dirty line. By this point, arena CL0
	 * reads above have completed (overlapped with scx_bpf_now). */
	mbox->tick_last_run_at = now;
	mbox->tick_slice       = final_slice;
	mbox->is_yielder = (raw_packed >> SHIFT_FLAGS) &
			    (CAKE_FLOW_YIELDER | CAKE_FLOW_WAKER_BOOST);
	mbox->cached_cpu = (u16)cpu;
	mbox->cached_tctx_ptr = (u64)tctx;
	mbox->cached_fused = raw_fused;
	mbox->cached_packed = raw_packed;
	mbox->cached_nvcsw = raw_nvcsw;

	/* ARENA TELEMETRY: Record run start time for task-level tracking.
     * Stored directly in BPF Arena for 0-syscall user-space sweeping. */
	if (CAKE_STATS_ENABLED) {
		if (tctx) {
			/* P4-4: Reuse now_full instead of extra scx_bpf_now() (~15ns saved) */
			u64 start = now_full;

			/* ALWAYS: run_start_ns must be set every run (stopping reads it) */
			tctx->telemetry.run_start_ns = start;

			/* DEFERRED TELEMETRY: Heavy CL1-CL3 writes every 64th stop.
			 * Reduces verbose overhead by 98.4%, making profiling less intrusive.
			 * TUI refreshes at 1-4Hz so 64x decimation is invisible. */
			if ((tctx->reclass_counter & 63) == 0) {
				/* 1. DISPATCH GAP */
				if (tctx->telemetry.run_start_ns > 0) {
					u64 gap = start - tctx->telemetry.run_start_ns;
					tctx->telemetry.dispatch_gap_ns = gap;
					u64 old_max_g = tctx->telemetry.max_dispatch_gap_ns;
					tctx->telemetry.max_dispatch_gap_ns = old_max_g + ((gap - old_max_g) & -(gap > old_max_g));
				}

				tctx->telemetry.core_placement = cpu;
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

/* cake_stopping — Disruptor handoff: zero-arena hot path
 *
 * ALL inputs pre-staged on mailbox CL0 by cake_running:
 *   cached_fused  = deficit_avg_fused (EWMA state)
 *   cached_packed = packed_info (yield/flow flags)
 *   cached_tctx_ptr = arena pointer (for writeback only)
 *
 * BenchLab proved: CL0 reads = 0ns above calibration, get_task_ctx = 16ns,
 * arena reads = 0ns but require tctx pointer derivation (16ns to get).
 * Pre-staging eliminates the get_task_ctx call entirely.
 *
 * Cost: ~0ns (all reads from L1-hot CL0) + ~0ns EWMA+yield = ~0ns. */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	ARENA_ASSOC();
	struct mega_mailbox_entry __arena *mbox = &per_cpu[cpu].mbox;

	u64 stopping_overhead_start = 0;
	if (CAKE_STATS_ENABLED) {
		stopping_overhead_start = scx_bpf_now();
		mbox->last_stopped_pid = p->pid;
	}

	/* Disruptor handoff: read ALL inputs from mailbox CL0.
	 * Pre-staged by cake_running — zero arena reads, zero get_task_ctx.
	 * Falls back to get_task_ctx() if cached ptr is null (first run). */
	u64 cached_ptr = mbox->cached_tctx_ptr;
	struct cake_task_ctx __arena *tctx = cached_ptr ?
		(struct cake_task_ctx __arena *)cached_ptr :
		get_task_ctx(p);
	if (!tctx)
		return;

	/* Read fused + packed from mailbox CL0 (pre-staged by cake_running).
	 * Eliminates 2 arena CL0 reads (tctx->deficit_avg_fused, tctx->packed_info). */
	u32 fused  = mbox->cached_fused;
	u32 packed = mbox->cached_packed;

	/* ── 1. EWMA (kept for quantum sizing, ~5 insns) ── */
	struct ewma_result er = compute_ewma(
		mbox->tick_slice, p->scx.slice,
		EXTRACT_AVG_RT(fused), EXTRACT_DEFICIT(fused));

	/* ── 2. YIELD DETECTION (binary, ~3 insns) ──
	 * nvcsw increments on every voluntary yield (futex, poll, DRM fence).
	 * GPU/audio/input/network threads all exhibit this pattern.
	 * Binary per-stop: set fresh every time. */
	u64 cur_nv = p->nvcsw;
	/* Fix 3: Read pre-staged nvcsw_snapshot from mailbox CL0 instead
	 * of arena tctx->nvcsw_snapshot. Eliminates cold arena read (~15ns). */
	u64 prev_nv = mbox->cached_nvcsw;
	bool yielder = cur_nv > prev_nv;

	/* Telemetry delta BEFORE snapshot update (fixes nvcsw_delta=0 bug) */
	if (CAKE_STATS_ENABLED && prev_nv > 0)
		tctx->telemetry.nvcsw_delta += (u32)(cur_nv - prev_nv);
	tctx->nvcsw_snapshot = cur_nv;

	/* P3-1: Branchless yielder flag set/clear (Rule 16/24/37) */
	u32 yl_mask = (u32)CAKE_FLOW_YIELDER << SHIFT_FLAGS;
	packed = (packed & ~yl_mask) | (yl_mask & -(u32)yielder);

	/* ── 3. DRR++ deficit exhaustion ── */
	if (er.deficit == 0 &&
	    (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)))
		packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);

	/* Clear WAKER_BOOST after one run-stop cycle.
	 * The boost is re-applied on next wakeup if waker is still a yielder. */
	packed &= ~((u32)CAKE_FLOW_WAKER_BOOST << SHIFT_FLAGS);

	u8 nf = (packed >> SHIFT_FLAGS) & 1;
	u8 yl = (u8)yielder; /* P3-7: bool is already 0/1, no ternary needed */

	/* ── 4. Write back to per-task arena ── */
	tctx->deficit_avg_fused = PACK_DEFICIT_AVG(er.deficit, er.new_avg);
	tctx->packed_info = packed;

	/* ── 5. YIELD-GATED QUANTUM + WEIGHTED VTIME (Phase 5.0) ──
	 * Slice = runtime-proportional, modulated by yield signal.
	 * Yielders: ceiling (50ms) — cooperators get generous preemption deadline.
	 *   The slice is NOT a fairness mechanism (vtime handles that).
	 *   Yielders voluntarily yield after 1-22ms; ceiling is never reached.
	 *   This eliminates ALL ICSW — no spike tracking needed.
	 * Non-yielders: EWMA × 1, capped at 2ms (forces release).
	 * Staging layout: [63]=valid | [49]=yielder | [48]=new_flow | [31:0]=weight_ns */
	u32 weight_ns = (u32)er.new_avg * 1000; /* µs→ns */

	p->scx.slice     = yield_gated_quantum_ns(er.new_avg, yielder);
	p->scx.dsq_vtime = (1ULL << 63) | ((u64)yl << 49) |
			    ((u64)nf << 48) | (u64)weight_ns;

	/* ── Telemetry + aggregate profiling (verbose only) ──
	 * Split into ALWAYS (lightweight CL0/BSS) + DEFERRED (heavy CL1-CL3).
	 * Deferred block runs every 64th stop via reclass_counter gate. */
	if (CAKE_STATS_ENABLED) {
		/* ALWAYS: lightweight counters (CL0 — same line as fused/packed) */
		tctx->reclass_counter++;
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
		s->nr_stop_ewma++;

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
 * The task gives up the CPU but remains runnable. */
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *p)
{
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
