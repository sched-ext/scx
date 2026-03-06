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
/* HOG detection now uses rt_raw >= tick_slice * 3/4 inline (zero RODATA). */
const u32  preempt_vip_ns        = CAKE_PREEMPT_VIP_THRESHOLD_NS;     /* 50µs VIP preempt */
const u32  preempt_yielder_ns    = CAKE_PREEMPT_YIELDER_THRESHOLD_NS; /* 100µs normal preempt */

/* JITTER REDUCTION: RODATA lookup tables indexed by task_class (0-3).
 * Eliminates branching chains — single indexed load is constant-time
 * regardless of class, zero pipeline misprediction variance.
 * Populated by Rust loader from hog/bg RODATA values. */
const u32  quantum_cap_ns[4]     = { 0, 0, 250000, 500000 };  /* NORMAL/GAME=0(no cap), HOG=250µs, BG=500µs */
/* ── TIERED DSQ ORDERING ──
 * Non-overlapping offsets guarantee class ordering in vtime DSQ.
 * GAME [0,5120] < NORMAL [8192,13312] < HOG [16384,21504] < BG [49152,54272].
 * Index: [NORMAL=0, GAME=1, HOG=2, BG=3] (matches CAKE_CLASS_* enum) */
const u32  tier_base[4]           = { 8192, 0, 16384, 49152 };  /* NORMAL=8192, GAME=0, HOG=16384, BG=49152 */
/* VRUNTIME COST: max rt_cost per class (clamped to inter-bucket gap).
 * Prevents runtime cost from pushing a task across bucket boundaries.
 * All gaps ≥3072 — uniform cap of 4096 is safe for every class. */
const u32  rt_cost_cap[4]        = { 4096, 4096, 4096, 4096 };  /* uniform cap */
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

/* Performance-ordered CPU scan arrays (populated by Rust loader).
 * cpus_fast_to_slow: GAME tasks scan highest-perf cores first → maximum boost.
 * cpus_slow_to_fast: non-GAME tasks scan lowest-perf cores first → power parking.
 * Source: amd_pstate_prefcore_ranking (Zen 4) or cpufreq_cap (fallback).
 * Terminated by 0xFF sentinel when nr_cpus < CAKE_MAX_CPUS. */
const u8 cpus_fast_to_slow[CAKE_MAX_CPUS] = {};
const u8 cpus_slow_to_fast[CAKE_MAX_CPUS] = {};

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

/* Audio stack TGIDs — detected once at startup, baked into RODATA.
 * PipeWire/PulseAudio/JACK daemons + PipeWire socket clients (mixers like
 * goxlr-daemon, easyeffects). Session-persistent (started at login, same
 * PID until logout). JIT constant-folds these to immediates.
 * Zero-terminated: unused slots = 0 (no valid TGID matches pid 0). */
const u32 nr_audio_tgids = 0;
const u32 audio_tgids[CAKE_MAX_AUDIO_TGIDS] = {};

/* Compositor TGIDs — detected once at startup, baked into RODATA.
 * Wayland compositors (kwin_wayland, mutter, sway, Hyprland, etc.) present
 * every frame to the display. Must dispatch promptly during GAMING.
 * Session-persistent like audio daemons. */
const u32 nr_compositor_tgids = 0;
const u32 compositor_tgids[CAKE_MAX_COMPOSITOR_TGIDS] = {};



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
 * the appropriate policy profile (squeeze, vprot kick, quantum ceiling).
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

/* PID→task_class cache: tunnels task_class from stopping → select_cpu Gate 2.
 * Eliminates bpf_task_storage_get (28ns avg, 1982ns worst-case jitter)
 * from the select_cpu wakeup path. BSS read = 14ns avg, 96ns jitter.
 * 4096 entries (4KB) indexed by p->pid & 4095. Hash collision risk with
 * ~100 gaming tasks is <0.1%. Written in stopping, read in select_cpu. */
#define PID_CLASS_CACHE_SIZE 4096
static u8 pid_class_cache[PID_CLASS_CACHE_SIZE];

/* Phase 5: Per-CPU BSS — arena-free running.
 * Each entry is 64B aligned (one cache line per CPU).
 * running writes, stopping reads (same CPU) + vprot kick reads (remote CPU). */
struct cake_cpu_bss cpu_bss[CAKE_MAX_CPUS];

/* O(1) GAME preemption bitmask: bit N set = CPU N running a GAME task.
 * Written atomically (or/and) in cake_running. Read in cake_enqueue.
 * Victim = __builtin_ctzll(~game_cpu_mask) = single tzcnt on Zen 4. */
static u64 game_cpu_mask;

/* DSQ MAILBOX: per-LLC flag tracks whether a kick has been sent to drain
 * the LLC DSQ. Set on enqueue (0→1 transition only, check-before-write).
 * Cleared in cake_dispatch after successful move_to_local.
 * Prevents tasks from rotting in DSQ when all CPUs use Gate 1 direct
 * dispatch (which bypasses cake_dispatch entirely).
 * MESI: read-first — stays Shared if already set, no cache bounce. */
u8 dsq_kick_needed[CAKE_MAX_LLCS];

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
			volatile u8 sib_idle = cpu_bss[sib & (CAKE_MAX_CPUS - 1)].idle_hint;
			/* Probe 3: home CPU idle_hint from BSS? (simulated as prev) */
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
static __always_inline u64 yield_gated_quantum_ns(u16 pelt_scaled,
						  bool yielder, u64 ceiling_ns)
{
	if (yielder)
		return aq_yielder_ceiling_ns;

	/* Bulk path: pelt_scaled × 1000, clamped [floor, ceiling]. */
	u64 q = (u64)pelt_scaled * 1000;
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
	 * Gaming wakes are signal-only — no data locality from SYNC.
	 * A/B tested: SYNC enabled = same or slightly worse FPS in Arc Raiders.
	 * bpfland/cosmos: conditional via no_wake_sync flag. Cake: unconditional
	 * because game wakes are always signal-only (vsync, futex, GPU done). */
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
	/* 3-GATE DESIGN: Gate 1 (prev_cpu idle) + Gate 2 (perf-ordered) + Gate 3 (kernel scan).
	 * No prev_idx, no aff_mask, no hot lookup on fast path. */

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

	/* ── GATE 2: Performance-ordered idle scan ──
	 * Scan CPUs in performance order for idle cores:
	 *   GAME:     fast→slow (P-cores first for max boost)
	 *   non-GAME: slow→fast (E-cores first for power parking)
	 * Uses RODATA cpus_fast_to_slow / cpus_slow_to_fast (populated by
	 * Rust loader from amd_pstate_prefcore_ranking).
	 * EEVDF TOPOLOGY: Always active when P/E cores exist, not just GAMING.
	 * Ensures GAME tasks always land on P-cores, BG on E-cores.
	 * Cost: 0ns on SMP (big_core_phys_mask=0 → short-circuits). */
	if (big_core_phys_mask) {
		/* READ TASK CLASS from BSS pid_class_cache (tunneled from stopping).
		 * Zero bpf_task_storage_get → eliminates 1982ns tail jitter.
		 * BSS read = 14ns avg, 96ns jitter (vs 28ns/1982ns task_storage).
		 * p->pid is L1-hot (same CL as p->scx.slice). */
		u8 g2_tc = pid_class_cache[p->pid & (PID_CLASS_CACHE_SIZE - 1)];
		bool is_game = (g2_tc == CAKE_CLASS_GAME);
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
				bool sib_game = (game_cpu_mask >> (sib & 63)) & 1;
				if (is_game ^ sib_game)
					continue;  /* class mismatch — skip */
			}

			if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
				u64 slice = p->scx.slice ?: quantum_ns;
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | candidate,
						   slice, wake_flags);
				return candidate;
			}
		}
	}

	/* ── GATE 3 (was Gate 1 MISS): Kernel find any idle CPU ──
	 * 3-GATE DESIGN: Gate 1 (prev_cpu) + Gate 2 (perf-ordered, GAMING) + Gate 3 (kernel).
	 * Let the kernel's authoritative idle scanner find the best CPU.
	 * scx_bpf_select_cpu_dfl handles affinity, SMT, LLC, NUMA natively.
	 * Tiered weights (tier_base) guarantee DSQ ordering — no need for
	 * custom gates to avoid the DSQ. */
	{
		bool is_idle = false;
		s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		if (is_idle) {
			u64 slice = p->scx.slice ?: quantum_ns;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					    slice, wake_flags);
			/* KICK_IDLE: wake target CPU if sleeping.
			 * CORE PARKING: during GAMING, suppress kick for migrated
			 * tasks — the CPU's idle bit is already cleared by
			 * scx_bpf_select_cpu_dfl, so the task runs when the core
			 * wakes naturally. Keeps cores in C-state for PBO headroom.
			 * Gate 1 handles 91% of GAME wakeups (prev_cpu fast path),
			 * so this Gate 3 path is mostly non-GAME tasks. */
			if (cpu != prev_cpu && sched_state != CAKE_STATE_GAMING)
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			if (stats_on) {
				struct cake_stats *s = get_local_stats();
				s->total_gate2_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
				struct cake_task_ctx __arena *tctx = get_task_ctx(p);
				if (tctx) {
					tctx->telemetry.gate_3_hits++;
					tctx->telemetry.direct_dispatch_count++;
					if (cpu != prev_cpu)
						tctx->telemetry.migration_count++;
				}
#endif
			}
			return cpu;
		}
	}

	/* ── TUNNEL: All CPUs busy — branchless fallthrough ──
	 * Zero decisions. Stage cached_now for enqueue, return prev_cpu.
	 * Tiered weights guarantee GAME [0,5120] sorts before NORMAL [8192,13312].
	 * DSQ ordering handles all priority — no preemption or kicks needed. */
	{
		u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		cpu_bss[tc_id].cached_now = scx_bpf_now();

		if (stats_on) {
			struct cake_stats *s = get_local_stats();
			s->total_gate2_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx)
				tctx->telemetry.gate_tun_hits++;
#endif
		}
	}
	return prev_cpu;
}


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

		/* MAILBOX: check-before-write. Only kick on 0→1 transition.
		 * Stays Shared in MESI if already set (no cache bounce). */
		if (!dsq_kick_needed[enq_llc]) {
			dsq_kick_needed[enq_llc] = 1;
			if (cpu_bss[enq_cpu].idle_hint)
				scx_bpf_kick_cpu(enq_cpu, SCX_KICK_IDLE);
			else
				scx_bpf_kick_cpu(enq_cpu, 0);
		}

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
		 * dsq_weight pre-computed in cake_stopping (zero MUL here). */
		u32 dsq_weight = (u32)(staged & 0xFFFFFFFF);
		u64 vtime = now_cached + dsq_weight;
		/* ASYMMETRIC STOLEN SLICE (Phase 4.0):
		 * Yielders keep 75% — cooperative tasks shouldn't be punished.
		 * Non-yielders keep 50% — forces faster CPU release for game wakeups.
		 * 200µs floor prevents micro-slicing (Rule 9). */
		/* GAME requeues keep 75% stolen slice (cooperative).
		 * Non-GAME requeues keep 50% (forces faster CPU release). */
		u8 yl_flag = (u8)(hot && hot->task_class == CAKE_CLASS_GAME);
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

		/* MAILBOX: check-before-write, 0→1 only. */
		if (!dsq_kick_needed[enq_llc]) {
			dsq_kick_needed[enq_llc] = 1;
			if (cpu_bss[enq_cpu].idle_hint)
				scx_bpf_kick_cpu(enq_cpu, SCX_KICK_IDLE);
			else
				scx_bpf_kick_cpu(enq_cpu, 0);
		}

		if (stats_on)
			enqueue_telemetry(p_reg, start_time, pre_kfunc, now_cached, stats_on, tctx_enq, enq_cpu);
		return;
	}

	/* Phase 4: weight carries tier offset — no class branching needed */
	u8 new_flow    = (staged >> STAGED_BIT_NEW_FLOW) & 1;
	u32 dsq_weight  = (u32)(staged & 0xFFFFFFFF);
	u64 slice = p_reg->scx.slice ?: quantum_ns;

	/* ═══ TIERED ORDERING: dsq_weight already has class offset from cake_stopping ═══
	 * GAME [0,5120] < NORMAL [8192,13312] < HOG [16384,21504] < BG [49152,54272]
	 * No penalty shifting, no anti-starvation hacks — tier guarantees ordering. */

	/* sleep_lag consumed in cake_stopping (local write, zero cross-core
	 * invalidation). dsq_weight in staged_vtime_bits already includes
	 * the lag credit. See stopping EEVDF LAG CREDIT comment. */

	u64 vtime = now_cached + dsq_weight;

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

	/* MAILBOX: every DSQ insert → check-before-write kick on 0→1.
	 * Read stays Shared in MESI if already set — no cache bounce.
	 * idle_hint fast path: idle CPU exists → KICK_IDLE.
	 * Fallback: self-kick(0) → TIF_NEED_RESCHED at next tick/syscall.
	 * Replaces old unconditional kick that wasted cache lines. */
	if (!dsq_kick_needed[enq_llc]) {
		dsq_kick_needed[enq_llc] = 1;
		if (cpu_bss[enq_cpu].idle_hint)
			scx_bpf_kick_cpu(enq_cpu, SCX_KICK_IDLE);
		else
			scx_bpf_kick_cpu(enq_cpu, 0);
	}

	/* GAME PREEMPTION KICK: When a GAME task enters the DSQ during
	 * GAMING state, find a CPU running a HOG or BG task and preempt it.
	 * This ensures GAME tasks don't wait in the DSQ for natural context
	 * switches when a less important task could be displaced immediately.
	 * Uses expanded is_yielder bit0: 0=not-GAME → valid preemption target.
	 * Bounded by nr_cpus (RODATA, typically 16-32). */
	if (sched_state == CAKE_STATE_GAMING &&
	    hot && hot->task_class == CAKE_CLASS_GAME) {
		/* O(1) victim finding via tzcnt on game_cpu_mask.
		 * ~game_cpu_mask has bits set for non-GAME CPUs.
		 * __builtin_ctzll = single tzcnt instruction on Zen 4 (1 cycle).
		 * Replaces O(n) linear scan through cpu_bss[]. */
		u64 non_game = ~game_cpu_mask;
		if (non_game) {
			u32 victim = __builtin_ctzll(non_game);
			if (victim < nr_cpus) {
				/* EEVDF VPROT: per-class percentage-scaled guard.
				 * Base: slice>>4 clamped [125µs, 500µs].
				 * Then scaled by victim's class priority:
				 *   NORMAL: 75% (×3>>2)  — useful work, good protection
				 *   BG:     50% (>>1)    — background noise, moderate
				 *   HOG:    25% (>>2)    — disposable compute, minimal
				 * All reads from same 64B CL of cpu_bss. */
				u32 vi = victim & (CAKE_MAX_CPUS - 1);
				u32 vprot_ns = (u32)(cpu_bss[vi].tick_slice >> 4);
				/* Branchless clamp to [125µs, 500µs] */
				vprot_ns -= (vprot_ns - 500000) & -(vprot_ns > 500000);
				vprot_ns += (125000 - vprot_ns) & -(vprot_ns < 125000);
				/* Per-class percentage scaling */
				u8 vc = cpu_bss[vi].running_class;
				if (vc == CAKE_CLASS_HOG)
					vprot_ns >>= 2;       /* 25% */
				else if (vc == CAKE_CLASS_BG)
					vprot_ns >>= 1;       /* 50% */
				else
					vprot_ns = (vprot_ns * 3) >> 2;  /* 75% (NORMAL) */
				u32 elapsed = (u32)now_cached - cpu_bss[vi].run_start;
				if (elapsed >= vprot_ns)
					scx_bpf_kick_cpu(victim, SCX_KICK_PREEMPT);
				else if (stats_on) {
					struct cake_stats *s = get_local_stats_for(enq_cpu);
					s->nr_vprot_suppressed++;
				}
			}
		}
	}

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
			/* MAILBOX CLEAR: DSQ drained. Check-before-write (Rule 11).
			 * Stays Shared if already 0 (MESI no-op on fast path). */
			if (dsq_kick_needed[my_llc]) dsq_kick_needed[my_llc] = 0;
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
			/* EEVDF TOPOLOGY: only cross-CCD steal when victim has 2+ tasks.
			 * Prevents cache-cold migration of single tasks that are better
			 * served waiting for their CCD's core to free up. Mirrors EEVDF's
			 * imbalance_pct threshold for cross-domain migration. */
			if (scx_bpf_dsq_nr_queued(victim_dsq) > 1 && scx_bpf_dsq_move_to_local(victim_dsq)) {
				/* MAILBOX CLEAR: stolen DSQ drained. */
				if (dsq_kick_needed[victim]) dsq_kick_needed[victim] = 0;
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
	 * Remote readers (select_cpu gate checks) read cpu_bss directly.
	 * ARENA_ASSOC kept for stats_on telemetry path. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

	u64 slice = p->scx.slice;

	/* CLOCK DOMAIN FIX: tick_last_run_at MUST come from scx_bpf_now(),
	 * NOT p->se.exec_start. exec_start is rq_clock_task() which subtracts
	 * IRQ + steal time. Consumers (anti-starvation clamp in cake_enqueue,
	 * Gate 2/3 idle checks in cake_select_cpu) compare against scx_bpf_now().
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

		/* Cache wake_counter to BSS for cross-CPU reads by Gate 2 SMT.
		 * Only on task change (last_pid check below gates this). */

	/* FAST PATH: Same task re-running on same CPU (~75% in gaming).
	 * is_yielder unchanged — skip 10ns get_task_hot + 2ns decode.
	 * vprot consumers tolerate 1-frame staleness on waker_boost
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
		/* EXPANDED BSS ENCODING (4-bit):
		 * bit0=GAME, bit1=not-HOG, bit2=waker_boost, bit3=BG.
		 * Enables fast preemption victim identification in cake_enqueue:
		 * kick scan checks !(is_yielder & 1) for non-GAME CPUs. */
		bss->is_yielder = ((u8)(tc == CAKE_CLASS_GAME) << 0)
				| ((u8)(tc != CAKE_CLASS_HOG) << 1)
				| (wb49 << 2)
				| ((u8)(tc == CAKE_CLASS_BG) << 3);
		/* VPROT: cache running class for cross-CPU vprot reads.
		 * Same CL as run_start/tick_slice — zero extra cost. */
		bss->running_class = tc;

		/* Cache wake_counter in BSS for Gate 2 SMT cross-CPU reads.
		 * Only fires on task change (~25%), not same-task re-runs.
		 * Null guard required: get_task_hot() can return NULL on
		 * task_storage miss (BPF verifier enforces this). */
		if (hot)
			bss->wake_freq = hot->wake_counter;

		/* O(1) GAME CPU bitmask: branchless set/clear.
		 * Plain read first — steady-state GAME re-runs skip atomics.
		 * set_mask/clear_mask use conditional arithmetic to avoid branches.
		 * Atomics only fire on task_class transitions (~1/64 stops). */
		{
			u64 bit = 1ULL << (cpu & 63);
			u64 cur = game_cpu_mask;  /* plain read, no fence */
			u64 want_set = bit & -(u64)(tc == CAKE_CLASS_GAME);
			u64 want_clear = bit & -(u64)(tc != CAKE_CLASS_GAME);
			if (want_set & ~cur)  /* need to set, bit not yet set */
				__sync_fetch_and_or(&game_cpu_mask, bit);
			if (want_clear & cur)  /* need to clear, bit currently set */
				__sync_fetch_and_and(&game_cpu_mask, ~bit);
		}

		/* CPUPERF: signal max boost for GAME, reduced for others.
		 * On amd_pstate_epp + high power: may be no-op (already at max).
		 * On other governors: front-runs ramp by 1-2ms.
		 * Check-before-write: skip kfunc if perf level unchanged.
		 * Cost: ~15ns kfunc, only on actual perf transition. */
		if (sched_state == CAKE_STATE_GAMING) {
			u32 perf = (tc == CAKE_CLASS_GAME) ? 1024 : 768;
			if (bss->cached_perf != perf) {
				bss->cached_perf = perf;
				scx_bpf_cpuperf_set(cpu, perf);
			}
		}

		/* Cluster hint: stamp tgid for COMPILATION cluster co-scheduling.
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

	/* pelt_scaled: declared here with = 0 for deferred telemetry.
	 * Computed from rt_raw (already in register) instead of cold p->se.avg CL. */
	u16 pelt_scaled = 0;

	/* Consumed runtime — hoisted for both DRR drain and vruntime cost.
	 * tick_slice (from cake_running) - remaining slice = consumed. */
	u32 rt_raw = (u32)(bss->tick_slice - p->scx.slice);
	rt_raw -= (rt_raw - (65535U << 10)) & -(rt_raw > (65535U << 10));

	/* EEVDF TOPOLOGY: capacity-scale rt_raw for P/E core correctness.
	 * E-cores deliver less compute per nanosecond — scale vruntime
	 * advance by CPU capacity so E-core tasks accumulate less cost.
	 * cpuperf_cap_table is RODATA (0-1024 scale, 1024=fastest).
	 * On SMP (all caps equal), JIT constant-folds to no-op. */
	{
		u32 cap = cpuperf_cap_table[cpu];
		if (cap > 0 && cap < 1024) {
			rt_raw = (u32)((u64)rt_raw * cap >> 10);
			if (stats_on) {
				struct cake_stats *s = get_local_stats_for(cpu);
				s->nr_capacity_scaled++;
			}
		}
	}

	/* Standalone deficit drain (DRR fairness, independent of PELT).
	 * Drains based on actual runtime delta.
	 * GAME ADVANTAGE: skip drain entirely for GAME tasks.
	 * Preserves NEW_FLOW flag → perpetual 3ms vtime head start (EEVDF half-slice).
	 * DRR fairness is irrelevant for GAME (unfair = desired).
	 * Saves 4 ALU ops per GAME stop + deficit write-back is MESI no-op. */
	u16 new_deficit;
	if (tc == CAKE_CLASS_GAME) {
		new_deficit = old_deficit;  /* preserve — skip drain */
	} else {
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

		/* AUDIO PROTECTION: audio daemons + PipeWire socket clients
		 * (mixers like goxlr-daemon, easyeffects). Promoted to GAME
		 * during GAMING for latency parity with game threads.
		 * JIT-constant: nr_audio_tgids==0 → dead-code eliminated. */
		bool cls_audio = false;
		u32 task_tgid = p->tgid;
		if (!cls_game && snap_sched_state == CAKE_STATE_GAMING &&
		    nr_audio_tgids) {
			#pragma unroll
			for (u32 i = 0; i < CAKE_MAX_AUDIO_TGIDS; i++) {
				if (i >= nr_audio_tgids)
					break;
				if (task_tgid == audio_tgids[i]) {
					cls_audio = true;
					break;
				}
			}
		}

		/* COMPOSITOR PROTECTION: Wayland compositors present every
		 * frame. During GAMING, promote to GAME so frame presentation
		 * is never blocked by compiler HOGs or BG tasks.
		 * JIT-constant: nr_compositor_tgids==0 → dead-code eliminated. */
		bool cls_compositor = false;
		if (!cls_game && !cls_audio &&
		    snap_sched_state == CAKE_STATE_GAMING &&
		    nr_compositor_tgids) {
			/* Reuse task_tgid from audio loop above */
			#pragma unroll
			for (u32 i = 0; i < CAKE_MAX_COMPOSITOR_TGIDS; i++) {
				if (i >= nr_compositor_tgids)
					break;
				if (task_tgid == compositor_tgids[i]) {
					cls_compositor = true;
					break;
				}
			}
		}

		/* SIMPLIFY: cls_squeeze + cls_gaming + !is_kthread fused into cls_penalty.
		 * 3 booleans instead of 5, 2 fewer register temporaries (Rule 36). */
		bool cls_penalty = !cls_game
			&& !(((packed >> SHIFT_FLAGS) & CAKE_FLOW_WAKER_BOOST))
			&& snap_sched_state == CAKE_STATE_GAMING
			&& !is_kthread;
		/* HOG detection via rt_raw (consumed runtime, already in register).
		 * HOG = non-game task consuming ≥ 75% of its quantum during GAMING.
		 * rt_raw and bss->tick_slice both already in registers from line 2393.
		 * Zero cold CL: replaces p->se.avg.util_avg (20-150 cycle miss). */
		u32 hog_thresh = ((u32)bss->tick_slice >> 2) * 3; /* 75% of quantum */
		bool cls_hog = cls_penalty && (rt_raw >= hog_thresh);
		bool cls_bg  = cls_penalty && !cls_hog;

		u8 new_tc = cls_game       ? CAKE_CLASS_GAME
			  : cls_audio      ? CAKE_CLASS_GAME  /* audio chain → GAME */
			  : cls_compositor ? CAKE_CLASS_GAME  /* compositor → GAME */
			  : cls_hog        ? CAKE_CLASS_HOG
			  : cls_bg         ? CAKE_CLASS_BG
			  : CAKE_CLASS_NORMAL;
		/* MESI: skip store if class unchanged (~95% stable).
		 * tc already loaded from hot->task_class — register compare. */
		if (hot->task_class != new_tc)
			hot->task_class = new_tc;
		tc = new_tc;  /* Use fresh classification for this stop */

		/* EEVDF NICE: recompute nice_shift on reclassify.
		 * p->scx.weight: nice 0 = 100, nice -20 ≈ 8876.
		 * Tier 7 = baseline. Computed once per 64 stops. */
		{
			u32 w = p->scx.weight ?: 100;
			u8 ns = (w >= 6400) ? 0 : (w >= 3200) ? 1 :
				(w >= 1600) ? 2 : (w >= 800) ? 3 :
				(w >= 400)  ? 4 : (w >= 200) ? 5 :
				(w >= 130)  ? 6 : (w >= 80)  ? 7 :
				(w >= 50)   ? 8 : (w >= 25)  ? 9 :
				(w >= 12)   ? 10 : (w >= 6) ? 11 : 12;
			if (hot->nice_shift != ns)
				hot->nice_shift = ns;
		}
	}

	/* Phase 2: Derive is_game/is_hog/bg_noise from task_class.
	 * Single byte read replaces 3 BSS reads + 6 comparisons. */
	/* R2: is_game inlined — tc already in register, 1-cycle compare (Rule 36). */

	/* P3-2: nvcsw tracking — stats-gated (telemetry only). */
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
	 * Anti-starvation clamp in cake_enqueue reads this field.
	 * CRITICAL: save prev value BEFORE overwriting — EWMA needs the delta. */
	u32 prev_run_at = hot->last_run_at;
	hot->last_run_at = bss->run_start;

	/* WAKEUP FREQUENCY EWMA: measures how often this task wakes.
	 * Higher wake_counter = more latency-critical (input > render > bg).
	 * 75/25 EWMA via shifts: new = (old * 3 + sample) >> 2.
	 * Log2-reciprocal approximation: sample ≈ (1<<20) >> clz(interval).
	 * __builtin_clz compiles to lzcnt (1 cycle Zen 4), replaces div (20-40 cycles).
	 * ORDERING: must read last_run_at BEFORE writing it above. */
	{
		u32 interval = (u32)(bss->run_start - prev_run_at) | 1;
		/* floor(log2(interval)) via lzcnt (1 cycle Zen 4). */
		u32 log2_interval = 31 - (u32)__builtin_clz(interval);
		/* Reciprocal: sample ≈ 2^(20-log2). Branchless clamp to [0,1023]. */
		u32 shift = 20 - log2_interval;
		shift &= -(u32)(shift < 20);  /* underflow guard: if log2 > 20 → 0 */
		u16 sample = (u16)(((1U << (shift & 15)) - 1) & 0x3FF);
		hot->wake_counter = (u16)(((u32)hot->wake_counter * 3 + sample) >> 2);
	}

	/* Phase 8: classify stopwatch end — reuses deferred_ts_start */
	u64 classify_end = 0;
	if (stats_on && deferred_ts_start) {
		classify_end = scx_bpf_now();
	}

	/* ═══ 5. WARM CPU HISTORY — migration-gated ring shift ═══
	 * Only fires on migration (cpu != warm_cpus[0]), ~9% of stops.
	 * 91% fast path: single comparison, zero writes.
	 * Feeds warm cache probes in cake_select_cpu. */

	/* Phase 8: warm history stopwatch — reuses classify_end as start */

	/* CHECK-BEFORE-WORK: Hoist get_task_ctx before runnable block.
	 * Eliminates duplicate 29ns arena TLB walk (was called at both
	 * line A inside runnable and line B outside it). */
	struct cake_task_ctx __arena * __maybe_unused tctx_stop = NULL;
	if (stats_on && classify_end)
		tctx_stop = get_task_ctx(p);

	/* RUNNABLE GATE: Only pack staged + warm_cpus + slice if task stays
	 * runnable. Sleeping tasks won't be enqueued — skip ~5ns of work.
	 * (~50% of stops are non-runnable in gaming.)
	 * EEVDF LAG: non-runnable → store sleep_lag for next wakeup.
	 * The lag = rt_cost of this run, giving the task credit for
	 * having voluntarily yielded. On wake, lag reduces dsq_weight
	 * so yielders (game threads at vsync, audio callbacks) dispatch
	 * ahead of continuous CPU consumers. */
	if (!runnable) {
		u32 lag_raw = rt_raw >> 10;
		u32 lag_cap = rt_cost_cap[tc & 3];
		lag_raw -= (lag_raw - lag_cap) & -(lag_raw > lag_cap);
		/* EEVDF NICE: scale lag by nice_shift (same as rt_cost).
		 * High-priority tasks get MORE lag credit (right-shift = less
		 * cost reduction → larger raw lag preserved as credit).
		 * Low-priority tasks get less credit. L1-hot read. */
		/* Branchless nice-shift: 4 ALU insns vs 2 cmp + 2 branch.
		 * right=0 when ns>=7, left=0 when ns<=7. */
		{
			u32 ns = hot->nice_shift;
			lag_raw = (lag_raw >> ((7 - ns) & 7)) << ((ns - 7) & 7);
		}
		hot->sleep_lag = (u16)(lag_raw & 0xFFFF);
	}
	if (runnable) {
		/* rt_raw already computed (line 2393): actual consumed runtime.
		 * Replaces cold p->se.avg.util_avg CL read (20-150 cycle miss).
		 * >> 10 scales to same ~0-5120 range as old pelt_scaled. */
		pelt_scaled = (u16)(rt_raw >> 10);

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

		/* pelt_scaled already computed above */
		u32 home_cpu_staged = (u32)(hot->warm_cpus[1] & 0xFF);

		/* ── TIERED WEIGHT ──
		 * RULE: lower weight → lower vtime → dispatches FIRST.
		 * Non-overlapping ranges guarantee class ordering:
		 *   GAME [0,5120] < NORMAL [8192,13312] < HOG [16384,21504] < BG [49152,54272]
		 *
		 * GAME DURING GAMING: invert PELT so render pipeline dispatches first.
		 * Higher PELT = more CPU work = more critical for frame delivery.
		 *   RenderThread (PELT 83) → weight ~824 < BG Worker (PELT 20) → ~879
		 * NON-GAMING or non-GAME: standard DRR fairness (low PELT = dispatch first).
		 *
		 * wake_counter bonus: high wakeup rate → lower weight → dispatch first.
		 * Applies in both modes as tiebreaker. */
		u32 dsq_weight;
		if (tc == CAKE_CLASS_GAME && sched_state == CAKE_STATE_GAMING) {
			/* Invert: high wake frequency gets LOW weight (dispatch first).
			 * wake_counter is 0-1023 EWMA (same range as PELT).
			 * RenderThread wakes ~500x/sec (high), BG worker ~5x/sec (low).
			 * Replaces cold p->se.avg.util_avg: wake_counter is hot CL0.
			 * wake_counter bonus MUST be clamped — if wake_counter is near
			 * 1024 (dsq_weight ~1), subtraction underflows → STALL. */
			dsq_weight = 1024 - ((u32)hot->wake_counter & 0x3FF);
			u32 wake_bonus = (hot->wake_counter >> 3) & 0x7F;
			dsq_weight -= wake_bonus & -(dsq_weight > wake_bonus);
		} else {
			dsq_weight = tier_base[tc & 3] + pelt_scaled;
			if (tc == CAKE_CLASS_GAME) {
				u32 wake_bonus = (hot->wake_counter >> 3) & 0x7F;
				dsq_weight -= wake_bonus & -(dsq_weight > wake_bonus);
			}
		}
		/* GAMING UNFAIRNESS: double vtime penalty for HOG/BG during GAMING.
		 * Widens DSQ gap — game tasks guaranteed front-of-queue.
		 * HOG: 16384→32768, BG: 49152→98304. NORMAL/GAME unaffected. */
		if (sched_state == CAKE_STATE_GAMING && tc >= CAKE_CLASS_HOG)
			dsq_weight += tier_base[tc & 3];

		/* VRUNTIME COST: running is expensive. ~0.1% of consumed runtime
		 * (>>10) added to dsq_weight. Heavy consumers sort later within
		 * their bucket. Provides meaningful differentiation:
		 *   50µs audio    → rt_cost ~48  (front of bucket)
		 *   100µs present → rt_cost ~97  (near front)
		 *   8ms render    → rt_cost ~7812 → clamped to 2048 (back)
		 *   250µs compiler→ rt_cost ~244  (mid-bucket)
		 * Clamped to inter-bucket gap so ordering is always preserved.
		 * 5 cycles: 1 shift + 1 load + 2 clamp + 1 add. */
		{
			u32 rt_cost = rt_raw >> 10;
			u32 cap = rt_cost_cap[tc & 3];
			rt_cost -= (rt_cost - cap) & -(rt_cost > cap);

			/* EEVDF NICE SCALING: shift-based, division-free.
			 * nice_shift is precomputed at init/reclassify.
			 * Same CL as task_class → L1-hot, zero cold reads.
			 * Tier 7 = nice 0 baseline (no shift).
			 * <7: high-priority → right-shift (less cost)
			 * >7: low-priority → left-shift (more cost)
			 * 95%+ tasks are nice 0 → branch predicted not-taken.
			 * Cost: 1 byte load (free) + 1 shift = ~2 cycles. */
			/* Branchless nice-shift: single expression, no branches. */
			{
				u32 ns = hot->nice_shift;
				rt_cost = (rt_cost >> ((7 - ns) & 7)) << ((ns - 7) & 7);
			}

			dsq_weight += rt_cost;
		}

		/* EEVDF LAG CREDIT (MESI FIX): apply sleep_lag to dsq_weight
		 * here in stopping (local CPU) instead of cake_enqueue.
		 * Enqueue runs on the WAKER's CPU — writing hot->sleep_lag=0
		 * there would invalidate this CL on the task's home CPU.
		 * By consuming sleep_lag here, all hot-> writes stay local.
		 * Yielders (game threads at vsync, audio) dispatch ahead of
		 * continuous consumers by subtracting their lag credit. */
		if (hot->sleep_lag) {
			u32 lag = (u32)hot->sleep_lag;
			dsq_weight -= lag & -(dsq_weight > lag);
			hot->sleep_lag = 0;  /* consumed — local write, zero invalidation */
		}

		/* TUNNEL: task_class → BSS pid_class_cache for Gate 2.
		 * Hoisted from both branches — identical write in GAME and non-GAME. */
		pid_class_cache[p->pid & (PID_CLASS_CACHE_SIZE - 1)] = (u8)tc;

		if (tc == CAKE_CLASS_GAME) {
			/* GAMING: 2x quantum ceiling for GAME tasks.
			 * Since GAME tasks are yielders (voluntary yield at
			 * vsync/frame boundaries), they'll never use 100ms.
			 * Higher ceiling prevents kernel preemption before
			 * their natural yield point. */
			u64 ceiling = quantum_ceiling_ns;
			if (sched_state == CAKE_STATE_GAMING)
				ceiling <<= 1;
			u64 slice = yield_gated_quantum_ns(pelt_scaled,
				true, ceiling);
			p->scx.slice = slice;
			hot->staged_vtime_bits = (1ULL << STAGED_BIT_VALID) |
					    ((u64)home_cpu_staged << STAGED_SHIFT_HOME) |
					    ((u64)nf << STAGED_BIT_NEW_FLOW) |
					    (u64)dsq_weight;
		} else {
			u64 ceiling = quantum_ceiling_ns;
			bool yielder = !!wb;
			u64 base_slice = yield_gated_quantum_ns(pelt_scaled,
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
					    (u64)dsq_weight;
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
				u64 expected_ns = (u64)pelt_scaled * 1000ULL;
				u64 d = dur - expected_ns;
				u64 mask = -(u64)(dur < expected_ns);
				u64 jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;

				/* Branchless max */
				u16 old_max_rt = tctx->telemetry.max_runtime_us;
				tctx->telemetry.max_runtime_us = old_max_rt + ((pelt_scaled - old_max_rt) & -(u16)(pelt_scaled > old_max_rt));

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
				tctx->telemetry.cpu_run_count[cpu]++;

				/* CL0 → arena sync: iter reads these from tctx, not hot.
				 * Values computed in reclassify path above (every 64th stop).
				 * Check-before-write avoids cache invalidation on unchanged fields. */
				if (tctx->nice_shift != hot->nice_shift)
					tctx->nice_shift = hot->nice_shift;
				if (tctx->sleep_lag != hot->sleep_lag)
					tctx->sleep_lag = hot->sleep_lag;
				if (tctx->task_class != hot->task_class)
					tctx->task_class = hot->task_class;
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
	 * enqueue classification, tunnel) reads tctx->ppid unconditionally. Must be outside
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
		hot->wake_counter      = 0;
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
		hot->nice_shift        = 7;  /* baseline nice 0 */
		hot->sleep_lag         = 0;
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
	rec.nice_shift     = tctx->nice_shift;
	rec.sleep_lag      = tctx->sleep_lag;

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
