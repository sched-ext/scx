// SPDX-License-Identifier: GPL-2.0
/* scx_cake — low-latency CAKE-inspired CPU scheduler.
 *
 * Core design:
 *   - direct dispatch when an idle CPU is available
 *   - per-LLC vtime fallback queues when no idle CPU is available
 *   - topology-aware CPU selection (V-Cache, hybrid P/E, SMT siblings)
 *   - lean hot paths with task-local vtime accounting
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#ifndef CAKE_NEEDS_ARENA
#define CAKE_NEEDS_ARENA 0
#endif
#if defined(CAKE_RELEASE) || !CAKE_NEEDS_ARENA
#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif
#else
#include <lib/arena_map.h> /* BPF_MAP_TYPE_ARENA definition */
#include <lib/sdt_task.h> /* scx_task_data, scx_task_alloc, scx_task_free */
#endif
#include "intf.h"
#include "bpf_compat.h"

/* Local CPU DSQs remain non-stealable; the default LLC-vtime policy uses
 * explicit per-LLC DSQs as the fallback arbiter instead. */
#define CAKE_LOCAL_CPU_ONLY 1

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA Config.
 * Release builds bake the floor-path knobs into immediates. Debug builds keep
 * volatile RODATA for runtime A/B work and TUI captures. */
#define CAKE_BUSY_WAKE_KICK_POLICY 0U
#define CAKE_BUSY_WAKE_KICK_PREEMPT 1U
#define CAKE_BUSY_WAKE_KICK_IDLE 2U
#ifndef CAKE_QUANTUM_NS
#define CAKE_QUANTUM_NS CAKE_DEFAULT_QUANTUM_NS
#endif
#ifndef CAKE_QUEUE_POLICY_VALUE
#define CAKE_QUEUE_POLICY_VALUE CAKE_QUEUE_POLICY_LLC_VTIME
#endif
#ifndef CAKE_STORM_GUARD_VALUE
#define CAKE_STORM_GUARD_VALUE CAKE_STORM_GUARD_OFF
#endif
#ifndef CAKE_BUSY_WAKE_KICK_VALUE
#define CAKE_BUSY_WAKE_KICK_VALUE CAKE_BUSY_WAKE_KICK_POLICY
#endif
#ifdef CAKE_RELEASE
const u64 quantum_ns = CAKE_QUANTUM_NS; /* Base time slice per dispatch */
#define CAKE_QUEUE_POLICY CAKE_QUEUE_POLICY_VALUE
#define CAKE_STORM_GUARD_MODE CAKE_STORM_GUARD_VALUE
#else
const volatile u64 quantum_ns	    = CAKE_DEFAULT_QUANTUM_NS;
const volatile u32 queue_policy	    = CAKE_QUEUE_POLICY_LLC_VTIME;
const volatile u32 storm_guard_mode = CAKE_STORM_GUARD_OFF;
#define CAKE_QUEUE_POLICY (*(volatile const u32 *)&queue_policy)
#define CAKE_STORM_GUARD_MODE (*(volatile const u32 *)&storm_guard_mode)
#endif
#ifndef CAKE_LOCALITY_EXPERIMENTS
#define CAKE_LOCALITY_EXPERIMENTS 0
#endif
#ifndef CAKE_RELEASE
const volatile bool enable_learned_locality    = false;
const volatile bool enable_wake_chain_locality = false;
const volatile u32  busy_wake_kick_mode	       = 0;
#endif
#if defined(CAKE_RELEASE)
#define CAKE_LEARNED_LOCALITY_ENABLED 0
#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0
#define CAKE_BUSY_WAKE_KICK_MODE CAKE_BUSY_WAKE_KICK_VALUE
#elif !CAKE_LOCALITY_EXPERIMENTS
#define CAKE_LEARNED_LOCALITY_ENABLED 0
#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0
#define CAKE_BUSY_WAKE_KICK_MODE CAKE_BUSY_WAKE_KICK_POLICY
#else
#define CAKE_LEARNED_LOCALITY_ENABLED \
	(*(volatile const bool *)&enable_learned_locality)
#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED \
	(*(volatile const bool *)&enable_wake_chain_locality)
#define CAKE_BUSY_WAKE_KICK_MODE (*(volatile const u32 *)&busy_wake_kick_mode)
#endif
#define cake_task_cpu(p) ((p)->thread_info.cpu)
/* new_flow_bonus_ns REMOVED: zero BPF readers. */

/* Dead RODATA removed:
 * aq_yielder_ceiling_ns, aq_min_ns — zero BPF readers.
 * preempt_vip_ns, preempt_yielder_ns — zero BPF readers.
 * rt_cost_cap[4], preempt_thresh_ns[4] — zero BPF readers.
 * All were remnants of the old AQ/preemption system. */

/* Legacy class gap table retained for debug/documentation only.
 * The release scheduler no longer injects these offsets into dsq_vtime. */
const u32 legacy_tier_base[4] = { 250000000, 0, 750000000, 500000000 };

/* Weight-aware vtime accounting:
 * the hot path reads p->scx.weight directly and applies an additive
 * adjustment instead of consulting a reciprocal lookup table. */

/* ═══ Telemetry Compile-Time Gates ═══
 *
 * RELEASE (CAKE_RELEASE=1, set by build.rs --release):
 *   CAKE_STATS_ENABLED = 0 (compile-time constant). Clang eliminates
 *   ALL stats/telemetry branches — zero instructions in production.
 *
 * DEBUG (default):
 *   CAKE_STATS_ENABLED reads a volatile RODATA bool. Loader patches it
 *   to true when --verbose is passed. JIT folds after patching. */
#ifndef CAKE_HOT_TELEMETRY
#define CAKE_HOT_TELEMETRY 0
#endif
/* Release stays on the lean production path. Debug builds compile the
 * experiment-aware path so runtime A/B knobs work without a rebuild. */
#if defined(CAKE_RELEASE) || !CAKE_LOCALITY_EXPERIMENTS
#define CAKE_LEAN_SCHED 1
#else
#define CAKE_LEAN_SCHED 0
#endif

#ifdef CAKE_RELEASE
#define CAKE_STATS_ENABLED 0
#define CAKE_STATS_ACTIVE 0
#define CAKE_PATH_STATS_ACTIVE 0
#else
const bool enable_stats __attribute__((used)) = false;
#if !defined(CAKE_RELEASE) && CAKE_HOT_TELEMETRY
/* Debug hot telemetry is compiled in as the default analytics path. Keeping it
 * behind a volatile runtime bool makes every hot callback carry both the
 * measured and unmeasured branch, which is exactly the stack/register pressure
 * we are trying to remove. Release still compiles this whole surface out. */
#define CAKE_STATS_ENABLED 1
#define CAKE_STATS_ACTIVE 1
#define CAKE_PATH_STATS_ACTIVE 1
#else
#define CAKE_STATS_ENABLED 0
#define CAKE_STATS_ACTIVE 0
#define CAKE_PATH_STATS_ACTIVE (*(volatile const bool *)&enable_stats)
#endif
#endif
#if defined(CAKE_RELEASE) || CAKE_HOT_TELEMETRY
#define CAKE_ACCEL_PATH 1
#else
#define CAKE_ACCEL_PATH 0
#endif
/* enable_dvfs REMOVED: dead — zero BPF readers. */

#define CAKE_SLOW_CALLBACK_NS 10000ULL
#define CAKE_SLOW_WAKEWAIT_NS 100000ULL
#define CAKE_QUICK_WAKE_KICK_NS 200000ULL
#define CAKE_TRACKED_WAKEWAIT_MAX_NS 5000000ULL
#define CAKE_EVT_TARGET_MISS_NS 250000ULL
#define CAKE_EVT_KICK_SLOW_NS 500000ULL
#define CAKE_EVT_DISPATCH_GAP_NS 1000000ULL
#define CAKE_STEER_UTIL_MIN 64U
#define CAKE_HOME_SCORE_MAX 15U
#define CAKE_CPU_PRESSURE_SAMPLE_SHIFT 13U
#define CAKE_CPU_PRESSURE_DECAY_SHIFT 2U
#define CAKE_CPU_PRESSURE_IDLE_DECAY_SHIFT 1U
#define CAKE_CPU_PRESSURE_SAMPLE_MAX 63U
#define CAKE_CPU_PRESSURE_SPILL_MIN 24U
#define CAKE_CPU_PRESSURE_SPILL_DELTA 12U
#define CAKE_CPU_PRESSURE_HOME_SCORE_MIN 8U
#define CAKE_PRIMARY_SCAN_CREDIT_PERIOD 8U
#define CAKE_HOT_PRIMARY_SCAN_CREDIT_PERIOD 8U
#define CAKE_HOT_PRIMARY_SCAN_UTIL_MAX 256U
#define CAKE_HOT_PRIMARY_SCAN_MIN_RUNS 128U
#define CAKE_HOT_PRIMARY_SCAN_AVG_RUN_NS 50000ULL
#define CAKE_BUSY_OWNER_SHORT_RUN_NS 100000U
#define CAKE_BUSY_OWNER_MIN_RUNS 32U
#define CAKE_OWNER_RUNTIME_AVG_SHIFT 3U
#define CAKE_CACHE_THROUGHPUT_MIN_RUNS 16U
#define CAKE_CACHE_THROUGHPUT_FULL_MIN_RUNS 32U
#define CAKE_CACHE_THROUGHPUT_SLICE_SHIFT 1U
#define CAKE_CACHE_THROUGHPUT_FULL_SLICE_SHIFT 2U
#define CAKE_CACHE_THROUGHPUT_SHIFT_LUT 0x5555555544332210ULL
#define CAKE_THROUGHPUT_FAIR_DISPATCH_BUDGET 2U
#define CAKE_BUSY_WAKE_SHRINK_MIN_NS 500000ULL
#define CAKE_TP_DEC_PULL_MASK 0x0fULL
#define CAKE_TP_DEC_FAIR_HINT (1ULL << 4)
#define CAKE_TP_DEC_OVERFLOW_HINT (1ULL << 5)
#define CAKE_TP_DEC_DISPATCH_MASK 0x3fULL
#define CAKE_TP_DEC_RUNTIME_SCALE_SHIFT 14U
#define CAKE_TP_DEC_RUNTIME_BUCKET_SHIFT 8U
#define CAKE_TP_DEC_RUN_BUCKET_SHIFT 16U
#define CAKE_TP_DEC_BUCKET_MASK 0xffULL
#define CAKE_TP_DEC_SAT_CACHE_MEM (1ULL << 24)
#define CAKE_TP_DEC_OWNER_MASK \
	((CAKE_TP_DEC_BUCKET_MASK << CAKE_TP_DEC_RUNTIME_BUCKET_SHIFT) | \
	 (CAKE_TP_DEC_BUCKET_MASK << CAKE_TP_DEC_RUN_BUCKET_SHIFT) | \
	 CAKE_TP_DEC_SAT_CACHE_MEM)
#define CAKE_WAKE_CHAIN_POLICY_SCORE_MIN 8U
#define CAKE_WAKE_CHAIN_HOME_SCORE_MIN 4U
#define CAKE_WAKE_CHAIN_SCORE_MAX 15U
#define CAKE_WAKE_CHAIN_SHORT_RUN_NS 125000U
#define CAKE_WAKE_CHAIN_LONG_RUN_NS 500000U
#define CAKE_WAKE_CHAIN_CREDIT_PERIOD 8U
#define CAKE_PRIMARY_SCAN_CREDIT_MASK 0x0FU
#define CAKE_WAKE_CHAIN_CREDIT_SHIFT 4U
#define CAKE_WAKE_CHAIN_CREDIT_MASK 0x0FU
#define CAKE_SEL_GATE2 0x0001U
#define CAKE_SEL_HOME 0x0002U
#define CAKE_SEL_HOME_CORE 0x0004U
#define CAKE_SEL_PRESSURE_CORE 0x0008U
#define CAKE_SEL_PREV_PRIMARY 0x0010U
#define CAKE_SEL_SCAN_PRIMARY 0x0020U
#define CAKE_SEL_PRIMARY_SCAN_ATTEMPTED 0x0040U
#define CAKE_SEL_PRIMARY_SCAN_GUARDED 0x0080U
#define CAKE_SEL_HOT_PRIMARY_SCAN_GUARDED 0x0100U
#define CAKE_SEL_WAKE_CHAIN_GUARDED 0x0200U
#define CAKE_SEL_WAKE_CHAIN_CREDIT_USED 0x0400U
#define CAKE_SEL_SCOREBOARD_PREV 0x0800U
#define CAKE_SEL_SCOREBOARD_SCAN 0x1000U
#define CAKE_FAST_PROBE_SLOTS 4U
#define CAKE_CONF_SELECT_EARLY_SHIFT 0U
#define CAKE_CONF_SELECT_ROW4_SHIFT 4U
#define CAKE_CONF_CLAIM_HEALTH_SHIFT 8U
#define CAKE_CONF_DISPATCH_EMPTY_SHIFT 12U
#define CAKE_CONF_KICK_SHAPE_SHIFT 20U
#define CAKE_CONF_PULL_SHAPE_SHIFT 24U
#define CAKE_CONF_ROUTE_SHIFT 28U
#define CAKE_CONF_ROUTE_KIND_SHIFT 32U
#define CAKE_CONF_ROUTE_AUDIT_SHIFT 36U
#define CAKE_CONF_PULL_AUDIT_SHIFT 40U
#define CAKE_CONF_ACCOUNT_AUDIT_SHIFT 44U
#define CAKE_CONF_FLOOR_GEAR_SHIFT 48U
#define CAKE_CONF_STATUS_TRUST_SHIFT 52U
#define CAKE_CONF_OWNER_STABLE_SHIFT 56U
#define CAKE_CONF_LOAD_SHOCK_SHIFT 60U
#define CAKE_CONF_NIBBLE_MASK 0xFULL
#define CAKE_CONF_INIT 8U
#define CAKE_CONF_HIGH 12U
#define CAKE_ROUTE_AUDIT_PERIOD 8U
#define CAKE_ROUTE_AUDIT_MASK (CAKE_ROUTE_AUDIT_PERIOD - 1U)
#define CAKE_PULL_AUDIT_PERIOD 8U
#define CAKE_PULL_AUDIT_MASK (CAKE_PULL_AUDIT_PERIOD - 1U)
#define CAKE_ACCOUNT_RELAX_AUDIT_PERIOD 4U
#define CAKE_ACCOUNT_RELAX_AUDIT_MASK (CAKE_ACCOUNT_RELAX_AUDIT_PERIOD - 1U)
#define CAKE_ACCOUNT_RELAX_MIN_RUNS 32U
#define CAKE_FLOOR_GEAR_RECOVERY 0U
#define CAKE_FLOOR_GEAR_AUDIT 1U
#define CAKE_FLOOR_GEAR_NARROW 2U
#define CAKE_FLOOR_GEAR_FLOOR 3U
#define CAKE_ROUTE_NONE 0U
#define CAKE_ROUTE_PREV 1U
#define CAKE_ROUTE_SLOT0 2U
#define CAKE_ROUTE_SLOT1 3U
#define CAKE_ROUTE_SLOT2 4U
#define CAKE_ROUTE_SLOT3 5U
#define CAKE_ROUTE_TUNNEL 6U
#define CAKE_ROUTE_PREDICT_NONE -1
#define CAKE_ROUTE_PREDICT_TUNNEL -2
#define CAKE_ROUTE_PREDICT_TRUST_MISS -3
#define CAKE_KICK_SHAPE_NONE 0U
#define CAKE_KICK_SHAPE_IDLE 1U
#define CAKE_KICK_SHAPE_PREEMPT 2U
#define CAKE_PULL_SHAPE_PULL 0U
#define CAKE_PULL_SHAPE_PROBE 1U
#define CAKE_PULL_SHAPE_SKIP 2U
#define CAKE_SELECT_CHOICE(path, reason) \
	((u16)((((u16)(reason)) << 8) | ((u16)(path))))
#define CAKE_SELECT_CHOICE_PATH(choice) ((u8)((choice) & 0xffU))
#define CAKE_SELECT_CHOICE_REASON(choice) ((u8)(((choice) >> 8) & 0xffU))

/* Topology config - JIT eliminates unused SMT steering when nr_cpus <= nr_phys_cpus.
 * has_hybrid removed: Rust loader pre-fills cpu_sibling_map for ALL topologies
 * via scx_utils::Topology::sibling_cpus(). No runtime branching needed. */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const volatile u32 nr_llcs = 1;
const volatile u32 nr_cpus =
	1; /* Set by loader. 1 = safe fallback — makes loader failure obvious. */
/* nr_phys_cpus REMOVED: zero BPF readers. */
const volatile u32 cpu_llc_id[CAKE_MAX_CPUS]				= {};
const volatile u8  cpu_core_id[CAKE_MAX_CPUS]				= {};
const volatile u64 cpu_meta[CAKE_MAX_CPUS]				= {};
const volatile u64 cpu_llc_dsq[CAKE_MAX_CPUS]				= {};
const volatile u16 cpu_fast_probe[CAKE_MAX_CPUS][CAKE_FAST_PROBE_SLOTS] = {};

#define CAKE_CPU_META_SIBLING_MASK 0xffffULL
#define CAKE_CPU_META_PRIMARY_SHIFT 16U
#define CAKE_CPU_META_LLC_SHIFT 32U
#define CAKE_CPU_META_CORE_SHIFT 40U
#define CAKE_CPU_META_PRIMARY_FLAG (1ULL << 48)
#define CAKE_CPU_META_SMT_FLAG (1ULL << 49)

/* Performance-ordered CPU scan arrays — HYBRID ONLY.
 * Compiled out on homogeneous AMD SMP (zero RODATA footprint).
 * cpus_fast_to_slow: high-performance-first scan order.
 * cpus_slow_to_fast: efficiency-first scan order. */
#ifdef CAKE_HAS_HYBRID
const cake_cpu_id_t cpus_fast_to_slow[CAKE_MAX_CPUS] = {};
const cake_cpu_id_t cpus_slow_to_fast[CAKE_MAX_CPUS] = {};
#endif

/* Topological O(1) Arrays — populated by loader */
const volatile u64 llc_cpu_mask[CAKE_MAX_LLCS] = {};
/* core_cpu_mask[] REMOVED: zero BPF readers. */
const volatile cake_cpu_id_t cpu_sibling_map[CAKE_MAX_CPUS] = {};
const volatile u8	     cpu_thread_bit[CAKE_MAX_CPUS]  = {};

/* CAKE_CPU_MASK_WORDS defined in intf.h with ceiling division.
 * At 16 CPUs: 1 word.  At 64: 1.  At 512: 8. */
#if CAKE_MAX_CPUS <= 64
#define CAKE_SCOREBOARD_SUMMARY 1
#else
#define CAKE_SCOREBOARD_SUMMARY 0
#endif

/* Heterogeneous Routing Masks — HYBRID ONLY.
 * Compiled out on homogeneous AMD SMP (zero mask RODATA). */
#ifdef CAKE_HAS_HYBRID
const u64 big_core_phys_mask[CAKE_CPU_MASK_WORDS] = {};
const u64 big_core_smt_mask[CAKE_CPU_MASK_WORDS]  = {};
const u64 little_core_mask[CAKE_CPU_MASK_WORDS]	  = {};
#endif
/* vcache_llc_mask[] REMOVED: zero BPF readers (Rust TUI reads topology directly). */
/* has_vcache REMOVED: zero BPF readers (Rust TUI reads topology directly). */
/* Preferred LLC steering and victim-scan tables were removed when Cake moved
 * to per-CPU local-first runnable ownership. */
#ifdef CAKE_HAS_HYBRID
const bool has_hybrid_cores = false; /* Set by loader — gate for Gate 2 scan */
#endif
/* has_cpuperf_control REMOVED: the scheduler no longer drives cpuperf
 * scaling from BPF. */

/* brain_class_cache[] REMOVED: 131KB BSS array, hydrated by Rust every
 * poll cycle, but had zero BPF readers. */

/* ═══ Additive Fairness Model ═══
 * Replaces the old reciprocal table with a direct adjustment derived from
 * p->scx.weight:
 *
 *   vtime += runtime + (100 - weight) * 20480
 *
 * This removes the per-task reciprocal cache and the runtime divide it
 * existed to avoid. Clang may still strength-reduce the shift/add sequence
 * into a multiply in generated BPF, so the source should not be read as a
 * guarantee of "no multiply" in the final object.
 *
 * For nice-0 (weight=100), the adjustment is zero. Lower-weight tasks
 * accumulate vtime faster and therefore run later within a bucket.
 *
 * vtime_mult_cache[] DELETED: -4KB BSS, -64 cache lines. */

/* telemetry.bpf.h owns debug BSS, stats accessors, and record helpers.
 * It depends on CAKE_STATS_ACTIVE plus topology RODATA declared above. */
#include "telemetry.bpf.h"

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
#if CAKE_NEEDS_ARENA
#define ARENA_ASSOC() asm volatile("" : : "r"(&arena))
#else
#define ARENA_ASSOC() \
	do {          \
	} while (0)
#endif

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Per-LLC DSQs with vtime-ordered priority.
 * Each LLC gets one shared DSQ keyed by p->scx.dsq_vtime.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */

/* vtime_now REMOVED: replaced by owner-published cpu_frontier lanes.
 * The global was written by every CPU on every context switch,
 * causing 15-core MESI invalidation storms. */

/* ═══ Per-CPU BSS (4KB-aligned per entry) ═══
 * Stores per-CPU scheduling state: run timestamps, idle hints,
 * owner policy, and dispatch bookkeeping.
 *
 * 4KB alignment isolates each CPU's state onto its own page-sized region.
 * At CAKE_MAX_CPUS=16: 64KB total. Untouched entries stay zero-page COW.
 *
 * Write pattern: cake_running writes, cake_stopping reads (same CPU).
 * Release wake placement reads cpu_status/cpu_frontier instead of this
 * private BSS object so remote CPUs don't touch local bookkeeping lines. */
struct cake_cpu_bss	 cpu_bss[CAKE_MAX_CPUS];
struct cake_cpu_status	 cpu_status[CAKE_MAX_CPUS];
#if CAKE_SCOREBOARD_SUMMARY
struct cake_scoreboard_summary scoreboard_summary[CAKE_MAX_LLCS];
#endif
struct cake_cpu_frontier cpu_frontier[CAKE_MAX_CPUS];
struct cake_throughput_lane throughput_lane[CAKE_MAX_CPUS];
struct cake_trust_user	 trust_user[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(64)));
struct cake_trust_bpf trust_bpf[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(64)));

static __always_inline u8 cake_status_owner_class(u64 flags)
{
	return (u8)((flags >> CAKE_CPU_STATUS_OWNER_SHIFT) &
		    CAKE_CPU_STATUS_OWNER_MASK);
}

static __always_inline u8 cake_status_owner_pressure(u64 flags)
{
	return (u8)((flags >> CAKE_CPU_STATUS_OWNER_SHIFT) & 0xffULL);
}

static __always_inline u8 cake_status_epoch(u64 flags)
{
	return (u8)((flags >> CAKE_CPU_STATUS_EPOCH_SHIFT) &
		    CAKE_CPU_STATUS_EPOCH_MASK);
}

static __always_inline u8 cake_status_next_epoch(u64 flags)
{
	return (cake_status_epoch(flags) + 1U) & (u8)CAKE_CPU_STATUS_EPOCH_MASK;
}

static __always_inline u64 cake_status_next_epoch_field(u64 flags)
{
	return (flags + (1ULL << CAKE_CPU_STATUS_EPOCH_SHIFT)) &
	       (CAKE_CPU_STATUS_EPOCH_MASK << CAKE_CPU_STATUS_EPOCH_SHIFT);
}

static __always_inline u64 cake_status_bump_epoch(u64 flags)
{
	u64 mask = CAKE_CPU_STATUS_EPOCH_MASK << CAKE_CPU_STATUS_EPOCH_SHIFT;

	return (flags & ~mask) | cake_status_next_epoch_field(flags);
}

static __always_inline bool cake_status_same_visible_state(u64 a, u64 b)
{
	u64 epoch_mask = CAKE_CPU_STATUS_EPOCH_MASK << CAKE_CPU_STATUS_EPOCH_SHIFT;

	return (a & ~epoch_mask) == (b & ~epoch_mask);
}

static __always_inline u8 cake_owner_latency_class(u8 owner_class)
{
	return (u8)((0x32110ULL >> ((owner_class & 7U) * 4U)) & 0xfU);
}

static __always_inline u64 cake_make_cpu_status(bool idle, u8 owner_class,
						u8 pressure, u8 latency_class,
						u8 epoch)
{
	u64 flags = (((u64)owner_class & CAKE_CPU_STATUS_OWNER_MASK)
		     << CAKE_CPU_STATUS_OWNER_SHIFT) |
		    (((u64)pressure & CAKE_CPU_STATUS_PRESS_MASK)
		     << CAKE_CPU_STATUS_PRESS_SHIFT) |
		    (((u64)epoch & CAKE_CPU_STATUS_EPOCH_MASK)
		     << CAKE_CPU_STATUS_EPOCH_SHIFT) |
		    (((u64)latency_class & CAKE_CPU_STATUS_LATENCY_MASK)
		     << CAKE_CPU_STATUS_LATENCY_SHIFT);
	u64 idle_mask = -(u64)idle;
	u64 heavy = (u64)((owner_class >= CAKE_CPU_OWNER_FRAME) &
			  (pressure >= CAKE_CPU_PRESSURE_HIGH));

	flags |= (idle_mask &
		  (CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_ACCEPT_WAKE)) |
		 (~idle_mask & -heavy & CAKE_CPU_STATUS_ACCEPT_WAKE);
	return flags;
}

static __always_inline bool cake_status_scoreboard_clean(u64 status)
{
	u32 op = cake_status_owner_pressure(status);
	u32 owner_class = op & CAKE_CPU_STATUS_OWNER_MASK;
	u32 pressure = op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
			      CAKE_CPU_STATUS_OWNER_SHIFT);

	return !(((0xf0U >> (owner_class & 7U)) |
		  (pressure & (pressure >> 1))) &
		 1U);
}

static __always_inline void cake_scoreboard_summary_publish(u32 cpu, u64 status)
{
#if CAKE_SCOREBOARD_SUMMARY
	u32 llc = cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)] & (CAKE_MAX_LLCS - 1);
	u64 bit = 1ULL << (cpu & 63U);

	if ((status & CAKE_CPU_STATUS_IDLE) &&
	    cake_status_scoreboard_clean(status))
		__sync_fetch_and_or(&scoreboard_summary[llc].idle_clean_mask,
				    bit);
	else
		__sync_fetch_and_and(&scoreboard_summary[llc].idle_clean_mask,
				     ~bit);
#else
	(void)cpu;
	(void)status;
#endif
}

static __always_inline __maybe_unused bool
cake_scoreboard_summary_maybe_clean(u32 cpu)
{
#if CAKE_SCOREBOARD_SUMMARY
	u32 llc = cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)] & (CAKE_MAX_LLCS - 1);
	u64 bit = 1ULL << (cpu & 63U);

	return READ_ONCE(scoreboard_summary[llc].idle_clean_mask) & bit;
#else
	(void)cpu;
	return true;
#endif
}

#if defined(CAKE_RELEASE) && CAKE_SCOREBOARD_SUMMARY && defined(CAKE_SINGLE_LLC)
static __always_inline bool cake_fast_mask_maybe_clean(u32 cpu)
{
	u64 mask = READ_ONCE(scoreboard_summary[0].idle_clean_mask);

	return (mask >> (cpu & 63U)) & 1U;
}
#else
static __always_inline bool cake_fast_mask_maybe_clean(u32 cpu)
{
	(void)cpu;
	return true;
}
#endif

static __always_inline u32 cake_clamp_u8_bucket(u32 value)
{
	return value - ((value - 255U) & -(value > 255U));
}

static __always_inline u32 cake_owner_bulk_min_ns(void)
{
	u32 q = (u32)quantum_ns;

	return q - (q >> 3);
}

static __always_inline bool cake_owner_cache_mem_saturated(u32 avg, u32 runs)
{
	return runs >= CAKE_CACHE_THROUGHPUT_MIN_RUNS &&
	       avg >= cake_owner_bulk_min_ns();
}

static __always_inline bool cake_throughput_decision_sat_cache_mem(u64 dec)
{
	return !!(dec & CAKE_TP_DEC_SAT_CACHE_MEM);
}

static __always_inline void
cake_throughput_update_owner_decision(struct cake_cpu_bss *bss, u32 runtime_ns,
				      u32 runs)
{
	u64 fields = ((u64)cake_clamp_u8_bucket(
			      runtime_ns >> CAKE_TP_DEC_RUNTIME_SCALE_SHIFT)
		      << CAKE_TP_DEC_RUNTIME_BUCKET_SHIFT) |
		     ((u64)cake_clamp_u8_bucket(runs)
		      << CAKE_TP_DEC_RUN_BUCKET_SHIFT);
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next;

	if (cake_owner_cache_mem_saturated(runtime_ns, runs))
		fields |= CAKE_TP_DEC_SAT_CACHE_MEM;

	next = (old_dec & ~CAKE_TP_DEC_OWNER_MASK) | fields;
	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

#if !CAKE_LEAN_SCHED
static __always_inline void
cake_throughput_reset_owner_decision(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next    = old_dec & ~CAKE_TP_DEC_OWNER_MASK;

	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}
#endif

static __always_inline void
cake_throughput_reset_dispatch_budget(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next    = old_dec & ~CAKE_TP_DEC_DISPATCH_MASK;

	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline void
cake_throughput_mark_shared_miss(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next    = old_dec | CAKE_TP_DEC_FAIR_HINT |
		   CAKE_TP_DEC_OVERFLOW_HINT;

	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline bool
cake_task_is_affinitized(const struct task_struct *p)
{
	u32 allowed = (u32)p->nr_cpus_allowed;

	return (allowed - 1U) < (nr_cpus - 1U);
}

static __always_inline u64
cake_cache_throughput_slice_for(struct cake_cpu_bss *bss,
				struct task_struct *p)
{
	u64 dec;
	u32 run_bucket;
	u32 shift_idx;
	u32 shift;
	u64 eligible;
	u64 slice;

	dec = READ_ONCE(bss->throughput_decision);
	run_bucket = (dec >> CAKE_TP_DEC_RUN_BUCKET_SHIFT) &
		     CAKE_TP_DEC_BUCKET_MASK;
	eligible = (u64)!(p->prio < 120 || p->scx.weight > 120) &
		   (u64)cake_throughput_decision_sat_cache_mem(dec);
	shift_idx = (run_bucket >> 4) & 0xfU;
	shift = (CAKE_CACHE_THROUGHPUT_SHIFT_LUT >> (shift_idx * 4U)) &
		0xfU;
	slice = quantum_ns << shift;
	return slice & -eligible;
}

static __always_inline u64 cake_min_requeue_slice(u64 slice)
{
	slice += (200000ULL - slice) & -(slice < 200000ULL);
	return slice;
}

static __always_inline u64 cake_requeue_base_slice(u64 slice, u64 target_status)
{
	u64 half = cake_min_requeue_slice(slice >> 1);
	u32 owner = cake_status_owner_pressure(target_status) &
		    CAKE_CPU_STATUS_OWNER_MASK;
	u64 shrink = (0x6ULL >> owner) & 1ULL; /* SHORT or INTERACTIVE */

	return slice ^ ((slice ^ half) & -shrink);
}

static __always_inline u64 cake_preserve_slice(u64 slice)
{
	return cake_min_requeue_slice(slice);
}

#if CAKE_LEAN_SCHED
static __always_inline u32 cake_update_owner_avg(struct cake_cpu_bss *bss,
						 u32 runtime_ns)
{
	u32 avg	 = READ_ONCE(bss->owner_avg_runtime_ns);
	u16 runs = READ_ONCE(bss->owner_run_count);
	u16 next_runs = runs;

	if (!runtime_ns)
		return avg;
	if (!avg)
		avg = runtime_ns;
	else
		avg = (((avg << 3) - avg) + runtime_ns) >> 3;
	WRITE_ONCE(bss->owner_avg_runtime_ns, avg);
	if (runs != 0xffff) {
		next_runs = runs + 1;
		WRITE_ONCE(bss->owner_run_count, next_runs);
	}
	cake_throughput_update_owner_decision(bss, avg, next_runs);
	return avg;
}
#endif

static __always_inline void cake_publish_cpu_idle(u32 cpu)
{
	u32 idx = cpu & (CAKE_MAX_CPUS - 1);
	u64 old = READ_ONCE(cpu_status[idx].flags);

	if (!(old & CAKE_CPU_STATUS_IDLE)) {
		u64 next = cake_status_bump_epoch(old) |
			   CAKE_CPU_STATUS_IDLE |
			   CAKE_CPU_STATUS_ACCEPT_WAKE;

		WRITE_ONCE(cpu_status[idx].flags, next);
		cake_scoreboard_summary_publish(cpu, next);
	}
}

static __always_inline void cake_publish_cpu_running(u32 cpu, bool task_changed)
{
	u32 idx = cpu & (CAKE_MAX_CPUS - 1);
	u64 old = READ_ONCE(cpu_status[idx].flags);

	if (task_changed) {
		u64 next = cake_make_cpu_status(false, CAKE_CPU_OWNER_UNKNOWN,
						CAKE_CPU_PRESSURE_LOW,
						CAKE_CPU_LATENCY_UNKNOWN,
						cake_status_next_epoch(old));

		if (!cake_status_same_visible_state(old, next)) {
			WRITE_ONCE(cpu_status[idx].flags, next);
			cake_scoreboard_summary_publish(cpu, next);
		}
		return;
	}
	if (old & CAKE_CPU_STATUS_IDLE) {
		u64 next = cake_status_bump_epoch(old) &
			   ~(CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_ACCEPT_WAKE);
		u32 op = cake_status_owner_pressure(old);
		u32 owner_class = op & CAKE_CPU_STATUS_OWNER_MASK;
		u32 pressure = (op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
				       CAKE_CPU_STATUS_OWNER_SHIFT)) &
			       CAKE_CPU_STATUS_PRESS_MASK;
		u32 heavy = (owner_class >= CAKE_CPU_OWNER_FRAME) &
			    (pressure >= CAKE_CPU_PRESSURE_HIGH);

		next |= CAKE_CPU_STATUS_ACCEPT_WAKE & -(u64)heavy;
		WRITE_ONCE(cpu_status[idx].flags, next);
		cake_scoreboard_summary_publish(cpu, next);
	}
}

static __always_inline void cake_publish_cpu_owner(u32 cpu,
						   struct cake_cpu_bss *bss,
						   u32 owner_avg_runtime_ns)
{
	u32 idx		= cpu & (CAKE_MAX_CPUS - 1);
	u64 old		= READ_ONCE(cpu_status[idx].flags);
	u32 q		= (u32)quantum_ns;
	u32 short_max	= q >> 3;
	u32 med_min	= q >> 2;
	u32 frame_min	= q >> 1;
	u32 bulk_min	= q - (q >> 3);
	u32 key;
	u8  owner_class;
	u8  pressure;
	u8  latency_class;
	u64 next;

	key = (owner_avg_runtime_ns > short_max) |
	      ((owner_avg_runtime_ns >= frame_min) << 1) |
	      ((owner_avg_runtime_ns >= bulk_min) << 2);
	owner_class = (0x44443321ULL >> (key * 4U)) & 0xfU;
	pressure = (owner_avg_runtime_ns >= med_min) +
		   (owner_avg_runtime_ns >= frame_min) +
		   (owner_avg_runtime_ns >= bulk_min);
	latency_class = cake_owner_latency_class(owner_class);

	next = cake_make_cpu_status(false, owner_class, pressure,
				    latency_class, cake_status_next_epoch(old));
	next |= CAKE_CPU_STATUS_SAT_CACHE_MEM &
		-(u64)cake_throughput_decision_sat_cache_mem(
			READ_ONCE(bss->throughput_decision));
	if (!cake_status_same_visible_state(old, next)) {
		WRITE_ONCE(cpu_status[idx].flags, next);
		cake_scoreboard_summary_publish(cpu, next);
	}
}

static __always_inline u64 cake_read_cpu_status(u32 cpu)
{
	return READ_ONCE(cpu_status[cpu & (CAKE_MAX_CPUS - 1)].flags);
}

static __always_inline u64 cake_cpu_meta_for(u32 cpu)
{
	return cpu_meta[cpu & (CAKE_MAX_CPUS - 1)];
}

static __always_inline __maybe_unused u32 cake_meta_sibling_cpu(u64 meta)
{
	return (u32)(meta & CAKE_CPU_META_SIBLING_MASK);
}

static __always_inline u32 cake_meta_primary_cpu(u64 meta)
{
	return (u32)((meta >> CAKE_CPU_META_PRIMARY_SHIFT) & 0xffffULL);
}

static __always_inline __maybe_unused u32 cake_meta_llc_id(u64 meta)
{
	return (u32)((meta >> CAKE_CPU_META_LLC_SHIFT) & 0xffULL);
}

static __always_inline void cake_publish_cpu_frontier(u32 cpu, u64 vtime)
{
	WRITE_ONCE(cpu_frontier[cpu & (CAKE_MAX_CPUS - 1)].vtime, vtime);
}

static __always_inline u64 cake_read_cpu_frontier(u32 cpu)
{
	return READ_ONCE(cpu_frontier[cpu & (CAKE_MAX_CPUS - 1)].vtime);
}

#if CAKE_ACCEL_PATH
#define CAKE_CLAIM_HEALTH_INIT 8U
#define CAKE_CLAIM_HEALTH_MIN 4U
#define CAKE_CLAIM_HEALTH_MAX 15U
#define CAKE_CLAIM_HEALTH_HIT_STEP 1U
#define CAKE_CLAIM_HEALTH_MISS_STEP 4U
#define CAKE_CLAIM_HEALTH_RECOVERY_STEP 1U

static __always_inline u8 cake_conf_value(u64 confidence, u32 shift)
{
	u8 value = (u8)((confidence >> shift) & CAKE_CONF_NIBBLE_MASK);

	return value ?: CAKE_CONF_INIT;
}

static __always_inline u8 cake_conf_raw_value(u64 confidence, u32 shift)
{
	return (u8)((confidence >> shift) & CAKE_CONF_NIBBLE_MASK);
}

static __always_inline bool cake_conf_init_or_zero(u8 value)
{
	return !value || (value & 8U);
}

static __always_inline u64 cake_conf_high_lanes(u64 confidence)
{
	return ((confidence >> 3) & (confidence >> 2)) &
	       0x1111111111111111ULL;
}

static __always_inline u8 cake_claim_health_value(u64 confidence)
{
	return cake_conf_value(confidence, CAKE_CONF_CLAIM_HEALTH_SHIFT);
}

static __always_inline u64 cake_claim_health_store(u64 confidence, u8 value)
{
	u64 mask = CAKE_CONF_NIBBLE_MASK << CAKE_CONF_CLAIM_HEALTH_SHIFT;

	return (confidence & ~mask) |
	       (((u64)value) << CAKE_CONF_CLAIM_HEALTH_SHIFT);
}

static __always_inline bool cake_claim_health_allows(struct cake_cpu_bss *bss)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u8  value      = cake_claim_health_value(confidence);

	if (value >= CAKE_CLAIM_HEALTH_MIN)
		return true;
	if (value < CAKE_CLAIM_HEALTH_MAX) {
		confidence = cake_claim_health_store(
			confidence, value + CAKE_CLAIM_HEALTH_RECOVERY_STEP);
		WRITE_ONCE(bss->decision_confidence, confidence);
	}
	return false;
}

static __always_inline u64 cake_claim_health_update(u64	 confidence,
						    bool success)
{
	u8 value = cake_claim_health_value(confidence);

	if (success) {
		value = value + CAKE_CLAIM_HEALTH_HIT_STEP;
		if (value > CAKE_CLAIM_HEALTH_MAX)
			value = CAKE_CLAIM_HEALTH_MAX;
	} else {
		value = value > CAKE_CLAIM_HEALTH_MISS_STEP ?
				value - CAKE_CLAIM_HEALTH_MISS_STEP :
				1;
	}
	return cake_claim_health_store(confidence, value);
}

static __always_inline u8 cake_floor_gear_for(u64 confidence)
{
	u8 pull_conf =
		cake_conf_raw_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);
	u8 status_trust =
		cake_conf_raw_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT);
	u64 high = cake_conf_high_lanes(confidence);
	u64 route_bit = 1ULL << CAKE_CONF_ROUTE_SHIFT;
	u64 floor_want = route_bit |
			 (1ULL << CAKE_CONF_SELECT_EARLY_SHIFT) |
			 (1ULL << CAKE_CONF_STATUS_TRUST_SHIFT);

	if (confidence & (8ULL << CAKE_CONF_LOAD_SHOCK_SHIFT))
		return CAKE_FLOOR_GEAR_RECOVERY;
	if (status_trust && !(status_trust & 8U))
		return CAKE_FLOOR_GEAR_RECOVERY;
	if ((high & floor_want) == floor_want &&
	    cake_conf_init_or_zero(pull_conf) &&
	    ((high & (1ULL << CAKE_CONF_OWNER_STABLE_SHIFT)) ||
	     (((confidence & ((0xfULL << CAKE_CONF_ROUTE_SHIFT) |
			      (0xfULL << CAKE_CONF_STATUS_TRUST_SHIFT))) ==
	       ((0xfULL << CAKE_CONF_ROUTE_SHIFT) |
		(0xfULL << CAKE_CONF_STATUS_TRUST_SHIFT))) &&
	      (high & (1ULL << CAKE_CONF_PULL_SHAPE_SHIFT)))))
		return CAKE_FLOOR_GEAR_FLOOR;
	if ((high & route_bit) && cake_conf_init_or_zero(status_trust))
		return CAKE_FLOOR_GEAR_NARROW;
	return CAKE_FLOOR_GEAR_AUDIT;
}

static __always_inline u64 cake_refresh_floor_gear_packed(u64 confidence)
{
	u8  gear = cake_floor_gear_for(confidence);
	u64 mask = CAKE_CONF_NIBBLE_MASK << CAKE_CONF_FLOOR_GEAR_SHIFT;

	return (confidence & ~mask) |
	       (((u64)gear) << CAKE_CONF_FLOOR_GEAR_SHIFT);
}

static __always_inline bool cake_floor_mode_ready(u64 confidence)
{
	u8 gear = cake_conf_raw_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT);

	return gear == CAKE_FLOOR_GEAR_FLOOR;
}

static __always_inline bool cake_route_predict_ready(u64 confidence)
{
	u64 high = cake_conf_high_lanes(confidence);
	u64 want = (1ULL << CAKE_CONF_ROUTE_SHIFT) |
		   (1ULL << CAKE_CONF_SELECT_EARLY_SHIFT) |
		   (1ULL << CAKE_CONF_STATUS_TRUST_SHIFT);

	return (high & (want | (1ULL << CAKE_CONF_LOAD_SHOCK_SHIFT))) == want;
}

static __always_inline u32 cake_route_predict_block_reason(u64 confidence)
{
	u64 high = cake_conf_high_lanes(confidence);
	u32 key = !!(high & (1ULL << CAKE_CONF_ROUTE_SHIFT)) |
		  (!!(high & (1ULL << CAKE_CONF_SELECT_EARLY_SHIFT)) << 1) |
		  (!!(high & (1ULL << CAKE_CONF_STATUS_TRUST_SHIFT)) << 2) |
		  (!!(high & (1ULL << CAKE_CONF_LOAD_SHOCK_SHIFT)) << 3);

	return (u32)((0x63435343c3435343ULL >> (key * 4U)) & 0xfU);
}

static __always_inline bool cake_trust_active(u32 cpu, u32 flag)
{
	u32 idx	   = cpu & (CAKE_MAX_CPUS - 1);
	u32 policy = READ_ONCE(trust_user[idx].policy);
	u32 generation;
	u32 blocked;
	u32 blocked_generation;

	if (!(policy & flag))
		return false;

	generation	   = READ_ONCE(trust_user[idx].generation);
	blocked		   = READ_ONCE(trust_bpf[idx].blocked);
	blocked_generation = READ_ONCE(trust_bpf[idx].generation);
	return blocked_generation != generation || !(blocked & flag);
}

static __always_inline void cake_trust_demote(u32 cpu, u32 flag, u32 reason)
{
	u32 idx	       = cpu & (CAKE_MAX_CPUS - 1);
	u32 generation = READ_ONCE(trust_user[idx].generation);
	u32 blocked    = READ_ONCE(trust_bpf[idx].blocked);
	u32 count      = READ_ONCE(trust_bpf[idx].demotion_count);

	WRITE_ONCE(trust_bpf[idx].reason, reason);
	WRITE_ONCE(trust_bpf[idx].generation, generation);
	WRITE_ONCE(trust_bpf[idx].demotion_count, count + 1);
	WRITE_ONCE(trust_bpf[idx].blocked, blocked | flag);
}

static __always_inline s32 cake_trust_prev_direct_claim(s32 prev_cpu)
{
	u32  cpu = (u32)prev_cpu;
	bool claimed;

	if (!cake_trust_active(cpu, CAKE_TRUST_FLAG_PREV_DIRECT))
		return CAKE_ROUTE_PREDICT_NONE;

	claimed = scx_bpf_test_and_clear_cpu_idle(cpu);
	cake_record_accel_trust_prev(claimed);
	if (claimed)
		return prev_cpu;

	cake_trust_demote(cpu, CAKE_TRUST_FLAG_PREV_DIRECT,
			  CAKE_TRUST_DEMOTE_PREV_CLAIM_MISS);
	return CAKE_ROUTE_PREDICT_TRUST_MISS;
}

static __always_inline u32 cake_floor_block_reason(u64 confidence)
{
	u64 high = cake_conf_high_lanes(confidence);
	u64 route_bit = 1ULL << CAKE_CONF_ROUTE_SHIFT;
	u64 select_bit = 1ULL << CAKE_CONF_SELECT_EARLY_SHIFT;
	u64 status_bit = 1ULL << CAKE_CONF_STATUS_TRUST_SHIFT;
	u64 owner_bit = 1ULL << CAKE_CONF_OWNER_STABLE_SHIFT;
	u64 pull_bit = 1ULL << CAKE_CONF_PULL_SHAPE_SHIFT;
	u8 gear = cake_conf_raw_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT);
	u8 route_conf = cake_conf_raw_value(confidence, CAKE_CONF_ROUTE_SHIFT);
	u8 status_trust =
		cake_conf_raw_value(confidence, CAKE_CONF_STATUS_TRUST_SHIFT);
	u8 pull_conf =
		cake_conf_raw_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);

	if (!(high & route_bit))
		return CAKE_ACCEL_BLOCK_ROUTE_LOW;
	if (!(high & select_bit))
		return CAKE_ACCEL_BLOCK_SELECT_LOW;
	if (!(high & status_bit))
		return CAKE_ACCEL_BLOCK_TRUST_LOW;
	if (!(high & owner_bit) &&
	    (route_conf != 15 || status_trust != 15 ||
	     !(high & pull_bit)))
		return CAKE_ACCEL_BLOCK_OWNER_LOW;
	if (confidence & (8ULL << CAKE_CONF_LOAD_SHOCK_SHIFT))
		return CAKE_ACCEL_BLOCK_LOAD_SHOCK;
	if (pull_conf && !(pull_conf & 8U))
		return CAKE_ACCEL_BLOCK_PULL_LOW;
	if (gear != CAKE_FLOOR_GEAR_FLOOR)
		return CAKE_ACCEL_BLOCK_FLOOR_LOW;
	return CAKE_ACCEL_BLOCK_FLOOR_LOW;
}

static __always_inline u8 cake_conf_adjust(u8 value, bool success)
{
	u32 shift = (value & 0xfU) * 4U;

	if (success)
		return (u8)((0xFFEDCBA987654329ULL >> shift) & 0xfU);
	return (u8)((0xDCBA987654321006ULL >> shift) & 0xfU);
}

static __always_inline u64 cake_conf_update_packed(u64 confidence, u32 shift,
						   bool success)
{
	u8  value = (u8)((confidence >> shift) & CAKE_CONF_NIBBLE_MASK);
	u64 mask  = CAKE_CONF_NIBBLE_MASK << shift;

	value	  = cake_conf_adjust(value, success);
	return (confidence & ~mask) | (((u64)value) << shift);
}

static __always_inline void cake_conf_update(struct cake_cpu_bss *bss,
					     u32 shift, bool success)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(confidence, shift, success);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_dispatch_record_probe_empty(struct cake_cpu_bss *bss)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_DISPATCH_EMPTY_SHIFT, true);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_PULL_SHAPE_SHIFT, true);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_dispatch_record_probe_work(struct cake_cpu_bss *bss)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_PULL_SHAPE_SHIFT, false);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline bool cake_conf_audit_due(struct cake_cpu_bss *bss,
						u32 shift, u32 mask_value)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u8  audit      = cake_conf_raw_value(confidence, shift);
	u64 mask       = CAKE_CONF_NIBBLE_MASK << shift;

	audit	       = (audit + 1) & mask_value;
	confidence     = (confidence & ~mask) | (((u64)audit) << shift);
	WRITE_ONCE(bss->decision_confidence, confidence);
	return audit == 0;
}

static __always_inline u8 cake_route_kind_value(u64 confidence)
{
	return (u8)((confidence >> CAKE_CONF_ROUTE_KIND_SHIFT) &
		    CAKE_CONF_NIBBLE_MASK);
}

static __always_inline u64 cake_route_update_packed(u64	 confidence,
						    u32	 route_kind,
						    bool success)
{
	u8  value     = (u8)((confidence >> CAKE_CONF_ROUTE_SHIFT) &
			     CAKE_CONF_NIBBLE_MASK);
	u8  old_kind  = cake_route_kind_value(confidence);
	u64 conf_mask = CAKE_CONF_NIBBLE_MASK << CAKE_CONF_ROUTE_SHIFT;
	u64 kind_mask = CAKE_CONF_NIBBLE_MASK << CAKE_CONF_ROUTE_KIND_SHIFT;

	if (success && route_kind != old_kind)
		value = CAKE_CONF_INIT;
	value	   = cake_conf_adjust(value, success);

	confidence = (confidence & ~conf_mask) |
		     (((u64)value) << CAKE_CONF_ROUTE_SHIFT);
	if (success && route_kind != CAKE_ROUTE_NONE) {
		confidence = (confidence & ~kind_mask) |
			     (((u64)route_kind & CAKE_CONF_NIBBLE_MASK)
			      << CAKE_CONF_ROUTE_KIND_SHIFT);
	}
	return confidence;
}

static __always_inline void cake_route_update(struct cake_cpu_bss *bss,
					      u32 route_kind, bool success)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence = cake_route_update_packed(confidence, route_kind, success);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void cake_conf_update_select(struct cake_cpu_bss *bss,
						    bool early_success,
						    bool row4_sample,
						    bool row4_success)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_SELECT_EARLY_SHIFT, early_success);
	if (row4_sample)
		confidence = cake_conf_update_packed(
			confidence, CAKE_CONF_SELECT_ROW4_SHIFT, row4_success);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_conf_update_select_route(struct cake_cpu_bss *bss, u32 route_kind,
			      bool early_success, bool row4_sample,
			      bool row4_success)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_SELECT_EARLY_SHIFT, early_success);
	if (row4_sample)
		confidence = cake_conf_update_packed(
			confidence, CAKE_CONF_SELECT_ROW4_SHIFT, row4_success);
	confidence = cake_route_update_packed(confidence, route_kind, true);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_scoreboard_claim_result(struct cake_cpu_bss *bss, u64 status, bool success)
{
	u64  confidence	  = READ_ONCE(bss->decision_confidence);
	u32  op	  = cake_status_owner_pressure(status);
	u8   owner_class  = op & CAKE_CPU_STATUS_OWNER_MASK;
	u8   pressure	  = (op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
				     CAKE_CPU_STATUS_OWNER_SHIFT)) &
			    CAKE_CPU_STATUS_PRESS_MASK;
	bool known_status = !!(status & CAKE_CPU_STATUS_IDLE) ||
			    owner_class != CAKE_CPU_OWNER_UNKNOWN;
	bool shock	  = !success || owner_class >= CAKE_CPU_OWNER_BULK ||
			    pressure >= CAKE_CPU_PRESSURE_HIGH;

	confidence	  = cake_claim_health_update(confidence, success);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_STATUS_TRUST_SHIFT,
					     known_status && success);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_LOAD_SHOCK_SHIFT, shock);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_scoreboard_status_result(struct cake_cpu_bss *bss, u64 status)
{
	u64  confidence	  = READ_ONCE(bss->decision_confidence);
	u32  op	  = cake_status_owner_pressure(status);
	u8   owner_class  = op & CAKE_CPU_STATUS_OWNER_MASK;
	u8   pressure	  = (op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
				     CAKE_CPU_STATUS_OWNER_SHIFT)) &
			    CAKE_CPU_STATUS_PRESS_MASK;
	bool known_status = !!(status & CAKE_CPU_STATUS_IDLE) ||
			    owner_class != CAKE_CPU_OWNER_UNKNOWN;
	bool shock	  = owner_class == CAKE_CPU_OWNER_UNKNOWN ||
			    owner_class >= CAKE_CPU_OWNER_BULK ||
			    pressure >= CAKE_CPU_PRESSURE_HIGH;

	confidence	  = cake_conf_update_packed(
		confidence, CAKE_CONF_STATUS_TRUST_SHIFT, known_status);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_LOAD_SHOCK_SHIFT, shock);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_scoreboard_owner_result(struct cake_cpu_bss *bss, u32 owner_avg_runtime_ns)
{
	u64  confidence = READ_ONCE(bss->decision_confidence);
	u32  q		= (u32)quantum_ns;
	u32  bulk_min	= q - (q >> 3);
	u16  runs	= READ_ONCE(bss->owner_run_count);
	bool stable	= runs >= CAKE_ACCOUNT_RELAX_MIN_RUNS;
	bool shock	= owner_avg_runtime_ns >= bulk_min;

	confidence	= cake_conf_update_packed(
		confidence, CAKE_CONF_OWNER_STABLE_SHIFT, stable);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_LOAD_SHOCK_SHIFT, shock);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void
cake_scoreboard_owner_reset(struct cake_cpu_bss *bss)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_OWNER_STABLE_SHIFT, false);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_LOAD_SHOCK_SHIFT, true);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline bool cake_route_audit_due(struct cake_cpu_bss *bss)
{
	return cake_conf_audit_due(bss, CAKE_CONF_ROUTE_AUDIT_SHIFT,
				   CAKE_ROUTE_AUDIT_MASK);
}

static __always_inline bool cake_pull_audit_due(struct cake_cpu_bss *bss)
{
	return cake_conf_audit_due(bss, CAKE_CONF_PULL_AUDIT_SHIFT,
				   CAKE_PULL_AUDIT_MASK);
}

static __always_inline bool cake_accounting_relaxed(struct cake_cpu_bss *bss)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u64 high = cake_conf_high_lanes(confidence);

	if (READ_ONCE(bss->owner_run_count) < CAKE_ACCOUNT_RELAX_MIN_RUNS)
		return false;
	if (!(high & ((1ULL << CAKE_CONF_ROUTE_SHIFT) |
		      (1ULL << CAKE_CONF_PULL_SHAPE_SHIFT))))
		return false;
	return !cake_conf_audit_due(bss, CAKE_CONF_ACCOUNT_AUDIT_SHIFT,
				    CAKE_ACCOUNT_RELAX_AUDIT_MASK);
}

static __always_inline u32 cake_select_fast_scan_limit(struct cake_cpu_bss *bss)
{
	u64 confidence;
	u8  early_conf;
	u8  row4_conf;

	confidence = READ_ONCE(bss->decision_confidence);
	early_conf = !!(cake_conf_high_lanes(confidence) &
			(1ULL << CAKE_CONF_SELECT_EARLY_SHIFT));
	row4_conf = cake_conf_raw_value(confidence, CAKE_CONF_SELECT_ROW4_SHIFT);

	return 2U + (((u32)!early_conf & (u32)cake_conf_init_or_zero(row4_conf))
		     << 1);
}

static __always_inline u32 cake_pull_shape_mode(struct cake_cpu_bss *bss,
						u64		     dsq_id)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u8  pull_conf =
		cake_conf_raw_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);

	(void)dsq_id;
	if (pull_conf >= CAKE_CONF_HIGH && !cake_pull_audit_due(bss))
		return CAKE_PULL_SHAPE_SKIP;
	if (cake_conf_init_or_zero(pull_conf))
		return CAKE_PULL_SHAPE_PROBE;
	return CAKE_PULL_SHAPE_PULL;
}

static __always_inline bool
cake_dispatch_dsq_should_pull(struct cake_cpu_bss *bss, u64 dsq_id)
{
	u32 mode = cake_pull_shape_mode(bss, dsq_id);
	s32 queued;

	cake_record_accel_pull_mode(mode);
	if (mode == CAKE_PULL_SHAPE_PULL)
		return true;

	queued = scx_bpf_dsq_nr_queued(dsq_id);
	if (queued == 0) {
		cake_record_accel_pull_probe(false);
		cake_dispatch_record_probe_empty(bss);
		return false;
	}
	cake_record_accel_pull_probe(true);
	cake_dispatch_record_probe_work(bss);
	return true;
}

static __always_inline void
cake_dispatch_record_pull_result(struct cake_cpu_bss *bss, bool hit)
{
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_DISPATCH_EMPTY_SHIFT, !hit);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_PULL_SHAPE_SHIFT, !hit);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
}

static __always_inline void cake_record_storm_guard_mode(u32 target_cpu,
							 u32 mode)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(target_cpu);

		if (mode < CAKE_STORM_GUARD_MAX)
			__sync_fetch_and_add(
				&stats->storm_guard_mode_count[mode], 1);
	}
#else
	(void)target_cpu;
	(void)mode;
#endif
}

static __always_inline void cake_record_storm_guard_decision(u32 target_cpu,
							     u32 decision)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(target_cpu);

		if (decision < CAKE_STORM_GUARD_DECISION_MAX)
			__sync_fetch_and_add(
				&stats->storm_guard_decision_count[decision],
				1);
	}
#else
	(void)target_cpu;
	(void)decision;
#endif
}

static __always_inline bool cake_smt_latency_neighbor_busy(u32 target_cpu)
{
	u64 meta    = cake_cpu_meta_for(target_cpu);
	u32 sibling = cake_meta_sibling_cpu(meta);
	u64 sibling_status;
	u32 owner;

	if (!(meta & CAKE_CPU_META_SMT_FLAG))
		return false;
	if (sibling >= nr_cpus || sibling == target_cpu)
		return false;
	sibling_status = cake_read_cpu_status(sibling);
	if (sibling_status & CAKE_CPU_STATUS_IDLE)
		return false;
	owner = (sibling_status >> CAKE_CPU_STATUS_OWNER_SHIFT) &
		CAKE_CPU_STATUS_OWNER_MASK;
	return (0x6U >> owner) & 1U;
}

static __always_inline bool cake_smt_interactive_neighbor_busy(u32 target_cpu)
{
	u64 meta    = cake_cpu_meta_for(target_cpu);
	u32 sibling = cake_meta_sibling_cpu(meta);
	u64 sibling_status;

	if (!(meta & CAKE_CPU_META_SMT_FLAG))
		return false;
	if (sibling >= nr_cpus || sibling == target_cpu)
		return false;
	sibling_status = cake_read_cpu_status(sibling);
	return (sibling_status &
		(CAKE_CPU_STATUS_IDLE |
		 (CAKE_CPU_STATUS_OWNER_MASK << CAKE_CPU_STATUS_OWNER_SHIFT))) ==
	       ((u64)CAKE_CPU_OWNER_INTERACTIVE << CAKE_CPU_STATUS_OWNER_SHIFT);
}

static __always_inline bool cake_accept_busy_wake(u32 target_cpu,
						  u64 target_status)
{
	u64 owner_bits = target_status &
			 (CAKE_CPU_STATUS_OWNER_MASK <<
			  CAKE_CPU_STATUS_OWNER_SHIFT);

	if (!(target_status & CAKE_CPU_STATUS_ACCEPT_WAKE) ||
	    (target_status & CAKE_CPU_STATUS_IDLE))
		return false;
	if (owner_bits < ((u64)CAKE_CPU_OWNER_FRAME
			  << CAKE_CPU_STATUS_OWNER_SHIFT))
		return false;
	if (cake_smt_latency_neighbor_busy(target_cpu))
		return false;
	cake_record_storm_guard_mode(target_cpu, CAKE_STORM_GUARD_MODE);
	cake_record_storm_guard_decision(target_cpu,
					 CAKE_STORM_GUARD_BASE_ALLOW);
	return true;
}

static __always_inline bool cake_storm_guard_accept_busy_wake(u32 target_cpu,
							      u64 target_status)
{
#ifdef CAKE_RELEASE
	if (CAKE_STORM_GUARD_MODE == CAKE_STORM_GUARD_SHADOW)
		return false;
#endif
	u32 mode	= CAKE_STORM_GUARD_MODE;
	u32 policy_mode = mode;
	u32 op;
	u8  owner_class;
	u8  pressure;
	bool allow = false;

	cake_record_storm_guard_mode(target_cpu, mode);
	cake_record_storm_guard_decision(target_cpu,
					 CAKE_STORM_GUARD_CANDIDATE);

	if (mode >= CAKE_STORM_GUARD_MAX) {
		cake_record_storm_guard_decision(
			target_cpu, CAKE_STORM_GUARD_POLICY_REJECTED);
		return false;
	}
	if (mode == CAKE_STORM_GUARD_OFF) {
		cake_record_storm_guard_decision(
			target_cpu, CAKE_STORM_GUARD_MODE_DISABLED);
		return false;
	}
	if (target_status & CAKE_CPU_STATUS_IDLE) {
		cake_record_storm_guard_decision(
			target_cpu, CAKE_STORM_GUARD_POLICY_REJECTED);
		return false;
	}

	op	    = cake_status_owner_pressure(target_status);
	owner_class = op & CAKE_CPU_STATUS_OWNER_MASK;
	pressure    = (op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
			   CAKE_CPU_STATUS_OWNER_SHIFT)) &
		   CAKE_CPU_STATUS_PRESS_MASK;
	if (owner_class == CAKE_CPU_OWNER_UNKNOWN) {
		cake_record_storm_guard_decision(
			target_cpu, CAKE_STORM_GUARD_UNKNOWN_OWNER);
		return false;
	}
	if (cake_smt_latency_neighbor_busy(target_cpu)) {
		cake_record_storm_guard_decision(target_cpu,
						 CAKE_STORM_GUARD_SMT_BLOCKED);
		return false;
	}

	if (mode == CAKE_STORM_GUARD_SHADOW)
		policy_mode = CAKE_STORM_GUARD_SHIELD;

	if (policy_mode == CAKE_STORM_GUARD_SHIELD) {
		if (owner_class >= CAKE_CPU_OWNER_FRAME ||
		    (owner_class == CAKE_CPU_OWNER_INTERACTIVE &&
		     pressure >= CAKE_CPU_PRESSURE_MED)) {
			cake_record_storm_guard_decision(
				target_cpu, CAKE_STORM_GUARD_SHIELD_ALLOW);
			allow = true;
		}
	} else if (policy_mode == CAKE_STORM_GUARD_FULL &&
		   owner_class >= CAKE_CPU_OWNER_SHORT) {
		cake_record_storm_guard_decision(target_cpu,
						 CAKE_STORM_GUARD_FULL_ALLOW);
		allow = true;
	}

	if (mode == CAKE_STORM_GUARD_SHADOW) {
		cake_record_storm_guard_decision(target_cpu,
						 CAKE_STORM_GUARD_SHADOW_ONLY);
		return false;
	}
	if (!allow)
		cake_record_storm_guard_decision(
			target_cpu, CAKE_STORM_GUARD_POLICY_REJECTED);
	return allow;
}

static __always_inline u32 cake_kick_shape_mode(struct cake_cpu_bss *bss,
						u64 target_status)
{
	u64 confidence;
	u8  kick_conf;
	u8  owner_class;
	u64 lut;
	u64 high_mask;

	if (target_status & CAKE_CPU_STATUS_IDLE)
		return CAKE_KICK_SHAPE_IDLE;

	confidence  = READ_ONCE(bss->decision_confidence);
	kick_conf   = cake_conf_raw_value(confidence, CAKE_CONF_KICK_SHAPE_SHIFT);
	owner_class = cake_status_owner_class(target_status);

	high_mask = -(u64)(kick_conf >= CAKE_CONF_HIGH);
	lut = 0x22221112ULL ^
	      ((0x22221112ULL ^ 0x22221002ULL) & high_mask);
	return (u32)((lut >> ((owner_class & 7U) * 4U)) & 0xfU);
}
#endif

#if !CAKE_LEAN_SCHED
static __always_inline u8 cake_read_cpu_pressure(u32 cpu)
{
	if (cpu >= nr_cpus)
		return 0;

	return READ_ONCE(cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].cpu_pressure);
}

static __always_inline void cake_update_cpu_pressure(struct cake_cpu_bss *bss,
						     u32 slice_consumed)
{
	u32 pressure = READ_ONCE(bss->cpu_pressure);
	u32 sample   = slice_consumed >> CAKE_CPU_PRESSURE_SAMPLE_SHIFT;

	sample |= (!sample) &
		  ((slice_consumed | (0U - slice_consumed)) >> 31);
	sample -= (sample - CAKE_CPU_PRESSURE_SAMPLE_MAX) &
		  -(sample > CAKE_CPU_PRESSURE_SAMPLE_MAX);

	pressure -= pressure >> CAKE_CPU_PRESSURE_DECAY_SHIFT;
	pressure = cake_clamp_u8_bucket(pressure + sample);
	WRITE_ONCE(bss->cpu_pressure, (u8)pressure);
}

static __always_inline void
cake_decay_cpu_pressure_idle(struct cake_cpu_bss *bss)
{
	u32 pressure = READ_ONCE(bss->cpu_pressure);

	pressure -= pressure >> CAKE_CPU_PRESSURE_IDLE_DECAY_SHIFT;
	WRITE_ONCE(bss->cpu_pressure, (u8)pressure);
}

static __always_inline void
cake_owner_runtime_policy_reset(struct cake_cpu_bss *bss)
{
	WRITE_ONCE(bss->owner_avg_runtime_ns, 0);
	WRITE_ONCE(bss->owner_run_count, 0);
	cake_throughput_reset_owner_decision(bss);
}

static __always_inline void
cake_owner_runtime_policy_update(struct cake_cpu_bss *bss, u32 runtime_ns)
{
	u32 avg	 = READ_ONCE(bss->owner_avg_runtime_ns);
	u32 runs = READ_ONCE(bss->owner_run_count);

	if (!runtime_ns)
		runtime_ns = 1;
	if (!avg)
		avg = runtime_ns;
	else if (runtime_ns >= avg)
		avg += (runtime_ns - avg) >> CAKE_OWNER_RUNTIME_AVG_SHIFT;
	else
		avg -= (avg - runtime_ns) >> CAKE_OWNER_RUNTIME_AVG_SHIFT;

	if (runs < 65535U)
		runs++;
	WRITE_ONCE(bss->owner_avg_runtime_ns, avg);
	WRITE_ONCE(bss->owner_run_count, (u16)runs);
	cake_throughput_update_owner_decision(bss, avg, runs);
}
#endif

static __always_inline u8 cake_score_add(u8 score, u32 add)
{
	u32 next = score + add;

	next -= (next - CAKE_WAKE_CHAIN_SCORE_MAX) &
		-(next > CAKE_WAKE_CHAIN_SCORE_MAX);
	return (u8)next;
}

static __always_inline u8 cake_score_sub(u8 score, u32 sub)
{
	u32 next = score - sub;

	return (u8)(next & -(score > sub));
}

static __always_inline u8
cake_wake_chain_score_read(struct cake_task_ctx __arena *tctx)
{
	return (READ_ONCE(tctx->packed_info) >> SHIFT_WAKE_CHAIN_SCORE) &
	       MASK_WAKE_CHAIN_SCORE;
}

static __always_inline void
cake_wake_chain_score_write(struct cake_task_ctx __arena *tctx, u8 score)
{
	u32 packed = READ_ONCE(tctx->packed_info);

	packed &= ~(MASK_WAKE_CHAIN_SCORE << SHIFT_WAKE_CHAIN_SCORE);
	packed |= ((u32)score & MASK_WAKE_CHAIN_SCORE)
		  << SHIFT_WAKE_CHAIN_SCORE;
	WRITE_ONCE(tctx->packed_info, packed);
}

static __always_inline void
cake_wake_chain_policy_update(struct cake_task_ctx __arena *tctx,
			      struct task_struct *p, u32 runtime_ns,
			      bool runnable)
{
	u8   score;
	u32  add	  = 0;
	u32  sub	  = 0;
	bool full_quantum = p->scx.slice == 0;
	bool blocks_early = !runnable && p->scx.slice > 0;

	if (!tctx)
		return;

	score = cake_wake_chain_score_read(tctx);

	if (runtime_ns > 0 && runtime_ns <= CAKE_WAKE_CHAIN_SHORT_RUN_NS)
		add += 2;
	if (blocks_early)
		add += 2;
	if (p->prio < 120 || p->scx.weight > 120)
		add += 2;

	if (full_quantum)
		sub += 5;
	if (runtime_ns >= CAKE_WAKE_CHAIN_LONG_RUN_NS)
		sub += 4;
	if (!runtime_ns)
		sub += 1;

	if (add > sub)
		score = cake_score_add(score, add - sub);
	else
		score = cake_score_sub(score, sub - add);

	cake_wake_chain_score_write(tctx, score);
}

#if !CAKE_LEAN_SCHED
static __always_inline bool
cake_busy_wake_policy_should_preempt(struct task_struct *wakee, u32 owner_runs,
				     u32 owner_avg_runtime_ns,
				     u8	 target_pressure)
{
	if (target_pressure >= 64)
		return true;
	if (wakee->prio < 120 || wakee->scx.weight > 120)
		return true;
	if (owner_runs >= CAKE_BUSY_OWNER_MIN_RUNS && owner_avg_runtime_ns &&
	    owner_avg_runtime_ns <= CAKE_BUSY_OWNER_SHORT_RUN_NS)
		return false;
	return true;
}
#endif

#ifndef CAKE_RELEASE
static __always_inline void cake_smt_record_run_start(struct cake_cpu_bss *bss,
						      u32 cpu, u64 start_ns)
{
	u16 sibling_cpu	   = cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];
	u8  sibling_active = 0;

	if (sibling_cpu < nr_cpus && sibling_cpu != cpu)
		sibling_active = !READ_ONCE(
			cpu_bss[sibling_cpu & (CAKE_MAX_CPUS - 1)].idle_hint);

	bss->smt_run_start_ns	      = start_ns;
	bss->smt_sibling_active_start = sibling_active;
}

static __always_inline void cake_smt_record_wake_wait(struct cake_stats *s,
						      u32 cpu, u64 wait_ns)
{
	u32 bucket = READ_ONCE(cpu_bss[cpu & (CAKE_MAX_CPUS - 1)]
				       .smt_sibling_active_start) ?
			     1 :
			     0;

	s->smt_wake_wait_ns[bucket] += wait_ns;
	s->smt_wake_wait_count[bucket]++;
	if (wait_ns > s->smt_wake_wait_max_ns[bucket])
		s->smt_wake_wait_max_ns[bucket] = wait_ns;
}

static __noinline u64 cake_smt_charge_runtime(struct cake_stats	  *s,
					      struct cake_cpu_bss *bss, u32 cpu,
					      u64 stop_ns)
{
	u64 start_ns = READ_ONCE(bss->smt_run_start_ns);
	u64 dur, overlap = 0;
	u16 sibling_cpu;
	u8  sibling_active_start, sibling_active_stop = 0;

	if (start_ns == 0 || stop_ns <= start_ns)
		return 0;

	dur		     = stop_ns - start_ns;
	sibling_active_start = READ_ONCE(bss->smt_sibling_active_start);
	sibling_cpu	     = cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];

	if (sibling_cpu < nr_cpus && sibling_cpu != cpu) {
		struct cake_cpu_bss *sib_bss =
			&cpu_bss[sibling_cpu & (CAKE_MAX_CPUS - 1)];
		u64 sib_start	    = READ_ONCE(sib_bss->smt_run_start_ns);
		u64 sib_stop	    = READ_ONCE(sib_bss->smt_last_stop_ns);

		sibling_active_stop = !READ_ONCE(sib_bss->idle_hint);
		if (sibling_active_stop && sib_start > 0 &&
		    stop_ns > sib_start) {
			u64 lo = start_ns > sib_start ? start_ns : sib_start;
			if (stop_ns > lo)
				overlap = stop_ns - lo;
		} else if (sibling_active_start && sib_stop > start_ns) {
			u64 hi = sib_stop < stop_ns ? sib_stop : stop_ns;
			if (hi > start_ns)
				overlap = hi - start_ns;
		}
	}

	if (overlap > dur)
		overlap = dur;

	if (sibling_active_start)
		s->smt_sibling_active_start_count++;
	if (sibling_active_stop)
		s->smt_sibling_active_stop_count++;

	if (overlap > 0) {
		s->smt_contended_runtime_ns += dur;
		s->smt_contended_run_count++;
		s->smt_overlap_runtime_ns += overlap;
	} else {
		s->smt_solo_runtime_ns += dur;
		s->smt_solo_run_count++;
	}

	bss->smt_last_stop_ns = stop_ns;
	return overlap;
}
#endif

#if !CAKE_LEAN_SCHED
static __noinline
	s32 cake_pick_pressure_sibling(struct cake_task_ctx __arena *tctx,
				       s32			     anchor_cpu,
				       const struct cpumask *cpumask, u8 site)
{
	s32 sibling_cpu;
	u8  anchor_pressure, sibling_pressure;

	cake_record_pressure_probe(site, CAKE_PRESSURE_PROBE_EVALUATED,
				   anchor_cpu);

	if (!tctx || anchor_cpu < 0 || anchor_cpu >= nr_cpus) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR, anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_INVALID, anchor_cpu);
		return -1;
	}
	if (cpu_thread_bit[anchor_cpu & (CAKE_MAX_CPUS - 1)] != 1) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR, anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_SECONDARY, anchor_cpu);
		return -1;
	}

	sibling_cpu = (s32)cpu_sibling_map[anchor_cpu & (CAKE_MAX_CPUS - 1)];
	if (sibling_cpu < 0 || sibling_cpu >= nr_cpus ||
	    sibling_cpu == anchor_cpu) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR, anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_NO_SIBLING, anchor_cpu);
		return -1;
	}
	if (tctx->home_score < CAKE_CPU_PRESSURE_HOME_SCORE_MIN) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_SCORE, anchor_cpu);
		return -1;
	}
	if (!bpf_cpumask_test_cpu((u32)sibling_cpu, cpumask)) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR, anchor_cpu);
		cake_record_pressure_anchor_block(
			site, CAKE_PRESSURE_ANCHOR_AFFINITY, anchor_cpu);
		return -1;
	}

	anchor_pressure	 = cake_read_cpu_pressure((u32)anchor_cpu);
	sibling_pressure = cake_read_cpu_pressure((u32)sibling_cpu);
	if (anchor_pressure < CAKE_CPU_PRESSURE_SPILL_MIN ||
	    anchor_pressure <
		    sibling_pressure + CAKE_CPU_PRESSURE_SPILL_DELTA) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_DELTA, anchor_cpu);
		return -1;
	}
	if (!scx_bpf_test_and_clear_cpu_idle(sibling_cpu)) {
		cake_record_pressure_probe(
			site, CAKE_PRESSURE_PROBE_BLOCKED_SIBLING_BUSY,
			anchor_cpu);
		return -1;
	}

	cake_record_pressure_probe(site, CAKE_PRESSURE_PROBE_SUCCESS,
				   anchor_cpu);

	return sibling_cpu;
}
#endif

/* ═══ Per-Task Context Accessors ═══ */

/* get_task_ctx: returns the task's arena-backed context.
 * Arena storage is allocated in cake_init_task (sleepable context).
 * Cost: ~16-29ns (scx_task_data kfunc + pointer cast).
 * Used by learned locality steering plus iter/debug telemetry. */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p)
{
#if defined(CAKE_RELEASE) || !CAKE_NEEDS_ARENA
	return (struct cake_task_ctx __arena *)0;
#else
	return (struct cake_task_ctx __arena *)scx_task_data(p);
#endif
}

/* get_task_hot: returns the task's Arena storage (~1ns).
 * All callers are behind #ifndef CAKE_RELEASE (telemetry, reclassifier). */
#if CAKE_NEEDS_ARENA
static __always_inline struct cake_task_ctx __arena *
get_task_hot(struct task_struct *p)
{
	return get_task_ctx(p);
}

#endif

#if !CAKE_LEAN_SCHED
static __always_inline bool cake_should_steer(struct task_struct *p,
					      u64		  wake_flags)
{
	if (p->flags & PF_KTHREAD)
		return false;

	/* Protect render/helper wake chains too, not just sustained hot tasks.
	 * A lot of gaming-critical helpers are sync-woken but never build enough
	 * util_avg to qualify as "hot" by PELT alone. */
	return p->se.avg.util_avg >= CAKE_STEER_UTIL_MIN ||
	       (wake_flags & SCX_WAKE_SYNC);
}

static __always_inline bool
cake_should_guard_primary_scan(struct cake_task_ctx __arena *tctx,
			       struct task_struct *p, u64 wake_flags)
{
	/* Behavior-based guard for tiny sync-woken helper chains: once a task has
	 * a stable home, let kernel idle selection handle wide searches instead of
	 * bouncing it across primary lanes on every short wake. */
	if (!(wake_flags & SCX_WAKE_SYNC))
		return false;
	if (p->se.avg.util_avg >= CAKE_STEER_UTIL_MIN)
		return false;
	if (cake_task_is_affinitized(p))
		return false;
	return tctx->home_score >= CAKE_CPU_PRESSURE_HOME_SCORE_MIN;
}

static __noinline bool
cake_should_guard_hot_primary_scan(struct cake_task_ctx __arena *tctx,
				   struct task_struct *p, u64 wake_flags)
{
#ifdef CAKE_RELEASE
	return false;
#else
	struct task_struct *waker;
	u64		    util_avg;
	u32		    runs;
	u64		    total_runtime_ns;

	if (cake_task_is_affinitized(p))
		return false;

	/* Hot same-TGID micro-workers can spend most wakeups proving that an idle
	 * primary lane exists elsewhere. Guard those broad primary scans, but keep
	 * a bounded util/runtime shape so main render/game threads still probe.
	 * This uses behavior shape instead of the wake-sync flag because some game
	 * worker fanouts are same-process and scan-heavy without that wake hint. */
	util_avg = p->se.avg.util_avg;
	if (util_avg < CAKE_STEER_UTIL_MIN ||
	    util_avg > CAKE_HOT_PRIMARY_SCAN_UTIL_MAX)
		return false;

	runs = tctx->telemetry.total_runs;
	if (runs < CAKE_HOT_PRIMARY_SCAN_MIN_RUNS)
		return false;

	waker = bpf_get_current_task_btf();
	if (!waker || waker->tgid != p->tgid)
		return false;

	total_runtime_ns = tctx->telemetry.total_runtime_ns;
	return total_runtime_ns <= (u64)runs * CAKE_HOT_PRIMARY_SCAN_AVG_RUN_NS;
#endif
}

static __always_inline bool
cake_should_hold_wake_chain_locality(struct cake_task_ctx __arena *tctx,
				     struct task_struct *p, u64 wake_flags)
{
	if (!CAKE_WAKE_CHAIN_LOCALITY_ENABLED)
		return false;
	if (!(wake_flags & SCX_WAKE_SYNC) &&
	    p->se.avg.util_avg < CAKE_STEER_UTIL_MIN)
		return false;
	if (p->flags & PF_KTHREAD)
		return false;
	if (cake_task_is_affinitized(p))
		return false;
	if (tctx->home_score < CAKE_WAKE_CHAIN_HOME_SCORE_MIN)
		return false;
	return cake_wake_chain_score_read(tctx) >=
	       CAKE_WAKE_CHAIN_POLICY_SCORE_MIN;
}

static __always_inline bool
cake_wake_chain_credit_allows(struct cake_task_ctx __arena *tctx)
{
	u32 raw	   = READ_ONCE(tctx->primary_scan_credit);
	u32 credit = ((raw >> CAKE_WAKE_CHAIN_CREDIT_SHIFT) &
		      CAKE_WAKE_CHAIN_CREDIT_MASK) +
		     1;

	if (credit >= CAKE_WAKE_CHAIN_CREDIT_PERIOD) {
		tctx->primary_scan_credit = raw & CAKE_PRIMARY_SCAN_CREDIT_MASK;
		return true;
	}

	tctx->primary_scan_credit = (raw & CAKE_PRIMARY_SCAN_CREDIT_MASK) |
				    ((credit & CAKE_WAKE_CHAIN_CREDIT_MASK)
				     << CAKE_WAKE_CHAIN_CREDIT_SHIFT);
	return false;
}

static __always_inline bool
cake_primary_scan_credit_allows_period(struct cake_task_ctx __arena *tctx,
				       u32			     period)
{
	u32 raw	   = READ_ONCE(tctx->primary_scan_credit);
	u32 credit = (raw & CAKE_PRIMARY_SCAN_CREDIT_MASK) + 1;

	if (credit >= period) {
		tctx->primary_scan_credit = raw &
					    ~CAKE_PRIMARY_SCAN_CREDIT_MASK;
		return true;
	}

	tctx->primary_scan_credit = (raw & ~CAKE_PRIMARY_SCAN_CREDIT_MASK) |
				    (credit & CAKE_PRIMARY_SCAN_CREDIT_MASK);
	return false;
}

static __always_inline bool
cake_primary_scan_credit_allows(struct cake_task_ctx __arena *tctx)
{
	return cake_primary_scan_credit_allows_period(
		tctx, CAKE_PRIMARY_SCAN_CREDIT_PERIOD);
}

static __always_inline bool
cake_hot_primary_scan_credit_allows(struct cake_task_ctx __arena *tctx)
{
	return cake_primary_scan_credit_allows_period(
		tctx, CAKE_HOT_PRIMARY_SCAN_CREDIT_PERIOD);
}
#endif

static __always_inline u16 cake_primary_cpu(u16 cpu)
{
	u64 meta;

	if (cpu >= nr_cpus)
		return CAKE_CPU_SENTINEL;

	meta = cake_cpu_meta_for(cpu);
	return (u16)cake_meta_primary_cpu(meta);
}

static __always_inline void
cake_update_home_cpu(struct cake_task_ctx __arena *tctx, u16 cpu)
{
	u16 primary = cake_primary_cpu(cpu);
	if (primary == CAKE_CPU_SENTINEL)
		return;

	if (tctx->home_cpu == CAKE_CPU_SENTINEL) {
		tctx->home_cpu	 = primary;
		tctx->home_score = 1;
		tctx->home_core	 = cpu_core_id[primary & (CAKE_MAX_CPUS - 1)];
		tctx->primary_scan_credit = 0;
		return;
	}

	if (tctx->home_cpu == primary) {
		if (tctx->home_score < CAKE_HOME_SCORE_MAX)
			tctx->home_score++;
		tctx->home_core = cpu_core_id[primary & (CAKE_MAX_CPUS - 1)];
		return;
	}

	if (tctx->home_score > 0) {
		tctx->home_score--;
		return;
	}

	tctx->home_cpu		  = primary;
	tctx->home_score	  = 1;
	tctx->home_core		  = cpu_core_id[primary & (CAKE_MAX_CPUS - 1)];
	tctx->primary_scan_credit = 0;
}

/* ═══ Dedup Helpers ═══
 * Extracted from repeated inline blocks to reduce instruction count
 * and i-cache pressure. All __always_inline: zero call overhead. */

/* smt_sibling removed — native fallback handles full SMT topology when Cake's
 * scoreboard probes do not claim a clean target. */

/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU: PREDICTED SCOREBOARD SELECTION
 * Gate hierarchy: route prediction → scoreboard probes → native fallback →
 * hybrid scan → local tunnel.
 * Task identity and fast-path scheduling state come from task_struct.
 *
 * PRINCIPLE: "Where to run" is orthogonal to "how long to run".
 *   1. Cake predictor: replay a trusted route from the CPU scorecard
 *   2. Cake scoreboard: claim prev/row candidates with cheap published state
 *   3. Native fallback: kernel helper for correctness and broad idle search
 *   4. Hybrid scan: perf-ordered backup when compiled in
 *   5. Tunnel: all busy -> keep prev_cpu and enqueue locally
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

#if CAKE_LEAN_SCHED
u32 select_cpu_and_args_key SEC(".bss");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct scx_bpf_select_cpu_and_args);
	__uint(max_entries, 1);
} select_cpu_and_args_scratch SEC(".maps");
#endif

/* Returns cpu if idle found, -1 otherwise. */
#if !CAKE_LEAN_SCHED
static __noinline s32 select_cpu_dfl_idle(struct task_struct *p, s32 prev_cpu,
					  u64 wake_flags)
{
	bool is_idle = false;
	s32  cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	return is_idle ? cpu : -1;
}
#endif

/* Returns cpu >= 0 if idle found, < 0 otherwise.
 * Compat-First CO-RE Dispatch: same wrapper strategy as local DSQ insert.
 * Prefers register-arg compat (0 stack) over struct-arg (24B on stack). */
#if CAKE_LEAN_SCHED
static __always_inline s32 select_cpu_and_idle(struct task_struct *p,
					       s32 prev_cpu, u64 wake_flags,
					       u64 enq_flags)
{
	if (bpf_ksym_exists(scx_bpf_select_cpu_and___compat))
		return scx_bpf_select_cpu_and___compat(p, prev_cpu, wake_flags,
						       p->cpus_ptr, enq_flags);

	if (bpf_core_type_exists(struct scx_bpf_select_cpu_and_args)) {
		struct scx_bpf_select_cpu_and_args *args = bpf_map_lookup_elem(
			&select_cpu_and_args_scratch, &select_cpu_and_args_key);
		if (!args)
			return -1;

		args->prev_cpu	 = prev_cpu;
		args->wake_flags = wake_flags;
		args->flags	 = enq_flags;
		return __scx_bpf_select_cpu_and(p, p->cpus_ptr, args);
	}
	return -1;
}
#else
static __noinline s32 select_cpu_and_idle(struct task_struct *p, s32 prev_cpu,
					  u64 wake_flags, u64 enq_flags)
{
	/* Path 1: Register-arg compat (0 stack, 5 direct args).
	 * Available 6.15-6.22. JIT dead-codes path 2. */
	if (bpf_ksym_exists(scx_bpf_select_cpu_and___compat))
		return scx_bpf_select_cpu_and___compat(p, prev_cpu, wake_flags,
						       p->cpus_ptr, enq_flags);
	/* Path 2: Struct-arg (6.19+ when compat dropped after v6.23).
	 * Stack build isolated in this __noinline frame. */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr,
				      enq_flags);
}
#endif

#if CAKE_ACCEL_PATH
static __always_inline bool cake_task_latency_biased(struct task_struct *p,
						     u64 wake_flags)
{
	if (wake_flags & SCX_WAKE_SYNC)
		return true;
	if (p->prio < 120)
		return true;
	if (p->scx.weight > 120)
		return true;
	return false;
}

static __always_inline void cake_scoreboard_kick_cpu_known(u32 target_cpu,
							   u64 target_status)
{
	u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[local_cpu];
	bool known_status	 = !!(target_status &
				      (CAKE_CPU_STATUS_IDLE |
				       (CAKE_CPU_STATUS_OWNER_MASK
					<< CAKE_CPU_STATUS_OWNER_SHIFT)));
	u32  mode;

	if ((target_cpu & (CAKE_MAX_CPUS - 1)) != local_cpu) {
		if (target_status & CAKE_CPU_STATUS_IDLE)
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
		else
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
		return;
	}

	if (!(target_status & CAKE_CPU_STATUS_IDLE)) {
		u32 busy_mode = CAKE_BUSY_WAKE_KICK_MODE;

		if (busy_mode == CAKE_BUSY_WAKE_KICK_IDLE) {
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			return;
		}
		if (busy_mode == CAKE_BUSY_WAKE_KICK_PREEMPT) {
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
			return;
		}
	}

	mode = cake_kick_shape_mode(bss, target_status);
	cake_conf_update(bss, CAKE_CONF_KICK_SHAPE_SHIFT, known_status);
	if (mode == CAKE_KICK_SHAPE_NONE)
		return;
	if (mode == CAKE_KICK_SHAPE_IDLE) {
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
		return;
	}
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
}

static __always_inline __maybe_unused void
cake_scoreboard_kick_cpu(u32 target_cpu)
{
	cake_scoreboard_kick_cpu_known(target_cpu,
				       cake_read_cpu_status(target_cpu));
}

static __always_inline bool cake_idle_scoreboard_clean(u64 status)
{
	return cake_status_scoreboard_clean(status);
}

static __noinline s32 cake_try_idle_candidate(
	struct cake_cpu_bss *local_bss, u32 candidate, bool smt_check
#ifndef CAKE_RELEASE
	,
	u32 route_kind
#endif
)
{
#ifdef CAKE_RELEASE
	const u32 route_kind = CAKE_ROUTE_NONE;
#endif
	u64  status;
	bool claimed;

	if (candidate >= nr_cpus) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_INVALID);
		return -1;
	}
#ifdef CAKE_RELEASE
	if (!cake_scoreboard_summary_maybe_clean(candidate)) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_DIRTY);
		return -1;
	}
#endif
	status = cake_read_cpu_status(candidate);
#ifdef CAKE_RELEASE
	if (!(status & CAKE_CPU_STATUS_IDLE) ||
	    !cake_idle_scoreboard_clean(status) ||
	    (smt_check && cake_smt_interactive_neighbor_busy(candidate))) {
		cake_scoreboard_status_result(local_bss, status);
		return -1;
	}
#else
	if (!(status & CAKE_CPU_STATUS_IDLE)) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_BUSY);
		cake_scoreboard_status_result(local_bss, status);
		return -1;
	}
	if (!cake_idle_scoreboard_clean(status)) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_DIRTY);
		cake_scoreboard_status_result(local_bss, status);
		return -1;
	}
	if (smt_check && cake_smt_interactive_neighbor_busy(candidate)) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_SMT_BUSY);
		cake_scoreboard_status_result(local_bss, status);
		return -1;
	}
#endif
	if (!cake_claim_health_allows(local_bss)) {
		cake_record_accel_probe(route_kind,
					CAKE_ACCEL_PROBE_CLAIM_SKIP);
		return -1;
	}
	claimed = scx_bpf_test_and_clear_cpu_idle(candidate);
	cake_scoreboard_claim_result(local_bss, status, claimed);
	if (claimed) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_HIT);
		return (s32)candidate;
	}
	cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_CLAIM_FAIL);
	return -1;
}

#ifdef CAKE_RELEASE
#define cake_try_clean_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, false)
#define cake_try_smt_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, true)
#else
#define cake_try_clean_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, false, route_kind)
#define cake_try_smt_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, true, route_kind)
#endif

static __noinline s32 cake_select_route_predict(struct task_struct *p,
						s32 prev_cpu, u64 wake_flags,
						struct cake_cpu_bss *local_bss)
{
	u64 confidence;
	u8  route_kind;
	u8  slot;
	bool smt_route = false;
	u32 row;
	u32 candidate;
	s32 selected;

	if (prev_cpu < 0 || prev_cpu >= nr_cpus) {
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_INVALID_PREV);
		return CAKE_ROUTE_PREDICT_NONE;
	}
	if (cake_task_is_affinitized(p)) {
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_AFFINITY);
		return CAKE_ROUTE_PREDICT_NONE;
	}
	if (p->flags & PF_KTHREAD) {
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_KTHREAD);
		return CAKE_ROUTE_PREDICT_NONE;
	}

	selected = cake_trust_prev_direct_claim(prev_cpu);
	if (selected >= 0)
		return selected;
	if (selected == CAKE_ROUTE_PREDICT_TRUST_MISS)
		return CAKE_ROUTE_PREDICT_NONE;

	confidence = READ_ONCE(local_bss->decision_confidence);
	if (!cake_route_predict_ready(confidence)) {
		cake_record_accel_route_block(
			cake_route_predict_block_reason(confidence));
		return CAKE_ROUTE_PREDICT_NONE;
	}

	route_kind = cake_route_kind_value(confidence);
	if (route_kind == CAKE_ROUTE_TUNNEL) {
		cake_record_accel_route_attempt(CAKE_ROUTE_TUNNEL);
		if (!cake_floor_mode_ready(confidence)) {
			cake_record_accel_route_result(CAKE_ROUTE_TUNNEL,
						       false);
			cake_record_accel_route_block(
				cake_floor_block_reason(confidence));
			return CAKE_ROUTE_PREDICT_NONE;
		}
		if (cake_route_audit_due(local_bss)) {
			cake_record_accel_route_result(CAKE_ROUTE_TUNNEL,
						       false);
			cake_record_accel_route_block(CAKE_ACCEL_BLOCK_AUDIT);
			return CAKE_ROUTE_PREDICT_NONE;
		}
		cake_record_accel_route_result(CAKE_ROUTE_TUNNEL, true);
		return CAKE_ROUTE_PREDICT_TUNNEL;
	}

	if (route_kind == CAKE_ROUTE_PREV) {
		candidate = (u32)prev_cpu;
		goto claim_clean_route;
	}

	row = ((u32)prev_cpu) & (CAKE_MAX_CPUS - 1);
	if (route_kind == CAKE_ROUTE_SLOT0) {
		candidate = cpu_fast_probe[row][0];
		goto claim_clean_route;
	}

	if (!cake_task_latency_biased(p, wake_flags)) {
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_LATENCY_GATE);
		return CAKE_ROUTE_PREDICT_NONE;
	}

	if ((u8)(route_kind - CAKE_ROUTE_SLOT1) <=
	    (CAKE_ROUTE_SLOT3 - CAKE_ROUTE_SLOT1)) {
		slot = route_kind - CAKE_ROUTE_SLOT0;
		candidate = cpu_fast_probe[row][slot & 3U];
		smt_route = true;
		goto claim_smt_route;
	}

	cake_record_accel_route_block(CAKE_ACCEL_BLOCK_UNKNOWN_ROUTE);
	return CAKE_ROUTE_PREDICT_NONE;

claim_clean_route:
	cake_record_accel_route_attempt(route_kind);
	selected = cake_try_clean_idle_candidate_record(local_bss, candidate,
						       route_kind);
	goto route_claim_done;

claim_smt_route:
	cake_record_accel_route_attempt(route_kind);
	selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
						     route_kind);

route_claim_done:
	(void)smt_route;
	cake_route_update(local_bss, route_kind, selected >= 0);
	cake_record_accel_route_result(route_kind, selected >= 0);
	return selected >= 0 ? selected : CAKE_ROUTE_PREDICT_NONE;
}

static __noinline s32 cake_select_cpu_fast_scan(struct task_struct *p,
						s32 prev_cpu, u64 wake_flags,
						struct cake_cpu_bss *local_bss)
{
	bool latency_biased;
	u32  candidate;
	u32  hit_route;
	u32  scan_limit;
	u32  row;
	s32  selected;

	if (prev_cpu < 0 || prev_cpu >= nr_cpus)
		return -1;
	if (cake_task_is_affinitized(p))
		return -1;

	row	       = ((u32)prev_cpu) & (CAKE_MAX_CPUS - 1);
	latency_biased = cake_task_latency_biased(p, wake_flags);

	cake_record_accel_fast_attempt(CAKE_ROUTE_PREV);
	selected = -1;
	if (cake_fast_mask_maybe_clean((u32)prev_cpu))
		selected = cake_try_clean_idle_candidate_record(
			local_bss, (u32)prev_cpu, CAKE_ROUTE_PREV);
	cake_record_accel_fast_result(CAKE_ROUTE_PREV, selected >= 0);
	if (selected >= 0) {
		hit_route = CAKE_ROUTE_PREV;
		goto fast_hit;
	}

	candidate = cpu_fast_probe[row][0];
	if (candidate != (u32)prev_cpu) {
		cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT0);
		selected = -1;
		if (cake_fast_mask_maybe_clean(candidate))
			selected = cake_try_clean_idle_candidate_record(
				local_bss, candidate, CAKE_ROUTE_SLOT0);
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT0, selected >= 0);
		if (selected >= 0) {
			hit_route = CAKE_ROUTE_SLOT0;
			goto fast_hit;
		}
	}

	if (!latency_biased) {
		goto fast_miss;
	}

	candidate = cpu_fast_probe[row][1];
	cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT1);
	selected = -1;
	if (cake_fast_mask_maybe_clean(candidate))
		selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
							      CAKE_ROUTE_SLOT1);
	cake_record_accel_fast_result(CAKE_ROUTE_SLOT1, selected >= 0);
	if (selected >= 0) {
		hit_route = CAKE_ROUTE_SLOT1;
		goto fast_hit;
	}

	scan_limit = cake_select_fast_scan_limit(local_bss);
	if (scan_limit <= 2) {
		goto fast_miss;
	}

	candidate = cpu_fast_probe[row][2];
	cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT2);
	selected = -1;
	if (cake_fast_mask_maybe_clean(candidate))
		selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
							      CAKE_ROUTE_SLOT2);
	cake_record_accel_fast_result(CAKE_ROUTE_SLOT2, selected >= 0);
	if (selected >= 0) {
		hit_route = CAKE_ROUTE_SLOT2;
		goto fast_hit_row4;
	}

	candidate = cpu_fast_probe[row][3];
	cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT3);
	selected = -1;
	if (cake_fast_mask_maybe_clean(candidate))
		selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
							      CAKE_ROUTE_SLOT3);
	cake_record_accel_fast_result(CAKE_ROUTE_SLOT3, selected >= 0);
	if (selected >= 0) {
		hit_route = CAKE_ROUTE_SLOT3;
		goto fast_hit_row4;
	}

	cake_conf_update_select(local_bss, false, true, false);
	return -1;

fast_miss:
	cake_conf_update_select(local_bss, false, false, false);
	return -1;

fast_hit:
	cake_conf_update_select_route(local_bss, hit_route, true, false, false);
	return selected;

fast_hit_row4:
	cake_conf_update_select_route(local_bss, hit_route, true, true, true);
	return selected;
}
#endif

#define CAKE_SELECT_RESULT(cpu, flags) \
	((((u64)(u32)(cpu)) & 0xffffffffULL) | (((u64)(flags)) << 32))
#define CAKE_SELECT_RESULT_CPU(result) ((s32)(u32)(result))
#define CAKE_SELECT_RESULT_FLAGS(result) ((u16)((result) >> 32))

#if !CAKE_LEAN_SCHED
static __noinline
	u64 cake_select_primary_scan(struct cake_task_ctx __arena *tctx,
				     struct task_struct *p, s32 prev_cpu,
				     u64 wake_flags, u32 local_cpu)
{
	struct cake_stats *stats    = get_local_stats_for(local_cpu);
	u16		   home_cpu = tctx->home_cpu;
	u16		   start_cpu;
	u16		   select_flags = 0;

	if (cpu_sibling_map[prev_cpu & (CAKE_MAX_CPUS - 1)] == prev_cpu)
		return CAKE_SELECT_RESULT(-1, 0);

	start_cpu = home_cpu < nr_cpus ? home_cpu : (u16)prev_cpu;
	start_cpu = cake_primary_cpu(start_cpu);
	if (start_cpu >= nr_cpus)
		return CAKE_SELECT_RESULT(-1, 0);

	if (cake_should_guard_primary_scan(tctx, p, wake_flags)) {
		if (cake_primary_scan_credit_allows(tctx))
			stats->nr_primary_scan_credit_used++;
		else
			select_flags |= CAKE_SEL_PRIMARY_SCAN_GUARDED;
	} else if (cake_should_guard_hot_primary_scan(tctx, p, wake_flags)) {
		if (cake_hot_primary_scan_credit_allows(tctx))
			stats->nr_primary_scan_credit_used++;
		else
			select_flags |= CAKE_SEL_HOT_PRIMARY_SCAN_GUARDED;
	}
	if (cake_should_hold_wake_chain_locality(tctx, p, wake_flags)) {
		if (cake_wake_chain_credit_allows(tctx))
			select_flags |= CAKE_SEL_WAKE_CHAIN_CREDIT_USED;
		else
			select_flags |= CAKE_SEL_WAKE_CHAIN_GUARDED;
	}
	if (!(select_flags & (CAKE_SEL_PRIMARY_SCAN_GUARDED |
			      CAKE_SEL_HOT_PRIMARY_SCAN_GUARDED |
			      CAKE_SEL_WAKE_CHAIN_GUARDED))) {
		for (u32 off = 0; off < CAKE_MAX_CPUS && off < nr_cpus; off++) {
			u16 candidate = (start_cpu + off) % nr_cpus;

			if (candidate == prev_cpu || candidate == home_cpu)
				continue;
			if (cpu_thread_bit[candidate & (CAKE_MAX_CPUS - 1)] !=
			    1)
				continue;
			if (!bpf_cpumask_test_cpu(candidate, p->cpus_ptr))
				continue;
			select_flags |= CAKE_SEL_PRIMARY_SCAN_ATTEMPTED;
			if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
				select_flags |= CAKE_SEL_SCAN_PRIMARY;
				return CAKE_SELECT_RESULT(candidate,
							  select_flags);
			}
		}
	}

	if (select_flags & CAKE_SEL_PRIMARY_SCAN_GUARDED)
		stats->nr_primary_scan_guarded++;
	if (select_flags & CAKE_SEL_HOT_PRIMARY_SCAN_GUARDED)
		stats->nr_primary_scan_hot_guarded++;
	if (select_flags & CAKE_SEL_WAKE_CHAIN_GUARDED)
		stats->nr_wake_chain_locality_guarded++;
	if (select_flags & CAKE_SEL_WAKE_CHAIN_CREDIT_USED)
		stats->nr_wake_chain_locality_credit_used++;
	if (select_flags & CAKE_SEL_PRIMARY_SCAN_ATTEMPTED)
		stats->nr_primary_scan_misses++;

	return CAKE_SELECT_RESULT(-1, select_flags);
}

static __noinline u64 cake_select_learned_locality(struct task_struct *p,
						   s32 prev_cpu, u64 wake_flags,
						   u32 local_cpu)
{
	struct cake_task_ctx __arena *steer_tctx;
	struct cake_stats	     *steer_stats;
	u16			      select_flags = 0;
	s32			      cpu	   = -1;

	if (!CAKE_LEARNED_LOCALITY_ENABLED || !cake_should_steer(p, wake_flags))
		return CAKE_SELECT_RESULT(-1, 0);

	steer_tctx = get_task_ctx(p);
	if (!steer_tctx)
		return CAKE_SELECT_RESULT(-1, 0);

	steer_stats   = get_local_stats_for(local_cpu);
	u16 home_cpu  = steer_tctx->home_cpu;
	u8  home_core = steer_tctx->home_core;

	steer_stats->nr_steer_eligible++;

	cpu = cake_pick_pressure_sibling(steer_tctx, (s32)home_cpu, p->cpus_ptr,
					 CAKE_PRESSURE_PROBE_SITE_HOME);
	if (cpu >= 0)
		return CAKE_SELECT_RESULT(cpu, CAKE_SEL_PRESSURE_CORE);

	if (home_cpu < nr_cpus && home_cpu != prev_cpu &&
	    bpf_cpumask_test_cpu(home_cpu, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(home_cpu))
			return CAKE_SELECT_RESULT(home_cpu, CAKE_SEL_HOME);
		steer_stats->nr_home_cpu_busy_misses++;
	}

	if ((wake_flags & SCX_WAKE_SYNC) && home_core < 0xFF &&
	    home_cpu < CAKE_MAX_CPUS) {
		u16 candidate = cpu_sibling_map[home_cpu & (CAKE_MAX_CPUS - 1)];

		if (candidate < nr_cpus && candidate != home_cpu &&
		    candidate != (u32)prev_cpu &&
		    cpu_core_id[candidate & (CAKE_MAX_CPUS - 1)] == home_core &&
		    bpf_cpumask_test_cpu(candidate, p->cpus_ptr)) {
			if (scx_bpf_test_and_clear_cpu_idle(candidate))
				return CAKE_SELECT_RESULT((s32)candidate,
							  CAKE_SEL_HOME_CORE);
		}
	}

	u16 prev_primary = cake_primary_cpu((u16)prev_cpu);
	cpu = cake_pick_pressure_sibling(steer_tctx, (s32)prev_primary,
					 p->cpus_ptr,
					 CAKE_PRESSURE_PROBE_SITE_PREV);
	if (cpu >= 0)
		return CAKE_SELECT_RESULT(cpu, CAKE_SEL_PRESSURE_CORE);

	if (prev_primary < nr_cpus && prev_primary != prev_cpu &&
	    prev_primary != home_cpu &&
	    bpf_cpumask_test_cpu(prev_primary, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_primary))
			return CAKE_SELECT_RESULT(prev_primary,
						  CAKE_SEL_PREV_PRIMARY);
		steer_stats->nr_prev_primary_busy_misses++;
	}

	{
		u64 primary = cake_select_primary_scan(steer_tctx, p, prev_cpu,
						       wake_flags, local_cpu);

		select_flags |= CAKE_SELECT_RESULT_FLAGS(primary);
		cpu = CAKE_SELECT_RESULT_CPU(primary);
		if (cpu >= 0)
			return CAKE_SELECT_RESULT(cpu, select_flags);
	}

	return CAKE_SELECT_RESULT(-1, select_flags);
}
#endif

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* Release uses arena-backed task context only after cake_should_steer()
	 * says the task has enough history to benefit from learned locality.
	 * ARENA_ASSOC is still debug-only bookkeeping. */
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

#ifndef CAKE_RELEASE
#define stats_on 1
	u32 local_cpu  = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	u64 start_time = bpf_ktime_get_ns();
#else
#define stats_on 0
	u64 start_time = 0;
	u32 local_cpu  = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
#endif
#if CAKE_ACCEL_PATH
	struct cake_cpu_bss *select_bss = &cpu_bss[local_cpu];
#endif
	u16 select_flags = 0;
	u64 gate2_start	 = 0;
	s32 cpu		 = -1;

	/* ── CAKE SCOREBOARD / PREDICTION ──
	 * This is the latency floor path. Native helpers are deliberately behind
	 * it and act as the safe fallback when prediction or cheap claims miss. */
#if CAKE_ACCEL_PATH
	if (prev_cpu >= 0 &&
	    (((u32)prev_cpu) & (CAKE_MAX_CPUS - 1)) == local_cpu) {
		cpu = cake_select_route_predict(p, prev_cpu, wake_flags,
						select_bss);
	} else {
		cpu = CAKE_ROUTE_PREDICT_NONE;
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_UNKNOWN_ROUTE);
	}
	if (cpu == CAKE_ROUTE_PREDICT_TUNNEL)
		goto tunnel;
	if (cpu >= 0) {
		select_flags |= cpu == prev_cpu ? CAKE_SEL_SCOREBOARD_PREV :
						  CAKE_SEL_SCOREBOARD_SCAN;
		goto idle_found;
	}

	cpu = cake_select_cpu_fast_scan(p, prev_cpu, wake_flags, select_bss);
	if (cpu >= 0) {
		select_flags |= cpu == prev_cpu ? CAKE_SEL_SCOREBOARD_PREV :
						  CAKE_SEL_SCOREBOARD_SCAN;
		goto idle_found;
	}
#endif

#if !CAKE_LEAN_SCHED
	{
		u64 learned = cake_select_learned_locality(
			p, prev_cpu, wake_flags, local_cpu);
		select_flags = CAKE_SELECT_RESULT_FLAGS(learned);
		cpu	     = CAKE_SELECT_RESULT_CPU(learned);
		if (cpu >= 0)
			goto idle_found;
	}
#endif

	if (select_flags & CAKE_SEL_WAKE_CHAIN_GUARDED)
		goto tunnel;

	cake_record_accel_native(CAKE_ACCEL_NATIVE_ENTRY);

	/* ── NATIVE IDLE FALLBACK ──
	 * Uses scx_bpf_select_cpu_and (6.17+) or scx_bpf_select_cpu_dfl (6.12+).
	 * CO-RE dead-code eliminates the unused path at load time.
	 * Both provide: prev_cpu idle test, SYNC wake-affine, SMT full-idle,
	 * LLC-scoped scan, NUMA-scoped scan, global scan, and proper
	 * affinity handling for restricted tasks (Wine/Proton). */
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
#if !CAKE_LEAN_SCHED
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		/* Kernel ≤ 6.16: scx_bpf_select_cpu_dfl via noinline wrapper.
		 * CO-RE prunes this entire block on 6.17+. */
		cake_record_accel_native(CAKE_ACCEL_NATIVE_DFL);
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
#endif

	/* Native idle selection handles affinity, SMT, and topology-aware idle
	 * choice. Keep the local branch tree small and let CO-RE prune the unused
	 * kernel ABI path at load time. */
	cake_record_accel_native(CAKE_ACCEL_NATIVE_AND);
	cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);
	if (cpu >= 0)
		goto idle_found;

	/* No idle CPU was found; tunnel back to prev_cpu for local enqueue. */
	if (cpu >= 0) {
idle_found:
		__attribute__((unused));
		u16 select_choice;

		if (select_flags & CAKE_SEL_HOME)
			select_choice =
				CAKE_SELECT_CHOICE(CAKE_SELECT_PATH_HOME_CPU,
						   CAKE_SELECT_REASON_HOME_CPU);
		else if (select_flags &
			 (CAKE_SEL_HOME_CORE | CAKE_SEL_PRESSURE_CORE))
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_HOME_CORE,
				(select_flags & CAKE_SEL_HOME_CORE) ?
					CAKE_SELECT_REASON_HOME_CORE :
					CAKE_SELECT_REASON_PRESSURE_CORE);
		else if (select_flags &
			 (CAKE_SEL_PREV_PRIMARY | CAKE_SEL_SCAN_PRIMARY))
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_PRIMARY,
				(select_flags & CAKE_SEL_PREV_PRIMARY) ?
					CAKE_SELECT_REASON_PREV_PRIMARY :
					CAKE_SELECT_REASON_PRIMARY_SCAN);
		else if (select_flags & CAKE_SEL_GATE2)
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_IDLE,
				CAKE_SELECT_REASON_HYBRID_SCAN);
		else if (select_flags & CAKE_SEL_SCOREBOARD_PREV)
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_IDLE,
				CAKE_SELECT_REASON_SCOREBOARD_PREV);
		else if (select_flags & CAKE_SEL_SCOREBOARD_SCAN)
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_IDLE,
				CAKE_SELECT_REASON_SCOREBOARD_SCAN);
		else if (cpu == prev_cpu)
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_IDLE,
				CAKE_SELECT_REASON_KERNEL_PREV);
		else
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_IDLE,
				CAKE_SELECT_REASON_KERNEL_IDLE);
		cake_record_select_choice(
			CAKE_SELECT_CHOICE_REASON(select_choice), prev_cpu,
			cpu);
		if (stats_on) {
			u64		   now = bpf_ktime_get_ns();
			u64		   dur = now - start_time;
			struct cake_stats *s   = get_local_stats_for(local_cpu);
			if (gate2_start) {
				s->total_gate1_latency_ns +=
					gate2_start - start_time;
				s->total_gate2_latency_ns += now - gate2_start;
			} else {
				s->total_gate1_latency_ns += dur;
			}
			if (select_flags & CAKE_SEL_HOME)
				s->nr_home_cpu_steers++;
			else if (select_flags &
				 (CAKE_SEL_HOME_CORE | CAKE_SEL_PRESSURE_CORE))
				s->nr_home_core_steers++;
			else if (select_flags & (CAKE_SEL_PREV_PRIMARY |
						 CAKE_SEL_SCAN_PRIMARY))
				s->nr_primary_cpu_steers++;
			s->select_path_count[CAKE_SELECT_CHOICE_PATH(
				select_choice)]++;
			s->total_select_cpu_ns += dur;
			cake_record_select_decision_cost(
				s, CAKE_SELECT_CHOICE_REASON(select_choice),
				dur);
			s->max_select_cpu_ns = s->max_select_cpu_ns +
					       ((dur - s->max_select_cpu_ns) &
						-(dur > s->max_select_cpu_ns));
			cake_record_cb(s, CAKE_CB_SELECT, dur);
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				cake_record_startup_select(tctx, s, start_time);
				tctx->telemetry.select_cpu_duration_ns =
					(u32)dur;
				tctx->telemetry.gate_cascade_ns = (u32)dur;
				tctx->telemetry.pending_select_path =
					CAKE_SELECT_CHOICE_PATH(select_choice);
				tctx->telemetry.pending_select_reason =
					CAKE_SELECT_CHOICE_REASON(
						select_choice);
				tctx->telemetry.last_place_class =
					cake_classify_home_place(
						tctx,
						cpu & (CAKE_MAX_CPUS - 1));
				tctx->telemetry.last_waker_place_class =
					cake_classify_waker_place(
						tctx,
						cpu & (CAKE_MAX_CPUS - 1));
				if (select_flags & CAKE_SEL_HOME)
					tctx->telemetry.gate_1c_hits++;
				else if (select_flags &
					 (CAKE_SEL_HOME_CORE |
					  CAKE_SEL_PRESSURE_CORE))
					tctx->telemetry.gate_1c_hits++;
				else if (select_flags & CAKE_SEL_PREV_PRIMARY)
					tctx->telemetry.gate_1cp_hits++;
				else if (select_flags & CAKE_SEL_SCAN_PRIMARY)
					tctx->telemetry.gate_1cp_hits++;
				else if (select_flags & CAKE_SEL_GATE2)
					tctx->telemetry.gate_2_hits++;
				else
					tctx->telemetry.gate_1_hits++;
				if (cpu != prev_cpu) {
					tctx->telemetry.migration_count++;
					cake_record_select_migration(
						s,
						CAKE_SELECT_CHOICE_PATH(
							select_choice),
						CAKE_SELECT_CHOICE_REASON(
							select_choice));
				}
			}
#endif
			if (dur >= CAKE_SLOW_CALLBACK_NS)
				cake_emit_dbg_event(p, local_cpu,
						    CAKE_DBG_EVENT_CALLBACK,
						    CAKE_CB_SELECT, dur, cpu);
		}
		return cpu;
	}

	/* ── GATE 2: Performance-ordered idle scan (HYBRID ONLY) ──
	 * Compiled out on homogeneous AMD SMP — verifier never sees this code.
	 * With game detection removed, this is a simple fast-to-slow idle scan. */
#ifdef CAKE_HAS_HYBRID
gate2:
	if (stats_on && !gate2_start)
		gate2_start = bpf_ktime_get_ns();
	if (has_hybrid_cores) {
		const u8 *scan_order = cpus_fast_to_slow;

		for (u32 i = 0; i < CAKE_MAX_CPUS && i < nr_cpus; i++) {
			u8 candidate = scan_order[i];
			if (candidate >= nr_cpus)
				break; /* 0xFF sentinel or out of range */

			if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
				cpu = candidate;
				select_flags |= CAKE_SEL_GATE2;
				goto idle_found;
			}
		}
	}
#endif

/* ── TUNNEL: All CPUs busy — return prev_cpu ──
	 * The enqueue path keeps runnable ownership local to the selected CPU,
	 * so select_cpu does not need a separate shared fallback state here. */
tunnel:
	/* When no idle core is found, keep placement on prev_cpu and let
	 * enqueue route the task through the normal per-CPU local path. */
	{
#if CAKE_ACCEL_PATH
		cake_route_update(select_bss, CAKE_ROUTE_TUNNEL, true);
#endif
		cake_record_select_choice(CAKE_SELECT_REASON_TUNNEL, prev_cpu,
					  -1);
		if (stats_on) {
			struct cake_stats *s = get_local_stats_for(local_cpu);
			u64 dur		     = bpf_ktime_get_ns() - start_time;
			s->nr_prev_cpu_tunnels++;
			s->select_path_count[CAKE_SELECT_PATH_TUNNEL]++;
			if (gate2_start) {
				s->total_gate1_latency_ns +=
					gate2_start - start_time;
				s->total_gate2_latency_ns +=
					dur - (gate2_start - start_time);
			} else {
				s->total_gate1_latency_ns += dur;
			}
			s->total_select_cpu_ns += dur;
			cake_record_select_decision_cost(
				s, CAKE_SELECT_REASON_TUNNEL, dur);
			s->max_select_cpu_ns = s->max_select_cpu_ns +
					       ((dur - s->max_select_cpu_ns) &
						-(dur > s->max_select_cpu_ns));
			cake_record_cb(s, CAKE_CB_SELECT, dur);
#ifndef CAKE_RELEASE
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				cake_record_startup_select(tctx, s, start_time);
				tctx->telemetry.select_cpu_duration_ns =
					(u32)dur;
				tctx->telemetry.gate_cascade_ns = (u32)dur;
				tctx->telemetry.gate_tun_hits++;
				tctx->telemetry.pending_select_path =
					CAKE_SELECT_PATH_TUNNEL;
				tctx->telemetry.pending_select_reason =
					CAKE_SELECT_REASON_TUNNEL;
				tctx->telemetry.last_place_class =
					cake_classify_home_place(
						tctx,
						prev_cpu & (CAKE_MAX_CPUS - 1));
				tctx->telemetry.last_waker_place_class =
					cake_classify_waker_place(
						tctx,
						prev_cpu & (CAKE_MAX_CPUS - 1));
			}
#endif
			if (dur >= CAKE_SLOW_CALLBACK_NS)
				cake_emit_dbg_event(p, local_cpu,
						    CAKE_DBG_EVENT_CALLBACK,
						    CAKE_CB_SELECT, dur,
						    prev_cpu);
		}
	}

	return prev_cpu;
#undef stats_on
}
/* Depth-scaled slicing was removed; local queues are intentionally kept
 * simple and short-lived, so queue-depth policy is not part of the fast path. */

/* enqueue_dsq_dispatch: inserts a task into the target CPU's local DSQ
 * and optionally direct-dispatches it when the target still looks idle.
 *
 * Follows kernel enqueue_entity pattern. All scheduling state lives in p:
 *   - p->scx.dsq_vtime: task's position in the vtime-ordered DSQ
 *   - p->scx.slice: remaining time slice for this dispatch
 *
 * schbench regresses if we force a direct handoff to a target CPU that
 * still appears busy, so direct dispatch remains gated by cake's per-CPU
 * idle hint.
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
 * ═══════════════════════════════════════════════════════════════════ */

static __noinline void dsq_insert_wrapper(struct task_struct *p, u64 dsq_id,
					  u64 slice, u64 enq_flags)
{
	if (bpf_ksym_exists(scx_bpf_dsq_insert___v2___compat))
		scx_bpf_dsq_insert___v2___compat(p, dsq_id, slice, enq_flags);
	else if (bpf_ksym_exists(scx_bpf_dsq_insert___v1))
		scx_bpf_dsq_insert___v1(p, dsq_id, slice, enq_flags);
	else
		scx_bpf_dispatch___compat(p, dsq_id, slice, enq_flags);

#ifndef CAKE_RELEASE
	cake_record_local_insert(dsq_id);
#endif
}

static __noinline void dsq_insert_vtime_wrapper(struct task_struct *p,
						u64 dsq_id, u64 slice,
						u64 vtime, u64 enq_flags)
{
	if (bpf_ksym_exists(scx_bpf_dsq_insert_vtime___compat))
		scx_bpf_dsq_insert_vtime___compat(p, dsq_id, slice, vtime,
						  enq_flags);
	else
		scx_bpf_dispatch_vtime___compat(p, dsq_id, slice, vtime,
						enq_flags);
}

static __always_inline __maybe_unused u32 cake_llc_id_for_cpu(u32 cpu)
{
#ifdef CAKE_SINGLE_LLC
	(void)cpu;
	return 0;
#else
	u32 llc = cake_meta_llc_id(cake_cpu_meta_for(cpu));

	if (llc >= nr_llcs)
		llc = 0;
	return llc;
#endif
}

static __always_inline u64 cake_llc_dsq_for_cpu(u32 cpu)
{
#ifdef CAKE_SINGLE_LLC
	(void)cpu;
	return LLC_DSQ_BASE;
#else
	return cpu_llc_dsq[cpu & (CAKE_MAX_CPUS - 1)];
#endif
}

static __always_inline void cake_record_shared_vtime_insert(u64	 enq_flags,
							    bool preserve_state,
							    u32	 stats_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(stats_cpu);

		stats->nr_shared_vtime_inserts++;
		stats->nr_dsq_queued++;
		if (enq_flags & (u64)SCX_ENQ_WAKEUP) {
			stats->nr_shared_wakeup_inserts++;
			stats->nr_wakeup_dsq_fallback_busy++;
			stats->nr_llc_vtime_wake_busy_shared++;
		} else if (preserve_state) {
			stats->nr_llc_vtime_nonwake_shared++;
			stats->nr_shared_preserve_inserts++;
		} else if (enq_flags &
			   ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT)) {
			stats->nr_llc_vtime_nonwake_shared++;
			stats->nr_shared_requeue_inserts++;
		} else {
			stats->nr_llc_vtime_nonwake_shared++;
			stats->nr_shared_other_inserts++;
		}
	}
#else
	(void)enq_flags;
	(void)preserve_state;
	(void)stats_cpu;
#endif
}

static __always_inline void cake_record_busy_local_insert(u32 stats_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(stats_cpu);

		__sync_fetch_and_add(&stats->nr_direct_local_inserts, 1);
		__sync_fetch_and_add(&stats->nr_wakeup_direct_dispatches, 1);
	}
#else
	(void)stats_cpu;
#endif
}

static __noinline void cake_clamp_wakeup_vtime(struct task_struct *p,
					       u32		   target_cpu);

static __always_inline u64 cake_throughput_dsq_for_cpu(u32 cpu)
{
	return CAKE_THROUGHPUT_DSQ_BASE + (cpu & (CAKE_MAX_CPUS - 1));
}

static __always_inline bool
cake_initial_shared_escape_candidate(const struct task_struct *p,
				     u64 target_status)
{
	u64 overloaded = ((u64)CAKE_CPU_OWNER_BULK
			  << CAKE_CPU_STATUS_OWNER_SHIFT) |
			 ((u64)CAKE_CPU_PRESSURE_HIGH
			  << CAKE_CPU_STATUS_PRESS_SHIFT);

	if ((target_status & CAKE_CPU_STATUS_IDLE) ||
	    !(target_status & overloaded))
		return false;
	if (target_status & CAKE_CPU_STATUS_SAT_CACHE_MEM)
		return false;
	if (cake_task_is_affinitized(p) || p->prio < 120 || p->scx.weight > 120)
		return false;
	return true;
}

static __always_inline bool
cake_requeue_shared_escape_candidate(const struct task_struct *p,
				     u64 target_status, u32 target_cpu)
{
	u64 overloaded = ((u64)CAKE_CPU_OWNER_BULK
			  << CAKE_CPU_STATUS_OWNER_SHIFT) |
			 ((u64)CAKE_CPU_PRESSURE_HIGH
			  << CAKE_CPU_STATUS_PRESS_SHIFT);

	if ((target_status & CAKE_CPU_STATUS_IDLE) ||
	    !(target_status & overloaded))
		return false;
	if (target_status & CAKE_CPU_STATUS_SAT_CACHE_MEM)
		return false;
	if (cake_task_is_affinitized(p) || p->prio < 120 || p->scx.weight > 120)
		return false;
	(void)target_cpu;
	return true;
}

static __always_inline void
cake_insert_shared_escape(struct task_struct *p, u64 enq_flags, u32 target_cpu,
			  u64 slice, bool preserve_state)
{
	dsq_insert_vtime_wrapper(p, cake_llc_dsq_for_cpu(target_cpu), slice,
				 p->scx.dsq_vtime, enq_flags);
	cake_record_shared_vtime_insert(enq_flags, preserve_state, target_cpu);
}

static __always_inline bool
cake_busy_wake_shared_escape_candidate(const struct task_struct *wakee,
				       u64 target_status)
{
	u64 owner_bits = target_status &
			 (CAKE_CPU_STATUS_OWNER_MASK <<
			  CAKE_CPU_STATUS_OWNER_SHIFT);

	if (target_status & CAKE_CPU_STATUS_IDLE)
		return false;
	if (target_status & CAKE_CPU_STATUS_SAT_CACHE_MEM)
		return false;
	if (!(target_status &
	      ((u64)CAKE_CPU_PRESSURE_HIGH << CAKE_CPU_STATUS_PRESS_SHIFT)) &&
	    owner_bits < ((u64)CAKE_CPU_OWNER_FRAME
			  << CAKE_CPU_STATUS_OWNER_SHIFT))
		return false;
	if (cake_task_is_affinitized(wakee) || wakee->prio < 120 ||
	    wakee->scx.weight > 120)
		return false;
	return true;
}

static __always_inline void cake_kick_busy_wake_shared_escape(u32 target_cpu,
							      u64 target_status)
{
	u32 owner = cake_status_owner_class(target_status) & 7U;
	u64 preempt = !!(target_status & CAKE_CPU_STATUS_SAT_CACHE_MEM) |
		      ((0xf1U >> owner) & 1U);
	u64 kick = (u64)SCX_KICK_IDLE ^
		   (((u64)SCX_KICK_IDLE ^ (u64)SCX_KICK_PREEMPT) & -preempt);

	scx_bpf_kick_cpu(target_cpu, kick);
}

static __noinline bool
cake_busy_wake_shrink_current(u32 target_cpu, struct task_struct *wakee,
			      u64 target_status)
{
	struct task_struct *curr;
	bool latency_wakee;
	u32 op;
	u32 owner_class;
	u32 pressure;
	bool can_tighten;
	u64 limit;

	if (target_status & CAKE_CPU_STATUS_IDLE)
		return false;

	op = cake_status_owner_pressure(target_status);
	owner_class = op & CAKE_CPU_STATUS_OWNER_MASK;
	if (owner_class == CAKE_CPU_OWNER_SHORT)
		return false;
	latency_wakee = wakee->prio < 120 || wakee->scx.weight > 120;
	pressure = (op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
			   CAKE_CPU_STATUS_OWNER_SHIFT)) &
		   CAKE_CPU_STATUS_PRESS_MASK;
	can_tighten = latency_wakee &&
		      !(target_status & CAKE_CPU_STATUS_SAT_CACHE_MEM) &&
		      pressure <= CAKE_CPU_PRESSURE_MED;
	if (!can_tighten)
		return false;

	curr = __COMPAT_scx_bpf_cpu_curr(target_cpu);
	if (!curr || curr == wakee || (curr->flags & PF_IDLE))
		return false;

	limit = quantum_ns >> 1;
	limit += (CAKE_BUSY_WAKE_SHRINK_MIN_NS - limit) &
		 -(limit < CAKE_BUSY_WAKE_SHRINK_MIN_NS);

	if (curr->scx.slice <= limit)
		return false;
	curr->scx.slice = limit;
	return true;
}

static __always_inline bool
cake_try_insert_throughput_lane(struct task_struct *p, u32 target_cpu,
			       u64 slice, u64 enq_flags)
{
	u32 idx = target_cpu & (CAKE_MAX_CPUS - 1);

	if (READ_ONCE(throughput_lane[idx].pending))
		return false;

	dsq_insert_vtime_wrapper(p, cake_throughput_dsq_for_cpu(target_cpu), slice,
				 p->scx.dsq_vtime, enq_flags);
	WRITE_ONCE(throughput_lane[idx].pending, 1);
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(idx);

		stats->nr_cache_throughput_lane_insert++;
		stats->nr_dsq_queued++;
	}
#endif
	return true;
}

static __always_inline void
cake_insert_throughput_overflow(struct task_struct *p,
			       struct cake_cpu_bss *target_bss,
			       u32 target_cpu, u64 slice, u64 enq_flags,
			       bool preserve_state)
{
	if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
	}

#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(target_cpu)
			->nr_cache_throughput_lane_spill++;
#endif
	cake_throughput_mark_shared_miss(target_bss);
	cake_insert_shared_escape(p, enq_flags, target_cpu, slice, preserve_state);
}

static __always_inline bool
cake_throughput_fairness_due(struct cake_cpu_bss *bss, u32 cpu)
{
	u64 dec = READ_ONCE(bss->throughput_decision);
	u32 pulls;
	s32 queued;

	if (dec & CAKE_TP_DEC_FAIR_HINT)
		return true;
	pulls = dec & CAKE_TP_DEC_PULL_MASK;
	if (pulls < CAKE_THROUGHPUT_FAIR_DISPATCH_BUDGET)
		return false;

	queued = scx_bpf_dsq_nr_queued(cake_llc_dsq_for_cpu(cpu));
	if (queued > 0)
		return true;

	cake_throughput_reset_dispatch_budget(bss);
	return false;
}

static __always_inline void
cake_throughput_charge_dispatch(struct cake_cpu_bss *bss)
{
	u64 dec = READ_ONCE(bss->throughput_decision);
	u32 pulls = dec & CAKE_TP_DEC_PULL_MASK;

	if (pulls < CAKE_THROUGHPUT_FAIR_DISPATCH_BUDGET) {
		u64 next = (dec & ~CAKE_TP_DEC_PULL_MASK) | (pulls + 1);

		WRITE_ONCE(bss->throughput_decision, next);
	}
}

static __always_inline bool
cake_dispatch_pull_throughput_cpu(u32 consumer_cpu, u32 owner_cpu, bool steal)
{
	u32 idx = owner_cpu & (CAKE_MAX_CPUS - 1);

	if (!READ_ONCE(throughput_lane[idx].pending))
		return false;

	if (scx_bpf_dsq_move_to_local(cake_throughput_dsq_for_cpu(owner_cpu), 0)) {
		WRITE_ONCE(throughput_lane[idx].pending, 0);
#ifndef CAKE_RELEASE
		if (CAKE_PATH_STATS_ACTIVE) {
			struct cake_stats *stats = get_local_stats_for(consumer_cpu);

			if (steal)
				stats->nr_cache_throughput_lane_steal_hit++;
			else
				stats->nr_cache_throughput_lane_local_hit++;
			stats->nr_dsq_consumed++;
		}
#endif
		return true;
	}

	WRITE_ONCE(throughput_lane[idx].pending, 0);
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(consumer_cpu)->nr_cache_throughput_lane_stale++;
#endif
	return false;
}

static __always_inline bool cake_dispatch_try_throughput_lane(u32 cpu_idx)
{
	u32 candidate;

	if (cake_dispatch_pull_throughput_cpu(cpu_idx, cpu_idx, false))
		return true;
	if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL)
		return false;

	candidate = cpu_fast_probe[cpu_idx][0];
	if (candidate < nr_cpus && candidate != cpu_idx)
		return cake_dispatch_pull_throughput_cpu(cpu_idx, candidate, true);
	return false;
}

static __noinline void cake_insert_llc_vtime(struct task_struct *p,
					     u64 enq_flags, u32 target_cpu,
					     u64 slice)
{
	bool preserve_state =
		!!(enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT));
	bool is_wakeup = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);

	if (is_wakeup) {
		u64 target_status   = cake_read_cpu_status(target_cpu);
		u8  scoreboard_idle = !!(target_status & CAKE_CPU_STATUS_IDLE);

		if (scoreboard_idle) {
#ifndef CAKE_RELEASE
			if (CAKE_PATH_STATS_ACTIVE) {
				struct cake_stats *stats =
					get_local_stats_for(target_cpu);

				stats->nr_llc_vtime_wake_idle_direct++;
				stats->nr_direct_local_inserts++;
				stats->nr_wakeup_direct_dispatches++;
			}
#endif
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   slice, enq_flags);
			return;
		}

#if CAKE_ACCEL_PATH
		if (cake_accept_busy_wake(target_cpu, target_status)) {
			cake_record_busy_local_insert(target_cpu);
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   slice, enq_flags);
			cake_scoreboard_kick_cpu_known(target_cpu,
						       target_status);
			return;
		}
		if (cake_storm_guard_accept_busy_wake(target_cpu,
						      target_status)) {
			cake_record_busy_local_insert(target_cpu);
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   slice, enq_flags);
			cake_scoreboard_kick_cpu_known(target_cpu,
						       target_status);
			return;
		}
#endif

		dsq_insert_vtime_wrapper(p, cake_llc_dsq_for_cpu(target_cpu),
					 slice, p->scx.dsq_vtime, enq_flags);
		cake_record_shared_vtime_insert(enq_flags, preserve_state,
						target_cpu);
#if CAKE_ACCEL_PATH
		cake_scoreboard_kick_cpu_known(target_cpu, target_status);
#else
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
#endif
		return;
	}

#if CAKE_ACCEL_PATH
	{
		u64 target_status = cake_read_cpu_status(target_cpu);

		if ((target_status & CAKE_CPU_STATUS_IDLE) &&
		    cake_idle_scoreboard_clean(target_status)) {
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu,
					   slice, enq_flags);
			return;
		}
	}
#endif

	dsq_insert_vtime_wrapper(p, cake_llc_dsq_for_cpu(target_cpu), slice,
				 p->scx.dsq_vtime, enq_flags);
	cake_record_shared_vtime_insert(enq_flags, preserve_state, target_cpu);
}

#if CAKE_LEAN_SCHED
static __always_inline
#else
static __noinline
#endif
	s64 calc_nice_adj(u32 weight)
{
	s32 wd = 100 - (s32)weight;
	return ((s64)wd << 14) + ((s64)wd << 12);
}

static __noinline void enqueue_dsq_dispatch(struct task_struct *p,
					    u64 enq_flags, u32 enq_cpu)
{
#if CAKE_LEAN_SCHED
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
		cake_insert_llc_vtime(p, enq_flags, enq_cpu, p->scx.slice);
		return;
	}

	u64 target_status   = cake_read_cpu_status(enq_cpu);
	u8  scoreboard_idle = !!(target_status & CAKE_CPU_STATUS_IDLE);

#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(enq_cpu);

		stats->nr_direct_local_inserts++;
		if (enq_flags & (u64)SCX_ENQ_WAKEUP) {
			if (scoreboard_idle)
				stats->nr_wakeup_direct_dispatches++;
			else
				stats->nr_wakeup_dsq_fallback_busy++;
		} else {
			stats->nr_direct_other_inserts++;
		}
	}
#endif
#if CAKE_ACCEL_PATH
	if ((enq_flags & (u64)SCX_ENQ_WAKEUP) && !scoreboard_idle) {
		if (cake_busy_wake_shared_escape_candidate(p,
							   target_status)) {
			cake_clamp_wakeup_vtime(p, enq_cpu);
			cake_insert_shared_escape(p, enq_flags, enq_cpu,
						  p->scx.slice, false);
#ifndef CAKE_RELEASE
			if (CAKE_PATH_STATS_ACTIVE) {
				struct cake_stats *stats =
					get_local_stats_for(enq_cpu);

				stats->nr_busy_wake_shared_escape++;
			}
#endif
			cake_kick_busy_wake_shared_escape(enq_cpu,
							  target_status);
			return;
		}
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
				   enq_flags);
		cake_busy_wake_shrink_current(enq_cpu, p, target_status);
		cake_scoreboard_kick_cpu_known(enq_cpu, target_status);
		return;
	}
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
			   enq_flags);
#ifndef CAKE_RELEASE
	if ((enq_flags & (u64)SCX_ENQ_WAKEUP) && !scoreboard_idle)
		scx_bpf_kick_cpu(enq_cpu, SCX_KICK_PREEMPT);
#endif
	return;
#else
	u32  target_cpu_idx    = enq_cpu & (CAKE_MAX_CPUS - 1);
	bool can_direct	       = false;
	u8   idle_hint	       = 0;
	s32  kick_cpu	       = -1;
	u64  kick_flags	       = SCX_KICK_IDLE;
	bool is_wakeup	       = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);
	bool wake_target_local = false;
#ifndef CAKE_RELEASE
	bool		   stats_on = CAKE_STATS_ACTIVE;
	struct cake_stats *stats    = stats_on ? get_local_stats() : NULL;
	struct cake_task_ctx __arena *tctx = NULL;
	if (stats_on) {
		tctx = get_task_ctx(p);
	}
#else
#define stats_on 0
#define stats ((struct cake_stats *)0)
#endif

	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
		cake_insert_llc_vtime(p, enq_flags, enq_cpu, p->scx.slice);
		return;
	}

	if (is_wakeup) {
#ifndef CAKE_RELEASE
		if (stats_on && tctx) {
			tctx->telemetry.pending_target_cpu = (u16)enq_cpu;
			tctx->telemetry.pending_kick_kind = CAKE_KICK_KIND_NONE;
			tctx->telemetry.pending_kick_ts_ns  = 0;
			tctx->telemetry.pending_blocker_pid = 0;
			tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
			tctx->telemetry.pending_strict_owner_class =
				CAKE_WAKE_CLASS_NONE;
			tctx->telemetry.pending_target_pressure = 0;
		}
#endif
		u32 current_cpu_idx = bpf_get_smp_processor_id() &
				      (CAKE_MAX_CPUS - 1);
		wake_target_local   = current_cpu_idx == target_cpu_idx;

		if (current_cpu_idx == target_cpu_idx) {
			if (stats) {
				stats->nr_wakeup_dsq_fallback_busy++;
				stats->nr_wakeup_busy_local_target++;
				stats->nr_enqueue_busy_local_skip_depth++;
			}
#ifndef CAKE_RELEASE
			if (tctx) {
				tctx->telemetry.pending_wake_reason =
					CAKE_WAKE_REASON_BUSY;
				tctx->telemetry.pending_blocker_pid = READ_ONCE(
					cpu_bss[target_cpu_idx].last_pid);
				tctx->telemetry.pending_blocker_cpu =
					(u16)target_cpu_idx;
				tctx->telemetry.pending_strict_owner_class =
					READ_ONCE(
						cpu_bss[target_cpu_idx]
							.last_strict_wake_class);
				tctx->telemetry.pending_target_pressure =
					READ_ONCE(cpu_bss[target_cpu_idx]
							  .cpu_pressure);
			}
#endif
		} else {
			if (stats_on)
				stats->nr_idle_hint_remote_reads++;
			idle_hint =
				READ_ONCE(cpu_bss[target_cpu_idx].idle_hint);
			if (stats_on) {
				if (idle_hint)
					stats->nr_idle_hint_remote_idle++;
				else
					stats->nr_idle_hint_remote_busy++;
			}
			if (!idle_hint) {
				if (stats) {
					stats->nr_wakeup_dsq_fallback_busy++;
					stats->nr_wakeup_busy_remote_target++;
					stats->nr_enqueue_busy_remote_skip_depth++;
				}
#ifndef CAKE_RELEASE
				if (tctx) {
					tctx->telemetry.pending_wake_reason =
						CAKE_WAKE_REASON_BUSY;
					tctx->telemetry.pending_blocker_pid =
						READ_ONCE(
							cpu_bss[target_cpu_idx]
								.last_pid);
					tctx->telemetry.pending_blocker_cpu =
						(u16)target_cpu_idx;
					tctx->telemetry
						.pending_strict_owner_class = READ_ONCE(
						cpu_bss[target_cpu_idx]
							.last_strict_wake_class);
					tctx->telemetry.pending_target_pressure =
						READ_ONCE(
							cpu_bss[target_cpu_idx]
								.cpu_pressure);
				}
#endif
			} else {
				can_direct = true;
			}
		}
	} else {
#ifndef CAKE_RELEASE
		if (tctx)
			tctx->telemetry.pending_wake_reason =
				CAKE_WAKE_REASON_QUEUED;
#endif
	}

	if (can_direct) {
		/* Queue empty and safe: bypass the shared DSQ and dispatch locally.
		 * Callers guarantee p->scx.slice is already non-zero. */
		if (stats) {
			stats->nr_direct_local_inserts++;
			if (is_wakeup)
				stats->nr_wakeup_direct_dispatches++;
			else
				stats->nr_direct_other_inserts++;
		}
#ifndef CAKE_RELEASE
		if (is_wakeup)
			cake_record_wake_target_insert(enq_cpu, true,
						       wake_target_local);
		if (is_wakeup && tctx) {
			tctx->telemetry.pending_wake_reason =
				CAKE_WAKE_REASON_DIRECT;
			tctx->telemetry.pending_blocker_pid = 0;
			tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
			tctx->telemetry.pending_strict_owner_class =
				CAKE_WAKE_CLASS_NONE;
			tctx->telemetry.pending_target_pressure = 0;
		}
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
				   enq_flags);
#ifndef CAKE_RELEASE
		if (stats_on) {
			if (tctx)
				tctx->telemetry.direct_dispatch_count++;
		}
#endif
	} else {
		/* Busy targets stay per-CPU as well. This keeps runnable ownership
		 * local instead of falling back to any shared queue. */
		if (stats) {
			stats->nr_direct_local_inserts++;
			stats->nr_direct_other_inserts++;
		}
#ifndef CAKE_RELEASE
		if (is_wakeup)
			cake_record_wake_target_insert(enq_cpu, false,
						       wake_target_local);
#endif
		if (is_wakeup) {
			u64 target_status = cake_read_cpu_status(enq_cpu);

			if (cake_busy_wake_shared_escape_candidate(
				    p, target_status)) {
				cake_clamp_wakeup_vtime(p, enq_cpu);
				cake_insert_shared_escape(p, enq_flags, enq_cpu,
							  p->scx.slice, false);
				if (stats)
					stats->nr_busy_wake_shared_escape++;
				cake_kick_busy_wake_shared_escape(enq_cpu,
								  target_status);
				return;
			}
			if (cake_busy_wake_shrink_current(enq_cpu, p,
							  target_status) &&
			    stats)
				stats->nr_busy_wake_slice_shrink++;
		}
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
				   enq_flags);
		kick_cpu   = enq_cpu;
		kick_flags = idle_hint ? SCX_KICK_IDLE : SCX_KICK_PREEMPT;
		if (is_wakeup && !idle_hint && wake_target_local) {
			u32 mode = CAKE_BUSY_WAKE_KICK_MODE;

			if (mode == CAKE_BUSY_WAKE_KICK_IDLE) {
				kick_flags = SCX_KICK_IDLE;
			} else if (mode == CAKE_BUSY_WAKE_KICK_PREEMPT) {
				kick_flags = SCX_KICK_PREEMPT;
			} else {
				struct cake_cpu_bss *target_bss =
					&cpu_bss[target_cpu_idx];
				u8 target_pressure =
					READ_ONCE(target_bss->cpu_pressure);
				u32 owner_runs =
					READ_ONCE(target_bss->owner_run_count);
				u32 owner_avg_runtime_ns = READ_ONCE(
					target_bss->owner_avg_runtime_ns);

				if (!cake_busy_wake_policy_should_preempt(
					    p, owner_runs, owner_avg_runtime_ns,
					    target_pressure))
					kick_flags = SCX_KICK_IDLE;
			}
		}
#ifndef CAKE_RELEASE
		if (is_wakeup && stats_on && tctx) {
			u32 reason_mask = 0;
			u8  wakee_class = cake_shadow_classify_task(
				p, tctx, &reason_mask);
			u8 owner_class = READ_ONCE(
				cpu_bss[target_cpu_idx].last_wake_class);
			u8 target_pressure =
				READ_ONCE(cpu_bss[target_cpu_idx].cpu_pressure);
			u8 decision;

			if (target_pressure >= 64)
				reason_mask |= cake_class_reason_bit(
					CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH);
			decision = cake_shadow_busy_preempt_decision(
				wakee_class, owner_class, target_pressure);
			if (wakee_class < CAKE_WAKE_CLASS_MAX) {
				stats->wake_class_sample_count[wakee_class]++;
				cake_record_wake_class_reasons(stats,
							       reason_mask);
			}
			cake_record_busy_preempt_shadow(stats, decision,
							wakee_class,
							owner_class,
							wake_target_local);
		}
#endif
	}

	if (kick_cpu >= 0) {
#ifndef CAKE_RELEASE
		if (stats_on && tctx) {
			tctx->telemetry.pending_kick_kind =
				cake_kick_kind_from_flags(kick_flags);
			tctx->telemetry.pending_kick_ts_ns = bpf_ktime_get_ns();
		}
#endif
		if (stats) {
			if (kick_flags == SCX_KICK_IDLE)
				stats->nr_wake_kick_idle++;
			else
				stats->nr_wake_kick_preempt++;
		}
	}

	if (kick_cpu >= 0)
		scx_bpf_kick_cpu(kick_cpu, kick_flags);
#if CAKE_LEAN_SCHED
#undef stats_on
#undef stats
#endif
#endif
}

#if !CAKE_LEAN_SCHED
static __noinline u32 cake_pick_allowed_cpu(const struct task_struct *p,
					    u32 preferred_cpu)
{
	if (preferred_cpu < nr_cpus &&
	    bpf_cpumask_test_cpu(preferred_cpu, p->cpus_ptr))
		return preferred_cpu;

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS && cpu < nr_cpus; cpu++) {
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}

	return preferred_cpu < nr_cpus ? preferred_cpu : 0;
}
#endif

static __noinline void cake_clamp_wakeup_vtime(struct task_struct *p,
					       u32		   target_cpu)
{
	u64 frontier, ceiling;

	if (target_cpu >= nr_cpus)
		return;

	frontier = cake_read_cpu_frontier(target_cpu);
	/* Responsiveness-first lag ceiling: sleepers should rejoin near the
	 * current CPU frontier instead of waiting behind seconds of CPU-bound
	 * progress. Allow two quanta of slack so we do not fully discard
	 * accumulated service, but never let wakees drift unboundedly far. */
	ceiling = frontier + (quantum_ns << 1);
	if (p->scx.dsq_vtime > ceiling)
		p->scx.dsq_vtime = ceiling;
}

#if !CAKE_LEAN_SCHED
static __noinline u32 cake_pick_cpu_from_mask(const struct cpumask *cpumask,
					      u32 fallback_cpu)
{
	if (fallback_cpu < nr_cpus &&
	    bpf_cpumask_test_cpu(fallback_cpu, cpumask))
		return fallback_cpu;

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS && cpu < nr_cpus; cpu++) {
		if (bpf_cpumask_test_cpu(cpu, cpumask))
			return cpu;
	}

	return fallback_cpu < nr_cpus ? fallback_cpu : 0;
}
#endif

/* enqueue_body: per-CPU local enqueue dispatcher.
 *
 * Release-path scheduling state comes from:
 *   - task_struct fields (p->scx.*, p->flags, p->prio)
 *   - published per-CPU frontier (cpu_frontier[cpu].vtime)
 *   - RODATA (quantum_ns) — JIT immediate
 *
 * Three mutually exclusive paths:
 *   1. kcritical (<1%): high-prio kthreads bypass DSQ
 *   2. nostaged (<1%): first dispatch, seed from published frontier
 *   3. requeue (~10%): yield/slice exhaust, adaptive slice
 *   4. wakeup (~90%): main dispatch path
 */
static __noinline void enqueue_body(struct task_struct *p, u64 enq_flags)
{
#if CAKE_LEAN_SCHED
	bool is_wakeup = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);
	bool preserve_state =
		!!(enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT));
	u32 target_cpu = cake_task_cpu(p);
	u64 slice      = quantum_ns;
#ifndef CAKE_RELEASE
	struct cake_stats *path_stats =
		CAKE_PATH_STATS_ACTIVE ? get_local_stats_for(target_cpu) : NULL;
#else
#define path_stats ((struct cake_stats *)0)
#endif

	if ((p->flags & PF_KTHREAD) && p->prio < 120) {
		if (path_stats) {
			path_stats->nr_enqueue_path_kthread++;
			path_stats->nr_direct_local_inserts++;
			path_stats->nr_direct_kthread_inserts++;
		}
		p->scx.slice = quantum_ns;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, quantum_ns,
				   enq_flags);
		return;
	}

	if (unlikely(p->scx.dsq_vtime == 0)) {
		if (path_stats)
			path_stats->nr_enqueue_path_initial++;
		p->scx.dsq_vtime = cake_read_cpu_frontier(target_cpu);
		p->scx.slice	 = quantum_ns;
		if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL &&
		    cake_initial_shared_escape_candidate(
			    p, cake_read_cpu_status(target_cpu))) {
			if (path_stats)
				path_stats->nr_initial_shared_escape++;
			cake_insert_shared_escape(p, enq_flags, target_cpu,
						  p->scx.slice, false);
			return;
		}
		enqueue_dsq_dispatch(p, enq_flags, target_cpu);
		return;
	}

	if (preserve_state) {
		u64 preserved = cake_preserve_slice(p->scx.slice);

		if (path_stats)
			path_stats->nr_enqueue_path_preserve++;
		p->scx.slice = preserved;
		if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
			cake_insert_llc_vtime(p, enq_flags, target_cpu,
					      preserved);
			return;
		}
		if (cake_requeue_shared_escape_candidate(
			    p, cake_read_cpu_status(target_cpu), target_cpu)) {
			cake_insert_shared_escape(p, enq_flags, target_cpu,
						  p->scx.slice, true);
			return;
		}
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, preserved,
				   enq_flags);
		return;
	}

	u32 weight   = p->scx.weight;
	s64 nice_adj = 0;
	if (unlikely(weight != 100))
		nice_adj = calc_nice_adj(weight);

	if (!is_wakeup) {
		struct cake_cpu_bss *target_bss =
			&cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		u64 target_status = cake_read_cpu_status(target_cpu);
		u64 throughput_slice;

		if (path_stats)
			path_stats->nr_enqueue_path_requeue++;
		slice = cake_requeue_base_slice(slice, target_status);
		throughput_slice =
			cake_cache_throughput_slice_for(target_bss, p);
		if (throughput_slice)
			slice = throughput_slice;
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice + nice_adj;
		if (throughput_slice &&
		    cake_try_insert_throughput_lane(p, target_cpu, slice,
						    enq_flags))
			return;
		if (throughput_slice) {
			cake_insert_throughput_overflow(p, target_bss,
							target_cpu, slice,
							enq_flags, false);
			return;
		}
		if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
			cake_insert_llc_vtime(p, enq_flags, target_cpu, slice);
			return;
		}
		if (cake_requeue_shared_escape_candidate(
			    p, target_status, target_cpu)) {
			cake_insert_shared_escape(p, enq_flags, target_cpu,
						  slice, false);
			return;
		}
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
	}

	if (path_stats)
		path_stats->nr_enqueue_path_wakeup++;
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice + nice_adj;
	cake_clamp_wakeup_vtime(p, target_cpu);
	enqueue_dsq_dispatch(p, enq_flags, target_cpu);
#ifdef CAKE_RELEASE
#undef path_stats
#endif
	return;
#else
#ifndef CAKE_RELEASE
	bool stats_on			   = CAKE_STATS_ACTIVE;
	bool path_stats_on		   = CAKE_PATH_STATS_ACTIVE;
	u32  local_cpu			   = 0;
	u64  enqueue_start		   = stats_on ? bpf_ktime_get_ns() : 0;
	struct cake_task_ctx __arena *tctx = NULL;
	u64			      dsq_insert_start = 0;
	struct cake_stats	     *stats	       = NULL;

	if (stats_on) {
		local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		stats	  = get_local_stats_for(local_cpu);
		tctx	  = get_task_ctx(p);
		cake_record_startup_enqueue(tctx, stats, enqueue_start);
		if (tctx) {
			tctx->telemetry.pending_blocker_pid = 0;
			tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
			tctx->telemetry.pending_strict_owner_class =
				CAKE_WAKE_CLASS_NONE;
			tctx->telemetry.pending_target_pressure = 0;
		}
	}
#endif
	bool is_wakeup = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);
	bool preserve_state =
		!!(enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT));
	bool affinitized = cake_task_is_affinitized(p);
	/* ── KCRITICAL BYPASS (zero arena) ──
	 * High-priority kthreads (ksoftirqd, GPU fence workers) bypass DSQ,
	 * but still use cake's bounded scheduler quantum instead of the
	 * kernel's 20ms default slice.
	 * p->flags and p->prio are task_struct fields (L1-hot). */
	if ((p->flags & PF_KTHREAD) && p->prio < 120) {
		u32 task_cpu = cake_task_cpu(p);
#ifndef CAKE_RELEASE
		if (stats) {
			stats->nr_enqueue_path_kthread++;
			stats->nr_direct_local_inserts++;
			stats->nr_direct_kthread_inserts++;
		}
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | task_cpu, quantum_ns,
				   enq_flags);
#ifndef CAKE_RELEASE
		if (stats_on) {
			u64 dur = bpf_ktime_get_ns() - enqueue_start;
			if (stats) {
				stats->total_enqueue_latency_ns += dur;
				cake_record_cb(stats, CAKE_CB_ENQUEUE, dur);
			}
			if (tctx) {
				tctx->telemetry.enqueue_duration_ns = (u32)dur;
				tctx->telemetry.dsq_insert_ns	    = (u32)dur;
				tctx->telemetry.enqueue_start_ns =
					enqueue_start;
			}
			if (dur >= CAKE_SLOW_CALLBACK_NS)
				cake_emit_dbg_event(p, local_cpu,
						    CAKE_DBG_EVENT_CALLBACK,
						    CAKE_CB_ENQUEUE, dur,
						    task_cpu);
		}
#endif
		return;
	}

	u32 target_cpu = 0;
	u64 slice      = quantum_ns;
	u64 target_status = 0;

	/* ── NOSTAGED: first dispatch / kthread cold path ──
	 * dsq_vtime == 0 signals a freshly spawned task that cake_enable
	 * has not yet seeded from the published CPU frontier.
		 *
		 * EFFICIENCY G1: fairness math deferred below this early exit.
		 * Nostaged path doesn't need it — saves 4 instructions + 2 regs
		 * of pressure across the unlikely branch. */
	if (unlikely(p->scx.dsq_vtime == 0)) {
		target_cpu = cake_task_cpu(p);
#ifndef CAKE_RELEASE
		if (stats)
			stats->nr_enqueue_path_initial++;
#endif
		if (affinitized)
			target_cpu = cake_pick_allowed_cpu(p, target_cpu);
		p->scx.dsq_vtime = cake_read_cpu_frontier(target_cpu);
		p->scx.slice	 = quantum_ns;
		if (affinitized)
			goto queue_affine_dispatch;
		if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL &&
		    cake_initial_shared_escape_candidate(
			    p, cake_read_cpu_status(target_cpu)))
			goto queue_shared_initial;
		goto queue_dispatch;
	}

	if (preserve_state) {
		slice = cake_preserve_slice(p->scx.slice);
#ifndef CAKE_RELEASE
		if (stats)
			stats->nr_enqueue_path_preserve++;
#endif
		if (affinitized) {
			target_cpu = cake_pick_allowed_cpu(p, cake_task_cpu(p));
			goto queue_affine_preserve;
		}
		goto queue_preserve;
	}

	/* ADDITIVE FAIRNESS: weight-delta penalty from task_struct (L1-hot).
	 * p->scx.weight is on the same cache line as p->scx.slice.
	 * For nice-0 (weight=100): wd=0, nice_adj=0 (identity).
	 * Approximates quantum_ns/100 ≈ 20000 ≈ (1<<14)+(1<<12) = 20480. */
	u32 weight   = p->scx.weight;
	s64 nice_adj = 0;
	if (unlikely(weight != 100))
		nice_adj = calc_nice_adj(weight);

	/* ── REQUEUE PATH (~10%) ── */
	if (!is_wakeup) {
		struct cake_cpu_bss *target_bss;
		u64 throughput_candidate_slice;

		slice = quantum_ns;
#ifndef CAKE_RELEASE
		if (stats)
			stats->nr_enqueue_path_requeue++;
#endif

		if (affinitized) {
			slice = cake_requeue_base_slice(slice, 0);
			target_cpu = cake_pick_allowed_cpu(p, cake_task_cpu(p));
			goto queue_affine_requeue;
		}

		target_cpu  = cake_task_cpu(p);
		target_bss  = &cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		target_status = cake_read_cpu_status(target_cpu);
		slice	    = cake_requeue_base_slice(slice, target_status);
		throughput_candidate_slice =
			cake_cache_throughput_slice_for(target_bss, p);
			if (throughput_candidate_slice) {
				slice = throughput_candidate_slice;
#ifndef CAKE_RELEASE
				if (path_stats_on)
					get_local_stats_for(target_cpu)
						->nr_cache_throughput_requeue++;
				if (stats_on)
					dsq_insert_start = bpf_ktime_get_ns();
#endif
				p->scx.slice = slice;
				p->scx.dsq_vtime += slice + nice_adj;
				if (cake_try_insert_throughput_lane(
					    p, target_cpu, slice, enq_flags))
					goto queue_done;
				cake_insert_throughput_overflow(
					p, target_bss, target_cpu, slice,
					enq_flags, false);
				goto queue_done;
			}
			goto queue_requeue;
	}

	p->scx.slice = slice;
#ifndef CAKE_RELEASE
	if (stats)
		stats->nr_enqueue_path_wakeup++;
#endif

	/* EEVDF Deadline Projection (additive fairness)
	 * Replaces: vslice = (slice * vm) >> 10
	 * With: runtime + weight-delta penalty */
	p->scx.dsq_vtime += slice + nice_adj;
	target_cpu = cake_task_cpu(p);
	cake_clamp_wakeup_vtime(p, target_cpu);
	if (affinitized) {
		target_cpu = cake_pick_allowed_cpu(p, target_cpu);
		goto queue_affine_dispatch;
	}
	goto queue_dispatch;

queue_affine_preserve:
	p->scx.slice = slice;
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_enqueue_path_affine_preserve++;
		stats->nr_direct_local_inserts++;
		stats->nr_direct_affine_inserts++;
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			   enq_flags);
	goto queue_done;

queue_affine_requeue:
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice + nice_adj;
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_enqueue_path_affine_requeue++;
		stats->nr_direct_local_inserts++;
		stats->nr_direct_affine_inserts++;
		stats->nr_direct_other_inserts++;
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			   enq_flags);
	goto queue_done;

queue_affine_dispatch:
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_enqueue_path_affine_dispatch++;
		stats->nr_direct_local_inserts++;
		stats->nr_direct_affine_inserts++;
		if (is_wakeup)
			stats->nr_wakeup_direct_dispatches++;
		else
			stats->nr_direct_other_inserts++;
	}
	if (stats_on && is_wakeup && tctx) {
		tctx->telemetry.pending_target_cpu  = (u16)target_cpu;
		tctx->telemetry.pending_wake_reason = CAKE_WAKE_REASON_DIRECT;
		tctx->telemetry.pending_kick_kind   = CAKE_KICK_KIND_NONE;
		tctx->telemetry.pending_kick_ts_ns  = 0;
		tctx->telemetry.pending_blocker_pid = 0;
		tctx->telemetry.pending_blocker_cpu = CAKE_CPU_SENTINEL;
		tctx->telemetry.pending_strict_owner_class =
			CAKE_WAKE_CLASS_NONE;
		tctx->telemetry.pending_target_pressure = 0;
	}
	if (stats_on && is_wakeup) {
		cake_record_wake_target_insert(
			target_cpu, true,
			local_cpu == (target_cpu & (CAKE_MAX_CPUS - 1)));
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			   enq_flags);
	goto queue_done;

queue_preserve:
	p->scx.slice = slice;
	target_cpu   = cake_task_cpu(p);
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
#ifndef CAKE_RELEASE
		if (stats_on)
			dsq_insert_start = bpf_ktime_get_ns();
#endif
		cake_insert_llc_vtime(p, enq_flags, target_cpu, p->scx.slice);
		goto queue_done;
	}
	if (cake_requeue_shared_escape_candidate(
		    p, cake_read_cpu_status(target_cpu), target_cpu))
		goto queue_shared_preserve;
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_other_inserts++;
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			   enq_flags);
	goto queue_done;

queue_requeue:
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice + nice_adj;
	target_cpu = cake_task_cpu(p);
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
#ifndef CAKE_RELEASE
		if (stats_on)
			dsq_insert_start = bpf_ktime_get_ns();
#endif
		cake_insert_llc_vtime(p, enq_flags, target_cpu, p->scx.slice);
		goto queue_done;
	}
	if (cake_requeue_shared_escape_candidate(p, target_status, target_cpu))
		goto queue_shared_requeue;
#ifndef CAKE_RELEASE
	if (stats) {
		stats->nr_direct_local_inserts++;
		stats->nr_direct_other_inserts++;
	}
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, p->scx.slice,
			   enq_flags);
	goto queue_done;

queue_shared_initial:
	p->scx.slice = slice;
#ifndef CAKE_RELEASE
	if (stats)
		stats->nr_initial_shared_escape++;
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	cake_insert_shared_escape(p, enq_flags, target_cpu, p->scx.slice,
				  false);
	goto queue_done;

queue_shared_preserve:
#ifndef CAKE_RELEASE
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	cake_insert_shared_escape(p, enq_flags, target_cpu, p->scx.slice, true);
	goto queue_done;

queue_shared_requeue:
#ifndef CAKE_RELEASE
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	cake_insert_shared_escape(p, enq_flags, target_cpu, p->scx.slice,
				  false);
	goto queue_done;

queue_dispatch:
#ifndef CAKE_RELEASE
	if (stats_on)
		dsq_insert_start = bpf_ktime_get_ns();
#endif
	enqueue_dsq_dispatch(p, enq_flags, target_cpu);

queue_done:;
#ifndef CAKE_RELEASE
	if (stats_on) {
		u64 enqueue_end	  = bpf_ktime_get_ns();
		u64 dur		  = enqueue_end - enqueue_start;
		u64 dsq_insert_ns = enqueue_end - dsq_insert_start;
		if (stats) {
			stats->total_enqueue_latency_ns += dur;
			cake_record_cb(stats, CAKE_CB_ENQUEUE, dur);
		}
		if (tctx) {
			tctx->telemetry.enqueue_duration_ns = (u32)dur;
			tctx->telemetry.dsq_insert_ns	 = (u32)dsq_insert_ns;
			tctx->telemetry.enqueue_start_ns = enqueue_end;
			tctx->telemetry.vtime_compute_ns =
				(u32)(dur - dsq_insert_ns);
		}
		if (dur >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(p, local_cpu,
					    CAKE_DBG_EVENT_CALLBACK,
					    CAKE_CB_ENQUEUE, dur,
					    cake_task_cpu(p));
	}
#endif
#endif
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

/* cake_dispatch: Cake reaches this when there is no already-dispatched local
 * task ready to run. Shared LLC work and cache-throughput lanes are pulled
 * before keep-running and idle bookkeeping. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	(void)prev;
	u32 cpu_idx = raw_cpu & (CAKE_MAX_CPUS - 1);
	/* EFFICIENCY G4: stats variables gated — CAKE_STATS_ACTIVE = 0 in
	 * release, so these were dead-code eliminated by compiler anyway.
	 * Explicit gate keeps source truthful. */
#ifndef CAKE_RELEASE
	bool stats_on	    = CAKE_STATS_ACTIVE;
	bool path_stats_on  = CAKE_PATH_STATS_ACTIVE;
	u64  dispatch_start = stats_on ? bpf_ktime_get_ns() : 0;
#else
#define stats_on 0
#define path_stats_on 0
	u64 dispatch_start = 0;
#endif
	struct cake_cpu_bss *dispatch_bss = &cpu_bss[cpu_idx];

	if (!cake_throughput_fairness_due(dispatch_bss, cpu_idx) &&
	    cake_dispatch_try_throughput_lane(cpu_idx)) {
		cake_throughput_charge_dispatch(dispatch_bss);
		return;
	}

	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME) ||
	    CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
#ifdef CAKE_SINGLE_LLC
		bool should_pull = true;
#if CAKE_ACCEL_PATH
		if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)
			should_pull = cake_dispatch_dsq_should_pull(
				dispatch_bss, LLC_DSQ_BASE);
#endif
		if (should_pull && scx_bpf_dsq_move_to_local(LLC_DSQ_BASE, 0)) {
#if CAKE_ACCEL_PATH
			cake_dispatch_record_pull_result(dispatch_bss, true);
#endif
			if (stats_on || path_stats_on) {
				struct cake_stats *s =
					get_local_stats_for(cpu_idx);
				s->nr_local_dispatches++;
				s->nr_dispatch_llc_local_hit++;
				s->nr_dsq_consumed++;
			}
			return;
		}
#if CAKE_ACCEL_PATH
		if (should_pull)
			cake_dispatch_record_pull_result(dispatch_bss, false);
#endif
		if (stats_on || path_stats_on)
			get_local_stats_for(cpu_idx)
				->nr_dispatch_llc_local_miss++;
#else
		u32  my_llc	 = cake_llc_id_for_cpu(cpu_idx);
		u64  my_dsq	 = LLC_DSQ_BASE + my_llc;
		bool should_pull = true;

#if CAKE_ACCEL_PATH
		if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)
			should_pull = cake_dispatch_dsq_should_pull(
				dispatch_bss, my_dsq);
#endif
		if (should_pull && scx_bpf_dsq_move_to_local(my_dsq, 0)) {
#if CAKE_ACCEL_PATH
			cake_dispatch_record_pull_result(dispatch_bss, true);
#endif
			if (stats_on || path_stats_on) {
				struct cake_stats *s =
					get_local_stats_for(cpu_idx);
				s->nr_local_dispatches++;
				s->nr_dispatch_llc_local_hit++;
				s->nr_dsq_consumed++;
			}
			return;
		}
#if CAKE_ACCEL_PATH
		if (should_pull)
			cake_dispatch_record_pull_result(dispatch_bss, false);
#endif
		if (stats_on || path_stats_on)
			get_local_stats_for(cpu_idx)
				->nr_dispatch_llc_local_miss++;

		if (nr_llcs > 1) {
			for (u32 off = 1; off < CAKE_MAX_LLCS; off++) {
				u32 victim;

				if (off >= nr_llcs)
					break;
				victim = my_llc + off;
				if (victim >= nr_llcs)
					victim -= nr_llcs;
				u64 victim_dsq = LLC_DSQ_BASE + victim;

				should_pull    = true;
#if CAKE_ACCEL_PATH
				if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)
					should_pull =
						cake_dispatch_dsq_should_pull(
							dispatch_bss,
							victim_dsq);
#endif
				if (should_pull &&
				    scx_bpf_dsq_move_to_local(victim_dsq, 0)) {
#if CAKE_ACCEL_PATH
					cake_dispatch_record_pull_result(
						dispatch_bss, true);
#endif
					if (stats_on || path_stats_on) {
						struct cake_stats *s =
							get_local_stats_for(
								cpu_idx);
						s->nr_stolen_dispatches++;
						s->nr_dispatch_llc_steal_hit++;
						s->nr_dsq_consumed++;
					}
					return;
				}
#if CAKE_ACCEL_PATH
				if (should_pull)
					cake_dispatch_record_pull_result(
						dispatch_bss, false);
#endif
			}
		}
#endif
	}

	if (cake_dispatch_try_throughput_lane(cpu_idx)) {
		cake_throughput_charge_dispatch(dispatch_bss);
		return;
	}

	if (stats_on || path_stats_on)
		get_local_stats_for(cpu_idx)->nr_dispatch_misses++;

	/* G3 keep_running: if no DSQ work is available and prev still wants to run,
	 * replenish its slice instead of forcing an avoidable context switch. */
	struct task_struct *keep_prev = bpf_get_current_task_btf();
	if (keep_prev && (keep_prev->scx.flags & SCX_TASK_QUEUED)) {
		u64 slice = quantum_ns;
		u64 throughput_slice =
			cake_cache_throughput_slice_for(dispatch_bss, keep_prev);

		if (throughput_slice)
			slice = throughput_slice;
		keep_prev->scx.slice = slice;
		if (stats_on || path_stats_on)
			get_local_stats_for(cpu_idx)->nr_dispatch_keep_running++;
		if (path_stats_on && throughput_slice)
			get_local_stats_for(cpu_idx)
				->nr_cache_throughput_keep_running++;
		/* Keep the stopping() baseline aligned with the replenished
		 * slice so same-task continuations charge the next run from the
		 * correct starting budget. */
		cpu_bss[cpu_idx].tick_slice = slice;
	}

	/* Check-before-write: only mark idle if not already idle.
	 * Avoids unnecessary cache line dirtying. Debug still mirrors the legacy
	 * BSS hint for telemetry; release publishes the owner-written status lane. */
#ifndef CAKE_RELEASE
	if (!READ_ONCE(cpu_bss[cpu_idx].idle_hint)) {
		WRITE_ONCE(cpu_bss[cpu_idx].idle_hint, 1);
#if !CAKE_LEAN_SCHED
		cake_decay_cpu_pressure_idle(&cpu_bss[cpu_idx]);
#endif
		if (stats_on)
			get_local_stats_for(cpu_idx)->nr_idle_hint_set_writes++;
	} else {
		if (stats_on)
			get_local_stats_for(cpu_idx)->nr_idle_hint_set_skips++;
	}
#endif
	cake_publish_cpu_idle(cpu_idx);

	if (stats_on) {
		struct cake_stats *s	= get_local_stats_for(cpu_idx);
		u64		   d_oh = bpf_ktime_get_ns() - dispatch_start;
		s->total_dispatch_ns += d_oh;
		s->max_dispatch_ns =
			s->max_dispatch_ns + ((d_oh - s->max_dispatch_ns) &
					      -(d_oh > s->max_dispatch_ns));
		cake_record_cb(s, CAKE_CB_DISPATCH, d_oh);
		if (d_oh >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(prev, cpu_idx,
					    CAKE_DBG_EVENT_CALLBACK,
					    CAKE_CB_DISPATCH, d_oh,
					    prev ? prev->pid : 0);
	}
#ifdef CAKE_RELEASE
#undef stats_on
#undef path_stats_on
#endif
}

/* tier_perf_target[] REMOVED: self-documented dead RODATA.
 * Was kept for loader compat only; JIT dead-coded it. */

#ifndef CAKE_RELEASE
struct cake_wake_wait_scratch {
	u64 start_ns;
	u64 wait_ns;
	u64 wait_us;
	u64 kick_ts_ns;
	u32 blocker_pid;
	u16 target_cpu;
	u16 blocker_cpu;
	u8  reason;
	u8  kick_kind;
	u8  select_path;
	u8  select_reason;
	u8  home_place;
	u8  waker_place;
	u8  _pad[2];
} __attribute__((aligned(64)));

struct cake_wake_wait_scratch wake_wait_scratch[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));

static __noinline void
running_record_startup(struct cake_task_ctx __arena *tctx,
		       struct cake_stats *s_run, u64 start)
{
	if (cake_startup_trace_open(tctx)) {
		u32 delta_us = cake_startup_delta_us(tctx, start);
		cake_record_startup_phase(tctx, CAKE_STARTUP_PHASE_RUNNING,
					  CAKE_STARTUP_MASK_RUNNING);
		tctx->telemetry.startup_latency_us = delta_us;
		cake_record_lifecycle_us(&s_run->lifecycle_init_run_us,
					 &s_run->lifecycle_init_run_count,
					 delta_us);
	}
}

static __noinline void running_record_follow(struct cake_task_ctx __arena *tctx,
					     struct task_struct *p, u32 cpu,
					     u64 start, u64 prev_run_start)
{
	if (!tctx->telemetry.postwake_watch ||
	    tctx->telemetry.enqueue_start_ns != 0 || prev_run_start == 0)
		return;

	struct cake_stats *s_run	 = get_local_stats_for(cpu);
	u8		   follow_reason = tctx->telemetry.postwake_reason;

	if (follow_reason > CAKE_WAKE_REASON_NONE &&
	    follow_reason < CAKE_WAKE_REASON_MAX) {
		bool same_follow = (u16)cpu ==
				   tctx->telemetry.postwake_first_cpu;
		if (same_follow)
			s_run->wake_followup_same_cpu_count[follow_reason]++;
		else {
			s_run->wake_followup_migrate_count[follow_reason]++;
			cake_emit_dbg_event(
				p, cpu, CAKE_DBG_EVENT_WAKE_FOLLOW_MIG,
				follow_reason, start - prev_run_start,
				((u32)tctx->telemetry.postwake_first_cpu
				 << 16) |
					(u32)cpu);
		}
#if CAKE_DEBUG_EVENT_STREAM
		cake_emit_wake_edge_follow_event(
			tctx, p, cpu, start - prev_run_start, same_follow);
#endif
	}
	tctx->telemetry.postwake_watch = 0;
}

static __noinline void
running_wake_wait_fill_scratch(struct cake_task_ctx __arena *tctx, u32 cpu,
			       u64 start)
{
	struct cake_wake_wait_scratch *ww =
		&wake_wait_scratch[cpu & (CAKE_MAX_CPUS - 1)];
	u64 enqueue_start = tctx->telemetry.enqueue_start_ns;

	ww->start_ns	  = start;
	ww->wait_ns	  = start - enqueue_start;
	ww->wait_us	  = ww->wait_ns >> 10;
	ww->reason	  = tctx->telemetry.pending_wake_reason;
	ww->target_cpu	  = tctx->telemetry.pending_target_cpu;
	ww->kick_kind	  = tctx->telemetry.pending_kick_kind;
	ww->select_path	  = tctx->telemetry.pending_select_path;
	ww->select_reason = tctx->telemetry.pending_select_reason;
	ww->kick_ts_ns	  = tctx->telemetry.pending_kick_ts_ns;
	ww->blocker_pid	  = tctx->telemetry.pending_blocker_pid;
	ww->blocker_cpu	  = tctx->telemetry.pending_blocker_cpu;
	ww->home_place	  = tctx->telemetry.last_place_class;
	ww->waker_place	  = tctx->telemetry.last_waker_place_class;
}

static __noinline void
running_wake_wait_clear_pending(struct cake_task_ctx __arena  *tctx,
				struct cake_wake_wait_scratch *ww)
{
	tctx->telemetry.wait_duration_ns	   = ww->wait_ns;
	tctx->telemetry.enqueue_start_ns	   = 0;
	tctx->telemetry.pending_wake_reason	   = CAKE_WAKE_REASON_NONE;
	tctx->telemetry.pending_target_cpu	   = CAKE_CPU_SENTINEL;
	tctx->telemetry.pending_kick_kind	   = CAKE_KICK_KIND_NONE;
	tctx->telemetry.pending_kick_ts_ns	   = 0;
	tctx->telemetry.pending_blocker_pid	   = 0;
	tctx->telemetry.pending_blocker_cpu	   = CAKE_CPU_SENTINEL;
	tctx->telemetry.pending_strict_owner_class = CAKE_WAKE_CLASS_NONE;
	tctx->telemetry.pending_target_pressure	   = 0;
	tctx->telemetry.last_select_path	   = ww->select_path;
	tctx->telemetry.last_select_reason	   = ww->select_reason;
	tctx->telemetry.pending_select_path	   = CAKE_SELECT_PATH_NONE;
	tctx->telemetry.pending_select_reason	   = CAKE_SELECT_REASON_NONE;
}

static __noinline void
running_wake_wait_emit_edge(struct cake_task_ctx __arena *tctx,
			    struct task_struct *p, u32 cpu,
			    struct cake_wake_wait_scratch *ww)
{
#if CAKE_DEBUG_EVENT_STREAM
	u64 packed = (u64)ww->reason | ((u64)ww->target_cpu << 8) |
		     ((u64)ww->select_path << 24) |
		     ((u64)ww->home_place << 32) | ((u64)ww->waker_place << 40);

	cake_emit_wake_edge_run_event(tctx, p, cpu, ww->wait_ns, packed);
#else
	(void)tctx;
	(void)p;
	(void)cpu;
	(void)ww;
#endif
}

static __noinline void
running_wake_wait_record_blocker(struct task_struct	       *p,
				 struct cake_wake_wait_scratch *ww)
{
	if (ww->reason == CAKE_WAKE_REASON_BUSY && ww->blocker_pid > 0) {
		if (ww->blocker_cpu < CAKE_MAX_CPUS) {
			u32 bcpu = ww->blocker_cpu & (CAKE_MAX_CPUS - 1);
			u64 max_seen;

			WRITE_ONCE(blocked_owner_pid[bcpu], ww->blocker_pid);
			WRITE_ONCE(blocked_waiter_pid[bcpu], p->pid);
			__sync_fetch_and_add(&blocked_owner_wait_ns[bcpu],
					     ww->wait_ns);
			__sync_fetch_and_add(&blocked_owner_wait_count[bcpu],
					     1);
			max_seen = READ_ONCE(blocked_owner_wait_max_ns[bcpu]);
			if (ww->wait_ns > max_seen)
				WRITE_ONCE(blocked_owner_wait_max_ns[bcpu],
					   ww->wait_ns);
		}
	}
}

static __noinline void
running_wake_wait_record_hist(struct cake_task_ctx __arena  *tctx,
			      struct cake_wake_wait_scratch *ww)
{
	if (ww->wait_us < 10)
		tctx->telemetry.wait_hist_lt10us++;
	else if (ww->wait_us < 100)
		tctx->telemetry.wait_hist_lt100us++;
	else if (ww->wait_us < 1000)
		tctx->telemetry.wait_hist_lt1ms++;
	else
		tctx->telemetry.wait_hist_ge1ms++;
}

static __noinline void running_wake_wait_record_reason_all(
	struct cake_task_ctx __arena *tctx, struct task_struct *p, u32 cpu,
	struct cake_stats *s_run, struct cake_wake_wait_scratch *ww)
{
	if (ww->reason <= CAKE_WAKE_REASON_NONE ||
	    ww->reason >= CAKE_WAKE_REASON_MAX)
		return;

	if (ww->target_cpu < CAKE_MAX_CPUS) {
		if ((u16)cpu == ww->target_cpu)
			s_run->wake_target_hit_count[ww->reason]++;
		else {
			s_run->wake_target_miss_count[ww->reason]++;
			if (ww->wait_ns >= CAKE_EVT_TARGET_MISS_NS)
				cake_emit_dbg_event(
					p, cpu, CAKE_DBG_EVENT_WAKE_TARGET_MISS,
					ww->reason, ww->wait_ns,
					((u32)ww->target_cpu << 16) | (u32)cpu);
		}
		cake_record_target_wait(ww->reason, ww->target_cpu,
					ww->wait_ns);
	}

	tctx->telemetry.postwake_watch	   = 1;
	tctx->telemetry.postwake_first_cpu = (u16)cpu;
	tctx->telemetry.postwake_reason	   = ww->reason;
	cake_record_wake_wait(s_run->wake_reason_wait_all_ns,
			      s_run->wake_reason_wait_all_count,
			      s_run->wake_reason_wait_all_max_ns, ww->reason,
			      ww->wait_ns);
	cake_smt_record_wake_wait(s_run, cpu, ww->wait_ns);
	s_run->wake_reason_bucket_count[ww->reason]
				       [cake_wake_bucket(ww->wait_ns)]++;

	if (ww->kick_kind > CAKE_KICK_KIND_NONE &&
	    ww->kick_kind < CAKE_KICK_KIND_MAX && ww->kick_ts_ns > 0 &&
	    ww->start_ns > ww->kick_ts_ns) {
		u64 kick_wait = ww->start_ns - ww->kick_ts_ns;

		s_run->nr_wake_kick_observed[ww->kick_kind]++;
		if (kick_wait <= CAKE_QUICK_WAKE_KICK_NS)
			s_run->nr_wake_kick_quick[ww->kick_kind]++;
		s_run->total_wake_kick_to_run_ns[ww->kick_kind] += kick_wait;
		if (kick_wait > s_run->max_wake_kick_to_run_ns[ww->kick_kind])
			s_run->max_wake_kick_to_run_ns[ww->kick_kind] =
				kick_wait;
		s_run->wake_kick_bucket_count[ww->kick_kind]
					     [cake_wake_bucket(kick_wait)]++;
		if (kick_wait >= CAKE_EVT_KICK_SLOW_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_KICK_SLOW,
					    ww->kick_kind, kick_wait,
					    ((u32)ww->reason << 16) |
						    (u32)ww->target_cpu);
	}
}

static __noinline void running_wake_wait_record_tracked(
	struct cake_task_ctx __arena *tctx, struct task_struct *p, u32 cpu,
	struct cake_stats *s_run, struct cake_wake_wait_scratch *ww)
{
	if (ww->reason > CAKE_WAKE_REASON_NONE &&
	    ww->reason < CAKE_WAKE_REASON_MAX &&
	    ww->wait_ns <= CAKE_TRACKED_WAKEWAIT_MAX_NS) {
		u32 idx = ww->reason - 1;
		u32 max_wait;

		tctx->telemetry.wake_reason_wait_ns[idx] += ww->wait_ns;
		tctx->telemetry.wake_reason_count[idx]++;
		max_wait = tctx->telemetry.wake_reason_max_us[idx];
		if (ww->wait_us > max_wait)
			tctx->telemetry.wake_reason_max_us[idx] =
				(u32)ww->wait_us;
		cake_record_wake_wait(s_run->wake_reason_wait_ns,
				      s_run->wake_reason_wait_count,
				      s_run->wake_reason_wait_max_ns,
				      ww->reason, ww->wait_ns);
		cake_record_place_wait(s_run, s_run->home_place_wait_ns,
				       s_run->home_place_wait_count,
				       s_run->home_place_wait_max_ns,
				       ww->home_place, ww->wait_ns);
		cake_record_place_wait(s_run, s_run->waker_place_wait_ns,
				       s_run->waker_place_wait_count,
				       s_run->waker_place_wait_max_ns,
				       ww->waker_place, ww->wait_ns);
		cake_record_task_home_wait(tctx, ww->home_place, ww->wait_ns);
		if (ww->wait_ns >= CAKE_SLOW_WAKEWAIT_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_WAKEWAIT,
					    ww->reason, ww->wait_ns,
					    ww->wait_us);
	}
}

static __noinline void
running_record_wake_wait(struct cake_task_ctx __arena *tctx,
			 struct task_struct *p, u32 cpu, u64 start,
			 struct cake_stats *s_run)
{
	/* Record wake-to-run outcome before dispatch-gap bookkeeping.
	 * This is the core signal for warm-vs-cold placement decisions. */
	if (tctx->telemetry.enqueue_start_ns > 0 &&
	    start > tctx->telemetry.enqueue_start_ns) {
		struct cake_wake_wait_scratch *ww =
			&wake_wait_scratch[cpu & (CAKE_MAX_CPUS - 1)];

		running_wake_wait_fill_scratch(tctx, cpu, start);
		running_wake_wait_clear_pending(tctx, ww);
		cake_record_select_decision_wait(s_run, ww->select_reason,
						 ww->wait_ns);
		running_wake_wait_emit_edge(tctx, p, cpu, ww);
		running_wake_wait_record_blocker(p, ww);
		running_wake_wait_record_hist(tctx, ww);
		running_wake_wait_record_reason_all(tctx, p, cpu, s_run, ww);
		running_wake_wait_record_tracked(tctx, p, cpu, s_run, ww);
	}
}

static __noinline void
running_record_dispatch_gap(struct cake_task_ctx __arena *tctx,
			    struct task_struct *p, u32 cpu, u64 start,
			    u64 prev_run_start)
{
	/* 1. DISPATCH GAP */
	if (prev_run_start > 0 && start > prev_run_start) {
		u64 gap = start - prev_run_start;
		u64 old_max_g;

		tctx->telemetry.dispatch_gap_ns = gap;
		old_max_g = tctx->telemetry.max_dispatch_gap_ns;
		tctx->telemetry.max_dispatch_gap_ns =
			old_max_g + ((gap - old_max_g) & -(gap > old_max_g));
		if (gap >= CAKE_EVT_DISPATCH_GAP_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_DISPATCH_GAP,
					    0, gap, 0);
	}
}

static __noinline void running_record_finish(struct cake_task_ctx __arena *tctx,
					     u32 cpu, u64 overhead_start,
					     u64 mbox_end)
{
	tctx->telemetry.llc_id = (u16)cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].llc_id;
	if (tctx->telemetry.llc_id < 16)
		tctx->telemetry.llc_run_mask |=
			(u16)(1u << tctx->telemetry.llc_id);

	u64 oh_run = bpf_ktime_get_ns() - overhead_start;
	tctx->telemetry.running_duration_ns = (u32)oh_run;

	/* Phase 8: mailbox staging duration (overhead_start == mbox_start) */
	tctx->telemetry.mbox_staging_ns = (u32)(mbox_end - overhead_start);
}

/* running_telemetry: cold-path arena telemetry for per-task stats.
 * Extracted to __noinline to isolate register pressure from cake_running.
 * Dead-code eliminated in CAKE_RELEASE builds.
 * Records: dispatch gap, wait histogram, overhead timing, mailbox staging. */
static __noinline void running_telemetry(struct task_struct *p, u32 cpu,
					 u64 overhead_start)
{
	/* Phase 8: mailbox staging stopwatch end (before arena work) */
	u64 mbox_end = bpf_ktime_get_ns();

	/* Verbose builds keep per-task run-side telemetry exact. */
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (!tctx)
		return;

	u64		   start = bpf_ktime_get_ns();
	struct cake_stats *s_run = get_local_stats_for(cpu);

	/* F4: Save OLD run_start BEFORE overwriting for dispatch_gap calc. */
	u64 prev_run_start	     = tctx->telemetry.run_start_ns;
	tctx->telemetry.run_start_ns = start;

	running_record_startup(tctx, s_run, start);
	running_record_follow(tctx, p, cpu, start, prev_run_start);
	running_record_wake_wait(tctx, p, cpu, start, s_run);
	running_record_dispatch_gap(tctx, p, cpu, start, prev_run_start);
	running_record_finish(tctx, cpu, overhead_start, mbox_end);
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
	bool stats_on		    = CAKE_STATS_ACTIVE;
	bool path_stats_on	    = CAKE_PATH_STATS_ACTIVE;
	u64  running_overhead_start = 0;
	if (stats_on)
		running_overhead_start = bpf_ktime_get_ns();
#else
#define stats_on 0
#define path_stats_on 0
#endif

	/* Batch kfuncs first: only p=r6 survives both calls (1 callee-save).
	 * p->scx.slice read DEFERRED until after both kfuncs to avoid
	 * forcing p through 2 separate spill/reload cycles. */
	u32		     cpu = cake_task_cpu(p) & (CAKE_MAX_CPUS - 1);

	struct cake_cpu_bss *bss = &cpu_bss[cpu];

#ifndef CAKE_RELEASE
	if (stats_on)
		cake_record_local_run(cpu);
#endif

#ifndef CAKE_RELEASE
	/* BPF-Native Clock: debug-only monotonic accumulator.
	 * Feeds run_start + running_telemetry (both debug-gated).
	 * In release, now_full has zero consumers → entire clock
	 * system (read, kfunc resync, accumulation) compiles out. */
	u64 now_full = bss->cake_clock;
#endif

	bool task_changed = bss->last_pid != p->pid;

	/* ── WRITE: owner-published CPU status ──
	 * Release keeps remote wake decisions on cpu_status instead of the private
	 * BSS line. Debug still mirrors idle_hint for telemetry and SMT accounting. */
	cake_publish_cpu_running(cpu, task_changed);
#ifndef CAKE_RELEASE
	if (READ_ONCE(bss->idle_hint)) {
		WRITE_ONCE(bss->idle_hint, 0);
		if (stats_on)
			get_local_stats_for(cpu)->nr_idle_hint_clear_writes++;
	} else {
		if (stats_on)
			get_local_stats_for(cpu)->nr_idle_hint_clear_skips++;
	}
#endif

#ifndef CAKE_RELEASE
	if (stats_on)
		cake_smt_record_run_start(bss, cpu, running_overhead_start);

	struct cake_task_ctx __arena *running_tctx = NULL;
	if (stats_on) {
		struct cake_stats *stats       = get_local_stats_for(cpu);
		u32		   reason_mask = 0;
		u8		   old_class = READ_ONCE(bss->last_wake_class);
		u8		   new_class;

		running_tctx = get_task_ctx(p);
		new_class    = cake_shadow_classify_task(p, running_tctx,
							 &reason_mask);
		if (new_class < CAKE_WAKE_CLASS_MAX) {
			stats->wake_class_sample_count[new_class]++;
			if (old_class < CAKE_WAKE_CLASS_MAX &&
			    old_class != new_class)
				stats->wake_class_transition_count[old_class]
								  [new_class]++;
			cake_record_wake_class_reasons(stats, reason_mask);
			WRITE_ONCE(bss->last_wake_class, new_class);
		}
	}
#endif

	/* FAST PATH: same task re-running on the same CPU.
	 * Slice load is deferred into the task-change block.
	 * Release/stats-off same-task re-runs keep zero kfunc calls and zero BSS
	 * writes beyond the published status update; debug stats refresh the
	 * shadow owner class. */
	if (stats_on || path_stats_on) {
		struct cake_stats *s_run = get_local_stats_for(cpu);
		if (task_changed)
			s_run->nr_running_task_change++;
		else
			s_run->nr_running_same_task++;
	}
	if (task_changed) {
		/* Task change: refresh local CPU state and learned home placement.
		 * Release reads task context here to maintain locality history. */
#ifndef CAKE_RELEASE
		now_full	= scx_bpf_now();
		bss->cake_clock = now_full;
#endif
		u64 slice	= p->scx.slice;
		bss->last_pid	= p->pid;
		bss->tick_slice = slice ?: quantum_ns;
#if !CAKE_LEAN_SCHED
		cake_owner_runtime_policy_reset(bss);
#else
		WRITE_ONCE(bss->owner_avg_runtime_ns, 0);
		WRITE_ONCE(bss->owner_run_count, 0);
#endif
#if CAKE_ACCEL_PATH
		cake_scoreboard_owner_reset(bss);
#endif

		/* Keep a live local frontier instead of a historical max so
		 * wakeup rescue stays anchored to currently active work. */
		cake_publish_cpu_frontier(cpu, p->scx.dsq_vtime);

#ifndef CAKE_RELEASE
		struct cake_task_ctx __arena *tctx =
			stats_on ? running_tctx :
				   (CAKE_LEARNED_LOCALITY_ENABLED ?
					    get_task_ctx(p) :
					    NULL);
#else
		struct cake_task_ctx __arena *tctx =
			CAKE_LEARNED_LOCALITY_ENABLED ? get_task_ctx(p) : NULL;
#endif
		if (tctx && CAKE_LEARNED_LOCALITY_ENABLED) {
#ifndef CAKE_RELEASE
			bool first_home = stats_on &&
					  tctx->home_cpu == CAKE_CPU_SENTINEL;
			u8 seed_reason	= tctx->telemetry.pending_select_reason;
#endif
			cake_update_home_cpu(tctx, (u16)cpu);
#ifndef CAKE_RELEASE
			if (first_home)
				cake_record_home_seed(tctx->home_cpu,
						      seed_reason);
#endif
		}
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
		running_telemetry(p, cpu, running_overhead_start);
	if (stats_on) {
		struct cake_stats *s_run = get_local_stats_for(cpu);
		u64 oh_run = bpf_ktime_get_ns() - running_overhead_start;
		s_run->total_running_ns += oh_run;
		s_run->max_running_ns = s_run->max_running_ns +
					((oh_run - s_run->max_running_ns) &
					 -(oh_run > s_run->max_running_ns));
		cake_record_cb(s_run, CAKE_CB_RUNNING, oh_run);
		if (oh_run >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_CALLBACK,
					    CAKE_CB_RUNNING, oh_run, 0);
	}
#endif
#ifdef CAKE_RELEASE
#undef stats_on
#undef path_stats_on
#endif
}

/* cake_stopping: struct_ops callback fired when a task stops on a CPU.
 *
 * The release path integrates consumed runtime into dsq_vtime using
 * task_struct and per-CPU BSS state. Debug builds add per-task telemetry. */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	u32		     cpu = cake_task_cpu(p) & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[cpu];

	/* Vtime integration.
	 * Release fast path uses task_struct, private BSS, and owner-published
	 * status/frontier lanes.
	 * Debug telemetry below adds extra reads and one deferred divide. */
	u32 slice_consumed = (u32)bss->tick_slice - (u32)p->scx.slice;
#ifndef CAKE_RELEASE
	/* Debug clock accumulator — feeds run_start/telemetry. Dead in release. */
	bss->cake_clock += slice_consumed;
#endif

	/* Branchless math bounding */
	u32 rt_raw = slice_consumed - ((slice_consumed - (65535U << 10)) &
				       -(slice_consumed > (65535U << 10)));

#ifndef CAKE_RELEASE
#if !CAKE_LEAN_SCHED
	cake_update_cpu_pressure(bss, slice_consumed);
	cake_owner_runtime_policy_update(bss, slice_consumed);
	u32 owner_avg_runtime_ns = READ_ONCE(bss->owner_avg_runtime_ns);
	cake_publish_cpu_owner(cpu, bss, owner_avg_runtime_ns);
#else
	u32 owner_avg_runtime_ns = cake_update_owner_avg(bss, rt_raw);
	cake_publish_cpu_owner(cpu, bss, owner_avg_runtime_ns);
#endif
#endif
	struct cake_task_ctx __arena *policy_tctx = NULL;
	if (CAKE_LEARNED_LOCALITY_ENABLED && CAKE_WAKE_CHAIN_LOCALITY_ENABLED) {
		policy_tctx = get_task_ctx(p);
		cake_wake_chain_policy_update(policy_tctx, p, slice_consumed,
					      runnable);
	}

	if (runnable) {
		/* Additive fairness from task weight in task_struct.
		 * Source uses shifts and adds, but the compiler may lower that
		 * expression to a multiply in generated BPF. */
		u32 weight   = p->scx.weight;
		s64 nice_adj = 0;
		if (unlikely(weight != 100))
			nice_adj = calc_nice_adj(weight);
		p->scx.dsq_vtime += (u64)rt_raw + nice_adj;
		cake_publish_cpu_frontier(cpu, p->scx.dsq_vtime);
	}

#if CAKE_ACCEL_PATH
#ifdef CAKE_RELEASE
	bool relaxed		  = cake_accounting_relaxed(bss);
	u32  owner_avg_runtime_ns = cake_update_owner_avg(bss, rt_raw);

	cake_publish_cpu_owner(cpu, bss, owner_avg_runtime_ns);
	if (!relaxed)
		cake_scoreboard_owner_result(bss, owner_avg_runtime_ns);
#else
	bool relaxed = cake_accounting_relaxed(bss);
	cake_record_accel_accounting(relaxed);
	if (!relaxed)
		cake_scoreboard_owner_result(bss, owner_avg_runtime_ns);
#endif
#endif

	bool stats_on		     = CAKE_STATS_ACTIVE;
	bool path_stats_on	     = CAKE_PATH_STATS_ACTIVE;
	u64  stopping_overhead_start = 0;

#ifndef CAKE_RELEASE
	struct cake_task_ctx __arena *tctx = policy_tctx;
	if (stats_on && !tctx)
		tctx = get_task_ctx(p);
	u32  nvcsw_accum = 0;
	bool smt_charged = false;
#endif

	if (path_stats_on && !stats_on) {
		struct cake_stats *s = get_local_stats_for(cpu);

		if (runnable)
			s->nr_stopping_runnable++;
		else
			s->nr_stopping_blocked++;
		if (p->scx.slice == 0)
			s->nr_quantum_full++;
		else if (!runnable)
			s->nr_quantum_yield++;
		else
			s->nr_quantum_preempt++;
	}

	if (stats_on) {
		stopping_overhead_start = bpf_ktime_get_ns();
#ifndef CAKE_RELEASE
		if (tctx) {
			struct cake_stats *s_task = get_local_stats_for(cpu);
			u8		   tc	  = tctx->task_class;
			if (tc != CAKE_CLASS_GAME) {
				u64 cur_nv  = p->nvcsw;
				u64 prev_nv = tctx->nvcsw_snapshot;
				if (prev_nv > 0)
					nvcsw_accum = (u32)(cur_nv - prev_nv);
				tctx->nvcsw_snapshot = cur_nv;
			}
			if (nvcsw_accum)
				tctx->telemetry.nvcsw_delta += nvcsw_accum;

			if (tctx->telemetry.run_start_ns > 0) {
				u64 now_stop = bpf_ktime_get_ns();
				u64 dur =
					now_stop - tctx->telemetry.run_start_ns;
				u32 raw_slice_used =
					(u32)(cpu_bss[cpu].tick_slice -
					      p->scx.slice);
				u64  expected_ns, d, mask, jitter;
				u16  old_max_rt;
				u64  dur_us;
				u64  tslice;
				u64  smt_overlap;
				bool same;

				tctx->telemetry.run_duration_ns = dur;
				smt_overlap = cake_smt_charge_runtime(
					s_task, bss, cpu, now_stop);
				if (smt_overlap > dur)
					smt_overlap = dur;
				if (smt_overlap > 0) {
					tctx->telemetry
						.smt_contended_runtime_ns +=
						dur;
					tctx->telemetry.smt_overlap_runtime_ns +=
						smt_overlap;
					tctx->telemetry
						.smt_contended_run_count++;
				} else {
					tctx->telemetry.smt_solo_runtime_ns +=
						dur;
					tctx->telemetry.smt_solo_run_count++;
				}
				smt_charged = true;
				cake_record_place_run(
					s_task, s_task->home_place_run_ns,
					s_task->home_place_run_count,
					s_task->home_place_run_max_ns,
					tctx->telemetry.last_place_class, dur);

				same = ((u16)cpu ==
					tctx->telemetry.core_placement);
				tctx->telemetry.same_cpu_streak =
					(tctx->telemetry.same_cpu_streak + 1) &
					-(u16)same;
				tctx->telemetry.core_placement = (u16)cpu;

				raw_slice_used -=
					(raw_slice_used - (65535U << 10)) &
					-(raw_slice_used > (65535U << 10));
				expected_ns =
					(u64)(raw_slice_used >> 10) * 1000ULL;
				d      = dur - expected_ns;
				mask   = -(u64)(dur < expected_ns);
				jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;
				tctx->telemetry.total_runtime_ns += dur;
				s_task->task_runtime_ns += dur;
				s_task->task_run_count++;

				old_max_rt = tctx->telemetry.max_runtime_us;
				dur_us	   = dur / 1000;
				if (dur_us > 65535)
					dur_us = 65535;
				tctx->telemetry.max_runtime_us =
					old_max_rt +
					(((u16)dur_us - old_max_rt) &
					 -(u16)((u16)dur_us > old_max_rt));

				tslice = cpu_bss[cpu].tick_slice ?: quantum_ns;
				tctx->telemetry.slice_util_pct =
					(u16)((dur << 7) / tslice);

				{
					u64 cur_nivcsw = p->nivcsw;
					u64 prev_nivcsw =
						tctx->telemetry.nivcsw_snapshot;
					if (prev_nivcsw > 0)
						tctx->telemetry.nivcsw_delta +=
							(u32)(cur_nivcsw -
							      prev_nivcsw);
					tctx->telemetry.nivcsw_snapshot =
						cur_nivcsw;
				}

				tctx->telemetry.stopping_duration_ns =
					(u32)(now_stop -
					      stopping_overhead_start);
			}

			if (p->scx.slice == 0)
				tctx->telemetry.quantum_full_count++;
			else if (!runnable)
				tctx->telemetry.quantum_yield_count++;
			else
				tctx->telemetry.quantum_preempt_count++;

			tctx->telemetry
				.cpu_run_count[cpu &
					       (CAKE_TELEM_MAX_CPUS - 1)]++;
		}
#endif /* !CAKE_RELEASE */

		/* Aggregate overhead timing (per-CPU BSS). */
		struct cake_stats *s = get_local_stats_for(cpu);
#ifndef CAKE_RELEASE
		if (!smt_charged)
			cake_smt_charge_runtime(s, bss, cpu,
						bpf_ktime_get_ns());
#endif
		if (runnable)
			s->nr_stopping_runnable++;
		else
			s->nr_stopping_blocked++;
		if (p->scx.slice == 0)
			s->nr_quantum_full++;
		else if (!runnable)
			s->nr_quantum_yield++;
		else
			s->nr_quantum_preempt++;
		u64 oh_agg = bpf_ktime_get_ns() - stopping_overhead_start;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns =
			s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) &
					      -(oh_agg > s->max_stopping_ns));
		cake_record_cb(s, CAKE_CB_STOPPING, oh_agg);
		s->nr_stop_deferred++;
		if (oh_agg >= CAKE_SLOW_CALLBACK_NS)
			cake_emit_dbg_event(p, cpu, CAKE_DBG_EVENT_CALLBACK,
					    CAKE_CB_STOPPING, oh_agg,
					    runnable ? 1 : 0);
	}
}

/* Initialize per-task arena storage.
 * Sleepable: bpf_arena_alloc_pages is sleepable-only, so all arena
 * allocation must happen here, not in hot paths.
 * Called before any scheduling ops fire for this task.
 *
 * Debug builds allocate full telemetry state; release builds omit this
 * callback from cake_ops entirely. */
#ifndef CAKE_RELEASE
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
#if !CAKE_NEEDS_ARENA
	return 0;
#else
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
	u32 init_ppid	  = p->real_parent ? p->real_parent->tgid : 0;
	tctx->ppid	  = init_ppid;
	tctx->task_weight = 100; /* Default weight for nice-0 (display only) */
	tctx->home_cpu	  = CAKE_CPU_SENTINEL;
	tctx->home_score  = 0;
	tctx->home_core	  = 0xFF;
	tctx->primary_scan_credit = 0;

	/* packed_info is now iter/debug transport only.
	 * We still seed NEW and KCRITICAL here so the TUI can identify fresh tasks
	 * and kernel-critical helpers without hot-path reads. */
	u32 packed = 0;
	packed |= ((u32)CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
	if (p->flags & PF_KTHREAD) {
		if (p->prio < 120) {
			packed |= (1u << BIT_KCRITICAL);
		} else {
			u64 comm_val = ((u64 *)p->comm)[0];
			if (comm_val == 0x71726974666f736bULL ||
			    (comm_val & 0x0000FFFFFFFFFFFFULL) ==
				    0x000061696469766eULL ||
			    (comm_val & 0x0000000000FFFFFFULL) ==
				    0x0000000000646d61ULL ||
			    (comm_val & 0x00000000FFFFFFFFULL) ==
				    0x0000000035313969ULL ||
			    (comm_val & 0x000000000000FFFFULL) ==
				    0x0000000000006578ULL) {
				packed |= (1u << BIT_KCRITICAL);
			}
		}
	}
	tctx->packed_info = packed;

	/* ── DEBUG-ONLY FIELD INITIALIZATION ──
	 * All of these are read only by debug telemetry paths. */
	if (CAKE_STATS_ENABLED) {
		tctx->task_class = CAKE_CLASS_NORMAL;
	}

	tctx->telemetry.pid   = p->pid;
	tctx->telemetry.tgid  = p->tgid;
	u64	    *comm_src = (u64 *)p->comm;
	u64 __arena *comm_dst = (u64 __arena *)tctx->telemetry.comm;
	comm_dst[0]	      = comm_src[0];
	comm_dst[1]	      = comm_src[1];
	tctx->telemetry.pending_target_cpu	   = CAKE_CPU_SENTINEL;
	tctx->telemetry.pending_blocker_cpu	   = CAKE_CPU_SENTINEL;
	tctx->telemetry.pending_strict_owner_class = CAKE_WAKE_CLASS_NONE;
	tctx->telemetry.pending_select_reason	   = CAKE_SELECT_REASON_NONE;
	tctx->telemetry.last_select_reason	   = CAKE_SELECT_REASON_NONE;
	tctx->telemetry.startup_first_phase	   = CAKE_STARTUP_PHASE_NONE;

	if (CAKE_STATS_ACTIVE) {
		tctx->telemetry.nivcsw_snapshot	   = p->nivcsw;
		u64 now_ns			   = bpf_ktime_get_ns();
		tctx->telemetry.startup_latency_us = (u32)(now_ns / 1000ULL);
		tctx->telemetry.lifecycle_init_ms  = (u32)(now_ns / 1000000ULL);
	}

	if (CAKE_STATS_ENABLED)
		tctx->nvcsw_snapshot = p->nvcsw;

	tctx->task_class = CAKE_CLASS_NORMAL;

	return 0;
#endif
}
#endif

/* cake_enable: initialize task vtime when it becomes schedulable. */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	/* Seed dsq_vtime directly in task_struct from the local frontier. */
	p->scx.dsq_vtime = cake_read_cpu_frontier(cake_task_cpu(p));
	p->scx.slice	 = quantum_ns;
}

/* cake_set_cpumask: event-driven affinity update — telemetry counter only.
 * Cached cpumask removed: kernel handles affinity natively. */
#ifndef CAKE_RELEASE
void BPF_STRUCT_OPS(cake_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
#if CAKE_LEAN_SCHED
	return;
#else
#ifndef CAKE_RELEASE
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
#endif
	u32 target_cpu = cake_pick_cpu_from_mask(cpumask, cake_task_cpu(p));

#ifndef CAKE_RELEASE
	if (tctx && tctx->home_cpu < nr_cpus &&
	    !bpf_cpumask_test_cpu(tctx->home_cpu, cpumask)) {
		tctx->home_cpu	 = CAKE_CPU_SENTINEL;
		tctx->home_score = 0;
		tctx->home_core	 = 0xFF;
		tctx->primary_scan_credit &= CAKE_PRIMARY_SCAN_CREDIT_MASK;
	}
#endif

	if (cake_task_is_affinitized(p)) {
		u64 kick_flags =
			READ_ONCE(cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)]
					  .idle_hint) ?
				SCX_KICK_IDLE :
				SCX_KICK_PREEMPT;
		p->scx.slice = quantum_ns;
		cake_clamp_wakeup_vtime(p, target_cpu);
#ifndef CAKE_RELEASE
		if (CAKE_STATS_ACTIVE) {
			struct cake_stats *s = get_local_stats();
			if (kick_flags == SCX_KICK_IDLE)
				s->nr_affine_kick_idle++;
			else
				s->nr_affine_kick_preempt++;
		}
#endif
		scx_bpf_kick_cpu(target_cpu, kick_flags);
	}
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ENABLED) {
		if (tctx)
			tctx->telemetry.cpumask_change_count++;
	}
#endif
#endif
}
#endif

/* Handle manual yields (e.g. sched_yield syscall).
 * Global stats keep an exact count, while per-task yield_count is TUI-only
 * telemetry (stats-gated). */
#ifndef CAKE_RELEASE
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *p)
{
	if (CAKE_STATS_ACTIVE) {
		struct cake_stats	     *s	   = get_local_stats();
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);

		s->nr_sched_yield_calls++;
		if (tctx) {
			u16 yield_count = tctx->telemetry.yield_count;
			if (yield_count != 65535)
				tctx->telemetry.yield_count = yield_count + 1;
		}
	}
	return false;
}
#endif

/* Handle preemption when a task is pushed off the CPU. */
#ifndef CAKE_RELEASE
void BPF_STRUCT_OPS(cake_runnable, struct task_struct *p, u64 enq_flags)
{
	if (CAKE_STATS_ACTIVE) {
		u32 local_cpu = bpf_get_smp_processor_id();
		u32 local_idx = local_cpu & (CAKE_MAX_CPUS - 1);
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			if (enq_flags & SCX_ENQ_PREEMPT) {
				tctx->telemetry.preempt_count++;
				if (tctx->telemetry.preempt_count >= 4 &&
				    (tctx->telemetry.preempt_count & 3) == 0)
					cake_emit_dbg_event(
						p, local_idx,
						CAKE_DBG_EVENT_PREEMPT_CHAIN, 0,
						0,
						tctx->telemetry.preempt_count);
			}
			/* Wakeup source: the currently running task is the waker */
			struct task_struct *waker = bpf_get_current_task_btf();
			if (waker) {
				struct cake_stats *s =
					get_local_stats_for(local_idx);
				tctx->telemetry.wakeup_source_pid = waker->pid;
				/* Wake chain tracking */
				tctx->telemetry.waker_cpu  = (u16)local_cpu;
				tctx->telemetry.waker_tgid = waker->tgid;
				if (waker->tgid == tctx->telemetry.tgid) {
					tctx->telemetry.wake_same_tgid_count++;
					if (s)
						s->nr_wake_same_tgid++;
				} else {
					tctx->telemetry.wake_cross_tgid_count++;
					if (s)
						s->nr_wake_cross_tgid++;
				}
				if (enq_flags & SCX_ENQ_WAKEUP) {
#if CAKE_DEBUG_EVENT_STREAM
					cake_emit_wake_edge_enqueue_event(
						tctx, waker, p);
#endif
				}
			}
		}
	}
}
#endif

/* Free per-task arena storage on task exit. */
#ifndef CAKE_RELEASE
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);

		if (tctx && tctx->telemetry.lifecycle_init_ms > 0) {
			u32 now_ms = (u32)(bpf_ktime_get_ns() / 1000000ULL);
			u32 alive_ms =
				now_ms - tctx->telemetry.lifecycle_init_ms;
			struct cake_stats *s = get_local_stats();

			cake_record_lifecycle_us(&s->lifecycle_init_exit_us,
						 &s->lifecycle_init_exit_count,
						 (u64)alive_ms * 1000ULL);
		}
	}
#if CAKE_NEEDS_ARENA
	/* Remove from PID→tctx map: removed — iter/task program handles visibility
	 * without explicit cleanup. Task storage freed below. */
	scx_task_free(p);
#endif
}
#endif

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME) ||
	    CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
		for (u32 i = 0; i < CAKE_MAX_LLCS; i++) {
			s32 ret;

			if (i >= nr_llcs)
				break;
			ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
			if (ret)
				return ret;
		}
	}

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS; cpu++) {
		s32 ret;

		if (cpu >= nr_cpus)
			break;
		ret = scx_bpf_create_dsq(CAKE_THROUGHPUT_DSQ_BASE + cpu, -1);
		if (ret)
			return ret;
		scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
	}

#ifndef CAKE_RELEASE
	/* Populate per-CPU LLC ID cache from RODATA.
	 * Set once at init — llc_id never changes for a given CPU. */
	for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
		if (i >= nr_cpus)
			break;
		cpu_bss[i].llc_id = (u8)cpu_llc_id[i];
	}
#endif

	return 0;
}

/* Scheduler exit - record exit info */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* iter.bpf.h owns the task iterator program and its copy helpers.
 * It depends on the task-context accessors and scheduler structs above. */
#include "iter.bpf.h"
/* cake_tick: LLC-vtime fallback dispatch is pull-driven from cake_dispatch,
 * so the tick hook is intentionally idle. */
#ifndef CAKE_RELEASE
void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
	(void)p;
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
#if CAKE_NEEDS_ARENA
	/* Mirror weight to arena for debug telemetry (iter reads tctx->task_weight).
	 * Semantic change: now stores raw weight (100=nice0) instead of reciprocal. */
	struct cake_task_ctx __arena *hot = get_task_hot(p);
	if (hot) {
		u16 w = (u16)(weight ?: 100);
		if (hot->task_weight != w)
			hot->task_weight = w;
	}
#endif
}
#endif

#ifdef CAKE_RELEASE
SCX_OPS_DEFINE(
	cake_ops, .select_cpu = (void *)cake_select_cpu,
	.enqueue = (void *)cake_enqueue, .dispatch = (void *)cake_dispatch,
	.running = (void *)cake_running, .stopping = (void *)cake_stopping,
	.enable = (void *)cake_enable, .init = (void *)cake_init,
	.exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	.timeout_ms = 5000, /* Override with SCX_TIMEOUT_MS when needed */
	.name	    = "cake");
#else
SCX_OPS_DEFINE(
	cake_ops, .select_cpu = (void *)cake_select_cpu,
	.enqueue = (void *)cake_enqueue, .dispatch = (void *)cake_dispatch,
	.tick = (void *)cake_tick, .running = (void *)cake_running,
	.stopping = (void *)cake_stopping, .yield = (void *)cake_yield,
	.runnable   = (void *)cake_runnable,
	.set_weight = (void *)cake_set_weight, .enable = (void *)cake_enable,
	.set_cpumask = (void *)cake_set_cpumask,
	.init_task   = (void *)cake_init_task,
	.exit_task = (void *)cake_exit_task, .init = (void *)cake_init,
	.exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	.timeout_ms = 5000, /* Override with SCX_TIMEOUT_MS when needed */
	.name	    = "cake");
#endif
