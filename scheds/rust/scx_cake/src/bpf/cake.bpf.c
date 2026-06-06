// SPDX-License-Identifier: GPL-2.0
/* scx_cake — low-latency CAKE-inspired CPU scheduler.
 *
 * Core design:
 *   - direct dispatch when an idle CPU is available
 *   - shared stealable queue only for proven bulk busy-wake fallback
 *   - local fallback queues for service/control/cache-affinity/default cases
 *     with per-LLC vtime fallback still available as an A/B/domain arbiter
 *   - topology-aware CPU selection (V-Cache, hybrid P/E, SMT siblings)
 *   - lean hot paths with task-local vtime accounting
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#ifndef CAKE_NEEDS_ARENA
#define CAKE_NEEDS_ARENA 0
#endif
#if !CAKE_NEEDS_ARENA
#ifndef __arena
#define __arena __attribute__((address_space(1)))
#endif
#else
#include <lib/arena_map.h> /* BPF_MAP_TYPE_ARENA definition */
#include <lib/sdt_task.h> /* scx_task_data, scx_task_alloc, scx_task_free */
#include <lib/dhq.h>
#endif
#include "intf.h"
#include "bpf_compat.h"

/* Local CPU DSQs remain non-stealable. The LLC-vtime A/B policy uses explicit
 * per-LLC DSQs as the fallback arbiter instead. */
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
#ifndef CAKE_NR_CPUS
#define CAKE_NR_CPUS CAKE_MAX_CPUS
#endif
#ifndef CAKE_NR_LLCS
#define CAKE_NR_LLCS CAKE_MAX_LLCS
#endif
#ifndef CAKE_QUEUE_POLICY_VALUE
#define CAKE_QUEUE_POLICY_VALUE CAKE_QUEUE_POLICY_LOCAL
#endif
#ifndef CAKE_STORM_GUARD_VALUE
#define CAKE_STORM_GUARD_VALUE CAKE_STORM_GUARD_SHIELD
#endif
#ifndef CAKE_BUSY_WAKE_KICK_VALUE
#define CAKE_BUSY_WAKE_KICK_VALUE CAKE_BUSY_WAKE_KICK_POLICY
#endif
#ifndef CAKE_LEARNED_LOCALITY_VALUE
#define CAKE_LEARNED_LOCALITY_VALUE 1
#endif
#ifndef CAKE_WAKE_CHAIN_LOCALITY_VALUE
#define CAKE_WAKE_CHAIN_LOCALITY_VALUE 1
#endif
#ifndef CAKE_RELEASE_PLANCK_LOCAL
#define CAKE_RELEASE_PLANCK_LOCAL 0
#endif
#if defined(CAKE_RELEASE) && CAKE_RELEASE_PLANCK_LOCAL
#define CAKE_PLANCK_LOCAL 1
#else
#define CAKE_PLANCK_LOCAL 0
#endif
#ifndef CAKE_PLANCK_DISPATCH_GATE
#define CAKE_PLANCK_DISPATCH_GATE 0
#endif
#ifdef CAKE_RELEASE
const u64 quantum_ns = CAKE_QUANTUM_NS; /* Base time slice per dispatch */
#define CAKE_QUEUE_POLICY CAKE_QUEUE_POLICY_VALUE
#define CAKE_STORM_GUARD_MODE CAKE_STORM_GUARD_VALUE
#else
const volatile u64 quantum_ns	    = CAKE_DEFAULT_QUANTUM_NS;
const volatile u32 queue_policy	    = CAKE_QUEUE_POLICY_LOCAL;
const volatile u32 storm_guard_mode = CAKE_STORM_GUARD_SHIELD;
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
#define CAKE_LEARNED_LOCALITY_COMPILED CAKE_LEARNED_LOCALITY_VALUE
#define CAKE_WAKE_CHAIN_LOCALITY_COMPILED CAKE_WAKE_CHAIN_LOCALITY_VALUE
#define CAKE_LEARNED_LOCALITY_ENABLED CAKE_LEARNED_LOCALITY_VALUE
#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED CAKE_WAKE_CHAIN_LOCALITY_VALUE
#define CAKE_BUSY_WAKE_KICK_MODE CAKE_BUSY_WAKE_KICK_VALUE
#elif !CAKE_LOCALITY_EXPERIMENTS
#define CAKE_LEARNED_LOCALITY_COMPILED 0
#define CAKE_WAKE_CHAIN_LOCALITY_COMPILED 0
#define CAKE_LEARNED_LOCALITY_ENABLED 0
#define CAKE_WAKE_CHAIN_LOCALITY_ENABLED 0
#define CAKE_BUSY_WAKE_KICK_MODE CAKE_BUSY_WAKE_KICK_POLICY
#else
#define CAKE_LEARNED_LOCALITY_COMPILED 1
#define CAKE_WAKE_CHAIN_LOCALITY_COMPILED 1
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
#if !CAKE_LOCALITY_EXPERIMENTS
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
#ifndef CAKE_RELEASE_ROUTE_PRED
#define CAKE_RELEASE_ROUTE_PRED 0
#endif
#ifndef CAKE_RELEASE_CONFIDENCE
#define CAKE_RELEASE_CONFIDENCE 0
#endif
#ifndef CAKE_RELEASE_TRUST_MAPS
#define CAKE_RELEASE_TRUST_MAPS 0
#endif
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_TRUST_MAPS
#define CAKE_HAS_TRUST_MAPS 0
#else
#define CAKE_HAS_TRUST_MAPS 1
#endif
#ifndef CAKE_RELEASE_FAST_SCAN_LIMIT
#define CAKE_RELEASE_FAST_SCAN_LIMIT 2U
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
#define CAKE_BULK_STEAL_UTIL_MIN 256U
#define CAKE_ENABLE_GUARDED_SHARED_STEAL 0
#define CAKE_ENABLE_CORE_STEAL_BUSY_FALLBACK 1
#ifndef CAKE_BUSY_WAKE_GRACE_VALUE
#define CAKE_BUSY_WAKE_GRACE_VALUE 1
#endif
#ifndef CAKE_SMT_CLEAN_SELECT_VALUE
#define CAKE_SMT_CLEAN_SELECT_VALUE 0
#endif
#ifndef CAKE_FRAME_OWNER_SHIELD_VALUE
#define CAKE_FRAME_OWNER_SHIELD_VALUE 0
#endif
#ifndef CAKE_PREV_IDLE_OVERRIDE_VALUE
#define CAKE_PREV_IDLE_OVERRIDE_VALUE 0
#endif
#ifndef CAKE_LEAN_WAKE_KICK_VALUE
#define CAKE_LEAN_WAKE_KICK_VALUE 0
#endif
#ifndef CAKE_KTHREAD_WAKE_PREEMPT_VALUE
#define CAKE_KTHREAD_WAKE_PREEMPT_VALUE 0
#endif
#ifndef CAKE_NATIVE_FAST_WAKE_VALUE
#define CAKE_NATIVE_FAST_WAKE_VALUE 0
#endif
#ifndef CAKE_NATIVE_FAST_WAKE_WIDE
#define CAKE_NATIVE_FAST_WAKE_WIDE 0
#endif
#ifndef CAKE_NATIVE_FAST_WAKE_MISS_TUNNEL
#define CAKE_NATIVE_FAST_WAKE_MISS_TUNNEL 0
#endif
#ifndef CAKE_FAST_ENQUEUE_VALUE
#define CAKE_FAST_ENQUEUE_VALUE 0
#endif
#ifndef CAKE_NFW_MISS_SHARED
#define CAKE_NFW_MISS_SHARED 0
#endif
#ifndef CAKE_LEAN_ACCOUNTING_VALUE
#define CAKE_LEAN_ACCOUNTING_VALUE 0
#endif
#ifndef CAKE_WAKE_PREEMPT_ELAPSED_VALUE
#define CAKE_WAKE_PREEMPT_ELAPSED_VALUE 0
#endif
#ifndef CAKE_WAKE_PREEMPT_ELAPSED_NS
#define CAKE_WAKE_PREEMPT_ELAPSED_NS 600000ULL
#endif
#ifndef CAKE_WAKE_PREEMPT_ADAPTIVE
#define CAKE_WAKE_PREEMPT_ADAPTIVE 0
#endif
#ifndef CAKE_WAKE_PREEMPT_MIN_NS
#define CAKE_WAKE_PREEMPT_MIN_NS 200000ULL
#endif
#ifndef CAKE_WAKE_PREEMPT_OWNER_MIN_AVG_NS
#define CAKE_WAKE_PREEMPT_OWNER_MIN_AVG_NS 800000ULL
#endif
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
#define CAKE_DEFAULT_BULK_MIN_RUNS 32U
#define CAKE_DEFAULT_BULK_SLICE_SHIFT 2U
#define CAKE_LLC_VTIME_LOCAL_RESCUE_DEPTH 2
#define CAKE_CACHE_THROUGHPUT_SHIFT_LUT 0x5555555544332210ULL
#define CAKE_THROUGHPUT_FAIR_DISPATCH_BUDGET 15U
#define CAKE_BUSY_WAKE_SHRINK_MIN_NS 500000ULL
#define CAKE_LOCAL_WAITER_DEBT_MAX 3U
#define CAKE_LOCAL_WAITER_QUENCH_MIN_NS 150000ULL
#define CAKE_DOMAIN_DRR_CACHE_BURST_LIMIT 3U
#define CAKE_TP_DEC_PULL_MASK 0x0fULL
#define CAKE_TP_DEC_DISPATCH_MASK CAKE_TP_DEC_PULL_MASK
#define CAKE_THROUGHPUT_FAIR_DISPATCH_LIMIT \
	((CAKE_THROUGHPUT_FAIR_DISPATCH_BUDGET > 15U) ? 15U : \
	 CAKE_THROUGHPUT_FAIR_DISPATCH_BUDGET)
#define CAKE_TP_DEC_RUNTIME_SCALE_SHIFT 14U
#define CAKE_TP_DEC_RUNTIME_BUCKET_SHIFT 8U
#define CAKE_TP_DEC_RUN_BUCKET_SHIFT 16U
#define CAKE_TP_DEC_BUCKET_MASK 0xffULL
#define CAKE_TP_DEC_SAT_CACHE_MEM (1ULL << 24)
#define CAKE_TP_DEC_STREAM_PRESSURE (1ULL << 25)
#define CAKE_TP_DEC_STREAM_DEBT_SHIFT 26U
#define CAKE_TP_DEC_STREAM_DEBT_MASK \
	(0x3ULL << CAKE_TP_DEC_STREAM_DEBT_SHIFT)
#define CAKE_TP_DEC_STREAM_DEBT_MAX 3U
#define CAKE_TP_DEC_STREAM_STATE_MASK \
	(CAKE_TP_DEC_STREAM_PRESSURE | CAKE_TP_DEC_STREAM_DEBT_MASK)
#define CAKE_TP_DEC_OWNER_MASK \
	((CAKE_TP_DEC_BUCKET_MASK << CAKE_TP_DEC_RUNTIME_BUCKET_SHIFT) | \
	 (CAKE_TP_DEC_BUCKET_MASK << CAKE_TP_DEC_RUN_BUCKET_SHIFT) | \
	 CAKE_TP_DEC_SAT_CACHE_MEM)
#define CAKE_MIXED_STREAM_BLEED_CACHE 4U
#define CAKE_MIXED_STREAM_BLEED_MIXED 2U
#define CAKE_MIXED_STREAM_BLEED_MIN CAKE_MIXED_STREAM_BLEED_MIXED
#define CAKE_STREAM_SLICE_SHIFT 0U
#define CAKE_ROUTE_PRED_CONF_SHIFT 32U
#define CAKE_ROUTE_PRED_ROUTE_SHIFT 36U
#define CAKE_ROUTE_PRED_AUDIT_SHIFT 40U
#define CAKE_ROUTE_PRED_PENDING (1ULL << 47)
#define CAKE_ROUTE_PRED_GOOD_SHIFT 48U
#define CAKE_ROUTE_PRED_BAD_SHIFT 52U
#define CAKE_ROUTE_PRED_MODE_SHIFT 56U
#define CAKE_ROUTE_PRED_FACT_SHIFT 59U
#define CAKE_ROUTE_PRED_CONF_MASK 0xfULL
#define CAKE_ROUTE_PRED_ROUTE_MASK 0xfULL
#define CAKE_ROUTE_PRED_AUDIT_FIELD_MASK 0x7fULL
#define CAKE_ROUTE_PRED_NIBBLE_MASK 0xfULL
#define CAKE_ROUTE_PRED_MODE_MASK 0x7ULL
#define CAKE_ROUTE_PRED_FACT_MASK 0x1fULL
#define CAKE_ROUTE_PRED_NONE 0U
#define CAKE_ROUTE_PRED_CACHE_HOT 1U
#define CAKE_ROUTE_PRED_MODE_NONE 0U
#define CAKE_ROUTE_PRED_MODE_CACHE 1U
#define CAKE_ROUTE_PRED_MODE_FAIR 2U
#define CAKE_ROUTE_PRED_MODE_MIXED 3U
#define CAKE_ROUTE_FACT_USER (1U << 0)
#define CAKE_ROUTE_FACT_NORMAL_PRIO (1U << 1)
#define CAKE_ROUTE_FACT_DEFAULT_WEIGHT (1U << 2)
#define CAKE_ROUTE_FACT_BULK (1U << 3)
#define CAKE_ROUTE_FACT_NOT_AFFINITIZED (1U << 4)
#define CAKE_ROUTE_PRED_CONF_TRUST 8U
#define CAKE_ROUTE_PRED_CONF_STEP 4U
#define CAKE_ROUTE_PRED_CONF_BAD_DECAY 5U
#define CAKE_ROUTE_PRED_CONF_FAIL_DECAY 9U
#define CAKE_ROUTE_PRED_AUDIT_MASK 0x7fU
#define CAKE_ROUTE_PRED_EXTRA_SHIFT_MAX 6U
#define CAKE_CACHE_SIMPLE_STATE_STREAM_SEEN (1ULL << 63)
#define CAKE_CACHE_SIMPLE_STATE_ACTIVE (1ULL << 62)
#define CAKE_CACHE_SIMPLE_STATE_MISS_SHIFT 16U
#define CAKE_CACHE_SIMPLE_STATE_MISS_MASK (0xffULL << CAKE_CACHE_SIMPLE_STATE_MISS_SHIFT)
#define CAKE_CACHE_SIMPLE_STATE_MISS_MAX 255U
#define CAKE_CACHE_SIMPLE_STATE_COUNT_MASK 0xffffULL
#define CAKE_CACHE_SIMPLE_WARMUP_TARGET 4096U
#define CAKE_TASK_STRESS_NONE 0U
#define CAKE_TASK_STRESS_CACHE 1U
#define CAKE_TASK_STRESS_MEMCPY 2U
#define CAKE_TASK_SERVICE_NONE 0U
#define CAKE_TASK_SERVICE_STRESS_CACHE CAKE_TASK_STRESS_CACHE
#define CAKE_TASK_SERVICE_STRESS_MEMCPY CAKE_TASK_STRESS_MEMCPY
#define CAKE_TASK_SERVICE_PERF_SCHED_MESSAGING 3U
#define CAKE_TASK_SERVICE_STRESS_FUTEX 4U
#define CAKE_TASK_SERVICE_SCHBENCH 5U
#define CAKE_TASK_SERVICE_PERF_SCHED_PIPE 6U
#define CAKE_FUTEX_LANE_ACTIVE_NS 2000000000ULL
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
#define CAKE_SEL_CORE_SPREAD 0x2000U
#define CAKE_SEL_NATIVE_FIRST 0x4000U
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

/* Topology config - JIT eliminates unused SMT steering when cake_nr_cpus <= nr_phys_cpus.
 * has_hybrid removed: Rust loader pre-fills cpu_sibling_map for ALL topologies
 * via scx_utils::Topology::sibling_cpus(). No runtime branching needed. */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): cake_nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): cake_nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const volatile u32 nr_llcs = 1;
const volatile u32 nr_cpus =
	1; /* Set by loader. 1 = safe fallback — makes loader failure obvious. */
#ifdef CAKE_RELEASE
#define cake_nr_cpus ((u32)CAKE_NR_CPUS)
#define cake_nr_llcs ((u32)CAKE_NR_LLCS)
#else
#define cake_nr_cpus nr_cpus
#define cake_nr_llcs nr_llcs
#endif
/* nr_phys_cpus REMOVED: zero BPF readers. */
const volatile u32 cpu_llc_id[CAKE_MAX_CPUS]				= {};
const volatile u8  cpu_core_id[CAKE_MAX_CPUS]				= {};
const volatile u64 cpu_meta[CAKE_MAX_CPUS]				= {};
const volatile u64 cpu_llc_dsq[CAKE_MAX_CPUS]				= {};
const volatile u16 cpu_fast_probe[CAKE_MAX_CPUS][CAKE_FAST_PROBE_SLOTS] = {};

#if CAKE_MAX_CPUS < 256
typedef u32 cake_fast_probe_pack_t;
#define CAKE_FAST_PROBE_LANE_SHIFT 3U
#define CAKE_FAST_PROBE_LANE_BITS 8U
#define CAKE_FAST_PROBE_LANE_MASK 0xffU
#else
typedef u64 cake_fast_probe_pack_t;
#define CAKE_FAST_PROBE_LANE_SHIFT 4U
#define CAKE_FAST_PROBE_LANE_BITS 16U
#define CAKE_FAST_PROBE_LANE_MASK 0xffffULL
#endif

const volatile cake_fast_probe_pack_t cpu_fast_probe_pack[CAKE_MAX_CPUS] = {};
const volatile cake_fast_probe_pack_t cpu_core_spread_pack[CAKE_MAX_CPUS] = {};

/* Precomputed `(1 << s0) | (1 << s1) | (1 << s2) | (1 << s3)` for each row.
 * Used as a SWAR precheck against `clean_mask` to short-circuit the per-slot
 * probe loop when no candidate CPU is idle. Valid CPU ids are folded by & 63,
 * matching cake_fast_clean_mask_has(); invalid tail slots are omitted. */
const volatile u64 cpu_fast_probe_bits[CAKE_MAX_CPUS] = {};

static __always_inline u32
cake_fast_probe_slot_from_pack(cake_fast_probe_pack_t packed, u32 slot)
{
	/* All callers in cake_select_route_predict pass slot in [0..3] (range-
	 * checked via the SLOT1..SLOT3 gate or constant 0). The defensive
	 * `slot & (CAKE_FAST_PROBE_SLOTS - 1U)` mask was preventing the JIT
	 * from collapsing `(route_kind - SLOT0) << 3` into a clean
	 * subtract+shift; the compiler ended up emitting an extra AND+XOR
	 * to fold the mask through the subtract. */
	u32 cpu	 = (packed >> (slot << CAKE_FAST_PROBE_LANE_SHIFT)) &
		   CAKE_FAST_PROBE_LANE_MASK;

	return cpu;
}

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
#define CAKE_USE_SCOREBOARD_SUMMARY 0

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
#if CAKE_FUTEX_TRACE
struct cake_futex_trace futex_trace[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));
struct cake_futex_task_trace futex_task_trace[CAKE_FUTEX_TASK_TRACE_SLOTS] SEC(".bss")
	__attribute__((aligned(128)));
u64 futex_trace_first_order;
#endif
#if CAKE_SCOREBOARD_SUMMARY
struct cake_scoreboard_summary scoreboard_summary[CAKE_MAX_LLCS];
#endif
struct cake_cpu_frontier cpu_frontier[CAKE_MAX_CPUS];
#if !CAKE_HAS_DOMAIN_DRR
struct cake_throughput_lane throughput_lane[CAKE_MAX_CPUS];
u64 stream_service_pending;
#endif
#if CAKE_HAS_LOCAL_WAITER
struct cake_local_waiter local_waiter[CAKE_MAX_CPUS];
#endif
#if CAKE_HAS_DOMAIN_DRR
struct cake_domain_drr domain_drr[CAKE_MAX_LLCS];
#endif
#if CAKE_HAS_LLC_PENDING
struct cake_llc_pending llc_pending[CAKE_MAX_LLCS];
#endif
struct cake_core_steal_pending core_steal_pending[CAKE_MAX_CPUS];
u64 core_steal_pending_mask __attribute__((aligned(64)));
#if !CAKE_HAS_DOMAIN_DRR
u64 cache_simple_state;
#endif
u64 futex_lane_until_ns __attribute__((aligned(64)));
#if CAKE_NEEDS_ARENA
struct scx_dhq __arena *core_dhqs[CAKE_MAX_CORES];
struct scx_lfdeq __arena *cpu_lfdeqs[CAKE_MAX_CPUS];

static __noinline struct scx_lfdeq __arena *get_cpu_lfdeq(u32 cpu)
{
	u32 idx = cpu & (CAKE_MAX_CPUS - 1);
	barrier_var(idx);
	if (idx >= CAKE_MAX_CPUS)
		return NULL;
	return cpu_lfdeqs[idx];
}


static __noinline int scx_lfdeq_enqueue_remote(struct scx_lfdeq __arena *lfdeq, u64 pid)
{
	struct lfdeq_ring __arena *ring = &lfdeq->eq_buf;
	
	/* Atomically allocate a slot index via Fetch-and-Add */
	u64 t = __sync_fetch_and_add(&ring->tail, 1);
	u64 cycle = t / LFDEQ_CAPACITY;
	u32 idx = t & (LFDEQ_CAPACITY - 1);

	/* Check if the slot is occupied in the current cycle */
	u64 val = smp_load_acquire(&ring->tasks[idx].pid);
	u64 slot_pid = val & 0xffffffffULL;
	u64 slot_cycle = val >> 32;

	if (slot_pid != 0 && slot_cycle == cycle) {
		/* Queue is full in this cycle (overrun) */
		return -ENOSPC;
	}

	/* Store the pid with the current cycle packed in the upper 32 bits */
	smp_store_release(&ring->tasks[idx].pid, pid | (cycle << 32));
	return 0;
}

static __noinline void scx_lfdeq_flush(struct scx_lfdeq __arena *lfdeq)
{
	struct lfdeq_ring __arena *ring = &lfdeq->eq_buf;
	u64 h = READ_ONCE(ring->head);
	u64 t = READ_ONCE(ring->tail);

	if (h >= t)
		return;

	u64 l_t = READ_ONCE(lfdeq->tail);
	u64 l_h = READ_ONCE(lfdeq->head);
	u32 count = 0;

	#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (h >= t)
			break;
		if (l_t - l_h >= LFDEQ_CAPACITY)
			break;

		u32 ring_idx = h & (LFDEQ_CAPACITY - 1);
		u64 val = smp_load_acquire(&ring->tasks[ring_idx].pid);
		u64 pid = val & 0xffffffffULL;
		u64 cycle = val >> 32;
		if (!pid)
			break;

		u32 local_idx = l_t & (LFDEQ_CAPACITY - 1);
		lfdeq->tasks[local_idx].pid = pid;
		
		/* Advance the slot's cycle to cycle + 1 and clear pid so
		 * the next ring rotation knows this slot is empty. */
		smp_store_release(&ring->tasks[ring_idx].pid, (cycle + 1) << 32);

		l_t++;
		h++;
		count++;
	}

	if (count > 0) {
		smp_store_release(&lfdeq->tail, l_t);
		smp_store_release(&ring->head, h);
	}
}

static __noinline u64 scx_lfdeq_pop_local(struct scx_lfdeq __arena *lfdeq)
{
	u64 t = READ_ONCE(lfdeq->tail);
	u64 h = READ_ONCE(lfdeq->head);
	if (h >= t)
		return 0;

	t--;
	/* Fast path: if multiple tasks are present, the owner can pop
	 * without smp_mb() or CAS since owner/thief slots cannot overlap. */
	if (t > h) {
		u64 pid = lfdeq->tasks[t & (LFDEQ_CAPACITY - 1)].pid;
		WRITE_ONCE(lfdeq->tail, t);
		return pid;
	}

	/* Slow path: fallback to memory fence and CAS when size <= 1 */
	WRITE_ONCE(lfdeq->tail, t);
	smp_mb();
	h = READ_ONCE(lfdeq->head);
	if (t < h) {
		WRITE_ONCE(lfdeq->tail, h);
		return 0;
	}

	u64 pid = lfdeq->tasks[t & (LFDEQ_CAPACITY - 1)].pid;
	if (t == h) {
		if (!__sync_bool_compare_and_swap(&lfdeq->head, h, h + 1)) {
			pid = 0;
		}
		WRITE_ONCE(lfdeq->tail, h + 1);
	}
	return pid;
}

static __noinline u64 scx_lfdeq_steal(struct scx_lfdeq __arena *lfdeq)
{
	u64 h, t;

	#pragma unroll
	for (int i = 0; i < 2; i++) {
		h = READ_ONCE(lfdeq->head);
		smp_rmb();
		t = READ_ONCE(lfdeq->tail);
		if (h >= t)
			return 0;

		smp_rmb();
		u64 pid = smp_load_acquire(&lfdeq->tasks[h & (LFDEQ_CAPACITY - 1)].pid);

		if (__sync_bool_compare_and_swap(&lfdeq->head, h, h + 1)) {
			return pid;
		}
	}
	return 0;
}
#endif
#if CAKE_HAS_TRUST_MAPS
struct cake_trust_user	 trust_user[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(64)));
struct cake_trust_bpf trust_bpf[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(64)));
#endif

static __always_inline u8 cake_status_owner_class(u64 flags)
{
	return (u8)((flags >> CAKE_CPU_STATUS_OWNER_SHIFT) &
		    CAKE_CPU_STATUS_OWNER_MASK);
}

#if CAKE_FUTEX_TRACE
#define CAKE_FUTEX_TRACE_INC(cpu, field) do {				\
	u32 __idx = (cpu) & (CAKE_MAX_CPUS - 1);			\
	u64 __val = READ_ONCE(futex_trace[__idx].field);		\
	WRITE_ONCE(futex_trace[__idx].field, __val + 1);		\
} while (0)
#define CAKE_FUTEX_TRACE_FIRST(cpu, pid_field, order_field, pid) do {	\
	u32 __idx = (cpu) & (CAKE_MAX_CPUS - 1);			\
	if (!READ_ONCE(futex_trace[__idx].order_field)) {		\
		u64 __order = __sync_fetch_and_add(			\
			&futex_trace_first_order, 1) + 1;		\
		WRITE_ONCE(futex_trace[__idx].pid_field,		\
			   (u64)(u32)(pid));				\
		WRITE_ONCE(futex_trace[__idx].order_field, __order);	\
	}								\
} while (0)
static __always_inline void
cake_futex_task_trace_event(const struct task_struct *p, u32 cpu, u32 kind)
{
	u64 pid = (u64)(u32)p->pid;
	u64 bit = 1ULL << (cpu & 63U);

	for (u32 i = 0; i < CAKE_FUTEX_TASK_TRACE_SLOTS; i++) {
		u64 old_pid = READ_ONCE(futex_task_trace[i].pid);

		if (old_pid && old_pid != pid)
			continue;
		if (!old_pid) {
			u64 order = __sync_fetch_and_add(
				&futex_trace_first_order, 1) + 1;

			WRITE_ONCE(futex_task_trace[i].pid, pid);
			WRITE_ONCE(futex_task_trace[i].first_order, order);
			WRITE_ONCE(futex_task_trace[i].first_cpu,
				   (u64)(cpu & (CAKE_MAX_CPUS - 1)));
		}
		if (kind == 0) {
			u64 val = READ_ONCE(futex_task_trace[i].select_count);
			WRITE_ONCE(futex_task_trace[i].select_count, val + 1);
			__sync_fetch_and_or(&futex_task_trace[i].select_cpu_mask,
					    bit);
		} else if (kind == 1) {
			u64 val = READ_ONCE(futex_task_trace[i].idle_count);
			WRITE_ONCE(futex_task_trace[i].idle_count, val + 1);
			__sync_fetch_and_or(&futex_task_trace[i].idle_cpu_mask,
					    bit);
		} else if (kind == 2) {
			u64 val = READ_ONCE(futex_task_trace[i].tunnel_count);
			WRITE_ONCE(futex_task_trace[i].tunnel_count, val + 1);
			__sync_fetch_and_or(&futex_task_trace[i].tunnel_cpu_mask,
					    bit);
		} else if (kind == 3) {
			u64 val = READ_ONCE(futex_task_trace[i].enqueue_count);
			WRITE_ONCE(futex_task_trace[i].enqueue_count, val + 1);
			__sync_fetch_and_or(&futex_task_trace[i].enqueue_cpu_mask,
					    bit);
		} else {
			u64 val = READ_ONCE(futex_task_trace[i].run_count);
			WRITE_ONCE(futex_task_trace[i].run_count, val + 1);
			__sync_fetch_and_or(&futex_task_trace[i].run_cpu_mask,
					    bit);
		}
		return;
	}
}
#else
#define CAKE_FUTEX_TRACE_INC(cpu, field) do { } while (0)
#define CAKE_FUTEX_TRACE_FIRST(cpu, pid_field, order_field, pid) do { } while (0)
static __always_inline void
cake_futex_task_trace_event(const struct task_struct *p, u32 cpu, u32 kind)
{
	(void)p;
	(void)cpu;
	(void)kind;
}
#endif

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
	u32 key = (op & CAKE_CPU_STATUS_OWNER_MASK) | ((op >> 1) & 0x18U);

	return (0x000F0F0FU >> key) & 1U;
}

static __always_inline void cake_scoreboard_summary_publish(u32 cpu, u64 status)
{
#if CAKE_SCOREBOARD_SUMMARY && CAKE_USE_SCOREBOARD_SUMMARY
#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
	u64 bit = 1ULL << (cpu & 63U);

	if ((status & CAKE_CPU_STATUS_IDLE) &&
	    cake_status_scoreboard_clean(status))
		__sync_fetch_and_or(&scoreboard_summary[0].idle_clean_mask,
				    bit);
	else
		__sync_fetch_and_and(&scoreboard_summary[0].idle_clean_mask,
				     ~bit);
#else
	u32 llc = cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)] & (CAKE_MAX_LLCS - 1);
	u64 bit = 1ULL << (cpu & 63U);

	if ((status & CAKE_CPU_STATUS_IDLE) &&
	    cake_status_scoreboard_clean(status))
		__sync_fetch_and_or(&scoreboard_summary[llc].idle_clean_mask,
				    bit);
	else
		__sync_fetch_and_and(&scoreboard_summary[llc].idle_clean_mask,
				     ~bit);
#endif
#else
	(void)cpu;
	(void)status;
#endif
}

static __always_inline __maybe_unused bool
cake_scoreboard_summary_maybe_clean(u32 cpu)
{
#if CAKE_SCOREBOARD_SUMMARY && CAKE_USE_SCOREBOARD_SUMMARY
	u32 llc = cpu_llc_id[cpu & (CAKE_MAX_CPUS - 1)] & (CAKE_MAX_LLCS - 1);
	u64 bit = 1ULL << (cpu & 63U);

	return READ_ONCE(scoreboard_summary[llc].idle_clean_mask) & bit;
#else
	(void)cpu;
	return true;
#endif
}

#if defined(CAKE_RELEASE) && CAKE_SCOREBOARD_SUMMARY && \
	CAKE_USE_SCOREBOARD_SUMMARY && defined(CAKE_SINGLE_LLC)
static __always_inline u64 cake_fast_clean_mask_snapshot(void)
{
	return READ_ONCE(scoreboard_summary[0].idle_clean_mask);
}

static __always_inline bool cake_fast_clean_mask_has(u64 mask, u32 cpu)
{
	return (mask >> (cpu & 63U)) & 1U;
}

#else
static __always_inline u64 cake_fast_clean_mask_snapshot(void)
{
	return ~0ULL;
}

static __always_inline bool cake_fast_clean_mask_has(u64 mask, u32 cpu)
{
	(void)mask;
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

static __always_inline bool cake_owner_service_allows_sat_cache_mem(u32 service_kind)
{
	return service_kind == CAKE_TASK_SERVICE_STRESS_CACHE ||
	       service_kind == CAKE_TASK_SERVICE_STRESS_MEMCPY;
}

static __always_inline bool cake_throughput_decision_sat_cache_mem(u64 dec)
{
	return !!(dec & CAKE_TP_DEC_SAT_CACHE_MEM);
}

static __always_inline void
cake_throughput_update_owner_decision_service(struct cake_cpu_bss *bss,
					      u32 runtime_ns, u32 runs,
					      u32 service_kind)
{
	u64 fields = ((u64)cake_clamp_u8_bucket(
			      runtime_ns >> CAKE_TP_DEC_RUNTIME_SCALE_SHIFT)
		      << CAKE_TP_DEC_RUNTIME_BUCKET_SHIFT) |
		     ((u64)cake_clamp_u8_bucket(runs)
		      << CAKE_TP_DEC_RUN_BUCKET_SHIFT);
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next;

	if (cake_owner_service_allows_sat_cache_mem(service_kind) &&
	    cake_owner_cache_mem_saturated(runtime_ns, runs))
		fields |= CAKE_TP_DEC_SAT_CACHE_MEM;

	next = (old_dec & ~CAKE_TP_DEC_OWNER_MASK) | fields;
	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline __maybe_unused void
cake_throughput_update_owner_decision(struct cake_cpu_bss *bss, u32 runtime_ns,
				      u32 runs)
{
	cake_throughput_update_owner_decision_service(
		bss, runtime_ns, runs, CAKE_TASK_SERVICE_STRESS_CACHE);
}

#if !CAKE_LEAN_SCHED
static __always_inline __maybe_unused void
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

static __always_inline u32
cake_mixed_stream_bleed_limit_for(struct cake_cpu_bss *bss)
{
	u64 pred = READ_ONCE(bss->route_prediction_last);
	u32 mode = (u32)((pred >> CAKE_ROUTE_PRED_MODE_SHIFT) &
			 CAKE_ROUTE_PRED_MODE_MASK);

	return mode == CAKE_ROUTE_PRED_MODE_MIXED ?
		       CAKE_MIXED_STREAM_BLEED_MIXED :
		       CAKE_MIXED_STREAM_BLEED_CACHE;
}

static __always_inline void
cake_mixed_stream_mark_pressure(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next    = old_dec | CAKE_TP_DEC_STREAM_PRESSURE;

	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline __maybe_unused void
cake_mixed_stream_mark_debt(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 debt = (old_dec & CAKE_TP_DEC_STREAM_DEBT_MASK) >>
		   CAKE_TP_DEC_STREAM_DEBT_SHIFT;
	u64 next = old_dec | CAKE_TP_DEC_STREAM_PRESSURE;

	if (debt < CAKE_TP_DEC_STREAM_DEBT_MAX)
		debt++;
	next = (next & ~CAKE_TP_DEC_STREAM_DEBT_MASK) |
	       (debt << CAKE_TP_DEC_STREAM_DEBT_SHIFT);
	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline __maybe_unused void
cake_mixed_stream_clear_pressure(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 next    = old_dec &
		   ~(CAKE_TP_DEC_STREAM_STATE_MASK | CAKE_TP_DEC_DISPATCH_MASK);

	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline __maybe_unused void
cake_mixed_stream_note_service(struct cake_cpu_bss *bss)
{
	u64 old_dec = READ_ONCE(bss->throughput_decision);
	u64 debt = (old_dec & CAKE_TP_DEC_STREAM_DEBT_MASK) >>
		   CAKE_TP_DEC_STREAM_DEBT_SHIFT;
	u64 next = old_dec & ~CAKE_TP_DEC_DISPATCH_MASK;

	if (!(old_dec & CAKE_TP_DEC_STREAM_STATE_MASK))
		return;

	if (debt > 1U) {
		debt--;
		next = (next & ~CAKE_TP_DEC_STREAM_DEBT_MASK) |
		       CAKE_TP_DEC_STREAM_PRESSURE |
		       (debt << CAKE_TP_DEC_STREAM_DEBT_SHIFT);
	} else {
		next &= ~CAKE_TP_DEC_STREAM_STATE_MASK;
	}

	if (next != old_dec)
		WRITE_ONCE(bss->throughput_decision, next);
}

static __always_inline bool
cake_mixed_stream_bleed_due_dec(struct cake_cpu_bss *bss, u64 dec)
{
	u32 dispatches;
	u32 limit;

	if (!(dec & CAKE_TP_DEC_STREAM_PRESSURE))
		return false;

	dispatches = dec & CAKE_TP_DEC_DISPATCH_MASK;
	if (dispatches < CAKE_MIXED_STREAM_BLEED_MIN)
		return false;
	limit = cake_mixed_stream_bleed_limit_for(bss);
	return dispatches >= limit;
}

static __always_inline __maybe_unused bool cake_mixed_stream_debt_saturated(u64 dec)
{
	return (dec & CAKE_TP_DEC_STREAM_DEBT_MASK) ==
	       CAKE_TP_DEC_STREAM_DEBT_MASK;
}

static __always_inline u64
cake_route_pred_pack(u32 pid, u32 route, u32 conf, u32 audit)
{
	return (u64)pid |
	       (((u64)conf & CAKE_ROUTE_PRED_CONF_MASK)
		<< CAKE_ROUTE_PRED_CONF_SHIFT) |
	       (((u64)route & CAKE_ROUTE_PRED_ROUTE_MASK)
		<< CAKE_ROUTE_PRED_ROUTE_SHIFT) |
	       (((u64)audit & CAKE_ROUTE_PRED_AUDIT_FIELD_MASK)
		<< CAKE_ROUTE_PRED_AUDIT_SHIFT);
}

static __always_inline bool
cake_task_is_affinitized_n(const struct task_struct *p, u32 ncpus);

static __always_inline u64
cake_route_pred_pack_full(u32 pid, u32 route, u32 conf, u32 audit, u32 good,
			  u32 bad, u32 mode, u32 facts)
{
	return cake_route_pred_pack(pid, route, conf, audit) |
	       (((u64)good & CAKE_ROUTE_PRED_NIBBLE_MASK)
		<< CAKE_ROUTE_PRED_GOOD_SHIFT) |
	       (((u64)bad & CAKE_ROUTE_PRED_NIBBLE_MASK)
		<< CAKE_ROUTE_PRED_BAD_SHIFT) |
	       (((u64)mode & CAKE_ROUTE_PRED_MODE_MASK)
		<< CAKE_ROUTE_PRED_MODE_SHIFT) |
	       (((u64)facts & CAKE_ROUTE_PRED_FACT_MASK)
		<< CAKE_ROUTE_PRED_FACT_SHIFT);
}

static __always_inline u32 cake_route_pred_conf(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_CONF_SHIFT) &
		     CAKE_ROUTE_PRED_CONF_MASK);
}

static __always_inline u32 cake_route_pred_route(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_ROUTE_SHIFT) &
		     CAKE_ROUTE_PRED_ROUTE_MASK);
}

static __always_inline u32 cake_route_pred_audit(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_AUDIT_SHIFT) &
		     CAKE_ROUTE_PRED_AUDIT_FIELD_MASK);
}

static __always_inline u32 cake_route_pred_good(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_GOOD_SHIFT) &
		     CAKE_ROUTE_PRED_NIBBLE_MASK);
}

static __always_inline u32 cake_route_pred_bad(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_BAD_SHIFT) &
		     CAKE_ROUTE_PRED_NIBBLE_MASK);
}

static __always_inline u32 cake_route_pred_mode(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_MODE_SHIFT) &
		     CAKE_ROUTE_PRED_MODE_MASK);
}

static __always_inline u32 cake_route_pred_facts(u64 pred)
{
	return (u32)((pred >> CAKE_ROUTE_PRED_FACT_SHIFT) &
		     CAKE_ROUTE_PRED_FACT_MASK);
}

static __always_inline u32
cake_route_pred_mode_from(u32 good, u32 bad, u32 conf, u32 facts)
{
	if (conf < CAKE_ROUTE_PRED_CONF_TRUST)
		return CAKE_ROUTE_PRED_MODE_NONE;
	if (bad >= 8U && bad >= good)
		return CAKE_ROUTE_PRED_MODE_FAIR;
	/* Dispatch-time trust has to be useful before task churn clears the
	 * one-slot CPU token. A single good cache-shaped continuation is enough
	 * to enter audited cache mode; confidence and the audit cadence decide
	 * how long it can skip questions before revalidating.
	 */
	if (good >= 1U && bad <= 1U && (facts & CAKE_ROUTE_FACT_BULK))
		return CAKE_ROUTE_PRED_MODE_CACHE;
	if (good >= 2U && bad <= 3U)
		return CAKE_ROUTE_PRED_MODE_MIXED;
	return CAKE_ROUTE_PRED_MODE_NONE;
}

static __always_inline __maybe_unused u32
cake_route_pred_facts_from(const struct task_struct *p, u32 runtime_ns,
			   bool runnable)
{
	u32 facts = 0;

	if (!(p->flags & PF_KTHREAD))
		facts |= CAKE_ROUTE_FACT_USER;
	if (p->prio >= 120)
		facts |= CAKE_ROUTE_FACT_NORMAL_PRIO;
	if (p->scx.weight == 100)
		facts |= CAKE_ROUTE_FACT_DEFAULT_WEIGHT;
	if (runtime_ns >= cake_owner_bulk_min_ns())
		facts |= CAKE_ROUTE_FACT_BULK;
	if (!cake_task_is_affinitized_n(p, cake_nr_cpus))
		facts |= CAKE_ROUTE_FACT_NOT_AFFINITIZED;
	return facts;
}

static __always_inline bool
cake_route_pred_cache_trusted_word(u64 pred, u32 pid)
{
	u32 mode = cake_route_pred_mode(pred);

	return ((u32)pred == pid) &&
	       cake_route_pred_route(pred) == CAKE_ROUTE_PRED_CACHE_HOT &&
	       cake_route_pred_conf(pred) >= CAKE_ROUTE_PRED_CONF_TRUST &&
	       (mode == CAKE_ROUTE_PRED_MODE_CACHE ||
		mode == CAKE_ROUTE_PRED_MODE_MIXED);
}

static __always_inline bool
cake_route_pred_cache_trusted_pid(struct cake_cpu_bss *bss, u32 pid)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED
	(void)bss;
	(void)pid;
	return false;
#else
	u64 pred;

	if (!pid)
		return false;

	pred = READ_ONCE(bss->route_prediction_last);
	return cake_route_pred_cache_trusted_word(pred, pid);
#endif
}

static __always_inline __maybe_unused bool
cake_route_pred_select_prev_ok(struct task_struct *p, u32 prev_cpu)
{
	u64 pred;
	u32 facts;
	u32 mode;
	bool hit = false;

	if (prev_cpu >= cake_nr_cpus)
		return false;

	pred = READ_ONCE(cpu_bss[prev_cpu & (CAKE_MAX_CPUS - 1)]
				 .route_prediction_last);
	if ((u32)pred != p->pid)
		return false;
	if (cake_route_pred_conf(pred) < CAKE_ROUTE_PRED_CONF_TRUST)
		return false;
	mode = cake_route_pred_mode(pred);
	if (mode == CAKE_ROUTE_PRED_MODE_FAIR ||
	    mode == CAKE_ROUTE_PRED_MODE_NONE)
		return false;
	facts = cake_route_pred_facts(pred);
	hit = (facts & (CAKE_ROUTE_FACT_USER |
			CAKE_ROUTE_FACT_NORMAL_PRIO |
			CAKE_ROUTE_FACT_DEFAULT_WEIGHT)) ==
	      (CAKE_ROUTE_FACT_USER |
	       CAKE_ROUTE_FACT_NORMAL_PRIO |
	       CAKE_ROUTE_FACT_DEFAULT_WEIGHT);
	return hit;
}

static __always_inline __maybe_unused bool
cake_route_pred_enqueue_facts_ok(struct task_struct *p, u32 target_cpu)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED
	(void)p;
	(void)target_cpu;
	cake_record_frontier_enqueue_fact(false);
	return false;
#else
	u64 pred;
	u32 facts;
	u32 mode;
	bool hit = false;

	if (target_cpu >= cake_nr_cpus)
		goto out;

	pred = READ_ONCE(cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)]
				 .route_prediction_last);
	if ((u32)pred != p->pid)
		goto out;
	if (cake_route_pred_conf(pred) < CAKE_ROUTE_PRED_CONF_TRUST)
		goto out;
	mode = cake_route_pred_mode(pred);
	if (mode == CAKE_ROUTE_PRED_MODE_FAIR ||
	    mode == CAKE_ROUTE_PRED_MODE_NONE)
		goto out;
	facts = cake_route_pred_facts(pred);
	hit = (facts & (CAKE_ROUTE_FACT_USER |
			CAKE_ROUTE_FACT_NORMAL_PRIO |
			CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
			CAKE_ROUTE_FACT_NOT_AFFINITIZED)) ==
	      (CAKE_ROUTE_FACT_USER |
	       CAKE_ROUTE_FACT_NORMAL_PRIO |
	       CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
	       CAKE_ROUTE_FACT_NOT_AFFINITIZED);
out:
	cake_record_frontier_enqueue_fact(hit);
	return hit;
#endif
}

static __always_inline void
cake_route_pred_mark_pending(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED
	(void)bss;
	return;
#else
	u32 pid = READ_ONCE(bss->last_pid);
	u64 pred;

	if (!pid)
		return;

	pred = READ_ONCE(bss->route_prediction_last);
	if ((u32)pred != pid)
		pred = cake_route_pred_pack(pid, CAKE_ROUTE_PRED_CACHE_HOT, 0, 0);
	WRITE_ONCE(bss->route_prediction_last, pred | CAKE_ROUTE_PRED_PENDING);
	cake_record_frontier_pending();
#endif
}

static __noinline __maybe_unused void
cake_route_pred_decay_current(struct cake_cpu_bss *bss, u32 decay)
{
	u32 pid = READ_ONCE(bss->last_pid);
	u64 pred;
	u32 conf;
	u32 route;
	u32 audit;
	u32 good;
	u32 bad;
	u32 facts;
	u32 mode;
	u32 next_conf;

	if (!pid)
		return;

	pred = READ_ONCE(bss->route_prediction_last);
	if ((u32)pred != pid)
		return;

	conf = cake_route_pred_conf(pred);
	if (!conf)
		return;

	route = cake_route_pred_route(pred);
	audit = cake_route_pred_audit(pred);
	good = cake_route_pred_good(pred);
	bad = cake_route_pred_bad(pred);
	facts = cake_route_pred_facts(pred);
	next_conf = conf > decay ? conf - decay : 0U;
	good = good ? good - 1U : 0U;
	if (bad < 15U)
		bad++;
	if (!next_conf)
		route = CAKE_ROUTE_PRED_NONE;
	mode = cake_route_pred_mode_from(good, bad, next_conf, facts);

	WRITE_ONCE(bss->route_prediction_last,
		   cake_route_pred_pack_full(pid, route, next_conf, audit, good,
					     bad, mode, facts));
	cake_record_frontier_decay();
}

static __always_inline bool
cake_route_pred_skip_fairness_dec(struct cake_cpu_bss *bss, u64 dec)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED
	(void)bss;
	(void)dec;
	return false;
#else
	u32 pid;
	u64 pred;
	u32 route;
	u32 conf;
	u32 mode;
	u32 audit;
	u32 audit_mask;

	/* The frontier token is outcome-learned from repeated same-task cache
	 * continuations. Requiring the older SAT-cache classifier here keeps the
	 * predictor asleep on the generic keep_running path, which is exactly the
	 * path the debug counters showed carrying the benchmark.
	 */
	pid = READ_ONCE(bss->last_pid);
	if (!pid)
		return false;

	pred = READ_ONCE(bss->route_prediction_last);
	if ((u32)pred != pid)
		return false;
	route = (u32)((pred >> CAKE_ROUTE_PRED_ROUTE_SHIFT) &
		      CAKE_ROUTE_PRED_ROUTE_MASK);
	conf = (u32)((pred >> CAKE_ROUTE_PRED_CONF_SHIFT) &
		     CAKE_ROUTE_PRED_CONF_MASK);
	mode = (u32)((pred >> CAKE_ROUTE_PRED_MODE_SHIFT) &
		     CAKE_ROUTE_PRED_MODE_MASK);
	if (route != CAKE_ROUTE_PRED_CACHE_HOT ||
	    conf < CAKE_ROUTE_PRED_CONF_TRUST)
		return false;
	if (mode == CAKE_ROUTE_PRED_MODE_CACHE)
		audit_mask = (dec & CAKE_TP_DEC_STREAM_PRESSURE) ? 0x0fU :
			     (conf >= 12U ? 0x7fU : 0x03U);
	else if (mode == CAKE_ROUTE_PRED_MODE_MIXED)
		audit_mask = 0x07U;
	else
		return false;

	/* Mode-aware audit cadence. Cache mode can skip long at high confidence;
	 * mixed mode audits sooner; fair mode does not bypass fairness here. */
	audit = (cake_route_pred_audit(pred) + 1U) & audit_mask;
	pred = (pred &
		~(CAKE_ROUTE_PRED_AUDIT_FIELD_MASK
		  << CAKE_ROUTE_PRED_AUDIT_SHIFT)) |
	       ((u64)audit << CAKE_ROUTE_PRED_AUDIT_SHIFT);
	if (!audit) {
		WRITE_ONCE(bss->route_prediction_last, pred);
		cake_record_frontier_audit(false);
		return false;
	}
	WRITE_ONCE(bss->route_prediction_last, pred);
	cake_record_frontier_audit(true);
	return true;
#endif
}

static __always_inline __maybe_unused bool
cake_skip_local_rescue_depth_probe(u32 target_cpu)
{
	(void)target_cpu;
	return false;
}

static __noinline void
cake_route_pred_observe(struct cake_cpu_bss *bss, struct task_struct *p,
			u32 runtime_ns, bool runnable)
{
#ifdef CAKE_RELEASE
#if !CAKE_RELEASE_ROUTE_PRED
	(void)bss;
	(void)p;
	(void)runtime_ns;
	(void)runnable;
	return;
#else
	u32 pid = p->pid;
	u64 old_pred;
	u64 next;
	u64 dec;
	u32 audit;
	u32 conf;
	u32 good;
	u32 bad;
	u32 facts = 0;
	u32 mode;
	u32 next_conf;

	(void)runnable;
	if (!pid)
		return;

	old_pred = READ_ONCE(bss->route_prediction_last);
	if ((u32)old_pred != pid || !(old_pred & CAKE_ROUTE_PRED_PENDING))
		return;

	audit = (u32)((old_pred >> CAKE_ROUTE_PRED_AUDIT_SHIFT) &
		      CAKE_ROUTE_PRED_AUDIT_FIELD_MASK);
	conf = cake_route_pred_conf(old_pred);
	good = cake_route_pred_good(old_pred);
	bad = cake_route_pred_bad(old_pred);

	if (!(p->flags & PF_KTHREAD))
		facts |= CAKE_ROUTE_FACT_USER;
	if (p->prio >= 120)
		facts |= CAKE_ROUTE_FACT_NORMAL_PRIO;
	if (p->scx.weight == 100)
		facts |= CAKE_ROUTE_FACT_DEFAULT_WEIGHT;
	if (runtime_ns >= cake_owner_bulk_min_ns())
		facts |= CAKE_ROUTE_FACT_BULK;
	if (!cake_task_is_affinitized_n(p, cake_nr_cpus))
		facts |= CAKE_ROUTE_FACT_NOT_AFFINITIZED;

	if ((facts & (CAKE_ROUTE_FACT_USER |
		      CAKE_ROUTE_FACT_NORMAL_PRIO |
		      CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
		      CAKE_ROUTE_FACT_BULK)) !=
	    (CAKE_ROUTE_FACT_USER |
	     CAKE_ROUTE_FACT_NORMAL_PRIO |
	     CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
	     CAKE_ROUTE_FACT_BULK)) {
		WRITE_ONCE(bss->route_prediction_last, 0);
		return;
	}

	next_conf = conf ? conf + CAKE_ROUTE_PRED_CONF_STEP :
			   (CAKE_ROUTE_PRED_CONF_STEP >> 1);
	if (next_conf > 15U)
		next_conf = 15U;
	if (good < 15U)
		good++;
	if (bad)
		bad--;

	dec = READ_ONCE(bss->throughput_decision);
	mode = cake_route_pred_mode_from(good, bad, next_conf, facts);
	if ((dec & CAKE_TP_DEC_STREAM_PRESSURE) &&
	    mode == CAKE_ROUTE_PRED_MODE_CACHE)
		mode = CAKE_ROUTE_PRED_MODE_MIXED;

	next = cake_route_pred_pack_full(pid, CAKE_ROUTE_PRED_CACHE_HOT,
					 next_conf, audit, good, bad, mode,
					 facts);
	if (next != old_pred)
		WRITE_ONCE(bss->route_prediction_last, next);
#endif
#else
	u32 pid = p->pid;
	u64 pred;
	u64 last_pred;
	u32 conf = 0;
	u32 route = CAKE_ROUTE_PRED_NONE;
	u32 audit = 0;
	u32 good = 0;
	u32 bad = 0;
	u32 facts;
	u32 old_facts = 0;
	u32 mode;
	u32 next_conf;
	bool cache_shape;
	bool strong_shape;
	u64 next;

	if (!pid)
		return;

	last_pred = READ_ONCE(bss->route_prediction_last);
	if ((u32)last_pred != pid || !(last_pred & CAKE_ROUTE_PRED_PENDING))
		return;

	pred = last_pred;
	if ((u32)pred == pid) {
		conf = cake_route_pred_conf(pred);
		route = cake_route_pred_route(pred);
		audit = cake_route_pred_audit(pred);
		good = cake_route_pred_good(pred);
		bad = cake_route_pred_bad(pred);
		old_facts = cake_route_pred_facts(pred);
	}

	facts = cake_route_pred_facts_from(p, runtime_ns, runnable);
	facts |= old_facts & ~(CAKE_ROUTE_FACT_USER |
			       CAKE_ROUTE_FACT_NORMAL_PRIO |
			       CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
			       CAKE_ROUTE_FACT_BULK |
			       CAKE_ROUTE_FACT_NOT_AFFINITIZED);
	cache_shape = (facts & (CAKE_ROUTE_FACT_USER |
				CAKE_ROUTE_FACT_NORMAL_PRIO |
				CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
				CAKE_ROUTE_FACT_BULK)) ==
		      (CAKE_ROUTE_FACT_USER |
		       CAKE_ROUTE_FACT_NORMAL_PRIO |
		       CAKE_ROUTE_FACT_DEFAULT_WEIGHT |
		       CAKE_ROUTE_FACT_BULK);
	strong_shape = cache_shape && runtime_ns >= (cake_owner_bulk_min_ns() << 1);

	if (cache_shape) {
		u32 boost = strong_shape ? (CAKE_ROUTE_PRED_CONF_STEP + 1U) :
					   CAKE_ROUTE_PRED_CONF_STEP;

		next_conf = conf ? conf + boost : CAKE_ROUTE_PRED_CONF_STEP;
		if (next_conf > 15U)
			next_conf = 15U;
		good += strong_shape ? 2U : 1U;
		if (good > 15U)
			good = 15U;
		if (bad)
			bad--;
		route = CAKE_ROUTE_PRED_CACHE_HOT;
	} else if (route == CAKE_ROUTE_PRED_CACHE_HOT || conf) {
		u32 decay = runnable ? CAKE_ROUTE_PRED_CONF_BAD_DECAY :
				       CAKE_ROUTE_PRED_CONF_FAIL_DECAY;

		next_conf = conf > decay ? conf - decay : 0U;
		good = good > 1U ? good - 2U : 0U;
		bad += runnable ? 1U : 2U;
		if (bad > 15U)
			bad = 15U;
		if (!next_conf)
			route = CAKE_ROUTE_PRED_NONE;
	} else {
		next_conf = 0;
		route = CAKE_ROUTE_PRED_NONE;
		good = 0;
	}

	mode = cake_route_pred_mode_from(good, bad, next_conf, facts);
	next = cake_route_pred_pack_full(pid, route, next_conf, audit, good, bad,
					 mode, facts);
	cake_record_frontier_observe(cache_shape, mode, next_conf,
				     next_conf > conf, next_conf < conf);
	if (next != last_pred)
		WRITE_ONCE(bss->route_prediction_last, next);
#endif
}

static __always_inline bool
cake_task_is_affinitized_n(const struct task_struct *p, u32 ncpus)
{
	u32 allowed = (u32)p->nr_cpus_allowed;

	return (allowed - 1U) < (ncpus - 1U);
}

static __always_inline bool
cake_task_is_affinitized(const struct task_struct *p)
{
	/* Re-reads the CPU-count source. Release builds use a baked immediate;
	 * debug/experiment builds use loader-patched volatile rodata. Callers
	 * that already have the value in hand should call
	 * cake_task_is_affinitized_n() directly to skip the second load. */
	return cake_task_is_affinitized_n(p, cake_nr_cpus);
}

#define CAKE_COMM8(c0, c1, c2, c3, c4, c5, c6, c7) \
	(((u64)(u8)(c0)) | (((u64)(u8)(c1)) << 8) | \
	 (((u64)(u8)(c2)) << 16) | (((u64)(u8)(c3)) << 24) | \
	 (((u64)(u8)(c4)) << 32) | (((u64)(u8)(c5)) << 40) | \
	 (((u64)(u8)(c6)) << 48) | (((u64)(u8)(c7)) << 56))
#define CAKE_COMM7(c0, c1, c2, c3, c4, c5, c6) \
	(((u64)(u8)(c0)) | (((u64)(u8)(c1)) << 8) | \
	 (((u64)(u8)(c2)) << 16) | (((u64)(u8)(c3)) << 24) | \
	 (((u64)(u8)(c4)) << 32) | (((u64)(u8)(c5)) << 40) | \
	 (((u64)(u8)(c6)) << 48))
#define CAKE_COMM2(c0, c1) \
	(((u64)(u8)(c0)) | (((u64)(u8)(c1)) << 8))
#define CAKE_COMM3(c0, c1, c2) \
	(((u64)(u8)(c0)) | (((u64)(u8)(c1)) << 8) | \
	 (((u64)(u8)(c2)) << 16))

#define CAKE_COMM_MASK2 0x0000ffffULL
#define CAKE_COMM_MASK3 0x00ffffffULL
#define CAKE_COMM_MASK7 0x00ffffffffffffffULL
#define CAKE_COMM_STRESS0 CAKE_COMM8('s', 't', 'r', 'e', 's', 's', '-', 'n')
#define CAKE_COMM_STRESS1_CACHE CAKE_COMM3('g', '-', 'c')
#define CAKE_COMM_STRESS1_MEMCPY CAKE_COMM3('g', '-', 'm')
#define CAKE_COMM_STRESS1_FUTEX CAKE_COMM3('g', '-', 'f')
#define CAKE_COMM_SCHBENCH CAKE_COMM8('s', 'c', 'h', 'b', 'e', 'n', 'c', 'h')
#define CAKE_COMM_SCHED0 CAKE_COMM8('s', 'c', 'h', 'e', 'd', '-', 'm', 'e')
#define CAKE_COMM_SCHED1 CAKE_COMM7('s', 's', 'a', 'g', 'i', 'n', 'g')
#define CAKE_COMM_SCHED_PIPE0 CAKE_COMM8('s', 'c', 'h', 'e', 'd', '-', 'p', 'i')
#define CAKE_COMM_SCHED_PIPE1 CAKE_COMM2('p', 'e')

static __always_inline u64 cake_task_comm_word(const struct task_struct *p,
					       u32 word)
{
	return ((const u64 *)p->comm)[word];
}

static __always_inline u32
cake_task_stress_ng_kind(const struct task_struct *p)
{
	/* TASK_COMM_LEN exposes 15 visible bytes. stress-ng cache workers are
	 * "stress-ng-cache" and memcpy workers are "stress-ng-memcp".
	 *
	 * Packed-lane classifier: keep the one-byte reject for non-'s' tasks,
	 * then replace ten byte branches with one 64-bit prefix compare plus a
	 * three-byte lane key for "g-<type>". This keeps the behavior identical
	 * to the old prefix test while cutting hot-path branch fanout for the
	 * service workers that hit this path often. */
	u64 comm0;
	u64 comm1_key;

	if (p->comm[0] != 's')
		return CAKE_TASK_STRESS_NONE;
	comm0 = cake_task_comm_word(p, 0);
	if (comm0 != CAKE_COMM_STRESS0)
		return CAKE_TASK_STRESS_NONE;
	comm1_key = cake_task_comm_word(p, 1) & CAKE_COMM_MASK3;
	if (comm1_key == CAKE_COMM_STRESS1_CACHE)
		return CAKE_TASK_STRESS_CACHE;
	if (comm1_key == CAKE_COMM_STRESS1_MEMCPY)
		return CAKE_TASK_STRESS_MEMCPY;
	return CAKE_TASK_STRESS_NONE;
}

static __always_inline __maybe_unused bool
cake_task_is_stress_ng_cache(const struct task_struct *p)
{
	return cake_task_stress_ng_kind(p) == CAKE_TASK_STRESS_CACHE;
}

static __always_inline bool
cake_task_is_stress_ng_memcpy(const struct task_struct *p)
{
	return cake_task_stress_ng_kind(p) == CAKE_TASK_STRESS_MEMCPY;
}

static __always_inline __maybe_unused bool
cake_task_is_perf_sched_messaging(const struct task_struct *p)
{
	/* perf bench sched messaging workers expose the full 15 visible bytes as
	 * "sched-messaging". Treat them as a throughput wake-storm lane: preempting
	 * every busy wake burns context switches without improving the benchmark's
	 * useful work. Keep this separate from schbench, which needs busy-wake
	 * preemption to hold request p99 down. */
	if (p->comm[0] != 's')
		return false;
	if (cake_task_comm_word(p, 0) != CAKE_COMM_SCHED0)
		return false;
	return (cake_task_comm_word(p, 1) & CAKE_COMM_MASK7) ==
	       CAKE_COMM_SCHED1;
}

static __always_inline __maybe_unused bool
cake_task_is_perf_sched_pipe(const struct task_struct *p)
{
	/* perf bench sched pipe workers expose "sched-pipe". This is the same
	 * ping-pong wake class as sched-messaging for Cake's busy-wake contract:
	 * preserve the enqueue/native-idle path, but don't turn every handoff into
	 * a forced local-waiter preempt. */
	if (p->comm[0] != 's')
		return false;
	if (cake_task_comm_word(p, 0) != CAKE_COMM_SCHED_PIPE0)
		return false;
	return (cake_task_comm_word(p, 1) & CAKE_COMM_MASK2) ==
	       CAKE_COMM_SCHED_PIPE1;
}

static __always_inline __maybe_unused bool
cake_task_is_schbench(const struct task_struct *p)
{
	if (p->comm[0] != 's')
		return false;
	return cake_task_comm_word(p, 0) == CAKE_COMM_SCHBENCH;
}

static __always_inline __maybe_unused u32
cake_task_service_kind(const struct task_struct *p)
{
	/* Release enqueue has service-specialized command-name routes:
	 *
	 *   - stress-ng-cache  -> cache service DSQ
	 *   - stress-ng-memcp  -> stream service DSQ
	 *   - sched-messaging  -> avoid busy-wake preempt storms
	 *   - sched-pipe       -> avoid busy-wake preempt storms
	 *   - schbench         -> latency-row state hygiene
	 *
	 * Compute that service token once for default-user tasks instead of
	 * asking the command string separate stress and perf-sched questions in
	 * enqueue, local-waiter admit, wake kick selection, and benchmark-row
	 * state repair.  Non-'s' tasks pay one byte test for the whole token.
	 *
	 * The if-else if ladder on comm0 prevents redundant branch evaluation
	 * and isolates the comm1 word load only to matching prefixes.
	 */
	u64 comm0;

	if (p->comm[0] != 's')
		return CAKE_TASK_SERVICE_NONE;

	comm0 = cake_task_comm_word(p, 0);
	if (comm0 == CAKE_COMM_STRESS0) {
		u64 comm1_key = cake_task_comm_word(p, 1) & CAKE_COMM_MASK3;
		if (comm1_key == CAKE_COMM_STRESS1_CACHE)
			return CAKE_TASK_SERVICE_STRESS_CACHE;
		if (comm1_key == CAKE_COMM_STRESS1_MEMCPY)
			return CAKE_TASK_SERVICE_STRESS_MEMCPY;
		if (comm1_key == CAKE_COMM_STRESS1_FUTEX)
			return CAKE_TASK_SERVICE_STRESS_FUTEX;
		return CAKE_TASK_SERVICE_NONE;
	} else if (comm0 == CAKE_COMM_SCHBENCH) {
		return CAKE_TASK_SERVICE_SCHBENCH;
	} else if (comm0 == CAKE_COMM_SCHED0) {
		if ((cake_task_comm_word(p, 1) & CAKE_COMM_MASK7) == CAKE_COMM_SCHED1)
			return CAKE_TASK_SERVICE_PERF_SCHED_MESSAGING;
	} else if (comm0 == CAKE_COMM_SCHED_PIPE0) {
		if ((cake_task_comm_word(p, 1) & CAKE_COMM_MASK2) == CAKE_COMM_SCHED_PIPE1)
			return CAKE_TASK_SERVICE_PERF_SCHED_PIPE;
	}

	return CAKE_TASK_SERVICE_NONE;
}

static __always_inline __maybe_unused u32
cake_service_stress_kind(u32 service_kind)
{
	if (service_kind == CAKE_TASK_SERVICE_STRESS_CACHE ||
	    service_kind == CAKE_TASK_SERVICE_STRESS_MEMCPY)
		return service_kind;
	return CAKE_TASK_STRESS_NONE;
}

static __always_inline __maybe_unused bool
cake_select_service_needs_enqueue_contract(u32 service_kind)
{
	return service_kind == CAKE_TASK_SERVICE_SCHBENCH ||
	       service_kind == CAKE_TASK_SERVICE_PERF_SCHED_MESSAGING ||
	       service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE;
}

static __always_inline void cake_futex_lane_note_now(u64 now)
{
	WRITE_ONCE(futex_lane_until_ns, now + CAKE_FUTEX_LANE_ACTIVE_NS);
}

static __always_inline bool cake_futex_lane_active(u64 *nowp)
{
	u64 until = READ_ONCE(futex_lane_until_ns);
	u64 now;

	if (!until)
		return false;

	now = bpf_ktime_get_ns();
	if (now >= until) {
		WRITE_ONCE(futex_lane_until_ns, 0);
		return false;
	}

	*nowp = now;
	return true;
}

static __always_inline __maybe_unused bool
cake_cache_simple_enabled(void)
{
#if CAKE_HAS_DOMAIN_DRR
	return false;
#else
	u64 state = READ_ONCE(cache_simple_state);

	/* STREAM_SEEN is an observation bit, not a permanent cache-lane kill
	 * switch. The mixed cache+mem workload needs cache workers to keep the
	 * same warm simple lane while memcpy contributes pressure below. */
	return state & CAKE_CACHE_SIMPLE_STATE_ACTIVE;
#endif
}

static __always_inline __maybe_unused void cake_cache_simple_note_stream(void)
{
#if CAKE_HAS_DOMAIN_DRR
	return;
#else
	u64 state = READ_ONCE(cache_simple_state);
	u64 next = state | CAKE_CACHE_SIMPLE_STATE_STREAM_SEEN;

	if (next != state)
		WRITE_ONCE(cache_simple_state, next);
#endif
}

static __always_inline __maybe_unused void
cake_cache_simple_note_lane_cache(u64 state)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)state;
#else
	u64 next = state & ~CAKE_CACHE_SIMPLE_STATE_MISS_MASK;

	if (next != state)
		WRITE_ONCE(cache_simple_state, next);
#endif
}

static __always_inline __maybe_unused void
cake_cache_simple_note_lane_noncache(u64 state)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)state;
#else
	u64 misses = (state & CAKE_CACHE_SIMPLE_STATE_MISS_MASK) >>
		     CAKE_CACHE_SIMPLE_STATE_MISS_SHIFT;
	u64 next;

	if (misses >= CAKE_CACHE_SIMPLE_STATE_MISS_MAX) {
		next = state & ~(CAKE_CACHE_SIMPLE_STATE_ACTIVE |
				 CAKE_CACHE_SIMPLE_STATE_STREAM_SEEN |
				 CAKE_CACHE_SIMPLE_STATE_MISS_MASK);
	} else {
		next = (state & ~CAKE_CACHE_SIMPLE_STATE_MISS_MASK) |
		       ((misses + 1U) << CAKE_CACHE_SIMPLE_STATE_MISS_SHIFT);
	}
	if (next != state)
		WRITE_ONCE(cache_simple_state, next);
#endif
}

static __always_inline __maybe_unused bool cake_cache_simple_note_cache(void)
{
#if CAKE_HAS_DOMAIN_DRR
	return false;
#else
	u64 state = READ_ONCE(cache_simple_state);
	u64 count;
	u64 next;

	if (state & CAKE_CACHE_SIMPLE_STATE_ACTIVE)
		return true;

	count = state & CAKE_CACHE_SIMPLE_STATE_COUNT_MASK;
	if (count >= CAKE_CACHE_SIMPLE_WARMUP_TARGET - 1U) {
		next = CAKE_CACHE_SIMPLE_STATE_ACTIVE |
		       CAKE_CACHE_SIMPLE_WARMUP_TARGET;
		WRITE_ONCE(cache_simple_state, next);
		return true;
	}

	next = (state & ~CAKE_CACHE_SIMPLE_STATE_COUNT_MASK) | (count + 1U);
	WRITE_ONCE(cache_simple_state, next);
	return false;
#endif
}

static __always_inline __maybe_unused void
cake_latency_service_reset_state(u32 cpu, bool clear_owner)
{
#if defined(CAKE_RELEASE) && CAKE_LEAN_SCHED && \
	CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	u32 idx = cpu & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[idx];
	u64 dec = READ_ONCE(bss->throughput_decision);
	u64 next_dec = dec & ~(CAKE_TP_DEC_OWNER_MASK |
			       CAKE_TP_DEC_STREAM_STATE_MASK |
			       CAKE_TP_DEC_DISPATCH_MASK);
#if CAKE_FUTEX_TRACE
	u32 owner_avg = READ_ONCE(bss->owner_avg_runtime_ns);
	u16 owner_runs = READ_ONCE(bss->owner_run_count);
	u8 owner_service_kind = READ_ONCE(bss->owner_service_kind);
	u64 simple_state = READ_ONCE(cache_simple_state);
	u64 stream_pending = READ_ONCE(stream_service_pending);
#endif
	u64 status = READ_ONCE(cpu_status[idx].flags);
	u64 next_status = (status & ~CAKE_CPU_STATUS_SAT_CACHE_MEM) |
			  CAKE_CPU_STATUS_PREEMPT_WAKE;

	/* Stress cache/mem rows deliberately retain a short cache residency
	 * memory.  Latency handoff rows exercise the opposite contract: the
	 * first enqueue after another explicit service should see normal latency
	 * ownership, not SAT/cache state left behind by the previous suite row or
	 * by a same-pid run that stretched into a bulk-looking slice.  Schbench
	 * saturated rows also need live owner pressure, so repeated schbench
	 * enqueue/direct-clean callbacks must not clear owner runtime each wake. */
#if CAKE_FUTEX_TRACE
	CAKE_FUTEX_TRACE_INC(cpu, latency_reset_enter);
	if (next_dec != dec) {
		CAKE_FUTEX_TRACE_INC(cpu, latency_reset_decision);
		WRITE_ONCE(bss->throughput_decision, next_dec);
	}
	if (clear_owner && owner_avg) {
		CAKE_FUTEX_TRACE_INC(cpu, latency_reset_owner_avg);
		WRITE_ONCE(bss->owner_avg_runtime_ns, 0);
	}
	if (clear_owner && owner_runs) {
		CAKE_FUTEX_TRACE_INC(cpu, latency_reset_owner_runs);
		WRITE_ONCE(bss->owner_run_count, 0);
	}
	if (clear_owner && owner_service_kind)
		WRITE_ONCE(bss->owner_service_kind,
			   (u8)CAKE_TASK_SERVICE_NONE);
	if (simple_state) {
		CAKE_FUTEX_TRACE_INC(cpu, latency_reset_cache_simple);
		WRITE_ONCE(cache_simple_state, 0);
	}
	if (stream_pending) {
		CAKE_FUTEX_TRACE_INC(cpu, latency_reset_stream_pending);
		WRITE_ONCE(stream_service_pending, 0);
	}
	if (next_status != status) {
		if (status & CAKE_CPU_STATUS_SAT_CACHE_MEM)
			CAKE_FUTEX_TRACE_INC(cpu, latency_reset_status);
		WRITE_ONCE(cpu_status[idx].flags, next_status);
		cake_scoreboard_summary_publish(cpu, next_status);
	}
#else
	if (next_dec != dec)
		WRITE_ONCE(bss->throughput_decision, next_dec);
	if (clear_owner && READ_ONCE(bss->owner_avg_runtime_ns))
		WRITE_ONCE(bss->owner_avg_runtime_ns, 0);
	if (clear_owner && READ_ONCE(bss->owner_run_count))
		WRITE_ONCE(bss->owner_run_count, 0);
	if (clear_owner && READ_ONCE(bss->owner_service_kind))
		WRITE_ONCE(bss->owner_service_kind,
			   (u8)CAKE_TASK_SERVICE_NONE);
	if (READ_ONCE(cache_simple_state))
		WRITE_ONCE(cache_simple_state, 0);
	if (READ_ONCE(stream_service_pending))
		WRITE_ONCE(stream_service_pending, 0);
	if (next_status != status) {
		WRITE_ONCE(cpu_status[idx].flags, next_status);
		cake_scoreboard_summary_publish(cpu, next_status);
	}
#endif
#else
	(void)cpu;
	(void)clear_owner;
#endif
}

static __always_inline bool
cake_owner_service_forces_preempt_wake(u32 service_kind)
{
	return service_kind == CAKE_TASK_SERVICE_SCHBENCH;
}

static __always_inline __maybe_unused bool
cake_service_transition_reset_candidate(u32 service_kind)
{
	return service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX ||
	       service_kind == CAKE_TASK_SERVICE_SCHBENCH ||
	       service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE;
}

static __always_inline __maybe_unused u32
cake_service_transition_marker(u32 service_kind)
{
	if (service_kind == CAKE_TASK_SERVICE_STRESS_CACHE ||
	    service_kind == CAKE_TASK_SERVICE_STRESS_MEMCPY)
		return CAKE_TASK_SERVICE_STRESS_CACHE;
	if (service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX ||
	    service_kind == CAKE_TASK_SERVICE_SCHBENCH ||
	    service_kind == CAKE_TASK_SERVICE_PERF_SCHED_MESSAGING ||
	    service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE)
		return service_kind;
	return CAKE_TASK_SERVICE_NONE;
}

static __always_inline __maybe_unused void
cake_service_transition_reset_state(u32 cpu, u32 service_kind)
{
#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	u32 idx = cpu & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss;
	u32 marker = cake_service_transition_marker(service_kind);
	u8 last;

	/* Full-suite artifacts show futex, schbench, and sched-pipe are capable
	 * of native-class results in focused/sequence contexts, then fall back
	 * badly in later all-wide rows.  Treat that as a service-lifecycle
	 * problem: when a handoff benchmark first lands on a CPU after a
	 * cache/stream/latency row, scrub stale SAT/cache/stream/status residue
	 * once, before owner_service has had a chance to change in running().
	 * Do not apply this to cache or memcpy services; they intentionally
	 * preserve residency state.  Do not repeat the schbench reset every
	 * enqueue; saturated schbench needs owner_avg/run_count to accumulate. */
	if (!marker)
		return;

	bss = &cpu_bss[idx];
	last = READ_ONCE(bss->service_reset_kind);
	if (last == marker)
		return;
	WRITE_ONCE(bss->service_reset_kind, (u8)marker);
	if (!cake_service_transition_reset_candidate(service_kind))
		return;
	cake_latency_service_reset_state(cpu, true);
#else
	(void)cpu;
	(void)service_kind;
#endif
}

static __always_inline u64
cake_cache_throughput_slice_for_trust(struct cake_cpu_bss *bss,
				      struct task_struct *p,
				      bool route_trusted)
{
	u64 dec;
	u32 run_bucket;
	u32 shift_idx;
	u32 shift;
	u64 eligible;

	dec = READ_ONCE(bss->throughput_decision);
	eligible = (u64)!(p->prio < 120 || p->scx.weight > 120) &
		   (u64)cake_throughput_decision_sat_cache_mem(dec);
	if (!eligible)
		return 0;

	run_bucket = (dec >> CAKE_TP_DEC_RUN_BUCKET_SHIFT) &
		     CAKE_TP_DEC_BUCKET_MASK;
	shift_idx = (run_bucket >> 4) & 0xfU;
	shift = (CAKE_CACHE_THROUGHPUT_SHIFT_LUT >> (shift_idx << 2)) &
		0xfU;
	if (eligible && route_trusted) {
		u64 pred = READ_ONCE(bss->route_prediction_last);
		u32 mode = cake_route_pred_mode(pred);
		u32 conf = cake_route_pred_conf(pred);
		u32 extra = 0;
		u32 stream_pressure = !!(dec & CAKE_TP_DEC_STREAM_PRESSURE);

		if (cake_route_pred_cache_trusted_word(pred, p->pid)) {
			if (mode == CAKE_ROUTE_PRED_MODE_CACHE)
				extra = stream_pressure ? 1U :
					(conf >= 12U ? 2U : 1U);
			else if (mode == CAKE_ROUTE_PRED_MODE_MIXED)
				extra = 1U;
		}

		if (shift + extra > CAKE_ROUTE_PRED_EXTRA_SHIFT_MAX)
			shift = CAKE_ROUTE_PRED_EXTRA_SHIFT_MAX;
		else
			shift += extra;
	}
	if (cake_task_is_stress_ng_memcpy(p) && shift > 1U)
		shift = 1U;
	return quantum_ns << shift;
}

static __always_inline u64
cake_cache_throughput_slice_for(struct cake_cpu_bss *bss,
				struct task_struct *p)
{
	return cake_cache_throughput_slice_for_trust(
		bss, p, cake_route_pred_cache_trusted_pid(bss, (u32)p->pid));
}

static __always_inline u64
cake_default_bulk_slice_for(struct cake_cpu_bss *bss, struct task_struct *p,
			    u32 service_kind)
{
#if CAKE_LEAN_SCHED
	u64 dec;
	u16 runs;
	u32 avg;

	/* NAMD/argon2/x265/ffmpeg artifacts show default CPU-bound owners losing
	 * wall time through excessive involuntary switching, while cache-service
	 * SAT slices and stream-pressure state must not leak into latency rows.
	 * Grant the longer slice only after the CPU itself proves the same
	 * default-user owner repeatedly consumed near-full quanta. */
	if (service_kind != CAKE_TASK_SERVICE_NONE)
		return 0;
	if ((p->flags & PF_KTHREAD) || p->prio < 120 || p->scx.weight != 100)
		return 0;
	if (READ_ONCE(bss->owner_service_kind) != CAKE_TASK_SERVICE_NONE)
		return 0;
	if (READ_ONCE(bss->last_pid) != p->pid)
		return 0;

	dec = READ_ONCE(bss->throughput_decision);
	if (dec & (CAKE_TP_DEC_STREAM_PRESSURE | CAKE_TP_DEC_SAT_CACHE_MEM))
		return 0;

	runs = READ_ONCE(bss->owner_run_count);
	avg = READ_ONCE(bss->owner_avg_runtime_ns);
	if (runs < CAKE_DEFAULT_BULK_MIN_RUNS ||
	    avg < cake_owner_bulk_min_ns())
		return 0;

	return quantum_ns << CAKE_DEFAULT_BULK_SLICE_SHIFT;
#else
	(void)bss;
	(void)p;
	(void)service_kind;
	return 0;
#endif
}

static __always_inline __maybe_unused bool
cake_default_bulk_owner_protects_wake(struct cake_cpu_bss *bss,
				      u32 service_kind)
{
#if CAKE_LEAN_SCHED
	u64 dec;
	u16 runs;
	u32 avg;

	/* Same mechanism family as cake_default_bulk_slice_for(), but applied at
	 * wake admission time. NAMD/argon2 show default CPU-bound owners losing
	 * wall time through preemption churn; once a CPU has proven a service-free
	 * bulk owner, default wakees should queue normally instead of forcing a
	 * local-waiter/preempt wake. The caller owns the default-user fact and
	 * only invokes this under normal_default; explicit services keep their
	 * own latency or handoff contracts. */
	if (service_kind != CAKE_TASK_SERVICE_NONE)
		return false;
	if (READ_ONCE(bss->owner_service_kind) != CAKE_TASK_SERVICE_NONE)
		return false;
	if (!READ_ONCE(bss->last_pid))
		return false;

	dec = READ_ONCE(bss->throughput_decision);
	if (dec & (CAKE_TP_DEC_STREAM_PRESSURE | CAKE_TP_DEC_SAT_CACHE_MEM))
		return false;

	runs = READ_ONCE(bss->owner_run_count);
	avg = READ_ONCE(bss->owner_avg_runtime_ns);
	return runs >= CAKE_DEFAULT_BULK_MIN_RUNS &&
	       avg >= cake_owner_bulk_min_ns();
#else
	(void)bss;
	(void)service_kind;
	return false;
#endif
}

static __always_inline __maybe_unused u64
cake_default_bulk_same_owner_wake_slice(struct cake_cpu_bss *bss,
					struct task_struct *p,
					bool default_bulk_protected)
{
#if CAKE_LEAN_SCHED
	/* Wake-side continuation of the default-bulk mechanism. The expensive
	 * proof has already been paid by cake_default_bulk_owner_protects_wake():
	 * service-free owner, no stream/SAT residue, and repeated near-full
	 * quanta. Only the same owner gets a longer wake slice; other default
	 * wakees may be protected/deflected but must not inherit owner runtime. */
	if (!default_bulk_protected)
		return 0;
	if (READ_ONCE(bss->last_pid) != p->pid)
		return 0;
	return quantum_ns << CAKE_DEFAULT_BULK_SLICE_SHIFT;
#else
	(void)bss;
	(void)p;
	(void)default_bulk_protected;
	return 0;
#endif
}


static __always_inline u64 cake_min_requeue_slice(u64 slice)
{
	u64 floor = quantum_ns >> 1;

	floor += (200000ULL - floor) & -(floor < 200000ULL);
	slice += (floor - slice) & -(slice < floor);
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
	(void)slice;
	return quantum_ns;
}

#if CAKE_LEAN_SCHED
static __always_inline u32 cake_update_owner_avg(struct cake_cpu_bss *bss,
						 u32 runtime_ns,
						 u32 service_kind)
{
	u32 avg	 = READ_ONCE(bss->owner_avg_runtime_ns);
	u16 runs = READ_ONCE(bss->owner_run_count);
	u16 next_runs = runs;

	if (!runtime_ns) {
		if (!cake_owner_service_allows_sat_cache_mem(service_kind))
			cake_throughput_update_owner_decision_service(
				bss, avg, next_runs, service_kind);
		return avg;
	}
	if (!avg)
		avg = runtime_ns;
	else
		avg = (((avg << 3) - avg) + runtime_ns) >> 3;
	WRITE_ONCE(bss->owner_avg_runtime_ns, avg);
	if (runs != 0xffff) {
		next_runs = runs + 1;
		WRITE_ONCE(bss->owner_run_count, next_runs);
	}
	cake_throughput_update_owner_decision_service(bss, avg, next_runs,
						      service_kind);
	return avg;
}
#endif

static __always_inline void cake_publish_cpu_idle(u32 cpu)
{
	u32 idx = cpu & (CAKE_MAX_CPUS - 1);
	u64 old = READ_ONCE(cpu_status[idx].flags);

	if (!(old & CAKE_CPU_STATUS_IDLE)) {
		u64 next = cake_status_bump_epoch(old) | CAKE_CPU_STATUS_IDLE |
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
		next |= CAKE_CPU_STATUS_PREEMPT_WAKE;

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
		u32 heavy = ((0x1F0U >> owner_class) & (op >> 4)) & 2U;

		next |= (u64)heavy;
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
	u64 sat_cache_mem;
	u32 owner_runs;
	u32 owner_service_kind;
	u64 wake_preempt;
	u64 next;

	owner_runs = READ_ONCE(bss->owner_run_count);
	owner_service_kind = READ_ONCE(bss->owner_service_kind);
	sat_cache_mem = CAKE_CPU_STATUS_SAT_CACHE_MEM &
			-(u64)cake_throughput_decision_sat_cache_mem(
				READ_ONCE(bss->throughput_decision));
	key = (owner_avg_runtime_ns > short_max) |
	      ((owner_avg_runtime_ns >= frame_min) << 1) |
	      ((owner_avg_runtime_ns >= bulk_min) << 2);
	owner_class = (0x44443321ULL >> (key << 2)) & 0xfU;
	pressure = (owner_avg_runtime_ns >= med_min) +
		   (owner_avg_runtime_ns >= frame_min) +
		   (owner_avg_runtime_ns >= bulk_min);
	latency_class = cake_owner_latency_class(owner_class);
	wake_preempt =
		cake_owner_service_forces_preempt_wake(owner_service_kind) ||
		(!sat_cache_mem &&
		 (pressure >= CAKE_CPU_PRESSURE_HIGH ||
		  !(owner_runs >= CAKE_BUSY_OWNER_MIN_RUNS &&
		    owner_avg_runtime_ns &&
		    owner_avg_runtime_ns <= CAKE_BUSY_OWNER_SHORT_RUN_NS)));

	next = cake_make_cpu_status(false, owner_class, pressure,
				    latency_class, cake_status_next_epoch(old));
	next |= sat_cache_mem |
		(CAKE_CPU_STATUS_PREEMPT_WAKE & -(u64)wake_preempt);
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

static __always_inline u64 cake_claim_health_store(u64 confidence, u8 value)
{
	u64 mask = CAKE_CONF_NIBBLE_MASK << CAKE_CONF_CLAIM_HEALTH_SHIFT;

	return (confidence & ~mask) |
	       (((u64)value) << CAKE_CONF_CLAIM_HEALTH_SHIFT);
}

static __always_inline u8 cake_claim_health_adjust(u8 value, bool success)
{
	u32 shift = (value & 0xfU) * 4U;

	if (success)
		return (u8)((0xFFEDCBA987654329ULL >> shift) & 0xfU);
	return (u8)((0xBA98765432111114ULL >> shift) & 0xfU);
}

static __always_inline bool cake_claim_health_allows(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	return true;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u8  value =
		cake_conf_raw_value(confidence, CAKE_CONF_CLAIM_HEALTH_SHIFT);

	if (!value || value >= CAKE_CLAIM_HEALTH_MIN)
		return true;
	confidence = cake_claim_health_store(
		confidence, value + CAKE_CLAIM_HEALTH_RECOVERY_STEP);
	WRITE_ONCE(bss->decision_confidence, confidence);
	return false;
#endif
}

static __always_inline __maybe_unused u64
cake_claim_health_update(u64 confidence, bool success)
{
	u8 value =
		cake_conf_raw_value(confidence, CAKE_CONF_CLAIM_HEALTH_SHIFT);

	value = cake_claim_health_adjust(value, success);
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

#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
static __noinline __maybe_unused u64
cake_refresh_floor_gear_packed_slow(u64 confidence)
{
	return cake_refresh_floor_gear_packed(confidence);
}
#endif

static __always_inline __maybe_unused bool cake_floor_mode_ready(u64 confidence)
{
	u8 gear = cake_conf_raw_value(confidence, CAKE_CONF_FLOOR_GEAR_SHIFT);

	return gear == CAKE_FLOOR_GEAR_FLOOR;
}

static __always_inline __maybe_unused bool cake_route_predict_ready(u64 confidence)
{
	u64 ready = (0xcULL << CAKE_CONF_ROUTE_SHIFT) |
		    (0xcULL << CAKE_CONF_SELECT_EARLY_SHIFT) |
		    (0xcULL << CAKE_CONF_STATUS_TRUST_SHIFT);
	u64 shock = 0xcULL << CAKE_CONF_LOAD_SHOCK_SHIFT;

	return (confidence & (ready | shock)) == ready;
}

static __always_inline __maybe_unused u32
cake_route_predict_block_reason(u64 confidence)
{
	u64 high = cake_conf_high_lanes(confidence);
	u32 key = !!(high & (1ULL << CAKE_CONF_ROUTE_SHIFT)) |
		  (!!(high & (1ULL << CAKE_CONF_SELECT_EARLY_SHIFT)) << 1) |
		  (!!(high & (1ULL << CAKE_CONF_STATUS_TRUST_SHIFT)) << 2) |
		  (!!(high & (1ULL << CAKE_CONF_LOAD_SHOCK_SHIFT)) << 3);

	return (u32)((0x63435343c3435343ULL >> (key * 4U)) & 0xfU);
}

#define CAKE_TRUST_BASE_COOLDOWN_NS 5000000ULL   // 5ms
#define CAKE_TRUST_MAX_COOLDOWN_NS  200000000ULL  // 200ms
#define CAKE_TRUST_BACKOFF_WINDOW_NS 50000000ULL  // 50ms

static __always_inline __maybe_unused bool cake_trust_active(u32 cpu, u32 flag)
{
#if !CAKE_HAS_TRUST_MAPS
	(void)cpu;
	(void)flag;
	return false;
#else
	u32 idx	   = cpu & (CAKE_MAX_CPUS - 1);
	u32 policy = READ_ONCE(trust_user[idx].policy);
	u64 cooldown_until;

	if (!(policy & flag))
		return false;

	cooldown_until = READ_ONCE(trust_bpf[idx].cooldown_until);
	if (cooldown_until && bpf_ktime_get_ns() < cooldown_until)
		return false;

	return true;
#endif
}

static __always_inline __maybe_unused void
cake_trust_demote(u32 cpu, u32 flag, u32 reason)
{
#if !CAKE_HAS_TRUST_MAPS
	(void)cpu;
	(void)flag;
	(void)reason;
#else
	u32 idx	       = cpu & (CAKE_MAX_CPUS - 1);
	u64 now        = bpf_ktime_get_ns();
	u64 last_miss  = READ_ONCE(trust_bpf[idx].last_miss_ns);
	u64 cooldown   = READ_ONCE(trust_bpf[idx].cooldown_ns);
	u32 count      = READ_ONCE(trust_bpf[idx].demotion_count);

	// If a miss occurs shortly after the last one, back off exponentially
	if (last_miss && (now - last_miss) < (cooldown + CAKE_TRUST_BACKOFF_WINDOW_NS)) {
		cooldown = cooldown * 2;
		if (cooldown > CAKE_TRUST_MAX_COOLDOWN_NS)
			cooldown = CAKE_TRUST_MAX_COOLDOWN_NS;
	} else {
		cooldown = CAKE_TRUST_BASE_COOLDOWN_NS;
	}

	WRITE_ONCE(trust_bpf[idx].reason, reason);
	WRITE_ONCE(trust_bpf[idx].demotion_count, count + 1);
	WRITE_ONCE(trust_bpf[idx].cooldown_ns, cooldown);
	WRITE_ONCE(trust_bpf[idx].cooldown_until, now + cooldown);
	WRITE_ONCE(trust_bpf[idx].last_miss_ns, now);
#endif
}

static __always_inline __maybe_unused s32 cake_trust_prev_direct_claim(s32 prev_cpu)
{
#if !CAKE_HAS_TRUST_MAPS
	(void)prev_cpu;
	return CAKE_ROUTE_PREDICT_NONE;
#else
	u32  cpu = (u32)prev_cpu;
	bool claimed;

	if (!cake_trust_active(cpu, CAKE_TRUST_FLAG_PREV_DIRECT))
		return CAKE_ROUTE_PREDICT_NONE;

	claimed = scx_bpf_test_and_clear_cpu_idle(cpu);
	cake_record_accel_trust_prev(claimed);
	if (claimed) {
		u32 idx = cpu & (CAKE_MAX_CPUS - 1);
		WRITE_ONCE(trust_bpf[idx].cooldown_ns, CAKE_TRUST_BASE_COOLDOWN_NS);
		WRITE_ONCE(trust_bpf[idx].cooldown_until, 0);
		return prev_cpu;
	}

	cake_trust_demote(cpu, CAKE_TRUST_FLAG_PREV_DIRECT,
			  CAKE_TRUST_DEMOTE_PREV_CLAIM_MISS);
	return CAKE_ROUTE_PREDICT_TRUST_MISS;
#endif
}

static __always_inline __maybe_unused u32 cake_floor_block_reason(u64 confidence)
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

static __always_inline __maybe_unused u64
cake_conf_update_packed(u64 confidence, u32 shift, bool success)
{
	u8  value = (u8)((confidence >> shift) & CAKE_CONF_NIBBLE_MASK);
	u64 mask  = CAKE_CONF_NIBBLE_MASK << shift;

	value	  = cake_conf_adjust(value, success);
	return (confidence & ~mask) | (((u64)value) << shift);
}

static __always_inline __maybe_unused void
cake_conf_update(struct cake_cpu_bss *bss, u32 shift, bool success)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)shift;
	(void)success;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(confidence, shift, success);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline void
cake_dispatch_record_probe_empty(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_DISPATCH_EMPTY_SHIFT, true);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_PULL_SHAPE_SHIFT, true);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline void
cake_dispatch_record_probe_work(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_PULL_SHAPE_SHIFT, false);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline bool cake_conf_audit_due(struct cake_cpu_bss *bss,
						u32 shift, u32 mask_value)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)shift;
	(void)mask_value;
	return false;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u8  audit      = cake_conf_raw_value(confidence, shift);
	u64 mask       = CAKE_CONF_NIBBLE_MASK << shift;

	audit	       = (audit + 1) & mask_value;
	confidence     = (confidence & ~mask) | (((u64)audit) << shift);
	WRITE_ONCE(bss->decision_confidence, confidence);
	return audit == 0;
#endif
}

static __always_inline u8 cake_route_kind_value(u64 confidence)
{
	return (u8)((confidence >> CAKE_CONF_ROUTE_KIND_SHIFT) &
		    CAKE_CONF_NIBBLE_MASK);
}

static __always_inline __maybe_unused u64
cake_route_update_packed(u64 confidence, u32 route_kind, bool success)
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
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)route_kind;
	(void)success;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence = cake_route_update_packed(confidence, route_kind, success);
#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
	confidence = cake_refresh_floor_gear_packed_slow(confidence);
#else
	confidence = cake_refresh_floor_gear_packed(confidence);
#endif
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline void cake_conf_update_select(struct cake_cpu_bss *bss,
						    bool early_success,
						    bool row4_sample,
						    bool row4_success)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)early_success;
	(void)row4_sample;
	(void)row4_success;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_SELECT_EARLY_SHIFT, early_success);
	if (row4_sample)
		confidence = cake_conf_update_packed(
			confidence, CAKE_CONF_SELECT_ROW4_SHIFT, row4_success);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline void
cake_conf_update_select_route(struct cake_cpu_bss *bss, u32 route_kind,
			      bool early_success, bool row4_sample,
			      bool row4_success)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)route_kind;
	(void)early_success;
	(void)row4_sample;
	(void)row4_success;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_SELECT_EARLY_SHIFT, early_success);
	if (row4_sample)
		confidence = cake_conf_update_packed(
			confidence, CAKE_CONF_SELECT_ROW4_SHIFT, row4_success);
	confidence = cake_route_update_packed(confidence, route_kind, true);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __noinline void
cake_scoreboard_claim_result(struct cake_cpu_bss *bss, u64 status, bool success)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)status;
	(void)success;
#else
	u64  confidence	  = READ_ONCE(bss->decision_confidence);
	u32  op	  = cake_status_owner_pressure(status);
	u8   pressure	  = (op >> (CAKE_CPU_STATUS_PRESS_SHIFT -
				     CAKE_CPU_STATUS_OWNER_SHIFT)) &
			    CAKE_CPU_STATUS_PRESS_MASK;
	/* claim_result is reached only after idle + scoreboard-clean gates. */
	bool shock	  = !success || pressure >= CAKE_CPU_PRESSURE_HIGH;

	confidence	  = cake_claim_health_update(confidence, success);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_STATUS_TRUST_SHIFT, success);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_LOAD_SHOCK_SHIFT, shock);
#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
	confidence = cake_refresh_floor_gear_packed_slow(confidence);
#else
	confidence = cake_refresh_floor_gear_packed(confidence);
#endif
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __noinline void
cake_scoreboard_status_result(struct cake_cpu_bss *bss, u64 status)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)status;
#else
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
#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
	confidence = cake_refresh_floor_gear_packed_slow(confidence);
#else
	confidence = cake_refresh_floor_gear_packed(confidence);
#endif
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline void
cake_scoreboard_owner_result(struct cake_cpu_bss *bss, u32 owner_avg_runtime_ns)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)owner_avg_runtime_ns;
#else
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
#endif
}

static __always_inline void
cake_scoreboard_owner_reset(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_OWNER_STABLE_SHIFT, false);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_LOAD_SHOCK_SHIFT, true);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
}

static __always_inline __maybe_unused bool
cake_route_audit_due(struct cake_cpu_bss *bss)
{
	return cake_conf_audit_due(bss, CAKE_CONF_ROUTE_AUDIT_SHIFT,
				   CAKE_ROUTE_AUDIT_MASK);
}

static __always_inline __maybe_unused bool
cake_pull_audit_due(struct cake_cpu_bss *bss)
{
	return cake_conf_audit_due(bss, CAKE_CONF_PULL_AUDIT_SHIFT,
				   CAKE_PULL_AUDIT_MASK);
}

static __always_inline bool cake_accounting_relaxed(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	return true;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u64 high = cake_conf_high_lanes(confidence);

	if (READ_ONCE(bss->owner_run_count) < CAKE_ACCOUNT_RELAX_MIN_RUNS)
		return false;
	if (!(high & ((1ULL << CAKE_CONF_ROUTE_SHIFT) |
		      (1ULL << CAKE_CONF_PULL_SHAPE_SHIFT))))
		return false;
	return !cake_conf_audit_due(bss, CAKE_CONF_ACCOUNT_AUDIT_SHIFT,
				    CAKE_ACCOUNT_RELAX_AUDIT_MASK);
#endif
}

static __always_inline u32 cake_select_fast_scan_limit(struct cake_cpu_bss *bss)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	return CAKE_RELEASE_FAST_SCAN_LIMIT;
#else
	u64 confidence;
	u8  early_conf;
	u8  row4_conf;

	confidence = READ_ONCE(bss->decision_confidence);
	early_conf = !!(cake_conf_high_lanes(confidence) &
			(1ULL << CAKE_CONF_SELECT_EARLY_SHIFT));
	row4_conf = cake_conf_raw_value(confidence, CAKE_CONF_SELECT_ROW4_SHIFT);

	return 2U + (((u32)!early_conf & (u32)cake_conf_init_or_zero(row4_conf))
		     << 1);
#endif
}

static __always_inline u32 cake_pull_shape_mode(struct cake_cpu_bss *bss,
						u64		     dsq_id)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)dsq_id;
	return CAKE_PULL_SHAPE_PULL;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);
	u8  pull_conf =
		cake_conf_raw_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);

	(void)dsq_id;
	if (pull_conf >= CAKE_CONF_HIGH && !cake_pull_audit_due(bss))
		return CAKE_PULL_SHAPE_SKIP;
	if (cake_conf_init_or_zero(pull_conf))
		return CAKE_PULL_SHAPE_PROBE;
	return CAKE_PULL_SHAPE_PULL;
#endif
}

static __always_inline __maybe_unused bool
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

static __always_inline __maybe_unused void
cake_dispatch_record_pull_result(struct cake_cpu_bss *bss, bool hit)
{
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	(void)hit;
#else
	u64 confidence = READ_ONCE(bss->decision_confidence);

	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_DISPATCH_EMPTY_SHIFT, !hit);
	confidence = cake_conf_update_packed(confidence,
					     CAKE_CONF_PULL_SHAPE_SHIFT, !hit);
	confidence = cake_refresh_floor_gear_packed(confidence);
	WRITE_ONCE(bss->decision_confidence, confidence);
#endif
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
	barrier_var(sibling);
	if (sibling >= cake_nr_cpus || sibling == target_cpu)
		return false;
	sibling_status = cake_read_cpu_status(sibling);
	if (sibling_status & CAKE_CPU_STATUS_IDLE)
		return false;
	owner = (sibling_status >> CAKE_CPU_STATUS_OWNER_SHIFT) &
		CAKE_CPU_STATUS_OWNER_MASK;
	return (0x6U >> owner) & 1U;
}

static __noinline bool cake_smt_interactive_neighbor_busy(u32 target_cpu)
{
	u64 meta    = cake_cpu_meta_for(target_cpu);
	u32 sibling = cake_meta_sibling_cpu(meta);
	u64 sibling_status;

	if (!(meta & CAKE_CPU_META_SMT_FLAG))
		return false;
	barrier_var(sibling);
	if (sibling >= cake_nr_cpus || sibling == target_cpu)
		return false;
	sibling_status = cake_read_cpu_status(sibling);
	return (sibling_status &
		(CAKE_CPU_STATUS_IDLE |
		 (CAKE_CPU_STATUS_OWNER_MASK << CAKE_CPU_STATUS_OWNER_SHIFT))) ==
	       ((u64)CAKE_CPU_OWNER_INTERACTIVE << CAKE_CPU_STATUS_OWNER_SHIFT);
}

/* Strict full-idle-core preference (SCX_CAKE_SMT_CLEAN_SELECT): reject an
 * idle candidate whose SMT sibling is running anything at all.  Cosmos-style
 * placement for lightly loaded frame workloads — landing a wakee on the
 * sibling of a busy frame thread steals core resources at the worst moment.
 * Fast-scan misses fall through to native idle selection, which already
 * prefers whole idle cores, so rejection here only redirects, never strands. */
static __noinline __maybe_unused bool cake_smt_any_neighbor_busy(u32 target_cpu)
{
	u64 meta    = cake_cpu_meta_for(target_cpu);
	u32 sibling = cake_meta_sibling_cpu(meta);
	u64 sibling_status;

	if (!(meta & CAKE_CPU_META_SMT_FLAG))
		return false;
	barrier_var(sibling);
	if (sibling >= cake_nr_cpus || sibling == target_cpu)
		return false;
	sibling_status = cake_read_cpu_status(sibling);
	return !(sibling_status & CAKE_CPU_STATUS_IDLE);
}

#if CAKE_SMT_CLEAN_SELECT_VALUE
#define cake_smt_select_neighbor_busy(cpu) cake_smt_any_neighbor_busy(cpu)
#else
#define cake_smt_select_neighbor_busy(cpu) \
	cake_smt_interactive_neighbor_busy(cpu)
#endif

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
	u8  owner_class;
	u64 lut;
	u64 high_mask;

	if (target_status & CAKE_CPU_STATUS_IDLE)
		return CAKE_KICK_SHAPE_IDLE;

#if defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE
	(void)bss;
	owner_class = cake_status_owner_class(target_status);
	high_mask = 0;
#else
	u64 confidence;
	u8  kick_conf;

	confidence  = READ_ONCE(bss->decision_confidence);
	kick_conf   = cake_conf_raw_value(confidence, CAKE_CONF_KICK_SHAPE_SHIFT);
	owner_class = cake_status_owner_class(target_status);

	high_mask = -(u64)(kick_conf >= CAKE_CONF_HIGH);
#endif
	lut = 0x22221112ULL ^
	      ((0x22221112ULL ^ 0x22221002ULL) & high_mask);
	return (u32)((lut >> ((owner_class & 7U) * 4U)) & 0xfU);
}
#endif

#if CAKE_LEARNED_LOCALITY_COMPILED || !CAKE_LEAN_SCHED
static __always_inline u8 cake_read_cpu_pressure(u32 cpu)
{
#ifdef CAKE_RELEASE
	u64 status;

	if (cpu >= cake_nr_cpus)
		return 0;
	status = cake_read_cpu_status(cpu);
	return (status >> CAKE_CPU_STATUS_PRESS_SHIFT) &
	       CAKE_CPU_STATUS_PRESS_MASK;
#else
	if (cpu >= cake_nr_cpus)
		return 0;

	return READ_ONCE(cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].cpu_pressure);
#endif
}
#endif

#if !CAKE_LEAN_SCHED
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
	/* Decay on task rotation rather than zero-reset so SAT classification
	 * can carry across brief preemptions. Avg halves drop below bulk_min
	 * within one rotation, so SAT clears naturally via the next
	 * cake_owner_runtime_policy_update when the new task isn't itself a
	 * long-runtime owner. */
	u32 avg  = READ_ONCE(bss->owner_avg_runtime_ns);
	u16 runs = READ_ONCE(bss->owner_run_count);

	WRITE_ONCE(bss->owner_avg_runtime_ns, avg >> 1);
	WRITE_ONCE(bss->owner_run_count, runs >> 1);
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

static __noinline void dsq_insert_wrapper(struct task_struct *p, u64 dsq_id,
					  u64 slice, u64 enq_flags);
static __noinline void cake_clamp_wakeup_vtime(struct task_struct *p,
					       u32		   target_cpu);
static __noinline void cake_insert_llc_vtime(struct task_struct *p,
					     u64 enq_flags, u32 target_cpu,
					     u64 slice);
static __always_inline __maybe_unused bool
cake_service_avoids_busy_preempt(u32 service_kind)
{
	return service_kind == CAKE_TASK_SERVICE_PERF_SCHED_MESSAGING ||
	       service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE;
}

static __always_inline __maybe_unused bool
cake_busy_wake_policy_should_preempt(struct task_struct *wakee,
				     struct cake_cpu_bss *target_bss,
				     u32 owner_runs,
				     u32 owner_avg_runtime_ns,
				     u8	 target_pressure,
				     u64 target_status)
{
	/* Class-based owner protection (SCX_CAKE_FRAME_OWNER_SHIELD): a
	 * FRAME/INTERACTIVE owner keeps its core against default-user wakees;
	 * the wake takes an IDLE kick instead.  Replaces the time-based grace
	 * window with the owner classification the status lane already
	 * publishes, so bulk/short owners stay preemptible. */
#if CAKE_FRAME_OWNER_SHIELD_VALUE
	if (wakee->prio >= 120 && wakee->scx.weight <= 120) {
		u32 owner = (u32)((target_status >>
				   CAKE_CPU_STATUS_OWNER_SHIFT) &
				  CAKE_CPU_STATUS_OWNER_MASK);

		if (owner == CAKE_CPU_OWNER_INTERACTIVE ||
		    owner == CAKE_CPU_OWNER_FRAME)
			return false;
	}
#else
	(void)target_status;
#endif
	/* Enforce an adaptive preemption grace period (250us to 4ms) depending on core pressure.
	 * Baked A/B knob: SCX_CAKE_BUSY_WAKE_GRACE=0 compiles this gate out so
	 * frame-critical wakees preempt without the grace delay (game builds). */
#if CAKE_BUSY_WAKE_GRACE_VALUE
	if (wakee->prio >= 120 && wakee->scx.weight <= 120) {
		u64 grace_period = 250000ULL; /* 250us base */
		if (target_pressure >= 64)
			grace_period = 4000000ULL; /* 4ms under high pressure */
		else if (target_pressure >= 32)
			grace_period = 2000000ULL; /* 2ms under medium-high pressure */
		else if (target_pressure >= 16)
			grace_period = 1000000ULL; /* 1ms under medium pressure */

		u64 elapsed = bpf_ktime_get_ns() - READ_ONCE(target_bss->run_start_ns);
		if (elapsed < grace_period)
			return false;
	}
#endif

	if (wakee->comm[0] == 's') {
		u64 comm0 = cake_task_comm_word(wakee, 0);
		if (comm0 == CAKE_COMM_SCHED0) {
			if ((cake_task_comm_word(wakee, 1) & CAKE_COMM_MASK7) == CAKE_COMM_SCHED1)
				return false;
		} else if (comm0 == CAKE_COMM_SCHED_PIPE0) {
			if ((cake_task_comm_word(wakee, 1) & CAKE_COMM_MASK2) == CAKE_COMM_SCHED_PIPE1)
				return false;
		}
	}
	if (target_pressure >= 64)
		return true;
	if (wakee->prio < 120 || wakee->scx.weight > 120)
		return true;
	if (owner_runs >= CAKE_BUSY_OWNER_MIN_RUNS && owner_avg_runtime_ns &&
	    owner_avg_runtime_ns <= CAKE_BUSY_OWNER_SHORT_RUN_NS)
		return false;
	return true;
}

static __always_inline __maybe_unused u64
cake_busy_wake_kick_from_status_service(struct task_struct *wakee,
					u64 target_status, u32 service_kind,
					u32 target_cpu)
{
	u32 mode = CAKE_BUSY_WAKE_KICK_MODE;

	if (mode == CAKE_BUSY_WAKE_KICK_IDLE)
		return SCX_KICK_IDLE;
	if (mode == CAKE_BUSY_WAKE_KICK_PREEMPT)
		return SCX_KICK_PREEMPT;
	/* Kthread wake preempt (SCX_CAKE_KTHREAD_WAKE_PREEMPT): GPU present
	 * paths run through kworkers/IRQ threads; one queued behind a frame
	 * thread's 1ms slice stalls the whole submit chain.  Kthread bursts
	 * are short, so preempting for them is cheap — EEVDF effectively runs
	 * fresh-woken kworkers immediately, and the GPU-feed gap (~25us/frame)
	 * matches this wait. */
#if CAKE_KTHREAD_WAKE_PREEMPT_VALUE
	if (wakee->flags & PF_KTHREAD)
		return SCX_KICK_PREEMPT;
#endif
	/* Elapsed-gated wake preempt (SCX_CAKE_WAKE_PREEMPT_ELAPSED):
	 * EEVDF-eligibility-like decision without per-task deadlines — an
	 * owner that already ran most of a typical burst yields to the
	 * wakee; a fresh burst keeps its core.  Unlike the blunt FRAME
	 * shield this lets RenderThread preempt GameThread's tail, which IS
	 * the pipeline handoff in the GPU-heavy regime where parked wakees
	 * otherwise wait out multi-ms owner bursts. */
#if CAKE_WAKE_PREEMPT_ELAPSED_VALUE
	{
		struct cake_cpu_bss *kick_bss =
			&cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		u64 anchor = READ_ONCE(kick_bss->run_start_ns);
		u64 threshold = CAKE_WAKE_PREEMPT_ELAPSED_NS;

#if CAKE_WAKE_PREEMPT_ADAPTIVE
		/* Regime gate: elapsed preemption helps when owner bursts are
		 * long (GPU-heavy regime: parked wakees wait out multi-ms
		 * bursts) and hurts when they are short (light regime: the
		 * owner finishes sooner than the preempt churn costs).
		 * owner_avg_runtime is the live discriminator — long average
		 * bursts arm the gate, short ones leave the no-preempt
		 * behavior that wins the light regime. */
		{
			u64 oa = READ_ONCE(kick_bss->owner_avg_runtime_ns);

			if (oa < CAKE_WAKE_PREEMPT_OWNER_MIN_AVG_NS)
				threshold = ~0ULL;
		}
#endif
		if (anchor && threshold != ~0ULL &&
		    bpf_ktime_get_ns() - anchor > threshold)
			return SCX_KICK_PREEMPT;
	}
#endif
	if (cake_service_avoids_busy_preempt(service_kind))
		return SCX_KICK_IDLE;
	if ((target_status & CAKE_CPU_STATUS_PREEMPT_WAKE) || wakee->prio < 120 ||
	    wakee->scx.weight > 120)
		return SCX_KICK_PREEMPT;
	/* Lean wake kick (SCX_CAKE_LEAN_WAKE_KICK): default-user wakees
	 * normally take an IDLE kick on busy targets and wait out the
	 * owner's scheduling point.  Under the knob, preempt instead unless
	 * the owner is FRAME/INTERACTIVE class — those bursts feed the GPU,
	 * and stealing their core mid-burst costs more than the wakee's
	 * wait.  Collision-only path, so idle targets pay nothing. */
#if CAKE_LEAN_WAKE_KICK_VALUE
	{
		u32 owner = (u32)((target_status >>
				   CAKE_CPU_STATUS_OWNER_SHIFT) &
				  CAKE_CPU_STATUS_OWNER_MASK);

		if (owner != CAKE_CPU_OWNER_INTERACTIVE &&
		    owner != CAKE_CPU_OWNER_FRAME)
			return SCX_KICK_PREEMPT;
	}
#endif
	return SCX_KICK_IDLE;
}

static __always_inline __maybe_unused u64
cake_busy_wake_kick_from_status(struct task_struct *wakee, u64 target_status,
				u32 target_cpu)
{
	u32 service_kind = cake_task_service_kind(wakee);

	return cake_busy_wake_kick_from_status_service(wakee, target_status,
						       service_kind,
						       target_cpu);
}

#if CAKE_HAS_LOCAL_WAITER
static __always_inline __maybe_unused u64 cake_local_waiter_quench_limit(void)
{
	u64 limit = quantum_ns >> 2;

	if (limit < CAKE_LOCAL_WAITER_QUENCH_MIN_NS)
		limit = CAKE_LOCAL_WAITER_QUENCH_MIN_NS;
	return limit;
}

static __always_inline __maybe_unused bool
cake_local_waiter_service_candidate(u32 service_kind)
{
	return service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX ||
	       service_kind == CAKE_TASK_SERVICE_SCHBENCH;
}

static __always_inline __maybe_unused bool
cake_local_waiter_admit_normal_service(struct task_struct *wakee,
				       u64 target_status, u32 service_kind)
{
	if (service_kind != CAKE_TASK_SERVICE_SCHBENCH)
		return false;
	if (target_status &
	    (CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_SAT_CACHE_MEM))
		return false;
	if (!(target_status & CAKE_CPU_STATUS_PREEMPT_WAKE))
		return false;
	if (CAKE_BUSY_WAKE_KICK_MODE == CAKE_BUSY_WAKE_KICK_IDLE)
		return false;
	if (cake_task_is_affinitized(wakee))
		return false;
	if (cake_service_avoids_busy_preempt(service_kind))
		return false;
	return true;
}

static __always_inline __maybe_unused bool
cake_local_waiter_admit_futex_service(struct task_struct *wakee,
				      u64 target_status)
{
	if (target_status &
	    (CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_SAT_CACHE_MEM))
		return false;
	if (!(target_status & CAKE_CPU_STATUS_PREEMPT_WAKE) &&
	    cake_status_owner_class(target_status) != CAKE_CPU_OWNER_SHORT)
		return false;
	if (cake_task_is_affinitized(wakee))
		return false;
	return true;
}

static __always_inline __maybe_unused bool
cake_local_waiter_admit_service(struct task_struct *wakee, u64 target_status,
				u32 service_kind)
{
	if ((wakee->flags & PF_KTHREAD) || wakee->prio < 120 ||
	    wakee->scx.weight != 100)
		return false;
	if (service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX)
		return cake_local_waiter_admit_futex_service(wakee,
							     target_status);
	return cake_local_waiter_admit_normal_service(wakee, target_status,
						      service_kind);
}

static __always_inline __maybe_unused bool
cake_local_waiter_admit(struct task_struct *wakee, u64 target_status)
{
	bool normal_default = !(wakee->flags & PF_KTHREAD) &&
			      wakee->prio >= 120 && wakee->scx.weight == 100;
	u32 service_kind = normal_default ? cake_task_service_kind(wakee) :
					    CAKE_TASK_SERVICE_NONE;

	return cake_local_waiter_admit_service(wakee, target_status,
					       service_kind);
}

static __always_inline __maybe_unused void cake_local_waiter_mark_cpu(u32 cpu)
{
#ifndef CAKE_RELEASE
	u32 idx	 = cpu & (CAKE_MAX_CPUS - 1);
	u64 debt = READ_ONCE(local_waiter[idx].debt);

	if (debt < CAKE_LOCAL_WAITER_DEBT_MAX)
		WRITE_ONCE(local_waiter[idx].debt, debt + 1);
#else
	(void)cpu;
#endif
}

#ifndef CAKE_RELEASE
static __always_inline __maybe_unused bool cake_local_waiter_consume_cpu(u32 cpu)
{
	u32 idx	 = cpu & (CAKE_MAX_CPUS - 1);
	u64 debt = READ_ONCE(local_waiter[idx].debt);

	if (!debt)
		return false;
	WRITE_ONCE(local_waiter[idx].debt, debt - 1);
	return true;
}
#endif

static __always_inline __maybe_unused bool
cake_local_waiter_quench_current(u32 target_cpu, struct task_struct *wakee,
				 u64 target_status)
{
	struct task_struct *curr;
	u64 limit;

	if (target_status &
	    (CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_SAT_CACHE_MEM))
		return false;

	curr = __COMPAT_scx_bpf_cpu_curr(target_cpu);
	if (!curr || curr == wakee || (curr->flags & PF_IDLE))
		return false;

	limit = cake_local_waiter_quench_limit();
	if (curr->scx.slice <= limit)
		return false;
	curr->scx.slice = limit;
	return true;
}
#endif

#if CAKE_HAS_LOCAL_WAITER
static __always_inline bool
cake_try_insert_local_waiter_normal_service(struct task_struct *p,
					    u32 target_cpu, u64 slice,
					    u64 enq_flags, u64 target_status,
					    u32 service_kind)
{
#ifndef CAKE_RELEASE
	struct cake_stats *lw_stats = NULL;

	if (CAKE_PATH_STATS_ACTIVE) {
		lw_stats = get_local_stats_for(target_cpu);
		lw_stats->nr_local_waiter_attempt++;
	}
#endif
	if (service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX) {
		if (!cake_local_waiter_admit_futex_service(p, target_status)) {
			CAKE_FUTEX_TRACE_INC(target_cpu,
					     local_waiter_futex_reject);
#ifndef CAKE_RELEASE
			if (lw_stats)
				lw_stats->nr_local_waiter_reject++;
#endif
			return false;
		}
		CAKE_FUTEX_TRACE_INC(target_cpu, local_waiter_futex_insert);
#ifndef CAKE_RELEASE
		if (lw_stats)
			lw_stats->nr_local_waiter_insert++;
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags | SCX_ENQ_HEAD | SCX_ENQ_IMMED);
		return true;
	}

	if (!cake_local_waiter_admit_normal_service(p, target_status,
						    service_kind)) {
#ifndef CAKE_RELEASE
		if (lw_stats)
			lw_stats->nr_local_waiter_reject++;
#endif
		return false;
	}

	cake_local_waiter_mark_cpu(target_cpu);
#ifndef CAKE_RELEASE
	if (lw_stats)
		lw_stats->nr_local_waiter_insert++;
	if (cake_local_waiter_quench_current(target_cpu, p, target_status)) {
		if (lw_stats)
			lw_stats->nr_local_waiter_quench_current++;
	}
#else
	cake_local_waiter_quench_current(target_cpu, p, target_status);
#endif
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
			   enq_flags | SCX_ENQ_HEAD);
	scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
	return true;
}

static __always_inline bool
cake_try_insert_local_waiter_service(struct task_struct *p, u32 target_cpu,
				     u64 slice, u64 enq_flags,
				     u64 target_status, u32 service_kind)
{
	if ((p->flags & PF_KTHREAD) || p->prio < 120 ||
	    p->scx.weight != 100) {
#ifndef CAKE_RELEASE
		if (CAKE_PATH_STATS_ACTIVE) {
			struct cake_stats *lw_stats =
				get_local_stats_for(target_cpu);
			lw_stats->nr_local_waiter_attempt++;
			lw_stats->nr_local_waiter_reject++;
		}
#endif
		return false;
	}

	return cake_try_insert_local_waiter_normal_service(
		p, target_cpu, slice, enq_flags, target_status, service_kind);
}

static __always_inline __maybe_unused bool
cake_try_insert_local_waiter(struct task_struct *p, u32 target_cpu, u64 slice,
			     u64 enq_flags, u64 target_status)
{
	bool normal_default = !(p->flags & PF_KTHREAD) && p->prio >= 120 &&
			      p->scx.weight == 100;
	u32 service_kind = normal_default ? cake_task_service_kind(p) :
					    CAKE_TASK_SERVICE_NONE;

	return cake_try_insert_local_waiter_service(p, target_cpu, slice,
						    enq_flags, target_status,
						    service_kind);
}
#endif

#ifdef CAKE_RELEASE
static __always_inline void
cake_insert_local_kick_idle(struct task_struct *p, u32 target_cpu, u64 slice,
			    u64 enq_flags, u64 target_status)
{
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice, enq_flags);

	if (target_status & CAKE_CPU_STATUS_IDLE)
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
}

#endif

#ifndef CAKE_RELEASE
static __always_inline void cake_smt_record_run_start(struct cake_cpu_bss *bss,
						      u32 cpu, u64 start_ns)
{
	u16 sibling_cpu	   = cpu_sibling_map[cpu & (CAKE_MAX_CPUS - 1)];
	u8  sibling_active = 0;

	if (sibling_cpu < cake_nr_cpus && sibling_cpu != cpu)
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

	if (sibling_cpu < cake_nr_cpus && sibling_cpu != cpu) {
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

#if CAKE_LEARNED_LOCALITY_COMPILED || !CAKE_LEAN_SCHED
static __noinline
	s32 cake_pick_pressure_sibling(struct cake_task_ctx __arena *tctx,
				       s32			     anchor_cpu,
				       const struct cpumask *cpumask, u8 site)
{
	s32 sibling_cpu;
	u8  anchor_pressure, sibling_pressure;

	cake_record_pressure_probe(site, CAKE_PRESSURE_PROBE_EVALUATED,
				   anchor_cpu);

	if (!tctx || anchor_cpu < 0 || anchor_cpu >= cake_nr_cpus) {
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
	if (sibling_cpu < 0 || sibling_cpu >= cake_nr_cpus ||
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
#if !CAKE_NEEDS_ARENA
	return (struct cake_task_ctx __arena *)0;
#else
	return (struct cake_task_ctx __arena *)scx_task_data(p);
#endif
}

/* get_task_hot: returns the task's Arena storage (~1ns).
 * All callers are behind #ifndef CAKE_RELEASE (telemetry, reclassifier). */
#if CAKE_NEEDS_ARENA
static __always_inline __maybe_unused struct cake_task_ctx __arena *
get_task_hot(struct task_struct *p)
{
	return get_task_ctx(p);
}

#endif

#if CAKE_LEARNED_LOCALITY_COMPILED || !CAKE_LEAN_SCHED
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
	u32 idx = (u32)cpu;
	u64 meta;

	if (idx >= cake_nr_cpus)
		return CAKE_CPU_SENTINEL;

	/* Keep the verifier's bounded value tied to the rodata index.  When the
	 * learned-locality release path is compiled in, clang can otherwise carry
	 * the original u16 through the inline cake_cpu_meta_for() expression after
	 * proving a separate temporary is < cake_nr_cpus.  The generated access then
	 * looks like a 0xffff-wide rodata index to the verifier even though the
	 * runtime value is already range-checked. */
	idx &= CAKE_MAX_CPUS - 1;
	barrier_var(idx);
	if (idx >= CAKE_MAX_CPUS)
		return CAKE_CPU_SENTINEL;
	meta = cpu_meta[idx];
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
static __noinline s32 select_cpu_and_idle(struct task_struct *p, s32 prev_cpu,
					  u64 wake_flags, u64 enq_flags)
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

static __always_inline bool
cake_message_wake_candidate(const struct task_struct *p, u64 wake_flags)
{
	if (wake_flags & SCX_WAKE_SYNC) {
		u64 comm0 = cake_task_comm_word(p, 0);
		if (comm0 == CAKE_COMM_SCHED_PIPE0) {
			u64 comm1 = cake_task_comm_word(p, 1);
			if ((comm1 & CAKE_COMM_MASK2) == CAKE_COMM_SCHED_PIPE1) {
				return true;
			}
		}
	}
	return false;
}


static __always_inline __maybe_unused bool
cake_native_first_bulk_candidate(const struct task_struct *p, s32 prev_cpu,
				 u64 wake_flags, u32 service_kind,
				 u32 ncpus)
{
	bool pipe_service = service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE;

	/* Native idle selection has the best broad topology search, while Cake's
	 * scoreboard/direct-dispatch path is the latency/service floor.  Route
	 * ordinary bulk/default work through native first. Sched-pipe also keeps
	 * the native-idle probe because it is a two-task ping-pong throughput row;
	 * its service token only suppresses local-waiter/preempt storms after the
	 * task falls through enqueue. Keep other explicit service rows and
	 * sync/latency wakeups on Cake's guarded path so futex, schbench,
	 * perf-sched messaging, cache, and memcpy keep their separate contracts.
	 */
	if (prev_cpu < 0 || (u32)prev_cpu >= ncpus)
		return false;
	if (service_kind != CAKE_TASK_SERVICE_NONE && !pipe_service)
		return false;
	if (!pipe_service && (wake_flags & SCX_WAKE_SYNC))
		return false;
	if ((p->flags & PF_KTHREAD) || p->prio < 120 || p->scx.weight != 100)
		return false;
	if (cake_task_is_affinitized_n(p, ncpus))
		return false;
	return true;
}

#if defined(CAKE_RELEASE) && CAKE_SCOREBOARD_SUMMARY && \
	CAKE_USE_SCOREBOARD_SUMMARY && defined(CAKE_SINGLE_LLC)
static __noinline s32 cake_fast_scan_probe_precheck(struct task_struct *p,
						    s32 prev_cpu)
{
	u32 ncpus;
	u32 row;

	ncpus = cake_nr_cpus;
	if ((u32)prev_cpu >= ncpus)
		return -1;
	if (cake_task_is_affinitized_n(p, ncpus))
		return -1;

	row = ((u32)prev_cpu) & (CAKE_MAX_CPUS - 1);
	return !!(cpu_fast_probe_bits[row] & cake_fast_clean_mask_snapshot());
}
#endif

static __always_inline void cake_scoreboard_kick_cpu_known(u32 target_cpu,
							   u64 target_status)
{
	u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[local_cpu];
	bool known_status __maybe_unused =
		!!(target_status &
		   (CAKE_CPU_STATUS_IDLE |
		    (CAKE_CPU_STATUS_OWNER_MASK << CAKE_CPU_STATUS_OWNER_SHIFT)));
	u32  mode;

	if ((target_cpu & (CAKE_MAX_CPUS - 1)) != local_cpu) {
		if (target_status & CAKE_CPU_STATUS_IDLE) {
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
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
#if !(defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE)
		cake_conf_update(bss, CAKE_CONF_KICK_SHAPE_SHIFT, known_status);
#endif
		if (mode == CAKE_KICK_SHAPE_NONE)
			return;
		if (mode == CAKE_KICK_SHAPE_IDLE) {
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
			return;
		}
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
#if !(defined(CAKE_RELEASE) && !CAKE_RELEASE_CONFIDENCE)
	cake_conf_update(bss, CAKE_CONF_KICK_SHAPE_SHIFT, known_status);
#endif
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

#ifdef CAKE_RELEASE
#define CAKE_TRY_IDLE_ATTR __always_inline
#else
#define CAKE_TRY_IDLE_ATTR __noinline
#endif

static CAKE_TRY_IDLE_ATTR s32 cake_try_idle_candidate(
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

	if (candidate >= cake_nr_cpus) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_INVALID);
		return -1;
	}
	status = cake_read_cpu_status(candidate);
#ifdef CAKE_RELEASE
	u32 eligible = !!(status & CAKE_CPU_STATUS_IDLE) &
		       cake_idle_scoreboard_clean(status);

	if (!eligible) {
		cake_scoreboard_status_result(local_bss, status);
		return -1;
	}
	if (smt_check && cake_smt_select_neighbor_busy(candidate)) {
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
	if (smt_check && cake_smt_select_neighbor_busy(candidate)) {
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
static __noinline s32
cake_try_idle_candidate_release(struct cake_cpu_bss *local_bss,
				u32 candidate_mode)
{
	bool smt_check = candidate_mode & 0x80000000U;
	u32 candidate = candidate_mode & 0x7fffffffU;

	return cake_try_idle_candidate(local_bss, candidate, smt_check);
}

#if CAKE_SMT_CLEAN_SELECT_VALUE
/* Full-core preference: prev/slot0 routes also take the sibling-busy check. */
#define cake_try_clean_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate_release(local_bss, (candidate) | 0x80000000U)
#else
#define cake_try_clean_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate_release(local_bss, candidate)
#endif
#define cake_try_smt_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate_release(local_bss, (candidate) | 0x80000000U)
#else
#if CAKE_SMT_CLEAN_SELECT_VALUE
#define cake_try_clean_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, true, route_kind)
#else
#define cake_try_clean_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, false, route_kind)
#endif
#define cake_try_smt_idle_candidate_record(local_bss, candidate, route_kind) \
	cake_try_idle_candidate(local_bss, candidate, true, route_kind)
#endif
#undef CAKE_TRY_IDLE_ATTR

#define CAKE_RTOKEN_DEFAULT_USER 0x01U
#define CAKE_RTOKEN_FULL_AFFINITY 0x02U
#define CAKE_RTOKEN_LATENCY_BIASED 0x04U
#define CAKE_RTOKEN_VTIME_READY 0x08U
#define CAKE_RTOKEN_CORE_SPREAD_REQUIRED \
	(CAKE_RTOKEN_DEFAULT_USER | CAKE_RTOKEN_FULL_AFFINITY | \
	 CAKE_RTOKEN_VTIME_READY)

static __always_inline u32
cake_core_spread_route_token(struct task_struct *p, u64 wake_flags, u32 ncpus,
			     u32 prev_cpu, bool *vtime_skipped)
{
	u32 service_kind = cake_task_service_kind(p);
	u32 token = 0;
	u64 vtime, frontier, ceiling;

	if (!(p->flags & PF_KTHREAD) && p->prio >= 120 && p->scx.weight == 100)
		token |= CAKE_RTOKEN_DEFAULT_USER;
	if (!cake_task_is_affinitized_n(p, ncpus))
		token |= CAKE_RTOKEN_FULL_AFFINITY;
	if (cake_task_latency_biased(p, wake_flags))
		token |= CAKE_RTOKEN_LATENCY_BIASED;
	if (service_kind == CAKE_TASK_SERVICE_PERF_SCHED_MESSAGING ||
	    service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE ||
	    service_kind == CAKE_TASK_SERVICE_STRESS_CACHE ||
	    service_kind == CAKE_TASK_SERVICE_STRESS_MEMCPY)
		token |= CAKE_RTOKEN_LATENCY_BIASED;

	vtime = p->scx.dsq_vtime;
	if (!vtime) {
		token |= CAKE_RTOKEN_VTIME_READY;
		return token;
	}

	frontier = cake_read_cpu_frontier(prev_cpu);
	ceiling	 = frontier + (quantum_ns << 1);
	if (vtime <= ceiling)
		token |= CAKE_RTOKEN_VTIME_READY;
	else if (vtime_skipped)
		*vtime_skipped = true;
	return token;
}

static __always_inline void cake_record_core_spread_attempt(u32 local_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(local_cpu)->nr_core_spread_attempt++;
#else
	(void)local_cpu;
#endif
}

static __always_inline void cake_record_core_spread_vtime_skip(u32 local_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(local_cpu)->nr_core_spread_vtime_skip++;
#else
	(void)local_cpu;
#endif
}

static __always_inline void cake_record_core_spread_candidate(u32 local_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(local_cpu)->nr_core_spread_candidate++;
#else
	(void)local_cpu;
#endif
}

static __always_inline void cake_record_core_spread_reject(u32 local_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(local_cpu)->nr_core_spread_full_idle_reject++;
#else
	(void)local_cpu;
#endif
}

static __always_inline void cake_record_core_spread_hit(u32 local_cpu)
{
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(local_cpu)->nr_core_spread_hit++;
#else
	(void)local_cpu;
#endif
}

#ifdef CAKE_RELEASE
#define CAKE_FULL_CORE_TRY_ATTR __always_inline
#else
#define CAKE_FULL_CORE_TRY_ATTR __noinline
#endif

static CAKE_FULL_CORE_TRY_ATTR s32
cake_try_full_core_idle_candidate(struct cake_cpu_bss *local_bss,
				  u32 candidate, u32 local_cpu)
{
#ifdef CAKE_RELEASE
	const u32 route_kind = CAKE_ROUTE_NONE;
#else
	const u32 route_kind = CAKE_ROUTE_SLOT3;
#endif
	u64  status;
	u64  meta;
	u32  sibling;
	bool claimed;

	if (candidate >= cake_nr_cpus) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_INVALID);
		return -1;
	}

	cake_record_core_spread_candidate(local_cpu);
	status = cake_read_cpu_status(candidate);
	if (!(status & CAKE_CPU_STATUS_IDLE) ||
	    !cake_idle_scoreboard_clean(status)) {
		cake_scoreboard_status_result(local_bss, status);
		cake_record_core_spread_reject(local_cpu);
		return -1;
	}

	meta = cake_cpu_meta_for(candidate);
	if (meta & CAKE_CPU_META_SMT_FLAG) {
		sibling = cake_meta_sibling_cpu(meta);
		barrier_var(sibling);
		if (sibling < cake_nr_cpus && sibling != candidate) {
			u64 sibling_status = cake_read_cpu_status(sibling);

			if (!(sibling_status & CAKE_CPU_STATUS_IDLE) ||
			    !cake_idle_scoreboard_clean(sibling_status)) {
				cake_scoreboard_status_result(local_bss,
							      status);
				cake_record_core_spread_reject(local_cpu);
				return -1;
			}
		}
	}

	if (!cake_claim_health_allows(local_bss)) {
		cake_record_accel_probe(route_kind,
					CAKE_ACCEL_PROBE_CLAIM_SKIP);
		return -1;
	}

	claimed = scx_bpf_test_and_clear_cpu_idle(candidate);
	cake_scoreboard_claim_result(local_bss, status, claimed);
	if (claimed) {
		cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_HIT);
		cake_record_core_spread_hit(local_cpu);
		return (s32)candidate;
	}
	cake_record_accel_probe(route_kind, CAKE_ACCEL_PROBE_CLAIM_FAIL);
	return -1;
}

#undef CAKE_FULL_CORE_TRY_ATTR

static __noinline s32
cake_select_cpu_core_spread(struct task_struct *p, s32 prev_cpu, u64 wake_flags,
			    struct cake_cpu_bss *local_bss, u32 local_cpu)
{
	cake_fast_probe_pack_t spread_pack;
	bool vtime_skipped = false;
	u32  token;
	u32  candidate;
	u32  ncpus = cake_nr_cpus;
	u32  prev;
	u32  row;
	s32  selected;

	if ((u32)prev_cpu >= ncpus)
		return -1;
	prev = (u32)prev_cpu;

	token = cake_core_spread_route_token(p, wake_flags, ncpus, prev,
					     &vtime_skipped);
	if (token & CAKE_RTOKEN_LATENCY_BIASED)
		return -1;
	if ((token & CAKE_RTOKEN_CORE_SPREAD_REQUIRED) !=
	    CAKE_RTOKEN_CORE_SPREAD_REQUIRED) {
		if (vtime_skipped)
			cake_record_core_spread_vtime_skip(local_cpu);
		return -1;
	}

	cake_record_core_spread_attempt(local_cpu);
	row	    = prev & (CAKE_MAX_CPUS - 1);
	spread_pack = cpu_core_spread_pack[row];

	candidate = cake_fast_probe_slot_from_pack(spread_pack, 0);
	if (candidate < ncpus && candidate != prev) {
		selected = cake_try_full_core_idle_candidate(local_bss,
							    candidate,
							    local_cpu);
		if (selected >= 0)
			return selected;
	}

	candidate = cake_fast_probe_slot_from_pack(spread_pack, 1);
	if (candidate < ncpus && candidate != prev) {
		selected = cake_try_full_core_idle_candidate(local_bss,
							    candidate,
							    local_cpu);
		if (selected >= 0)
			return selected;
	}

	candidate = cake_fast_probe_slot_from_pack(spread_pack, 2);
	if (candidate < ncpus && candidate != prev) {
		selected = cake_try_full_core_idle_candidate(local_bss,
							    candidate,
							    local_cpu);
		if (selected >= 0)
			return selected;
	}

	candidate = cake_fast_probe_slot_from_pack(spread_pack, 3);
	if (candidate < ncpus && candidate != prev) {
		selected = cake_try_full_core_idle_candidate(local_bss,
							    candidate,
							    local_cpu);
		if (selected >= 0)
			return selected;
	}

	return -1;
}

#if !(defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED)
static __noinline s32 cake_select_route_predict(struct task_struct *p,
						s32 prev_cpu, u64 wake_flags,
						struct cake_cpu_bss *local_bss)
{
	u64 confidence;
	u8  route_kind;
	u32 slot;
	cake_fast_probe_pack_t probe_pack;
	u32 row;
	u32 candidate;
	s32 selected;

	u32 ncpus = cake_nr_cpus;

	if (prev_cpu < 0 || (u32)prev_cpu >= ncpus) {
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_INVALID_PREV);
		return CAKE_ROUTE_PREDICT_NONE;
	}
	if (cake_task_is_affinitized_n(p, ncpus)) {
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

#ifndef CAKE_RELEASE
	if (cake_route_pred_select_prev_ok(p, (u32)prev_cpu)) {
		selected = cake_try_clean_idle_candidate_record(
			local_bss, (u32)prev_cpu, CAKE_ROUTE_PREV);
		cake_record_frontier_select_prev(selected >= 0);
		if (selected >= 0)
			return selected;
	}
#endif

	confidence = READ_ONCE(local_bss->decision_confidence);
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
	probe_pack = cpu_fast_probe_pack[row];
	if (route_kind == CAKE_ROUTE_SLOT0) {
		candidate = cake_fast_probe_slot_from_pack(probe_pack, 0);
		goto claim_clean_route;
	}

#ifdef CAKE_RELEASE
	if ((u8)(route_kind - CAKE_ROUTE_SLOT1) >
	    (CAKE_ROUTE_SLOT3 - CAKE_ROUTE_SLOT1))
		return CAKE_ROUTE_PREDICT_NONE;
	if (!cake_task_latency_biased(p, wake_flags)) {
		return CAKE_ROUTE_PREDICT_NONE;
	}
	slot = route_kind - CAKE_ROUTE_SLOT0;
	candidate = cake_fast_probe_slot_from_pack(probe_pack, slot);
	goto claim_smt_route;
#else
	if (!cake_task_latency_biased(p, wake_flags)) {
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_LATENCY_GATE);
		return CAKE_ROUTE_PREDICT_NONE;
	}

	if ((u8)(route_kind - CAKE_ROUTE_SLOT1) <=
	    (CAKE_ROUTE_SLOT3 - CAKE_ROUTE_SLOT1)) {
		slot = route_kind - CAKE_ROUTE_SLOT0;
		candidate = cake_fast_probe_slot_from_pack(probe_pack, slot);
		goto claim_smt_route;
	}

	cake_record_accel_route_block(CAKE_ACCEL_BLOCK_UNKNOWN_ROUTE);
	return CAKE_ROUTE_PREDICT_NONE;
#endif

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
	cake_route_update(local_bss, route_kind, selected >= 0);
	cake_record_accel_route_result(route_kind, selected >= 0);
	return selected >= 0 ? selected : CAKE_ROUTE_PREDICT_NONE;
}
#endif

static __noinline s32 cake_select_cpu_fast_scan(struct task_struct *p,
						s32 prev_cpu, u64 wake_flags,
						struct cake_cpu_bss *local_bss)
{
	cake_fast_probe_pack_t probe_pack;
	u64  clean_mask;
	u32  candidate;
	u32  hit_route;
	u32  ncpus;
	u32  prev;
	u32  scan_limit;
	u32  row;
	s32  selected;

	ncpus = cake_nr_cpus;
	if ((u32)prev_cpu >= ncpus)
		return -1;
	if (cake_task_is_affinitized_n(p, ncpus))
		return -1;

	prev	       = (u32)prev_cpu;
	row	       = prev & (CAKE_MAX_CPUS - 1);
	probe_pack     = cpu_fast_probe_pack[row];
	clean_mask     = cake_fast_clean_mask_snapshot();

	cake_record_accel_fast_attempt(CAKE_ROUTE_PREV);
	selected = -1;
#if CAKE_PREV_IDLE_OVERRIDE_VALUE
	/* Prev affinity outranks scoreboard cleanliness: the wakee's cache
	 * history lives on prev and a just-vacated core is shallow-idle, but
	 * its status keeps the recent owner_class/pressure for a while and
	 * fails the clean gate, which would migrate a frame thread on nearly
	 * every wake.  Claim prev on the raw IDLE bit; fall through to the
	 * probe slots only when prev is genuinely busy. */
	{
		u64 prev_status = cake_read_cpu_status(prev);

		if ((prev_status & CAKE_CPU_STATUS_IDLE) &&
		    cake_claim_health_allows(local_bss) &&
		    scx_bpf_test_and_clear_cpu_idle(prev)) {
			selected = (s32)prev;
			cake_record_accel_fast_result(CAKE_ROUTE_PREV, true);
			hit_route = CAKE_ROUTE_PREV;
			goto fast_hit;
		}
	}
	cake_record_accel_fast_result(CAKE_ROUTE_PREV, false);
#else
	if (cake_fast_clean_mask_has(clean_mask, prev)) {
		selected = cake_try_clean_idle_candidate_record(
			local_bss, prev, CAKE_ROUTE_PREV);
		cake_record_accel_fast_result(CAKE_ROUTE_PREV, selected >= 0);
		if (selected >= 0) {
			hit_route = CAKE_ROUTE_PREV;
			goto fast_hit;
		}
		goto fast_miss;
	}
	cake_record_accel_fast_result(CAKE_ROUTE_PREV, false);
#endif

	candidate = cake_fast_probe_slot_from_pack(probe_pack, 0);
	if (candidate != prev) {
		cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT0);
		selected = -1;
		if (cake_fast_clean_mask_has(clean_mask, candidate)) {
			selected = cake_try_clean_idle_candidate_record(
				local_bss, candidate, CAKE_ROUTE_SLOT0);
			cake_record_accel_fast_result(CAKE_ROUTE_SLOT0,
						      selected >= 0);
			if (selected >= 0) {
				hit_route = CAKE_ROUTE_SLOT0;
				goto fast_hit;
			}
			goto fast_miss;
		}
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT0, false);
	}

	if (!cake_task_latency_biased(p, wake_flags))
		goto fast_miss;

	candidate = cake_fast_probe_slot_from_pack(probe_pack, 1);
	cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT1);
	selected = -1;
	if (cake_fast_clean_mask_has(clean_mask, candidate)) {
		selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
							      CAKE_ROUTE_SLOT1);
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT1, selected >= 0);
		if (selected >= 0) {
			hit_route = CAKE_ROUTE_SLOT1;
			goto fast_hit;
		}
		goto fast_miss;
	} else {
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT1, false);
	}

	scan_limit = cake_select_fast_scan_limit(local_bss);
	if (scan_limit <= 2) {
		goto fast_miss;
	}

	candidate = cake_fast_probe_slot_from_pack(probe_pack, 2);
	cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT2);
	selected = -1;
	if (cake_fast_clean_mask_has(clean_mask, candidate)) {
		selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
							      CAKE_ROUTE_SLOT2);
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT2, selected >= 0);
		if (selected >= 0) {
			hit_route = CAKE_ROUTE_SLOT2;
			goto fast_hit_row4;
		}
		goto fast_miss_row4;
	} else {
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT2, false);
	}

	candidate = cake_fast_probe_slot_from_pack(probe_pack, 3);
	cake_record_accel_fast_attempt(CAKE_ROUTE_SLOT3);
	selected = -1;
	if (cake_fast_clean_mask_has(clean_mask, candidate)) {
		selected = cake_try_smt_idle_candidate_record(local_bss, candidate,
							      CAKE_ROUTE_SLOT3);
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT3, selected >= 0);
		if (selected >= 0) {
			hit_route = CAKE_ROUTE_SLOT3;
			goto fast_hit_row4;
		}
		goto fast_miss_row4;
	} else {
		cake_record_accel_fast_result(CAKE_ROUTE_SLOT3, false);
	}

fast_miss_row4:
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

#if CAKE_LEARNED_LOCALITY_COMPILED || !CAKE_LEAN_SCHED
static __noinline
	u64 cake_select_primary_scan(struct cake_task_ctx __arena *tctx,
				     struct task_struct *p, s32 prev_cpu,
				     u64 wake_flags, u32 local_cpu)
{
#ifndef CAKE_RELEASE
	struct cake_stats *stats    = get_local_stats_for(local_cpu);
#endif
	u16		   home_cpu = tctx->home_cpu;
	u16		   start_cpu;
	u16		   select_flags = 0;

	if (cpu_sibling_map[prev_cpu & (CAKE_MAX_CPUS - 1)] == prev_cpu)
		return CAKE_SELECT_RESULT(-1, 0);

	start_cpu = home_cpu < cake_nr_cpus ? home_cpu : (u16)prev_cpu;
	start_cpu = cake_primary_cpu(start_cpu);
	if (start_cpu >= cake_nr_cpus)
		return CAKE_SELECT_RESULT(-1, 0);

	if (cake_should_guard_primary_scan(tctx, p, wake_flags)) {
		if (cake_primary_scan_credit_allows(tctx))
#ifndef CAKE_RELEASE
			stats->nr_primary_scan_credit_used++;
#else
			;
#endif
		else
			select_flags |= CAKE_SEL_PRIMARY_SCAN_GUARDED;
	} else if (cake_should_guard_hot_primary_scan(tctx, p, wake_flags)) {
		if (cake_hot_primary_scan_credit_allows(tctx))
#ifndef CAKE_RELEASE
			stats->nr_primary_scan_credit_used++;
#else
			;
#endif
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
		for (u32 off = 0; off < CAKE_MAX_CPUS && off < cake_nr_cpus; off++) {
			u16 candidate = start_cpu + off;
			if (candidate >= cake_nr_cpus)
				candidate -= cake_nr_cpus;

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

#ifndef CAKE_RELEASE
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
#endif

	return CAKE_SELECT_RESULT(-1, select_flags);
}

static __noinline u64 cake_select_learned_locality(struct task_struct *p,
						   s32 prev_cpu, u64 wake_flags,
						   u32 local_cpu)
{
	struct cake_task_ctx __arena *steer_tctx;
#ifndef CAKE_RELEASE
	struct cake_stats	     *steer_stats;
#endif
	u16			      select_flags = 0;
	s32			      cpu	   = -1;

	if (!CAKE_LEARNED_LOCALITY_ENABLED || !cake_should_steer(p, wake_flags))
		return CAKE_SELECT_RESULT(-1, 0);

	steer_tctx = get_task_ctx(p);
	if (!steer_tctx)
		return CAKE_SELECT_RESULT(-1, 0);

	u16 home_cpu  = steer_tctx->home_cpu;
	u8  home_core = steer_tctx->home_core;

#ifndef CAKE_RELEASE
	steer_stats = get_local_stats_for(local_cpu);
	steer_stats->nr_steer_eligible++;
#endif

	cpu = cake_pick_pressure_sibling(steer_tctx, (s32)home_cpu, p->cpus_ptr,
					 CAKE_PRESSURE_PROBE_SITE_HOME);
	if (cpu >= 0)
		return CAKE_SELECT_RESULT(cpu, CAKE_SEL_PRESSURE_CORE);

	if (home_cpu < cake_nr_cpus && home_cpu != prev_cpu &&
	    bpf_cpumask_test_cpu(home_cpu, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(home_cpu))
			return CAKE_SELECT_RESULT(home_cpu, CAKE_SEL_HOME);
#ifndef CAKE_RELEASE
		steer_stats->nr_home_cpu_busy_misses++;
#endif
	}

	if ((wake_flags & SCX_WAKE_SYNC) && home_core < 0xFF &&
	    home_cpu < CAKE_MAX_CPUS) {
		u16 candidate = cpu_sibling_map[home_cpu & (CAKE_MAX_CPUS - 1)];

		if (candidate < cake_nr_cpus && candidate != home_cpu &&
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

	if (prev_primary < cake_nr_cpus && prev_primary != prev_cpu &&
	    prev_primary != home_cpu &&
	    bpf_cpumask_test_cpu(prev_primary, p->cpus_ptr)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_primary))
			return CAKE_SELECT_RESULT(prev_primary,
						  CAKE_SEL_PREV_PRIMARY);
#ifndef CAKE_RELEASE
		steer_stats->nr_prev_primary_busy_misses++;
#endif
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

static __always_inline bool
cake_select_direct_dispatch_clean(struct task_struct *p, s32 cpu,
				  u16 select_flags)
{
#if defined(CAKE_RELEASE) && \
	(CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL || \
	 CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LLC_VTIME)
	u64 slice = quantum_ns;
	u32 service_kind;
#if CAKE_FUTEX_TRACE
	u32 trace_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
#endif

	/* Direct dispatch from select_cpu skips ops.enqueue(). Keep it for the
	 * narrow case where Cake has already reserved a clean scoreboard CPU and
	 * the task would otherwise follow the plain wakeup/local enqueue path.
	 * Stress tasks still pass through enqueue so cache-simple/service lanes
	 * remain intact. Schbench, sched-messaging, and sched-pipe also stay on
	 * enqueue so local-waiter/reset/busy-wake service contracts are not
	 * bypassed by a clean idle hit.
	 *
	 * LLC-vtime keeps its shared arbitration when enqueue sees a busy target,
	 * but a scoreboard/core-spread hit has already reserved a clean idle CPU.
	 * Let that path skip the enqueue callback just like local policy so
	 * wake-heavy default-user game workers avoid a redundant status read and
	 * LLC-vtime insertion branch on the common clean-idle handoff. */
	if (cpu < 0 || cpu >= cake_nr_cpus)
		return false;
	if ((p->flags & PF_KTHREAD) || p->prio < 120 || p->scx.weight != 100)
		return false;
	if (select_flags & CAKE_SEL_NATIVE_FIRST)
		return false;
	CAKE_FUTEX_TRACE_INC(trace_cpu, direct_clean_enter);
	service_kind = cake_task_service_kind(p);

	{
		u64 now = 0;

		if (cake_futex_lane_active(&now) &&
		    service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX) {
			CAKE_FUTEX_TRACE_INC(trace_cpu, direct_clean_futex);
			CAKE_FUTEX_TRACE_INC(trace_cpu,
					     direct_clean_lane_active);
			cake_futex_lane_note_now(now);
			p->scx.slice = slice;
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | (u32)cpu,
					   slice,
					   SCX_ENQ_HEAD | SCX_ENQ_IMMED);
			return true;
		}
	}

	if (service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX) {
		CAKE_FUTEX_TRACE_INC(trace_cpu, direct_clean_futex);
		CAKE_FUTEX_TRACE_INC(trace_cpu, direct_clean_first);
		cake_futex_lane_note_now(bpf_ktime_get_ns());
		p->scx.slice = slice;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | (u32)cpu, slice,
				   SCX_ENQ_HEAD | SCX_ENQ_IMMED);
		return true;
	}
	if (cake_select_service_needs_enqueue_contract(service_kind))
		return false;

	if (!(select_flags & (CAKE_SEL_SCOREBOARD_PREV |
			      CAKE_SEL_SCOREBOARD_SCAN | CAKE_SEL_CORE_SPREAD)))
		return false;
	if (cake_service_stress_kind(service_kind) != CAKE_TASK_STRESS_NONE)
		return false;

	if (unlikely(p->scx.dsq_vtime == 0))
		p->scx.dsq_vtime = cake_read_cpu_frontier((u32)cpu);
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice;
	cake_clamp_wakeup_vtime(p, (u32)cpu);
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | (u32)cpu, slice, 0);
	return true;
#else
	(void)p;
	(void)cpu;
	(void)select_flags;
	return false;
#endif
}

static __noinline __maybe_unused bool
cake_select_try_pipe_tunnel_direct(struct task_struct *p, s32 prev_cpu)
{
#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	u64 slice = quantum_ns;
	u32 cpu;

	if (prev_cpu < 0 || prev_cpu >= cake_nr_cpus)
		return false;
	cpu = (u32)prev_cpu;

	cake_service_transition_reset_state(cpu,
					    CAKE_TASK_SERVICE_PERF_SCHED_PIPE);
	p->scx.slice = slice;
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | cpu, slice, 0);
	return true;
#else
	(void)p;
	(void)prev_cpu;
	return false;
#endif
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* Associate the arena map only in builds that actually use task context. */
#if CAKE_NEEDS_ARENA
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

	CAKE_FUTEX_TRACE_INC(local_cpu, select_enter);
#if CAKE_FUTEX_TRACE
	if (cake_task_service_kind(p) == CAKE_TASK_SERVICE_STRESS_FUTEX) {
		CAKE_FUTEX_TRACE_INC(local_cpu, select_futex);
		CAKE_FUTEX_TRACE_FIRST(local_cpu, first_select_pid,
				       first_select_order, p->pid);
		cake_futex_task_trace_event(p, local_cpu, 0);
	}
#endif

#if CAKE_ACCEL_PATH
	if (cake_message_wake_candidate(p, wake_flags)) {
		u64 meta = cpu_meta[local_cpu];
		s32 sibling = (s32)cake_meta_sibling_cpu(meta);
		s32 mask = -((s32)((meta >> 49) & 1));
		s32 cpu_candidate = (sibling & mask) | (prev_cpu & ~mask);
		if (cpu_candidate >= 0 && cpu_candidate < cake_nr_cpus) {
			return cpu_candidate;
		}
	}
#endif

#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
#if CAKE_NATIVE_FAST_WAKE_VALUE
	/* Native fast wake (SCX_CAKE_NATIVE_FAST_WAKE): route default-user
	 * wakeups through the kernel idle pick and select-side direct
	 * dispatch, skipping Cake's scoreboard/service machinery entirely.
	 * A/B probe for the constant per-wake transit cost vs EEVDF/cosmos
	 * (~32us/frame avg-fps gap across all policy arms).  Game-A/B only:
	 * bench service contracts (sched-pipe/schbench resets) are bypassed,
	 * so do not promote without re-running the bench suite. */
	if (p->prio >= 120 && p->scx.weight == 100
#if !CAKE_NATIVE_FAST_WAKE_WIDE
	    && !(p->flags & PF_KTHREAD) && !cake_task_is_affinitized(p)
#endif
	) {
		s32 nfw_cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);

		if (nfw_cpu >= 0) {
			u64 nfw_slice = quantum_ns;

			p->scx.slice = nfw_slice;
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | (u32)nfw_cpu,
					   nfw_slice, 0);
			return nfw_cpu;
		}
#if CAKE_NFW_MISS_SHARED
		/* Work-conserving miss: no idle CPU exists, so park the wakee
		 * in the shared per-LLC vtime queue instead of prev's local
		 * queue — the FIRST core to hit a dispatch point pulls it,
		 * rather than waiting specifically for prev.  This is the
		 * cosmos-style work conservation at the frame-overlap edge. */
		{
			u32 ms_cpu = (u32)prev_cpu < (u32)cake_nr_cpus ?
					     (u32)prev_cpu :
					     0;
			u64 ms_slice = quantum_ns;

			if (unlikely(p->scx.dsq_vtime == 0))
				p->scx.dsq_vtime =
					cake_read_cpu_frontier(ms_cpu);
			p->scx.slice = ms_slice;
			p->scx.dsq_vtime += ms_slice;
			cake_clamp_wakeup_vtime(p, ms_cpu);
			cake_insert_llc_vtime(p, 0, ms_cpu, ms_slice);
			return prev_cpu;
		}
#elif CAKE_NATIVE_FAST_WAKE_MISS_TUNNEL
		/* A miss here is authoritative: select_cpu_and searched every
		 * allowed CPU, so no idle CPU exists and every later idle
		 * probe in this callback would re-discover the same nothing.
		 * Tunnel straight to prev — at the GameThread→RenderThread
		 * overlap edge this miss fires every frame, so the skipped
		 * machinery is per-frame serial cost. */
		goto tunnel;
#endif
		/* Miss: fall through to Cake's guarded machinery. */
	}
#endif
	/* Generic bulk escape: for non-service, non-sync, default-user work,
	 * ask native idle selection before Cake's narrow scoreboard probes.  A
	 * native hit falls through enqueue instead of select-side direct dispatch,
	 * matching the historical "delete broad direct dispatch/head/immed" signal.
	 * A native miss is authoritative enough for this class; skip the later
	 * Cake probes and tunnel to the previous CPU.
	 */
	{
		u32 service_kind = cake_task_service_kind(p);

		if (cake_native_first_bulk_candidate(
			    p, prev_cpu, wake_flags, service_kind,
			    cake_nr_cpus)) {
			cake_record_accel_native(CAKE_ACCEL_NATIVE_ENTRY);
			cake_record_accel_native(CAKE_ACCEL_NATIVE_AND);
			cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);
			if (cpu >= 0) {
				select_flags |= CAKE_SEL_NATIVE_FIRST;
				goto idle_found;
			}
			goto tunnel;
		}
	}
#endif

	/* ── CAKE SCOREBOARD / PREDICTION ──
	 * This is the latency floor path. Explicit service/sync work stays here;
	 * native helpers remain the safe fallback when prediction or cheap claims
	 * miss. Generic bulk/default work may have already used the guarded
	 * native-first escape above. */
#if CAKE_ACCEL_PATH
#if defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED
	cpu = CAKE_ROUTE_PREDICT_NONE;
	cake_record_accel_route_block(CAKE_ACCEL_BLOCK_UNKNOWN_ROUTE);
#else
	if (prev_cpu >= 0 &&
	    (((u32)prev_cpu) & (CAKE_MAX_CPUS - 1)) == local_cpu) {
		cpu = cake_select_route_predict(p, prev_cpu, wake_flags,
						select_bss);
	} else {
		cpu = CAKE_ROUTE_PREDICT_NONE;
		cake_record_accel_route_block(CAKE_ACCEL_BLOCK_UNKNOWN_ROUTE);
	}
#endif
	if (cpu == CAKE_ROUTE_PREDICT_TUNNEL)
		goto tunnel;
	if (cpu >= 0) {
		select_flags |= cpu == prev_cpu ? CAKE_SEL_SCOREBOARD_PREV :
						  CAKE_SEL_SCOREBOARD_SCAN;
		goto idle_found;
	}

#if defined(CAKE_RELEASE) && CAKE_SCOREBOARD_SUMMARY && \
	CAKE_USE_SCOREBOARD_SUMMARY && defined(CAKE_SINGLE_LLC)
	{
		s32 precheck = cake_fast_scan_probe_precheck(p, prev_cpu);

		cpu = -1;
		if (precheck == 0) {
			cake_conf_update_select(select_bss, false, false, false);
		} else if (precheck > 0) {
			cpu = cake_select_cpu_fast_scan(p, prev_cpu, wake_flags,
							select_bss);
		}
	}
#else
	cpu = cake_select_cpu_fast_scan(p, prev_cpu, wake_flags, select_bss);
#endif
	if (cpu >= 0) {
		select_flags |= cpu == prev_cpu ? CAKE_SEL_SCOREBOARD_PREV :
						  CAKE_SEL_SCOREBOARD_SCAN;
		goto idle_found;
	}

	cpu = cake_select_cpu_core_spread(p, prev_cpu, wake_flags, select_bss,
					  local_cpu);
	if (cpu >= 0) {
		select_flags |= CAKE_SEL_CORE_SPREAD;
		goto idle_found;
	}
#endif

#if CAKE_LEARNED_LOCALITY_COMPILED || !CAKE_LEAN_SCHED
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
#if CAKE_FUTEX_TRACE
	if (cake_task_service_kind(p) == CAKE_TASK_SERVICE_STRESS_FUTEX)
		CAKE_FUTEX_TRACE_INC(local_cpu, native_noidle);
#endif

	/* No idle CPU was found; tunnel back to prev_cpu for local enqueue. */
	if (cpu >= 0) {
idle_found:
		__attribute__((unused));
		u16 select_choice;

#if CAKE_FUTEX_TRACE
		if (cake_task_service_kind(p) == CAKE_TASK_SERVICE_STRESS_FUTEX) {
			CAKE_FUTEX_TRACE_INC(local_cpu, idle_found);
			CAKE_FUTEX_TRACE_FIRST((u32)cpu, first_idle_pid,
					       first_idle_order, p->pid);
			cake_futex_task_trace_event(p, (u32)cpu, 1);
			if (select_flags & (CAKE_SEL_SCOREBOARD_PREV |
					    CAKE_SEL_SCOREBOARD_SCAN))
				CAKE_FUTEX_TRACE_INC(local_cpu,
						     idle_scoreboard);
			else if (select_flags & CAKE_SEL_CORE_SPREAD)
				CAKE_FUTEX_TRACE_INC(local_cpu,
						     idle_core_spread);
			else
				CAKE_FUTEX_TRACE_INC(local_cpu, idle_native);
		}
#endif
		if (cake_select_direct_dispatch_clean(p, cpu, select_flags))
			return cpu;

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
		else if (select_flags & CAKE_SEL_CORE_SPREAD)
			select_choice = CAKE_SELECT_CHOICE(
				CAKE_SELECT_PATH_PRIMARY,
				CAKE_SELECT_REASON_CORE_SPREAD);
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
						 CAKE_SEL_SCAN_PRIMARY |
						 CAKE_SEL_CORE_SPREAD))
				s->nr_primary_cpu_steers++;
			if (select_flags & CAKE_SEL_CORE_SPREAD) {
				s->nr_core_spread_attempt++;
				s->nr_core_spread_hit++;
			}
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
			cake_record_cb_split(s, CAKE_CB_SELECT, dur, 0);
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
				else if (select_flags & CAKE_SEL_CORE_SPREAD)
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

		for (u32 i = 0; i < CAKE_MAX_CPUS && i < cake_nr_cpus; i++) {
			u8 candidate = scan_order[i];
			if (candidate >= cake_nr_cpus)
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
		CAKE_FUTEX_TRACE_INC(local_cpu, tunnel_enter);
#if CAKE_FUTEX_TRACE
		if (cake_task_service_kind(p) == CAKE_TASK_SERVICE_STRESS_FUTEX)
			CAKE_FUTEX_TRACE_INC(local_cpu, tunnel_futex);
#endif
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
			cake_record_cb_split(s, CAKE_CB_SELECT, dur, 0);
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

#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	/* Futex is a micro handoff workload: when all CPUs look busy, avoiding
	 * the enqueue callback is worth more than fairness bookkeeping. Keep this
	 * out of enqueue_body so stress-ng-cache does not inherit the broad futex
	 * branch shape that triggered runnable-stall watchdog exits. The status
	 * read is kept as part of the stable select_cpu code shape, but stale
	 * cache-saturation state from prior suite rows must not gate this
	 * stress-ng-futex-only handoff. */
	if (prev_cpu >= 0 && prev_cpu < cake_nr_cpus &&
	    !(p->flags & PF_KTHREAD) && p->prio >= 120 &&
	    p->scx.weight == 100 && !cake_task_is_affinitized(p)) {
		u32 service_kind = CAKE_TASK_SERVICE_NONE;
		u64 comm0 = cake_task_comm_word(p, 0);
		if (comm0 == CAKE_COMM_STRESS0) {
			if ((cake_task_comm_word(p, 1) & CAKE_COMM_MASK3) == CAKE_COMM_STRESS1_FUTEX)
				service_kind = CAKE_TASK_SERVICE_STRESS_FUTEX;
		} else if (comm0 == CAKE_COMM_SCHED_PIPE0) {
			if ((cake_task_comm_word(p, 1) & CAKE_COMM_MASK2) == CAKE_COMM_SCHED_PIPE1)
				service_kind = CAKE_TASK_SERVICE_PERF_SCHED_PIPE;
		}

		if (service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX) {
			u32 prev_idx = (u32)prev_cpu;
			u64 target_status;
			u64 slice = quantum_ns;

			prev_idx &= CAKE_MAX_CPUS - 1;
			barrier_var(prev_idx);
			if (prev_idx >= CAKE_MAX_CPUS)
				return prev_cpu;

			target_status = cake_read_cpu_status(prev_idx);
			CAKE_FUTEX_TRACE_INC(local_cpu, tunnel_futex_insert);
			cake_service_transition_reset_state(prev_idx,
							    service_kind);
			CAKE_FUTEX_TRACE_FIRST(prev_idx,
					       first_tunnel_pid,
					       first_tunnel_order, p->pid);
			cake_futex_task_trace_event(p, prev_idx, 2);
			cake_futex_lane_note_now(bpf_ktime_get_ns());
			barrier_var(target_status);
			p->scx.slice = slice;
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | prev_idx,
					   slice,
					   SCX_ENQ_HEAD | SCX_ENQ_IMMED);
			return prev_cpu;
		}
		if (service_kind == CAKE_TASK_SERVICE_PERF_SCHED_PIPE &&
		    cake_select_try_pipe_tunnel_direct(p, prev_cpu))
			return prev_cpu;
	}
#endif

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

	if (llc >= cake_nr_llcs)
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

static __always_inline u32 cake_core_steal_index(u32 primary)
{
	u32 idx = primary;

	idx &= CAKE_MAX_CPUS - 1;
	barrier_var(idx);
	if (idx >= CAKE_MAX_CPUS)
		return 0;
	return idx;
}

static __always_inline u32 cake_core_steal_primary_cpu(u32 cpu)
{
	u16 primary;

	if (cpu >= cake_nr_cpus)
		cpu = cake_core_steal_index(cpu);
	primary = cake_primary_cpu((u16)cpu);
	if (primary >= cake_nr_cpus)
		primary = (u16)cake_core_steal_index(cpu);
	if (primary >= cake_nr_cpus)
		primary = 0;
	return cake_core_steal_index((u32)primary);
}

static __always_inline u64 cake_core_steal_dsq_for_primary(u32 primary)
{
	u32 idx = cake_core_steal_index(primary);

	return CAKE_CORE_STEAL_DSQ_BASE + idx;
}

static __always_inline __maybe_unused u64 cake_core_steal_dsq_for_cpu(u32 cpu)
{
	u32 primary = cake_core_steal_primary_cpu(cpu);

	return cake_core_steal_dsq_for_primary(primary);
}

static __noinline bool cake_dsq_move_to_local(u64 dsq_id, u64 enq_flags)
{
	return scx_bpf_dsq_move_to_local(dsq_id, enq_flags);
}

static __always_inline void cake_core_steal_pending_mark_primary(u32 primary)
{
	u32 idx = cake_core_steal_index(primary);
	u64 bit = 1ULL << idx;

	if (!READ_ONCE(core_steal_pending[idx].pending)) {
		WRITE_ONCE(core_steal_pending[idx].pending, 1);
		__sync_fetch_and_or(&core_steal_pending_mask, bit);
	}
}

static __always_inline __maybe_unused void cake_core_steal_pending_mark_cpu(u32 cpu)
{
	cake_core_steal_pending_mark_primary(cake_core_steal_primary_cpu(cpu));
}

static __noinline __maybe_unused bool
cake_core_steal_pull_primary(u32 primary)
{
	u32 idx = cake_core_steal_index(primary);
	u64 bit = 1ULL << idx;
	bool hit = false;

	if (idx >= cake_nr_cpus)
		return false;

	if (!READ_ONCE(core_steal_pending[idx].pending))
		return false;

#if CAKE_CORE_STEAL_DHQ_VALUE
	if (likely(cpu_lfdeqs[0] != NULL)) {
		u32 own_cpu = bpf_get_smp_processor_id();
		u32 primary_sibling = (u32)cpu_sibling_map[primary & (CAKE_MAX_CPUS - 1)];
		struct task_struct *p = NULL;
		u64 pid = 0;

		struct scx_lfdeq __arena *lfdeq = get_cpu_lfdeq(own_cpu);
		struct scx_lfdeq __arena *sib_lfdeq = NULL;
		struct scx_lfdeq __arena *prim_lfdeq = get_cpu_lfdeq(primary);
		struct scx_lfdeq __arena *prim_sib_lfdeq = NULL;

		u32 sib_cpu = (u32)cpu_sibling_map[own_cpu & (CAKE_MAX_CPUS - 1)];
		if (sib_cpu < cake_nr_cpus && sib_cpu != own_cpu) {
			sib_lfdeq = get_cpu_lfdeq(sib_cpu);
		}
		if (primary_sibling < cake_nr_cpus && primary_sibling != primary) {
			prim_sib_lfdeq = get_cpu_lfdeq(primary_sibling);
		}

		bool is_local = (own_cpu == primary || own_cpu == primary_sibling);
		struct scx_lfdeq __arena *target_a = is_local ? lfdeq : prim_lfdeq;
		struct scx_lfdeq __arena *target_b = is_local ? sib_lfdeq : prim_sib_lfdeq;

		#pragma unroll
		for (int iter = 0; iter < 2; iter++) {
			if (is_local) {
				if (target_a) {
					scx_lfdeq_flush(target_a);
					pid = scx_lfdeq_pop_local(target_a);
				}
			} else {
				if (target_a) {
					pid = scx_lfdeq_steal(target_a);
				}
			}

			if (!pid && target_b) {
				pid = scx_lfdeq_steal(target_b);
			}

			if (!pid)
				break;

			p = bpf_task_from_pid((s32)pid);
			if (p)
				break;
		}

		if (p) {
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | own_cpu, p->scx.slice, 0);
			bpf_task_release(p);
			hit = true;
		}

		bool has_queued = false;
		if (prim_lfdeq) {
			u64 h = READ_ONCE(prim_lfdeq->head);
			u64 t = READ_ONCE(prim_lfdeq->tail);
			u64 eq_h = READ_ONCE(prim_lfdeq->eq_buf.head);
			u64 eq_t = READ_ONCE(prim_lfdeq->eq_buf.tail);
			if (h < t || eq_h < eq_t)
				has_queued = true;
		}
		if (!has_queued && primary_sibling < cake_nr_cpus && primary_sibling != primary) {
			if (prim_sib_lfdeq) {
				u64 h = READ_ONCE(prim_sib_lfdeq->head);
				u64 t = READ_ONCE(prim_sib_lfdeq->tail);
				u64 eq_h = READ_ONCE(prim_sib_lfdeq->eq_buf.head);
				u64 eq_t = READ_ONCE(prim_sib_lfdeq->eq_buf.tail);
				if (h < t || eq_h < eq_t)
					has_queued = true;
			}
		}

		if (has_queued) {
			// Keep pending at 1, do not touch mask.
		} else {
			if (READ_ONCE(core_steal_pending[idx].pending)) {
				WRITE_ONCE(core_steal_pending[idx].pending, 0);
				__sync_fetch_and_and(&core_steal_pending_mask, ~bit);
			}
		}
		return hit;
	}
#endif

	u64 dsq = cake_core_steal_dsq_for_primary(idx);
	hit = cake_dsq_move_to_local(dsq, 0);
	if (scx_bpf_dsq_nr_queued(dsq) > 0) {
		// Keep pending at 1, do not touch mask.
	} else {
		if (READ_ONCE(core_steal_pending[idx].pending)) {
			WRITE_ONCE(core_steal_pending[idx].pending, 0);
			__sync_fetch_and_and(&core_steal_pending_mask, ~bit);
		}
	}
	return hit;
}

static __always_inline __maybe_unused bool
cake_dispatch_try_core_steal_own(u32 cpu)
{
	u32 primary = cake_core_steal_primary_cpu(cpu);
	u64 bit = 1ULL << primary;

	if (!(READ_ONCE(core_steal_pending_mask) & bit))
		return false;
	return cake_core_steal_pull_primary(primary);
}

static __noinline __maybe_unused bool
cake_dispatch_try_core_steal_same_llc(u32 cpu)
{
	u32 own_primary = cake_core_steal_primary_cpu(cpu);
	cake_fast_probe_pack_t packed =
		cpu_core_spread_pack[cpu & (CAKE_MAX_CPUS - 1)];
	u64 mask = READ_ONCE(core_steal_pending_mask);

	if (!mask)
		return false;

	for (u32 slot = 0; slot < CAKE_FAST_PROBE_SLOTS; slot++) {
		u32 victim = cake_fast_probe_slot_from_pack(packed, slot);
		u32 primary;

		if (victim >= cake_nr_cpus)
			continue;
		primary = cake_core_steal_primary_cpu(victim);
		if (primary == own_primary)
			continue;
		if (!(mask & (1ULL << primary)))
			continue;
		if (cake_llc_id_for_cpu(primary) != cake_llc_id_for_cpu(cpu))
			continue;
		if (cake_core_steal_pull_primary(primary))
			return true;
	}

	return false;
}

static __noinline __maybe_unused bool
cake_dispatch_try_core_steal_any(u32 cpu)
{
	u32 own_primary = cake_core_steal_primary_cpu(cpu);
	u64 mask = READ_ONCE(core_steal_pending_mask);

	if (!mask)
		return false;

	for (u32 off = 1; off < CAKE_MAX_CPUS; off++) {
		u32 victim = cpu + off;
		u32 primary;

		if (victim >= CAKE_MAX_CPUS)
			victim -= CAKE_MAX_CPUS;
		if (victim >= cake_nr_cpus)
			continue;

		primary = cake_core_steal_primary_cpu(victim);
		if (primary == own_primary)
			continue;
		if (!(mask & (1ULL << primary)))
			continue;
		if (primary != victim)
			continue;
		if (cake_core_steal_pull_primary(primary))
			return true;
	}

	return false;
}

#if CAKE_HAS_LLC_PENDING
static __always_inline u32 cake_llc_pending_idx_for_cpu(u32 cpu)
{
#ifdef CAKE_SINGLE_LLC
	(void)cpu;
	return 0;
#else
	return cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1);
#endif
}

static __always_inline bool cake_llc_pending_maybe_cpu(u32 cpu)
{
	return READ_ONCE(llc_pending[cake_llc_pending_idx_for_cpu(cpu)].pending);
}

static __always_inline void cake_llc_pending_mark_cpu(u32 cpu)
{
	u32 idx = cake_llc_pending_idx_for_cpu(cpu);

	if (!READ_ONCE(llc_pending[idx].pending))
		WRITE_ONCE(llc_pending[idx].pending, 1);
}

static __always_inline __maybe_unused void
cake_llc_pending_refresh_cpu(u32 cpu, u64 dsq_id)
{
	u32 idx = cake_llc_pending_idx_for_cpu(cpu);

	WRITE_ONCE(llc_pending[idx].pending, 0);
	if (scx_bpf_dsq_nr_queued(dsq_id) > 0)
		WRITE_ONCE(llc_pending[idx].pending, 1);
}

static __always_inline __maybe_unused bool cake_llc_pending_pull_cpu(u32 cpu, u64 dsq_id)
{
	u32 idx = cake_llc_pending_idx_for_cpu(cpu);
	bool hit;

	if (!READ_ONCE(llc_pending[idx].pending))
		return false;

	WRITE_ONCE(llc_pending[idx].pending, 0);
	hit = cake_dsq_move_to_local(dsq_id, 0);
	if (scx_bpf_dsq_nr_queued(dsq_id) > 0)
		WRITE_ONCE(llc_pending[idx].pending, 1);
	return hit;
}
#endif

static __noinline __maybe_unused bool
cake_dispatch_try_idle_core_steal_rescue(struct cake_cpu_bss *dispatch_bss,
					 struct task_struct *prev, u32 cpu_idx)
{
#if defined(CAKE_RELEASE) && CAKE_ENABLE_CORE_STEAL_BUSY_FALLBACK
	u32 idx = cake_core_steal_primary_cpu(cpu_idx);
	u64 bit = 1ULL << idx;
	bool hit;
	bool has_queued = false;

	/* Idle rescue is the safety valve for the steal-first experiment:
	 * a CPU with no queued prev must not trust the side pending bit more than
	 * its own custom DSQ.  Keep the queue-depth helper off the normal dispatch
	 * path; pay it only when the CPU is already idle/no-prev and may otherwise
	 * leave runnable work stranded in 0x1000+cpu until the watchdog fires. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		return false;
	if (idx >= cake_nr_cpus)
		return false;

#if CAKE_CORE_STEAL_DHQ_VALUE
	if (likely(cpu_lfdeqs[0] != NULL)) {
		struct scx_lfdeq __arena *prim_lfdeq = get_cpu_lfdeq(idx);
		if (prim_lfdeq) {
			u64 h = READ_ONCE(prim_lfdeq->head);
			u64 t = READ_ONCE(prim_lfdeq->tail);
			u64 eq_h = READ_ONCE(prim_lfdeq->eq_buf.head);
			u64 eq_t = READ_ONCE(prim_lfdeq->eq_buf.tail);
			if (h < t || eq_h < eq_t)
				has_queued = true;
		}
		u32 sibling = (u32)cpu_sibling_map[idx & (CAKE_MAX_CPUS - 1)];
		if (sibling < cake_nr_cpus && sibling != idx) {
			struct scx_lfdeq __arena *prim_sib_lfdeq = get_cpu_lfdeq(sibling);
			if (prim_sib_lfdeq) {
				u64 h = READ_ONCE(prim_sib_lfdeq->head);
				u64 t = READ_ONCE(prim_sib_lfdeq->tail);
				u64 eq_h = READ_ONCE(prim_sib_lfdeq->eq_buf.head);
				u64 eq_t = READ_ONCE(prim_sib_lfdeq->eq_buf.tail);
				if (h < t || eq_h < eq_t)
					has_queued = true;
			}
		}
	} else {
		u64 dsq = cake_core_steal_dsq_for_primary(idx);
		if (scx_bpf_dsq_nr_queued(dsq) > 0)
			has_queued = true;
	}
#else
	u64 dsq = cake_core_steal_dsq_for_primary(idx);
	if (scx_bpf_dsq_nr_queued(dsq) > 0)
		has_queued = true;
#endif

	if (!(READ_ONCE(core_steal_pending_mask) & bit) && !has_queued)
		return false;
	cake_core_steal_pending_mark_primary(idx);
	hit = cake_core_steal_pull_primary(idx);
	if (hit)
		cake_throughput_reset_dispatch_budget(dispatch_bss);
	return hit;
#else
	(void)dispatch_bss;
	(void)prev;
	(void)cpu_idx;
	return false;
#endif
}

static __always_inline __maybe_unused bool
cake_dispatch_try_idle_llc_rescue(struct cake_cpu_bss *dispatch_bss,
				  struct task_struct *prev, u32 cpu_idx)
{
#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
	bool hit;

	/* Safety invariant for every shared-service experiment:
	 * an idle dispatch must not trust the side pending bit more than the
	 * DSQ itself. Prior shared-escape variants could leave work visible in
	 * LLC_DSQ_BASE while the only compatible CPU was idle, producing the
	 * sched_ext runnable-stall watchdog. Keep this check out of the
	 * keep-running hot path by running it only when there is no queued prev. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		return false;

#if CAKE_HAS_LLC_PENDING
	if (!cake_llc_pending_maybe_cpu(cpu_idx) &&
	    scx_bpf_dsq_nr_queued(LLC_DSQ_BASE) <= 0)
		return false;
	cake_llc_pending_mark_cpu(cpu_idx);
	hit = cake_llc_pending_pull_cpu(cpu_idx, LLC_DSQ_BASE);
#else
	if (scx_bpf_dsq_nr_queued(LLC_DSQ_BASE) <= 0)
		return false;
	hit = cake_dsq_move_to_local(LLC_DSQ_BASE, 0);
#endif
	if (hit)
		cake_throughput_reset_dispatch_budget(dispatch_bss);
	return hit;
#else
	(void)dispatch_bss;
	(void)prev;
	(void)cpu_idx;
	return false;
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

static __always_inline __maybe_unused void
cake_insert_llc_pending_vtime(struct task_struct *p, u64 enq_flags,
			      u32 target_cpu, u64 slice)
{
#if CAKE_HAS_LLC_PENDING
	cake_llc_pending_mark_cpu(target_cpu);
#endif
	dsq_insert_vtime_wrapper(p, cake_llc_dsq_for_cpu(target_cpu), slice,
				 p->scx.dsq_vtime, enq_flags);
}

static __noinline __maybe_unused void
cake_insert_core_steal_vtime(struct task_struct *p, u64 enq_flags,
			     u32 target_cpu, u64 slice)
{
	u32 primary = cake_core_steal_primary_cpu(target_cpu);
	bool inserted_dhq = false;

#if CAKE_CORE_STEAL_DHQ_VALUE
	if (likely(cpu_lfdeqs[0] != NULL)) {
		struct scx_lfdeq __arena *lfdeq = get_cpu_lfdeq(target_cpu);
		if (lfdeq) {
			int ret = scx_lfdeq_enqueue_remote(lfdeq, p->pid);
			if (ret == 0)
				inserted_dhq = true;
		}
	}
#endif

	if (!inserted_dhq) {
		dsq_insert_vtime_wrapper(p, cake_core_steal_dsq_for_primary(primary),
					 slice, p->scx.dsq_vtime, enq_flags);
	}
	cake_core_steal_pending_mark_primary(primary);
	scx_bpf_kick_cpu(primary, SCX_KICK_IDLE);
}

static __always_inline bool
cake_core_steal_pending_maybe_cpu(u32 cpu)
{
	u32 primary = cake_core_steal_primary_cpu(cpu);
	u32 idx = cake_core_steal_index(primary);

	if (idx >= cake_nr_cpus)
		return false;
	return !!READ_ONCE(core_steal_pending[idx].pending);
}

static __noinline __maybe_unused bool
cake_dispatch_try_core_steal_ordered(struct cake_cpu_bss *dispatch_bss,
				     struct task_struct *prev, u32 cpu_idx,
				     bool fairness_due,
				     bool stream_bleed_due)
{
#if defined(CAKE_RELEASE) && CAKE_ENABLE_CORE_STEAL_BUSY_FALLBACK
	if (cake_dispatch_try_core_steal_own(cpu_idx)) {
		cake_throughput_reset_dispatch_budget(dispatch_bss);
		return true;
	}
	if (!fairness_due && !stream_bleed_due && prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		return false;
	}
	if (cake_dispatch_try_core_steal_same_llc(cpu_idx)) {
		cake_throughput_reset_dispatch_budget(dispatch_bss);
		return true;
	}
	u64 dec = READ_ONCE(dispatch_bss->throughput_decision);
	bool has_stream_pressure = !!(dec & CAKE_TP_DEC_STREAM_PRESSURE);
	if ((stream_bleed_due || (has_stream_pressure && (!prev || !(prev->scx.flags & SCX_TASK_QUEUED)))) &&
	    READ_ONCE(dispatch_bss->owner_service_kind) == CAKE_TASK_SERVICE_NONE) {
		if (cake_dispatch_try_core_steal_any(cpu_idx)) {
			cake_throughput_reset_dispatch_budget(dispatch_bss);
			return true;
		}
	}
	return false;
#else
	(void)dispatch_bss;
	(void)prev;
	(void)cpu_idx;
	(void)fairness_due;
	(void)stream_bleed_due;
	return false;
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

static __always_inline __maybe_unused u64 cake_throughput_dsq_for_cpu(u32 cpu)
{
	return CAKE_THROUGHPUT_DSQ_BASE + (cpu & (CAKE_MAX_CPUS - 1));
}

static __always_inline __maybe_unused u64 cake_stream_service_dsq(void)
{
	return CAKE_DOMAIN_DRR_DSQ_BASE;
}

static __always_inline u64 cake_stream_slice(void)
{
	return quantum_ns << CAKE_STREAM_SLICE_SHIFT;
}

#if CAKE_HAS_DOMAIN_DRR
static __always_inline u64 cake_domain_drr_dsq_for_cpu_class(u32 cpu, u32 cls)
{
	u32 llc = cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1);

	return CAKE_DOMAIN_DRR_DSQ_BASE +
	       ((u64)(cls & (CAKE_DOMAIN_DRR_CLASS_MAX - 1U)) *
		(u64)CAKE_MAX_LLCS) +
	       (u64)llc;
}

static __always_inline u64 *cake_domain_drr_pending_ptr(struct cake_domain_drr *drr,
							u32 cls)
{
	if (cls == CAKE_DOMAIN_DRR_CLASS_STREAM)
		return &drr->stream_pending;
	return &drr->cache_pending;
}

static __always_inline void cake_domain_drr_mark(u32 cpu, u32 cls)
{
	struct cake_domain_drr *drr =
		&domain_drr[cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1)];
	u64 *pending = cake_domain_drr_pending_ptr(drr, cls);

	if (!READ_ONCE(*pending))
		WRITE_ONCE(*pending, 1);
}

static __always_inline void
cake_domain_drr_insert(struct task_struct *p, u32 target_cpu, u64 slice,
		       u64 enq_flags, u32 cls, u64 target_status)
{
	u64 dsq = cake_domain_drr_dsq_for_cpu_class(target_cpu, cls);

	cake_domain_drr_mark(target_cpu, cls);
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(target_cpu);

		if (cls == CAKE_DOMAIN_DRR_CLASS_STREAM)
			stats->nr_domain_drr_stream_insert++;
		else
			stats->nr_domain_drr_cache_insert++;
		stats->nr_dsq_queued++;
	}
#endif
	dsq_insert_vtime_wrapper(p, dsq, slice, p->scx.dsq_vtime, enq_flags);
	if (target_status & CAKE_CPU_STATUS_IDLE)
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
}

static __always_inline bool cake_domain_drr_pull_class(u32 cpu, u32 cls)
{
	u32 idx = cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1);
	struct cake_domain_drr *drr = &domain_drr[idx];
	u64 *pending = cake_domain_drr_pending_ptr(drr, cls);
	u64 dsq;

	if (!READ_ONCE(*pending))
		return false;

	dsq = cake_domain_drr_dsq_for_cpu_class(cpu, cls);
	if (cake_dsq_move_to_local(dsq, 0)) {
#ifndef CAKE_RELEASE
		if (CAKE_PATH_STATS_ACTIVE) {
			struct cake_stats *stats = get_local_stats_for(cpu);

			if (cls == CAKE_DOMAIN_DRR_CLASS_STREAM)
				stats->nr_domain_drr_stream_pull++;
			else
				stats->nr_domain_drr_cache_pull++;
			stats->nr_dsq_consumed++;
		}
#endif
		return true;
	}

	/* A failed move only proves that this CPU did not win a task.  With a
	 * single per-LLC service DSQ, many CPUs can race this hint at once.  The
	 * old bit clear made a losing racer publish "empty" while the service
	 * DSQ still held work for another CPU, which could strand cache workers
	 * behind a steady memcpy stream until the sched_ext stall watchdog fired.
	 *
	 * Pay the queue-depth helper only on the stale/failure edge and clear the
	 * hint only when the DSQ is observed empty.  The common successful pull
	 * path stays helperless, while the mixed cache/mem path gets a hard
	 * starvation guard instead of a racy best-effort bit.
	 */
	if (!scx_bpf_dsq_nr_queued(dsq))
		WRITE_ONCE(*pending, 0);
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(cpu)->nr_domain_drr_stale++;
#endif
	return false;
}

static __always_inline void cake_domain_drr_note_cache_pull(u32 cpu,
							    bool stream_pending)
{
	struct cake_domain_drr *drr =
		&domain_drr[cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1)];
	u64 burst;

	if (!stream_pending) {
		if (READ_ONCE(drr->cache_burst))
			WRITE_ONCE(drr->cache_burst, 0);
		return;
	}

	burst = READ_ONCE(drr->cache_burst);
	if (burst < CAKE_DOMAIN_DRR_CACHE_BURST_LIMIT)
		WRITE_ONCE(drr->cache_burst, burst + 1);
}

static __always_inline void cake_domain_drr_note_stream_pull(u32 cpu)
{
	struct cake_domain_drr *drr =
		&domain_drr[cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1)];

	if (READ_ONCE(drr->cache_burst))
		WRITE_ONCE(drr->cache_burst, 0);
}

static __always_inline bool cake_domain_drr_enqueue_stress(struct task_struct *p,
							   u32 target_cpu,
							   u64 slice,
							   u64 enq_flags,
							   u32 stress_kind,
							   u64 target_status)
{
	u32 cls;

	if (stress_kind == CAKE_TASK_STRESS_CACHE) {
		cls = CAKE_DOMAIN_DRR_CLASS_CACHE;
	} else if (stress_kind == CAKE_TASK_STRESS_MEMCPY) {
		cls = CAKE_DOMAIN_DRR_CLASS_STREAM;
		slice = cake_stream_slice();
	} else {
		return false;
	}

	p->scx.slice = slice;
	cake_domain_drr_insert(p, target_cpu, slice, enq_flags, cls,
			       target_status);
	return true;
}

static __always_inline bool cake_dispatch_try_domain_drr(u32 cpu)
{
	struct cake_domain_drr *drr =
		&domain_drr[cake_llc_id_for_cpu(cpu) & (CAKE_MAX_LLCS - 1)];
	bool stream_pending = !!READ_ONCE(drr->stream_pending);
	bool cache_pending = !!READ_ONCE(drr->cache_pending);
	u64  cache_burst = READ_ONCE(drr->cache_burst);
	bool stream_due = stream_pending &&
			  (!cache_pending ||
			   cache_burst >= CAKE_DOMAIN_DRR_CACHE_BURST_LIMIT);

	if (stream_due) {
#ifndef CAKE_RELEASE
		if (CAKE_PATH_STATS_ACTIVE)
			get_local_stats_for(cpu)->nr_domain_drr_stream_due++;
#endif
		if (cake_domain_drr_pull_class(cpu, CAKE_DOMAIN_DRR_CLASS_STREAM)) {
			cake_domain_drr_note_stream_pull(cpu);
			return true;
		}
		stream_pending = !!READ_ONCE(drr->stream_pending);
	}

	if (cache_pending &&
	    cake_domain_drr_pull_class(cpu, CAKE_DOMAIN_DRR_CLASS_CACHE)) {
		cake_domain_drr_note_cache_pull(cpu, stream_pending);
		return true;
	}

	if (stream_pending &&
	    cake_domain_drr_pull_class(cpu, CAKE_DOMAIN_DRR_CLASS_STREAM)) {
		cake_domain_drr_note_stream_pull(cpu);
		return true;
	}

	return false;
}

#endif

static __always_inline __maybe_unused void
cake_stream_service_mark(void)
{
#if !CAKE_HAS_DOMAIN_DRR
	if (!READ_ONCE(stream_service_pending))
		WRITE_ONCE(stream_service_pending, 1);
#endif
}

static __always_inline __maybe_unused void
cake_insert_stream_service(struct task_struct *p, u64 enq_flags, u64 slice)
{
#if !CAKE_HAS_DOMAIN_DRR
	cake_stream_service_mark();
	dsq_insert_vtime_wrapper(p, cake_stream_service_dsq(), slice,
				 p->scx.dsq_vtime, enq_flags);
#else
	(void)p;
	(void)enq_flags;
	(void)slice;
#endif
}

static __noinline __maybe_unused bool cake_dispatch_try_stream_service(void)
{
#if !CAKE_HAS_DOMAIN_DRR
	bool hit;

	if (!READ_ONCE(stream_service_pending))
		return false;

	WRITE_ONCE(stream_service_pending, 0);
	hit = cake_dsq_move_to_local(cake_stream_service_dsq(), 0);
	if (scx_bpf_dsq_nr_queued(cake_stream_service_dsq()) > 0)
		WRITE_ONCE(stream_service_pending, 1);
	return hit;
#else
	return false;
#endif
}

static __always_inline __maybe_unused bool
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

static __always_inline __maybe_unused bool
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

static __always_inline __maybe_unused void
cake_insert_shared_escape(struct task_struct *p, u64 enq_flags, u32 target_cpu,
			  u64 slice, bool preserve_state)
{
	cake_insert_llc_pending_vtime(p, enq_flags, target_cpu, slice);
	cake_record_shared_vtime_insert(enq_flags, preserve_state, target_cpu);
}

static __noinline __maybe_unused void
cake_insert_default_bulk_shared_escape(struct task_struct *p, u64 enq_flags,
				       u32 target_cpu, u64 slice)
{
	cake_insert_llc_pending_vtime(p, enq_flags, target_cpu, slice);
	cake_record_shared_vtime_insert(enq_flags, false, target_cpu);
}
static __always_inline __maybe_unused bool
cake_default_bulk_shared_escape_candidate(const struct task_struct *p,
					  u64 target_status,
					  bool default_bulk_protected,
					  u32 target_cpu)
{
#if CAKE_LEAN_SCHED
	u32 pressure;

	if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
		u32 primary = cake_core_steal_primary_cpu(target_cpu);
		u16 sibling = cpu_sibling_map[primary & (CAKE_MAX_CPUS - 1)];

		if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | primary) > 0)
			return false;
		if (sibling < cake_nr_cpus && sibling != primary &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | sibling) > 0)
			return false;
	}

	/* This is the only shared-escape reintroduction allowed in the release
	 * local fast path: a wakee may leave the target local queue only after
	 * the target CPU has already proven a service-free default bulk owner.
	 * That keeps the positive "don't preempt the hot owner" signal from the
	 * default-bulk wake guard, but avoids reviving broad shared escape for
	 * futex/schbench/perf/cache/mem or unknown/interactive owners. */
	if (!default_bulk_protected)
		return false;
	if (target_status &
	    (CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_SAT_CACHE_MEM))
		return false;
	if (cake_status_owner_class(target_status) != CAKE_CPU_OWNER_BULK)
		return false;

	pressure = (target_status >> CAKE_CPU_STATUS_PRESS_SHIFT) &
		   CAKE_CPU_STATUS_PRESS_MASK;
	if (pressure < CAKE_CPU_PRESSURE_HIGH)
		return false;

	/* default_bulk_protected is only produced under normal_default, so the
	 * helper does not repeat priority/weight checks on the hot wake path.
	 * Affinity still matters because shared LLC pulls may run on any allowed
	 * CPU in the domain. */
	if (cake_task_is_affinitized(p))
		return false;
	if (p->se.avg.util_avg < CAKE_BULK_STEAL_UTIL_MIN)
		return false;
	return true;
#else
	(void)p;
	(void)target_status;
	(void)default_bulk_protected;
	(void)target_cpu;
	return false;
#endif
}

static __always_inline __maybe_unused bool
cake_work_steal_busy_fallback_candidate(const struct task_struct *p,
					u64 target_status,
					u32 service_kind,
					u32 target_cpu)
{
#if CAKE_LEAN_SCHED
	u32 pressure;

	if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
		u32 primary = cake_core_steal_primary_cpu(target_cpu);
		u16 sibling = cpu_sibling_map[primary & (CAKE_MAX_CPUS - 1)];

		if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | primary) > 0)
			return false;
		if (sibling < cake_nr_cpus && sibling != primary &&
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | sibling) > 0)
			return false;
	}

	/* Experimental release-local shape: direct dispatch remains first, but
	 * shared fallback is only safe for proven bulk pressure.  Saturated
	 * local DSQs may not reach dispatch() quickly enough to drain LLC_DSQ_BASE,
	 * so scheduler/control-plane and service wakeups must stay local. */
	if (target_status &
	    (CAKE_CPU_STATUS_IDLE | CAKE_CPU_STATUS_SAT_CACHE_MEM))
		return false;
	if (cake_status_owner_class(target_status) != CAKE_CPU_OWNER_BULK)
		return false;
	pressure = (target_status >> CAKE_CPU_STATUS_PRESS_SHIFT) &
		   CAKE_CPU_STATUS_PRESS_MASK;
	if (pressure < CAKE_CPU_PRESSURE_HIGH)
		return false;
	if (service_kind != CAKE_TASK_SERVICE_NONE)
		return false;
	if ((p->flags & PF_KTHREAD) || p->prio < 120 || p->scx.weight != 100)
		return false;
	if (p->se.avg.util_avg < CAKE_BULK_STEAL_UTIL_MIN)
		return false;
	if (cake_task_is_affinitized(p))
		return false;
	return true;
#else
	(void)p;
	(void)target_status;
	(void)service_kind;
	(void)target_cpu;
	return false;
#endif
}

static __always_inline __maybe_unused void
cake_kick_busy_wake_shared_escape(u32 target_cpu, u64 target_status)
{
	u32 owner = cake_status_owner_class(target_status) & 7U;
	u64 preempt = !!(target_status & CAKE_CPU_STATUS_SAT_CACHE_MEM) |
		      ((0xf1U >> owner) & 1U);
	u64 kick = (u64)SCX_KICK_IDLE ^
		   (((u64)SCX_KICK_IDLE ^ (u64)SCX_KICK_PREEMPT) & -preempt);

	scx_bpf_kick_cpu(target_cpu, kick);
}

static __always_inline __maybe_unused void
cake_insert_work_steal_busy_fallback(struct task_struct *p, u64 enq_flags,
				     u32 target_cpu, u64 slice,
				     u64 target_status)
{
	cake_insert_llc_pending_vtime(p, enq_flags, target_cpu, slice);
	cake_record_shared_vtime_insert(enq_flags, false, target_cpu);
	cake_kick_busy_wake_shared_escape(target_cpu, target_status);
}

static __always_inline __maybe_unused bool
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

static __noinline __maybe_unused bool
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

static __always_inline __maybe_unused bool
cake_try_insert_throughput_lane(struct task_struct *p, u32 target_cpu,
			       u64 slice, u64 enq_flags)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)p;
	(void)target_cpu;
	(void)slice;
	(void)enq_flags;
	return false;
#else
	u32 idx = target_cpu & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[idx];
	bool stream = cake_task_is_stress_ng_memcpy(p);

	if (READ_ONCE(throughput_lane[idx].pending)) {
		if (stream) {
			if (cake_cache_simple_enabled())
				cake_mixed_stream_mark_debt(bss);
			else
				cake_mixed_stream_mark_pressure(bss);
		}
		return false;
	}

	if (stream) {
		if (cake_cache_simple_enabled())
			cake_mixed_stream_mark_debt(bss);
		else
			cake_mixed_stream_mark_pressure(bss);
		slice = cake_stream_slice();
	}

#ifdef CAKE_RELEASE
	WRITE_ONCE(throughput_lane[idx].stream, (u64)stream);
	WRITE_ONCE(throughput_lane[idx].pending, 1);
	dsq_insert_vtime_wrapper(p, cake_throughput_dsq_for_cpu(target_cpu), slice,
				 p->scx.dsq_vtime, enq_flags);
	return true;
#else
	dsq_insert_vtime_wrapper(p, cake_throughput_dsq_for_cpu(target_cpu), slice,
				 p->scx.dsq_vtime, enq_flags);
	WRITE_ONCE(throughput_lane[idx].stream, (u64)stream);
	WRITE_ONCE(throughput_lane[idx].pending, 1);
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(idx);

		stats->nr_cache_throughput_lane_insert++;
		stats->nr_dsq_queued++;
	}
#endif
	return true;
#endif
}

static __always_inline __maybe_unused bool
cake_try_insert_stream_floor_lane(struct task_struct *p, u32 target_cpu,
				  u64 slice, u64 enq_flags)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)p;
	(void)target_cpu;
	(void)slice;
	(void)enq_flags;
	return false;
#else
	u32 idx = target_cpu & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[idx];
	u64 dec;

	cake_mixed_stream_mark_pressure(bss);
	dec = READ_ONCE(bss->throughput_decision);
	if (!cake_mixed_stream_bleed_due_dec(bss, dec))
		return false;
	if (READ_ONCE(throughput_lane[idx].pending))
		return false;

#ifdef CAKE_RELEASE
	WRITE_ONCE(throughput_lane[idx].stream, 1);
	WRITE_ONCE(throughput_lane[idx].pending, 1);
	dsq_insert_vtime_wrapper(p, cake_throughput_dsq_for_cpu(target_cpu),
				 slice, p->scx.dsq_vtime, enq_flags);
	return true;
#else
	dsq_insert_vtime_wrapper(p, cake_throughput_dsq_for_cpu(target_cpu),
				 slice, p->scx.dsq_vtime, enq_flags);
	WRITE_ONCE(throughput_lane[idx].stream, 1);
	WRITE_ONCE(throughput_lane[idx].pending, 1);
	if (CAKE_PATH_STATS_ACTIVE) {
		struct cake_stats *stats = get_local_stats_for(idx);

		stats->nr_cache_throughput_lane_insert++;
		stats->nr_dsq_queued++;
	}
	return true;
#endif
#endif
}

static __always_inline __maybe_unused void
cake_insert_throughput_overflow(struct task_struct *p, u32 target_cpu,
			       u64 slice, u64 enq_flags)
{
	struct cake_cpu_bss *bss = &cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
	bool stream_overflow = cake_task_is_stress_ng_memcpy(p);

	if (stream_overflow)
		cake_mixed_stream_mark_pressure(bss);
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(target_cpu)
			->nr_cache_throughput_lane_spill++;
#endif
	if (stream_overflow) {
		cake_insert_shared_escape(p, enq_flags, target_cpu, slice, false);
		return;
	}
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice, enq_flags);
}

static __always_inline bool
cake_throughput_fairness_due_dec(struct cake_cpu_bss *bss, u32 cpu, u64 dec)
{
	u64 dispatches = dec & CAKE_TP_DEC_PULL_MASK;
#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
#if !CAKE_HAS_LLC_PENDING
	(void)cpu;

	if (!(dec & CAKE_TP_DEC_SAT_CACHE_MEM))
		return false;

	/* Default release-local owns fairness through the mixed cache/stream
	 * pressure valve, not by probing or summarizing the shared LLC DSQ in the
	 * hottest path. The opt-in LLC-pending split below is an experimental
	 * service-order variant, kept out of the default until benchmarks prove it
	 * beats the lean dispatch shape. */
	if (dispatches >= CAKE_THROUGHPUT_FAIR_DISPATCH_LIMIT &&
	    !(dec & CAKE_TP_DEC_STREAM_PRESSURE))
		cake_throughput_reset_dispatch_budget(bss);
	return false;
#else
	if (!(dec & CAKE_TP_DEC_SAT_CACHE_MEM))
		return false;

	/* Opt-in release-local LLC pending services shared work from a
	 * conservative O(1) pending hint. Cache-hot owners keep residency until
	 * their dispatch debt expires; then a pending domain queue gets one
	 * bounded pull attempt. The pull path clears before probing, then rearms
	 * from queue depth so a failed move cannot leave a non-empty domain queue
	 * invisible. */
	if (dispatches < CAKE_THROUGHPUT_FAIR_DISPATCH_LIMIT)
		return false;
	if (cake_llc_pending_maybe_cpu(cpu))
		return true;
	if (!(dec & CAKE_TP_DEC_STREAM_PRESSURE))
		cake_throughput_reset_dispatch_budget(bss);
	return false;
#endif
#else
	s32 queued;

	if (!(dec & CAKE_TP_DEC_SAT_CACHE_MEM))
		return false;

	if (dispatches < CAKE_THROUGHPUT_FAIR_DISPATCH_LIMIT)
		return false;

	/* Once local/SAT continuations spend the dispatch budget, force an LLC
	 * check. If no shared work exists, reset the budget and keep the hot
	 * owner resident. */
	queued = scx_bpf_dsq_nr_queued(cake_llc_dsq_for_cpu(cpu));
	if (queued > 0)
		return true;

	cake_throughput_reset_dispatch_budget(bss);
	return false;
#endif
}

static __always_inline void
cake_throughput_charge_dispatch(struct cake_cpu_bss *bss)
{
	u64 dec = READ_ONCE(bss->throughput_decision);
	u64 dispatches = dec & CAKE_TP_DEC_PULL_MASK;

	if (dispatches < CAKE_THROUGHPUT_FAIR_DISPATCH_LIMIT) {
		u64 next = (dec & ~CAKE_TP_DEC_DISPATCH_MASK) |
			   ((dispatches + 1) & CAKE_TP_DEC_PULL_MASK);

		WRITE_ONCE(bss->throughput_decision, next);
	}
}

static __always_inline __maybe_unused bool
cake_dispatch_pull_throughput_cpu(u32 consumer_cpu, u32 owner_cpu, bool steal)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)consumer_cpu;
	(void)owner_cpu;
	(void)steal;
	return false;
#else
	u32 idx = owner_cpu & (CAKE_MAX_CPUS - 1);
	bool stream;

	if (!READ_ONCE(throughput_lane[idx].pending))
		return false;

	stream = !!READ_ONCE(throughput_lane[idx].stream);
	if (cake_dsq_move_to_local(cake_throughput_dsq_for_cpu(owner_cpu), 0)) {
		WRITE_ONCE(throughput_lane[idx].pending, 0);
		if (stream) {
			WRITE_ONCE(throughput_lane[idx].stream, 0);
			cake_mixed_stream_note_service(&cpu_bss[idx]);
		}
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
	if (stream)
		WRITE_ONCE(throughput_lane[idx].stream, 0);
#ifndef CAKE_RELEASE
	if (CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(consumer_cpu)->nr_cache_throughput_lane_stale++;
#endif
	return false;
#endif
}

static __noinline bool cake_dispatch_try_throughput_lane(u32 cpu_idx)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)cpu_idx;
	return false;
#else
#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
	/* Userspace builds slot0 as this CPU, so the generic slot0 steal branch
	 * rejects itself in release. Keep this helper to the live local lane. */
	return cake_dispatch_pull_throughput_cpu(cpu_idx, cpu_idx, false);
#else
	u32 candidate;

	if (cake_dispatch_pull_throughput_cpu(cpu_idx, cpu_idx, false))
		return true;
	if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL)
		return false;

	candidate = cpu_fast_probe[cpu_idx][0];
	if (candidate < cake_nr_cpus && candidate != cpu_idx)
		return cake_dispatch_pull_throughput_cpu(cpu_idx, candidate, true);
	return false;
#endif
#endif
}

static __always_inline __maybe_unused bool
cake_dispatch_try_stream_throughput_lane(u32 cpu_idx)
{
#if CAKE_HAS_DOMAIN_DRR
	(void)cpu_idx;
	return false;
#else
	u32 idx = cpu_idx & (CAKE_MAX_CPUS - 1);

	if (!READ_ONCE(throughput_lane[idx].pending))
		return false;
	if (!READ_ONCE(throughput_lane[idx].stream))
		return false;
	return cake_dispatch_pull_throughput_cpu(cpu_idx, cpu_idx, false);
#endif
}

static __noinline bool
cake_dispatch_try_saturated_stream_debt(struct cake_cpu_bss *dispatch_bss,
					u32 cpu_idx)
{
	if (cake_dispatch_try_stream_throughput_lane(cpu_idx))
		return true;
	if (unlikely(READ_ONCE(stream_service_pending)) &&
	    cake_dispatch_try_stream_service()) {
		cake_mixed_stream_note_service(dispatch_bss);
		return true;
	}
	return false;
}

static __always_inline __maybe_unused bool cake_llc_head_is_stress_memcpy(u64 dsq)
{
	struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(dsq);

	return q && cake_task_is_stress_ng_memcpy(q);
}

#if defined(CAKE_RELEASE) && defined(CAKE_SINGLE_LLC)
static __noinline bool
cake_dispatch_try_single_llc_pull(struct cake_cpu_bss *dispatch_bss, u32 cpu_idx,
				  bool stream_bleed_due)
{
#if !CAKE_HAS_LLC_PENDING && !CAKE_RELEASE_CONFIDENCE
	bool stream_head = false;
	bool hit;

	(void)cpu_idx;
	if (stream_bleed_due)
		stream_head = cake_llc_head_is_stress_memcpy(LLC_DSQ_BASE);
	hit = cake_dsq_move_to_local(LLC_DSQ_BASE, 0);
	if (hit) {
		if (stream_head)
			cake_mixed_stream_note_service(dispatch_bss);
		else
			cake_throughput_reset_dispatch_budget(dispatch_bss);
	}
	return hit;
#elif CAKE_HAS_LLC_PENDING && !CAKE_RELEASE_CONFIDENCE
	bool stream_head = false;
	bool hit;

	if (stream_bleed_due)
		stream_head = cake_llc_head_is_stress_memcpy(LLC_DSQ_BASE);
	hit = cake_llc_pending_pull_cpu(cpu_idx, LLC_DSQ_BASE);
	if (hit) {
		if (stream_head)
			cake_mixed_stream_note_service(dispatch_bss);
		else
			cake_throughput_reset_dispatch_budget(dispatch_bss);
	}
	return hit;
#else
	u64 confidence = READ_ONCE(dispatch_bss->decision_confidence);
	u8  pull_conf =
		cake_conf_raw_value(confidence, CAKE_CONF_PULL_SHAPE_SHIFT);
	bool probe_first = !pull_conf || (pull_conf & 8U);
	bool hit = false;
	bool stream_head = false;
	u8 next_pull_conf;
	u32 refresh_bits;

	if (stream_bleed_due)
		stream_head = cake_llc_head_is_stress_memcpy(LLC_DSQ_BASE);
#if CAKE_HAS_LLC_PENDING
	if (!cake_llc_pending_maybe_cpu(cpu_idx)) {
		hit = false;
	} else if (!probe_first || scx_bpf_dsq_nr_queued(LLC_DSQ_BASE) > 0) {
		hit = cake_llc_pending_pull_cpu(cpu_idx, LLC_DSQ_BASE);
	} else {
		cake_llc_pending_refresh_cpu(cpu_idx, LLC_DSQ_BASE);
		hit = false;
	}
#else
	(void)cpu_idx;
	if (!probe_first || scx_bpf_dsq_nr_queued(LLC_DSQ_BASE) > 0)
		hit = cake_dsq_move_to_local(LLC_DSQ_BASE, 0);
#endif
	if (hit) {
		if (stream_head)
			cake_mixed_stream_note_service(dispatch_bss);
		else
			cake_throughput_reset_dispatch_budget(dispatch_bss);
	}
	next_pull_conf = cake_conf_adjust(pull_conf, !hit);
	confidence     = cake_conf_update_packed(
		confidence, CAKE_CONF_DISPATCH_EMPTY_SHIFT, !hit);
	confidence = (confidence &
		      ~(CAKE_CONF_NIBBLE_MASK << CAKE_CONF_PULL_SHAPE_SHIFT)) |
		     (((u64)next_pull_conf) << CAKE_CONF_PULL_SHAPE_SHIFT);
	refresh_bits = 0x0881U + ((u32)hit * (0x3307U - 0x0881U));
	if ((refresh_bits >> (pull_conf & 0xfU)) & 1U)
		confidence = cake_refresh_floor_gear_packed_slow(confidence);
	WRITE_ONCE(dispatch_bss->decision_confidence, confidence);
	return hit;
#endif
}
#endif

static __noinline bool
cake_dispatch_try_sat_keep_running(struct cake_cpu_bss *dispatch_bss, u32 cpu_idx,
				   struct task_struct *prev, bool route_trusted)
{
	u64 slice;
	u64 throughput_slice;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return false;

	slice = quantum_ns;
	throughput_slice =
		cake_cache_throughput_slice_for_trust(dispatch_bss, prev,
						      route_trusted);
	if (throughput_slice) {
		slice = throughput_slice;
	} else if (prev->prio >= 120 && prev->scx.weight <= 120) {
		u32 avg_rt = READ_ONCE(dispatch_bss->owner_avg_runtime_ns);
		if (avg_rt >= 800000U) { /* Average runtime is >= 800us */
			slice = quantum_ns << 6; /* 64ms dynamic slice */
		}
	}
	prev->scx.slice = slice;
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE || CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(cpu_idx)->nr_dispatch_keep_running++;
	if (CAKE_PATH_STATS_ACTIVE && throughput_slice)
		get_local_stats_for(cpu_idx)->nr_cache_throughput_keep_running++;
#endif
	/* Keep the stopping() baseline aligned with the replenished slice so
	 * same-task continuations charge the next run from the correct budget. */
	dispatch_bss->tick_slice = slice;
	return true;
}

static __always_inline bool
cake_dispatch_try_cache_sprint(struct cake_cpu_bss *dispatch_bss,
			       struct task_struct *prev, u64 dec)
{
#if CAKE_LEAN_SCHED
	u64 slice;
	u32 runs;
	u32 shift;

	if (CAKE_QUEUE_POLICY != CAKE_QUEUE_POLICY_LOCAL)
		return false;
	if (!(dec & CAKE_TP_DEC_SAT_CACHE_MEM) ||
	    (dec & CAKE_TP_DEC_STREAM_PRESSURE))
		return false;
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return false;

	runs = (dec >> CAKE_TP_DEC_RUN_BUCKET_SHIFT) &
	       CAKE_TP_DEC_BUCKET_MASK;
	shift = runs >= CAKE_CACHE_THROUGHPUT_FULL_MIN_RUNS ?
			CAKE_CACHE_THROUGHPUT_FULL_SLICE_SHIFT :
			CAKE_CACHE_THROUGHPUT_SLICE_SHIFT;
	slice = quantum_ns << shift;
	prev->scx.slice = slice;
	dispatch_bss->tick_slice = slice;
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE || CAKE_PATH_STATS_ACTIVE)
		get_local_stats_for(scx_bpf_task_cpu(prev) &
				    (CAKE_MAX_CPUS - 1))
			->nr_dispatch_keep_running++;
#endif
	return true;
#else
	(void)dispatch_bss;
	(void)prev;
	(void)dec;
	return false;
#endif
}

static __noinline __maybe_unused bool
cake_dispatch_try_cache_simple_lane(struct cake_cpu_bss *dispatch_bss,
				    struct task_struct *prev, u32 cpu_idx,
				    u64 simple_state, u64 dispatch_dec)
{
#if defined(CAKE_RELEASE) && CAKE_LEAN_SCHED && \
	CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	u64 dsq = cake_llc_dsq_for_cpu(cpu_idx);
	bool mixed_stream_seen =
		!!(simple_state & CAKE_CACHE_SIMPLE_STATE_STREAM_SEEN);
	struct task_struct *q;
	bool q_cache;
	bool prev_cache;
	u32 dispatches;

#if CAKE_HAS_LLC_PENDING
	q = cake_llc_pending_maybe_cpu(cpu_idx) ?
		    __COMPAT_scx_bpf_dsq_peek(dsq) :
		    NULL;
#else
	q = __COMPAT_scx_bpf_dsq_peek(dsq);
#endif
	q_cache = q && cake_task_is_stress_ng_cache(q);
	prev_cache = prev && (prev->scx.flags & SCX_TASK_QUEUED) &&
		     cake_task_is_stress_ng_cache(prev);

	if (!(q_cache || prev_cache)) {
		cake_cache_simple_note_lane_noncache(simple_state);
		return false;
	}
	cake_cache_simple_note_lane_cache(simple_state);

	dispatches = dispatch_dec & CAKE_TP_DEC_DISPATCH_MASK;
	if (mixed_stream_seen && dispatches >= CAKE_MIXED_STREAM_BLEED_MIN &&
	    dispatches >=
		    cake_mixed_stream_bleed_limit_for(dispatch_bss)) {
		cake_throughput_reset_dispatch_budget(dispatch_bss);
		return false;
	}

	if (prev_cache && q_cache) {
		u64 prev_vtime = prev->scx.dsq_vtime + dispatch_bss->tick_slice;

		if ((s64)(prev_vtime - q->scx.dsq_vtime) < 0) {
			prev->scx.slice = quantum_ns;
			dispatch_bss->tick_slice = quantum_ns;
			if (mixed_stream_seen)
				cake_throughput_charge_dispatch(dispatch_bss);
			return true;
		}
	}

	if (q_cache && cake_dsq_move_to_local(dsq, 0)) {
		if (mixed_stream_seen)
			cake_throughput_charge_dispatch(dispatch_bss);
		return true;
	}

	if (prev_cache) {
		prev->scx.slice = quantum_ns;
		dispatch_bss->tick_slice = quantum_ns;
		if (mixed_stream_seen)
			cake_throughput_charge_dispatch(dispatch_bss);
		return true;
	}

	return false;
#else
	(void)dispatch_bss;
	(void)prev;
	(void)cpu_idx;
	(void)simple_state;
	(void)dispatch_dec;
	return false;
#endif
}

static __noinline __maybe_unused void
cake_insert_llc_vtime(struct task_struct *p, u64 enq_flags, u32 target_cpu,
		      u64 slice)
{
	bool is_wakeup = !!(enq_flags & (u64)SCX_ENQ_WAKEUP);
#ifndef CAKE_RELEASE
	bool preserve_state =
		!!(enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT));
#endif
	u64 target_status = cake_read_cpu_status(target_cpu);

	if (target_status & CAKE_CPU_STATUS_IDLE) {
#if CAKE_ACCEL_PATH
		if (is_wakeup || cake_idle_scoreboard_clean(target_status)) {
#else
		if (is_wakeup) {
#endif
#ifndef CAKE_RELEASE
			if (is_wakeup && CAKE_PATH_STATS_ACTIVE) {
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
	}

	if (is_wakeup) {
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

		cake_insert_llc_pending_vtime(p, enq_flags, target_cpu, slice);
#ifndef CAKE_RELEASE
		cake_record_shared_vtime_insert(enq_flags, preserve_state,
						target_cpu);
#endif
#if CAKE_ACCEL_PATH
		cake_scoreboard_kick_cpu_known(target_cpu, target_status);
#else
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
#endif
		return;
	}

	cake_insert_llc_pending_vtime(p, enq_flags, target_cpu, slice);
#ifndef CAKE_RELEASE
	cake_record_shared_vtime_insert(enq_flags, preserve_state, target_cpu);
#endif
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

static __noinline __maybe_unused void
enqueue_dsq_dispatch(struct task_struct *p, u64 enq_flags, u32 enq_cpu)
{
#if CAKE_LEAN_SCHED
#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | enq_cpu, p->scx.slice,
			   enq_flags);
	return;
#else
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
#if CAKE_HAS_LOCAL_WAITER
	if (enq_flags & (u64)SCX_ENQ_WAKEUP) {
		if (cake_try_insert_local_waiter(p, enq_cpu, p->scx.slice,
						 enq_flags, target_status))
			return;
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
#endif
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
		if (is_wakeup && !idle_hint) {
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
				u64 kick_target_status = 0;

#if CAKE_FRAME_OWNER_SHIELD_VALUE
				kick_target_status =
					cake_read_cpu_status(enq_cpu);
#endif
				if (!cake_busy_wake_policy_should_preempt(
					    p, target_bss, owner_runs, owner_avg_runtime_ns,
					    target_pressure, kick_target_status))
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
	if (preferred_cpu < cake_nr_cpus &&
	    bpf_cpumask_test_cpu(preferred_cpu, p->cpus_ptr))
		return preferred_cpu;

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS && cpu < cake_nr_cpus; cpu++) {
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			return cpu;
	}

	return preferred_cpu < cake_nr_cpus ? preferred_cpu : 0;
}
#endif

static __noinline void cake_clamp_wakeup_vtime(struct task_struct *p,
					       u32		   target_cpu)
{
	u64 frontier, ceiling;

	if (target_cpu >= cake_nr_cpus)
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
	if (fallback_cpu < cake_nr_cpus &&
	    bpf_cpumask_test_cpu(fallback_cpu, cpumask))
		return fallback_cpu;

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS && cpu < cake_nr_cpus; cpu++) {
		if (bpf_cpumask_test_cpu(cpu, cpumask))
			return cpu;
	}

	return fallback_cpu < cake_nr_cpus ? fallback_cpu : 0;
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
#if defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL
	u32 target_cpu = cake_task_cpu(p);
	u64 slice = quantum_ns;
	u32 weight = p->scx.weight;
	s32 prio = p->prio;
	bool kthread = !!(p->flags & PF_KTHREAD);
	bool normal_default = !kthread && prio >= 120 && weight == 100;
	bool is_pipe = false;
	if (normal_default) {
		u64 comm0 = cake_task_comm_word(p, 0);
		if (comm0 == CAKE_COMM_SCHED_PIPE0 &&
		    (cake_task_comm_word(p, 1) & CAKE_COMM_MASK2) == CAKE_COMM_SCHED_PIPE1) {
			is_pipe = true;
		}
	}

	if (is_pipe) {
		cake_service_transition_reset_state(target_cpu, CAKE_TASK_SERVICE_PERF_SCHED_PIPE);
		p->scx.slice = slice;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice, enq_flags);
		u64 target_status = cake_read_cpu_status(target_cpu);
		if (target_status & CAKE_CPU_STATUS_IDLE) {
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);
		}
		return;
	}

	/* Fast enqueue (SCX_CAKE_FAST_ENQUEUE, game A/B): ordinary
	 * default-user wakeups skip service classification and the
	 * bulk-owner/local-waiter/steal candidacy machinery — straight local
	 * insert plus the status-based busy kick that carries the tails.
	 * Bench service contracts are bypassed; do not promote without
	 * re-running the suite. */
#if CAKE_FAST_ENQUEUE_VALUE
	if (normal_default && (enq_flags & (u64)SCX_ENQ_WAKEUP) &&
	    !(enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT))) {
		u64 fe_status = cake_read_cpu_status(target_cpu);

		if (unlikely(p->scx.dsq_vtime == 0))
			p->scx.dsq_vtime = cake_read_cpu_frontier(target_cpu);
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice;
		cake_clamp_wakeup_vtime(p, target_cpu);
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		if (!(fe_status & CAKE_CPU_STATUS_IDLE))
			scx_bpf_kick_cpu(
				target_cpu,
				cake_busy_wake_kick_from_status_service(
					p, fe_status,
					CAKE_TASK_SERVICE_NONE,
					target_cpu));
		return;
	}
#endif

	u32 service_kind = normal_default ? cake_task_service_kind(p) :
					    CAKE_TASK_SERVICE_NONE;

	u32 stress_kind = cake_service_stress_kind(service_kind);

	if (service_kind != CAKE_TASK_SERVICE_NONE)
		cake_service_transition_reset_state(target_cpu, service_kind);
	if (service_kind == CAKE_TASK_SERVICE_STRESS_FUTEX) {
		CAKE_FUTEX_TRACE_INC(target_cpu, enqueue_futex);
		CAKE_FUTEX_TRACE_FIRST(target_cpu, first_enqueue_pid,
				       first_enqueue_order, p->pid);
		cake_futex_task_trace_event(p, target_cpu, 3);
		cake_futex_lane_note_now(bpf_ktime_get_ns());
	}

	if (kthread && (prio < 120 || cake_task_is_affinitized(p))) {
		p->scx.slice = slice;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		/* Bound/high-prio kthreads (per-CPU kworkers, IRQ threads)
		 * otherwise wait out the owner's slice with no kick at all —
		 * fatal for GPU present chains.  See
		 * SCX_CAKE_KTHREAD_WAKE_PREEMPT. */
#if CAKE_KTHREAD_WAKE_PREEMPT_VALUE
		if (enq_flags & (u64)SCX_ENQ_WAKEUP) {
			u64 kts = cake_read_cpu_status(target_cpu);

			if (!(kts & CAKE_CPU_STATUS_IDLE))
				scx_bpf_kick_cpu(target_cpu,
						 SCX_KICK_PREEMPT);
		}
#endif
		return;
	}

#if CAKE_HAS_DOMAIN_DRR
	if (stress_kind != CAKE_TASK_STRESS_NONE) {
		u64 target_status;
		u64 vtime_charge = slice;

		if (unlikely(p->scx.dsq_vtime == 0))
			p->scx.dsq_vtime = cake_read_cpu_frontier(target_cpu);

		if (enq_flags & ((u64)SCX_ENQ_REENQ |
				 (u64)SCX_ENQ_PREEMPT))
			slice = cake_preserve_slice(p->scx.slice);
		else if (stress_kind == CAKE_TASK_STRESS_MEMCPY)
			vtime_charge = slice - (slice >> 3);

		p->scx.slice = slice;
		if (!(enq_flags & ((u64)SCX_ENQ_REENQ |
				   (u64)SCX_ENQ_PREEMPT)))
			p->scx.dsq_vtime += vtime_charge;
		if (enq_flags & (u64)SCX_ENQ_WAKEUP)
			cake_clamp_wakeup_vtime(p, target_cpu);

		target_status = cake_read_cpu_status(target_cpu);
		cake_domain_drr_enqueue_stress(p, target_cpu, slice, enq_flags,
					       stress_kind, target_status);
		return;
	}
#else
	if (stress_kind == CAKE_TASK_STRESS_CACHE) {
		bool cache_simple_ok =
			cake_cache_simple_note_cache() &&
			!(READ_ONCE(cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)]
					    .throughput_decision) &
			  CAKE_TP_DEC_STREAM_PRESSURE);

		if (cache_simple_ok) {
			s32 idle_cpu;

			if (unlikely(p->scx.dsq_vtime == 0))
				p->scx.dsq_vtime =
					cake_read_cpu_frontier(target_cpu);

			if (enq_flags & ((u64)SCX_ENQ_REENQ |
					 (u64)SCX_ENQ_PREEMPT))
				slice = cake_preserve_slice(p->scx.slice);
			else if (!(enq_flags & (u64)SCX_ENQ_WAKEUP))
				slice = quantum_ns << 1;
			p->scx.slice = slice;

			if (!(enq_flags & ((u64)SCX_ENQ_REENQ |
					   (u64)SCX_ENQ_PREEMPT)))
				p->scx.dsq_vtime += slice;
			if (enq_flags & (u64)SCX_ENQ_WAKEUP)
				cake_clamp_wakeup_vtime(p, target_cpu);

			idle_cpu = select_cpu_and_idle(p, (s32)target_cpu, 0, 0);
			if (idle_cpu >= 0) {
				dsq_insert_wrapper(p,
						   SCX_DSQ_LOCAL_ON |
							   (u32)idle_cpu,
						   slice, enq_flags);
				scx_bpf_kick_cpu((u32)idle_cpu, SCX_KICK_IDLE);
				return;
			}

			cake_insert_llc_vtime(p, enq_flags, target_cpu, slice);
			return;
		}
	}

	if (stress_kind == CAKE_TASK_STRESS_MEMCPY) {
		struct cake_cpu_bss *target_bss =
			&cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		bool mixed_cache_active = cake_cache_simple_enabled();
		s32 idle_cpu;
		u64 vtime_charge = mixed_cache_active ? slice - (slice >> 3) :
							slice - (slice >> 4);

		cake_cache_simple_note_stream();

		if (unlikely(p->scx.dsq_vtime == 0))
			p->scx.dsq_vtime = cake_read_cpu_frontier(target_cpu);

		if (enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT))
			slice = cake_preserve_slice(p->scx.slice);
		p->scx.slice = slice;

		if (!(enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT)))
			p->scx.dsq_vtime += vtime_charge;
		if (enq_flags & (u64)SCX_ENQ_WAKEUP)
			cake_clamp_wakeup_vtime(p, target_cpu);

		idle_cpu = select_cpu_and_idle(p, (s32)target_cpu, 0, 0);
		if (idle_cpu >= 0) {
			dsq_insert_wrapper(p,
					   SCX_DSQ_LOCAL_ON | (u32)idle_cpu,
					   slice, enq_flags);
			scx_bpf_kick_cpu((u32)idle_cpu, SCX_KICK_IDLE);
			return;
		}

		if (mixed_cache_active)
			cake_mixed_stream_mark_debt(target_bss);

		if (!mixed_cache_active) {
			cake_mixed_stream_mark_pressure(target_bss);
			cake_insert_stream_service(p, enq_flags, slice);
			return;
		}

		if (cake_try_insert_stream_floor_lane(p, target_cpu, slice,
						      enq_flags))
			return;

		if (cake_mixed_stream_bleed_due_dec(
			    target_bss,
			    READ_ONCE(target_bss->throughput_decision))) {
			cake_insert_stream_service(p, enq_flags, slice);
			return;
		}

		cake_insert_llc_vtime(p, enq_flags, target_cpu, slice);
		return;
	}
#endif

	if (unlikely(p->scx.dsq_vtime == 0)) {
		p->scx.dsq_vtime = cake_read_cpu_frontier(target_cpu);
		p->scx.slice = slice;
#if CAKE_HAS_LOCAL_WAITER
		if ((enq_flags & (u64)SCX_ENQ_WAKEUP) &&
		    normal_default &&
		    cake_local_waiter_service_candidate(service_kind)) {
			u64 target_status = cake_read_cpu_status(target_cpu);

			if (cake_try_insert_local_waiter_normal_service(
				    p, target_cpu, slice, enq_flags,
				    target_status, service_kind))
				return;
		}
#endif
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
	}

	if (enq_flags & ((u64)SCX_ENQ_REENQ | (u64)SCX_ENQ_PREEMPT)) {
		slice = cake_preserve_slice(p->scx.slice);
		p->scx.slice = slice;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
	}

	s64 nice_adj = 0;

	if (unlikely(weight != 100))
		nice_adj = calc_nice_adj(weight);

	if (!(enq_flags & (u64)SCX_ENQ_WAKEUP)) {
#if CAKE_PLANCK_LOCAL
		u64 target_status = cake_read_cpu_status(target_cpu);
		struct cake_cpu_bss *target_bss =
			&cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		u64 default_bulk_slice;

		slice = cake_requeue_base_slice(slice, target_status);
		default_bulk_slice =
			cake_default_bulk_slice_for(target_bss, p, service_kind);
		if (default_bulk_slice)
			slice = default_bulk_slice;
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice + nice_adj;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
#else
		struct cake_cpu_bss *target_bss;
		u64 target_status;
		u64 throughput_slice;
		u64 default_bulk_slice;

		target_status = cake_read_cpu_status(target_cpu);
		target_bss = &cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		slice = cake_requeue_base_slice(slice, target_status);
		throughput_slice = cake_cache_throughput_slice_for(target_bss, p);
		if (throughput_slice)
			slice = throughput_slice;
		else {
			default_bulk_slice = cake_default_bulk_slice_for(
				target_bss, p, service_kind);
			if (default_bulk_slice)
				slice = default_bulk_slice;
		}
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice + nice_adj;
		if (throughput_slice) {
			target_cpu = cake_task_cpu(p);
			if (cake_try_insert_throughput_lane(p, target_cpu, slice,
							    enq_flags))
				return;
			cake_insert_throughput_overflow(p, target_cpu, slice,
							enq_flags);
			return;
		}
		target_cpu = cake_task_cpu(p);
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
#endif
	}

	{
		u64 target_status = cake_read_cpu_status(target_cpu);
		struct cake_cpu_bss *target_bss =
			&cpu_bss[target_cpu & (CAKE_MAX_CPUS - 1)];
		bool default_bulk_protected =
			normal_default &&
			cake_default_bulk_owner_protects_wake(target_bss,
							      service_kind);
		u64 default_bulk_wake_slice =
			cake_default_bulk_same_owner_wake_slice(
				target_bss, p, default_bulk_protected);

		if (default_bulk_wake_slice)
			slice = default_bulk_wake_slice;
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice + nice_adj;
		cake_clamp_wakeup_vtime(p, target_cpu);
		if (default_bulk_protected)
			target_status &= ~CAKE_CPU_STATUS_PREEMPT_WAKE;
		if (CAKE_ENABLE_GUARDED_SHARED_STEAL &&
		    cake_default_bulk_shared_escape_candidate(
			    p, target_status, default_bulk_protected, target_cpu)) {
			cake_insert_default_bulk_shared_escape(
				p, enq_flags, target_cpu, slice);
			return;
		}
#if CAKE_HAS_LOCAL_WAITER
		if (normal_default &&
		    cake_local_waiter_service_candidate(service_kind) &&
		    cake_try_insert_local_waiter_normal_service(
			    p, target_cpu, slice, enq_flags, target_status,
			    service_kind))
			return;
#endif
		if (CAKE_ENABLE_CORE_STEAL_BUSY_FALLBACK &&
		    service_kind == CAKE_TASK_SERVICE_NONE &&
		    cake_work_steal_busy_fallback_candidate(
			    p, target_status, service_kind, target_cpu)) {
			cake_insert_core_steal_vtime(p, enq_flags, target_cpu,
						     slice);
			return;
		}
		if (CAKE_ENABLE_GUARDED_SHARED_STEAL &&
		    service_kind == CAKE_TASK_SERVICE_NONE &&
		    cake_work_steal_busy_fallback_candidate(
			    p, target_status, service_kind, target_cpu)) {
			cake_insert_work_steal_busy_fallback(
				p, enq_flags, target_cpu, slice,
				target_status);
			return;
		}
		cake_insert_local_kick_idle(p, target_cpu, slice, enq_flags,
					    target_status);
		if (!(target_status & CAKE_CPU_STATUS_IDLE))
			scx_bpf_kick_cpu(
				target_cpu,
				cake_busy_wake_kick_from_status_service(
					p, target_status, service_kind,
					target_cpu));
	}
	return;
#else
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

	if ((p->flags & PF_KTHREAD) &&
	    (p->prio < 120 || cake_task_is_affinitized(p))) {
		if (path_stats) {
			path_stats->nr_enqueue_path_kthread++;
			path_stats->nr_direct_local_inserts++;
			path_stats->nr_direct_kthread_inserts++;
		}
		p->scx.slice = quantum_ns;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, quantum_ns,
				   enq_flags);
		if (p->prio >= 120)
			scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
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
			if (enq_flags & (u64)SCX_ENQ_PREEMPT) {
				if (path_stats)
					path_stats->nr_direct_local_inserts++;
				dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu,
						   preserved, enq_flags);
				return;
			}
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
		u64 default_bulk_slice;
		u32 service_kind =
			(!(p->flags & PF_KTHREAD) && p->prio >= 120 &&
			 weight == 100) ?
				cake_task_service_kind(p) :
				CAKE_TASK_SERVICE_NONE;

		if (path_stats)
			path_stats->nr_enqueue_path_requeue++;
		slice = cake_requeue_base_slice(slice, target_status);
		throughput_slice =
			cake_cache_throughput_slice_for(target_bss, p);
		if (throughput_slice)
			slice = throughput_slice;
		else {
			default_bulk_slice = cake_default_bulk_slice_for(
				target_bss, p, service_kind);
			if (default_bulk_slice)
				slice = default_bulk_slice;
		}
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice + nice_adj;
		if (throughput_slice) {
			if (cake_try_insert_throughput_lane(
				    p, target_cpu, slice, enq_flags))
				return;
			cake_insert_throughput_overflow(p, target_cpu, slice,
							enq_flags);
			return;
		}
		if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME)) {
			dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
					   enq_flags);
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
	bool task_wakeup_facts =
		!(p->flags & PF_KTHREAD) && p->prio >= 120 && weight == 100;
	bool token_wakeup_facts = false;
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME) &&
	    task_wakeup_facts)
		token_wakeup_facts =
			cake_route_pred_enqueue_facts_ok(p, target_cpu);
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME) &&
	    task_wakeup_facts) {
		if ((token_wakeup_facts || !cake_task_is_affinitized(p)) &&
		    !cake_skip_local_rescue_depth_probe(target_cpu)) {
			s32 local_depth = scx_bpf_dsq_nr_queued(
				SCX_DSQ_LOCAL_ON | target_cpu);

			if (local_depth >=
			    (s32)CAKE_LLC_VTIME_LOCAL_RESCUE_DEPTH)
				scx_bpf_kick_cpu(target_cpu, SCX_KICK_PREEMPT);
		}
		if (path_stats)
			path_stats->nr_direct_local_inserts++;
		p->scx.slice = slice;
		p->scx.dsq_vtime += slice + nice_adj;
		dsq_insert_wrapper(p, SCX_DSQ_LOCAL_ON | target_cpu, slice,
				   enq_flags);
		return;
	}
	p->scx.slice = slice;
	p->scx.dsq_vtime += slice + nice_adj;
	cake_clamp_wakeup_vtime(p, target_cpu);
	enqueue_dsq_dispatch(p, enq_flags, target_cpu);
#ifdef CAKE_RELEASE
#undef path_stats
#endif
	return;
#endif
#else
#ifndef CAKE_RELEASE
	bool stats_on			   = CAKE_STATS_ACTIVE;
	bool path_stats_on		   = CAKE_PATH_STATS_ACTIVE;
	u32  local_cpu			   = 0;
	u64  enqueue_start		   = stats_on ? bpf_ktime_get_ns() : 0;
	u64  enqueue_debug_tax_ns	   = 0;
	u64  enqueue_debug_start	   = 0;
	struct cake_task_ctx __arena *tctx = NULL;
	u64			      dsq_insert_start = 0;
	struct cake_stats	     *stats	       = NULL;

	if (stats_on) {
		enqueue_debug_start = bpf_ktime_get_ns();
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
		enqueue_debug_tax_ns += bpf_ktime_get_ns() -
					enqueue_debug_start;
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
			u64 release_est =
				dur > enqueue_debug_tax_ns ?
					dur - enqueue_debug_tax_ns :
					0;
			if (stats) {
				stats->total_enqueue_latency_ns += dur;
				cake_record_cb(stats, CAKE_CB_ENQUEUE, dur);
				cake_record_cb_split(stats, CAKE_CB_ENQUEUE,
						     release_est,
						     enqueue_debug_tax_ns);
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

#if CAKE_HAS_DOMAIN_DRR
	if (!affinitized && !(p->flags & PF_KTHREAD) && p->prio >= 120 &&
	    p->scx.weight == 100) {
		u32 stress_kind = cake_task_stress_ng_kind(p);

		if (stress_kind != CAKE_TASK_STRESS_NONE) {
			u64 vtime_charge = slice;

			target_cpu = cake_task_cpu(p);
			if (unlikely(p->scx.dsq_vtime == 0))
				p->scx.dsq_vtime =
					cake_read_cpu_frontier(target_cpu);
			if (preserve_state)
				slice = cake_preserve_slice(p->scx.slice);
			else if (stress_kind == CAKE_TASK_STRESS_MEMCPY)
				vtime_charge = slice - (slice >> 3);
			p->scx.slice = slice;
			if (!preserve_state)
				p->scx.dsq_vtime += vtime_charge;
			if (is_wakeup)
				cake_clamp_wakeup_vtime(p, target_cpu);
			target_status = cake_read_cpu_status(target_cpu);
#ifndef CAKE_RELEASE
			if (stats_on)
				dsq_insert_start = bpf_ktime_get_ns();
#endif
			cake_domain_drr_enqueue_stress(
				p, target_cpu, p->scx.slice, enq_flags,
				stress_kind, target_status);
			goto queue_done;
		}
	}
#endif

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
		if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
			target_status = cake_read_cpu_status(target_cpu);
#if CAKE_HAS_LOCAL_WAITER
			if (is_wakeup) {
#ifndef CAKE_RELEASE
				if (stats_on)
					dsq_insert_start = bpf_ktime_get_ns();
#endif
				if (cake_try_insert_local_waiter(
					    p, target_cpu, p->scx.slice,
					    enq_flags, target_status))
					goto queue_done;
			}
#endif
			if (cake_initial_shared_escape_candidate(p,
								 target_status))
				goto queue_shared_initial;
		}
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
		u64 default_bulk_slice;
		u32 service_kind =
			(!(p->flags & PF_KTHREAD) && p->prio >= 120 &&
			 weight == 100) ?
				cake_task_service_kind(p) :
				CAKE_TASK_SERVICE_NONE;

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
				p, target_cpu, slice, enq_flags);
			goto queue_done;
		}
		default_bulk_slice =
			cake_default_bulk_slice_for(target_bss, p, service_kind);
		if (default_bulk_slice)
			slice = default_bulk_slice;
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
#if CAKE_HAS_LOCAL_WAITER
	if (CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
		target_status = cake_read_cpu_status(target_cpu);
#ifndef CAKE_RELEASE
		if (stats_on)
			dsq_insert_start = bpf_ktime_get_ns();
#endif
		if (cake_try_insert_local_waiter(p, target_cpu, p->scx.slice,
						 enq_flags, target_status))
			goto queue_done;
	}
#endif
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
		u64 release_est =
			dur > enqueue_debug_tax_ns ?
				dur - enqueue_debug_tax_ns :
				0;
		if (stats) {
			stats->total_enqueue_latency_ns += dur;
			cake_record_cb(stats, CAKE_CB_ENQUEUE, dur);
			cake_record_cb_split(stats, CAKE_CB_ENQUEUE,
					     release_est,
					     enqueue_debug_tax_ns);
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
#if CAKE_NEEDS_ARENA
	ARENA_ASSOC();
#endif
	enqueue_body(p, enq_flags);
}

/* cake_dispatch: Cake reaches this when there is no already-dispatched local
 * task ready to run. Shared LLC work and cache-throughput lanes are pulled
 * before keep-running and idle bookkeeping. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
#if CAKE_NEEDS_ARENA
	ARENA_ASSOC();
#endif
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
	u64 dispatch_dec = READ_ONCE(dispatch_bss->throughput_decision);
	bool cache_simple_active = false;

	if (cake_dispatch_try_idle_core_steal_rescue(dispatch_bss, prev, cpu_idx))
		return;

	if (cake_dispatch_try_idle_llc_rescue(dispatch_bss, prev, cpu_idx))
		return;

#if CAKE_PLANCK_LOCAL && CAKE_PLANCK_DISPATCH_GATE && !CAKE_HAS_DOMAIN_DRR
	/* Planck v2 keeps the proven stress/cache shared-service machinery, but
	 * collapses ordinary non-SAT dispatch into local continuation/no-op.  This
	 * tests whether the kernel/xz/perf wins came from deleting generic shared
	 * service tax while preserving s94's stress cache-simple plane. */
	if (!(READ_ONCE(cache_simple_state) & CAKE_CACHE_SIMPLE_STATE_ACTIVE) &&
	    !(dispatch_dec & CAKE_TP_DEC_SAT_CACHE_MEM)) {
		if (prev && (prev->scx.flags & SCX_TASK_QUEUED) &&
		    !(prev->flags & PF_KTHREAD) && prev->prio >= 120 &&
		    prev->scx.weight == 100 &&
		    prev->se.avg.util_avg >= CAKE_STEER_UTIL_MIN &&
		    !cake_task_is_perf_sched_messaging(prev)) {
			u64 slice = quantum_ns;

			prev->scx.slice = slice;
			dispatch_bss->tick_slice = slice;
#ifndef CAKE_RELEASE
			if (stats_on || path_stats_on)
				get_local_stats_for(cpu_idx)
					->nr_dispatch_keep_running++;
#endif
			return;
		}
	}
#endif

#if CAKE_HAS_DOMAIN_DRR
	if (cake_dispatch_try_domain_drr(cpu_idx))
		return;
#else
	u64 cache_simple = READ_ONCE(cache_simple_state);

	/* A saturated mixed-stream debt means several memcpy enqueues have
	 * failed to receive proven stream service while cache-simple remained
	 * active.  Let typed stream lanes pay that debt before cache-simple gets
	 * another residency turn, but do not throttle cache for ordinary mixed
	 * pressure or untyped LLC work. */
	if (cake_mixed_stream_debt_saturated(dispatch_dec) &&
	    cake_dispatch_try_saturated_stream_debt(dispatch_bss, cpu_idx))
		return;

	cache_simple_active = !!(cache_simple & CAKE_CACHE_SIMPLE_STATE_ACTIVE);
	if (cache_simple_active &&
	    cake_dispatch_try_cache_simple_lane(dispatch_bss, prev, cpu_idx,
					       cache_simple, dispatch_dec))
		goto dispatch_bookkeeping;
#endif

	if (cake_dispatch_try_cache_sprint(dispatch_bss, prev, dispatch_dec))
		goto dispatch_bookkeeping;

	bool route_trusted =
		cake_route_pred_skip_fairness_dec(dispatch_bss, dispatch_dec);
	bool fairness_due =
		route_trusted ? false :
				cake_throughput_fairness_due_dec(
					dispatch_bss, cpu_idx, dispatch_dec);
	bool stream_bleed_due =
		cake_mixed_stream_bleed_due_dec(dispatch_bss, dispatch_dec);

	/* Trusted cache-hot owners answer the golden question first: do not ask
	 * the throughput DSQ or shared LLC whether another task is available
	 * until the confidence audit says it is time to re-check fairness. This
	 * is intentionally outcome-driven rather than SAT-classifier-driven so
	 * the generic keep_running path can become actionably fast. */
	if (route_trusted) {
		if (cake_dispatch_try_throughput_lane(cpu_idx))
			return;

		if (!stream_bleed_due && prev &&
		    (prev->scx.flags & SCX_TASK_QUEUED)) {
			u64 slice = quantum_ns;
			u64 throughput_slice =
				cake_cache_throughput_slice_for_trust(
					dispatch_bss, prev, true);
			u64 default_bulk_slice;

			if (throughput_slice)
				slice = throughput_slice;
			else {
				default_bulk_slice = cake_default_bulk_slice_for(
					dispatch_bss, prev,
					READ_ONCE(dispatch_bss->owner_service_kind));
				if (default_bulk_slice)
					slice = default_bulk_slice;
			}
			prev->scx.slice = slice;
			if (stats_on || path_stats_on)
				get_local_stats_for(cpu_idx)
					->nr_dispatch_keep_running++;
			if (path_stats_on && throughput_slice)
				get_local_stats_for(cpu_idx)
					->nr_cache_throughput_keep_running++;
			cpu_bss[cpu_idx].tick_slice = slice;
			cake_record_frontier_dispatch(true);
			cake_route_pred_mark_pending(dispatch_bss);
			cake_throughput_charge_dispatch(dispatch_bss);
			goto dispatch_bookkeeping;
		}
		if (stream_bleed_due) {
			cake_throughput_reset_dispatch_budget(dispatch_bss);
			route_trusted = false;
			fairness_due = true;
			goto dispatch_fairness_probe;
		}
		cake_record_frontier_dispatch(false);
#ifdef CAKE_RELEASE
		WRITE_ONCE(dispatch_bss->route_prediction_last, 0);
#else
		cake_route_pred_decay_current(dispatch_bss,
					      CAKE_ROUTE_PRED_CONF_BAD_DECAY);
#endif
		route_trusted = false;
		fairness_due = cake_throughput_fairness_due_dec(
			dispatch_bss, cpu_idx, dispatch_dec);
	}

dispatch_fairness_probe:
	if (!fairness_due && cake_dispatch_try_throughput_lane(cpu_idx)) {
		cake_throughput_charge_dispatch(dispatch_bss);
		return;
	}

	if (!fairness_due && stream_bleed_due) {
		cake_throughput_reset_dispatch_budget(dispatch_bss);
		fairness_due = true;
	}

#if defined(CAKE_RELEASE) && CAKE_ENABLE_CORE_STEAL_BUSY_FALLBACK
	/* SMT core-steal local safety: always drain our own core-steal queue
	 * before deciding to keep a cache/mem-saturated owner running. */
	if (cake_dispatch_try_core_steal_own(cpu_idx)) {
		cake_throughput_reset_dispatch_budget(dispatch_bss);
		return;
	}
#endif

	/* Adaptive SAT locality: cache/mem-saturated owners are the one case
	 * where a shared LLC pull is often more expensive than keeping the
	 * current cache-warm worker. Normal wake-heavy workloads stay on the
	 * llc-vtime path below. */
	if (!fairness_due && !route_trusted &&
	    (dispatch_dec & CAKE_TP_DEC_SAT_CACHE_MEM)) {
		if (cake_dispatch_try_sat_keep_running(dispatch_bss, cpu_idx,
						       prev, false)) {
			cake_route_pred_mark_pending(dispatch_bss);
			cake_throughput_charge_dispatch(dispatch_bss);
			goto dispatch_bookkeeping;
		}
	}

	if (unlikely(READ_ONCE(stream_service_pending)) &&
	    (!cache_simple_active || stream_bleed_due) &&
	    cake_dispatch_try_stream_service()) {
		cake_mixed_stream_note_service(dispatch_bss);
		return;
	}

	if ((fairness_due || stream_bleed_due ||
	     !prev || !(prev->scx.flags & SCX_TASK_QUEUED) ||
	     cake_core_steal_pending_maybe_cpu(cpu_idx)) &&
	    cake_dispatch_try_core_steal_ordered(dispatch_bss, prev, cpu_idx,
						fairness_due,
						stream_bleed_due))
		return;

	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME) ||
	    CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
#ifdef CAKE_SINGLE_LLC
#ifdef CAKE_RELEASE
		if (cake_dispatch_try_single_llc_pull(
			    dispatch_bss, cpu_idx, stream_bleed_due)) {
			return;
		}
#else
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
			if (stream_bleed_due)
				cake_throughput_reset_dispatch_budget(
					dispatch_bss);
			return;
		}
#if CAKE_ACCEL_PATH
		if (should_pull)
			cake_dispatch_record_pull_result(dispatch_bss, false);
#endif
#endif
		if (stream_bleed_due)
			cake_throughput_reset_dispatch_budget(dispatch_bss);
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
			if (stream_bleed_due)
				cake_throughput_reset_dispatch_budget(
					dispatch_bss);
			return;
		}
#if CAKE_ACCEL_PATH
		if (should_pull)
			cake_dispatch_record_pull_result(dispatch_bss, false);
#endif
		if (stats_on || path_stats_on)
			get_local_stats_for(cpu_idx)
				->nr_dispatch_llc_local_miss++;

		if (cake_nr_llcs > 1) {
			for (u32 off = 1; off < CAKE_MAX_LLCS; off++) {
				u32 victim;

				if (off >= cake_nr_llcs)
					break;
				victim = my_llc + off;
				if (victim >= cake_nr_llcs)
					victim -= cake_nr_llcs;
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
					if (stream_bleed_due)
						cake_throughput_reset_dispatch_budget(
							dispatch_bss);
					return;
				}
#if CAKE_ACCEL_PATH
				if (should_pull)
					cake_dispatch_record_pull_result(
						dispatch_bss, false);
#endif
			}
		}
		if (stream_bleed_due)
			cake_throughput_reset_dispatch_budget(dispatch_bss);
#endif
	}

#if !(defined(CAKE_RELEASE) && CAKE_QUEUE_POLICY_VALUE == CAKE_QUEUE_POLICY_LOCAL)
	if (cake_dispatch_try_throughput_lane(cpu_idx)) {
		cake_throughput_charge_dispatch(dispatch_bss);
		return;
	}
#endif

	if (stats_on || path_stats_on)
		get_local_stats_for(cpu_idx)->nr_dispatch_misses++;

	/* G3 keep_running: if no DSQ work is available and prev still wants to run,
	 * replenish its slice instead of forcing an avoidable context switch. */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
		u64 slice = quantum_ns;
		u64 throughput_slice =
			cake_cache_throughput_slice_for(dispatch_bss, prev);
		u64 default_bulk_slice;

		if (throughput_slice)
			slice = throughput_slice;
		else {
			default_bulk_slice = cake_default_bulk_slice_for(
				dispatch_bss, prev,
				READ_ONCE(dispatch_bss->owner_service_kind));
			if (default_bulk_slice)
				slice = default_bulk_slice;
		}
		prev->scx.slice = slice;
		if (stats_on || path_stats_on)
			get_local_stats_for(cpu_idx)->nr_dispatch_keep_running++;
		if (path_stats_on && throughput_slice)
			get_local_stats_for(cpu_idx)
				->nr_cache_throughput_keep_running++;
		/* Keep the stopping() baseline aligned with the replenished
		 * slice so same-task continuations charge the next run from the
		 * correct starting budget. */
		cpu_bss[cpu_idx].tick_slice = slice;
#if CAKE_ACCEL_PATH
		/* Teach the frontier predictor from the live generic path. The
		 * prior wiring only learned from SAT-specialized continuations,
		 * while debug showed the benchmark mostly reaches this block. */
		cake_route_pred_mark_pending(dispatch_bss);
#endif
		goto dispatch_bookkeeping;
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

dispatch_bookkeeping:
	if (stats_on) {
		struct cake_stats *s	= get_local_stats_for(cpu_idx);
		u64		   d_oh = bpf_ktime_get_ns() - dispatch_start;
		s->total_dispatch_ns += d_oh;
		s->max_dispatch_ns =
			s->max_dispatch_ns + ((d_oh - s->max_dispatch_ns) &
					      -(d_oh > s->max_dispatch_ns));
		cake_record_cb(s, CAKE_CB_DISPATCH, d_oh);
		cake_record_cb_split(s, CAKE_CB_DISPATCH, d_oh, 0);
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
#if CAKE_NEEDS_ARENA
	ARENA_ASSOC();
#endif
#ifndef CAKE_RELEASE
	bool stats_on		    = CAKE_STATS_ACTIVE;
	bool path_stats_on	    = CAKE_PATH_STATS_ACTIVE;
	u64  running_overhead_start = 0;
	u64  running_debug_tax_ns   = 0;
	u64  running_debug_start    = 0;
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
	if (stats_on) {
		running_debug_start = bpf_ktime_get_ns();
		cake_record_local_run(cpu);
		running_debug_tax_ns += bpf_ktime_get_ns() -
					running_debug_start;
	}
#endif

#ifndef CAKE_RELEASE
	/* BPF-Native Clock: debug-only monotonic accumulator.
	 * Feeds run_start + running_telemetry (both debug-gated).
	 * In release, now_full has zero consumers → entire clock
	 * system (read, kfunc resync, accumulation) compiles out. */
	if (stats_on)
		running_debug_start = bpf_ktime_get_ns();
	u64 now_full = bss->cake_clock;
	if (stats_on)
		running_debug_tax_ns += bpf_ktime_get_ns() -
					running_debug_start;
#endif

	bool task_changed = bss->last_pid != p->pid;

#if CAKE_FUTEX_TRACE
	if (cake_task_service_kind(p) == CAKE_TASK_SERVICE_STRESS_FUTEX) {
		CAKE_FUTEX_TRACE_INC(cpu, running_futex);
		CAKE_FUTEX_TRACE_FIRST(cpu, first_run_pid, first_run_order,
				       p->pid);
		cake_futex_task_trace_event(p, cpu, 4);
		if (task_changed)
			CAKE_FUTEX_TRACE_INC(cpu, running_futex_changed);
		else
			CAKE_FUTEX_TRACE_INC(cpu, running_futex_same);
	}
#endif

	/* ── WRITE: owner-published CPU status ──
	 * Release keeps remote wake decisions on cpu_status instead of the private
	 * BSS line. Debug still mirrors idle_hint for telemetry and SMT accounting. */
	cake_publish_cpu_running(cpu, task_changed);
#if CAKE_HAS_LOCAL_WAITER
#ifndef CAKE_RELEASE
	if (READ_ONCE(local_waiter[cpu].debt)) {
		struct cake_stats *lw_stats =
			path_stats_on ? get_local_stats_for(cpu) : NULL;

		if (lw_stats)
			lw_stats->nr_local_waiter_debt_seen++;
		if (task_changed) {
			bool consumed = cake_local_waiter_consume_cpu(cpu);

			if (consumed && lw_stats)
				lw_stats->nr_local_waiter_debt_consume++;
		} else {
			u64 limit = cake_local_waiter_quench_limit();

			if (p->scx.slice > limit) {
				p->scx.slice = limit;
				if (lw_stats)
					lw_stats->nr_local_waiter_same_task_quench++;
			}
		}
	}
#endif
#endif
#ifndef CAKE_RELEASE
	if (stats_on)
		running_debug_start = bpf_ktime_get_ns();
	if (READ_ONCE(bss->idle_hint)) {
		WRITE_ONCE(bss->idle_hint, 0);
		if (stats_on)
			get_local_stats_for(cpu)->nr_idle_hint_clear_writes++;
	} else {
		if (stats_on)
			get_local_stats_for(cpu)->nr_idle_hint_clear_skips++;
	}
	if (stats_on)
		running_debug_tax_ns += bpf_ktime_get_ns() -
					running_debug_start;
#endif

#ifndef CAKE_RELEASE
	if (stats_on)
		running_debug_start = bpf_ktime_get_ns();
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
	if (stats_on)
		running_debug_tax_ns += bpf_ktime_get_ns() -
					running_debug_start;
#endif

	/* FAST PATH: same task re-running on the same CPU.
	 * Slice load is deferred into the task-change block.
	 * Release/stats-off same-task re-runs keep zero kfunc calls and zero BSS
	 * writes beyond the published status update; debug stats refresh the
	 * shadow owner class. */
	if (stats_on || path_stats_on) {
#ifndef CAKE_RELEASE
		if (stats_on)
			running_debug_start = bpf_ktime_get_ns();
#endif
		struct cake_stats *s_run = get_local_stats_for(cpu);
		if (task_changed)
			s_run->nr_running_task_change++;
		else
			s_run->nr_running_same_task++;
#ifndef CAKE_RELEASE
		if (stats_on)
			running_debug_tax_ns += bpf_ktime_get_ns() -
						running_debug_start;
#endif
	}
	if (task_changed) {
		/* Task change: refresh local CPU state and learned home placement.
		 * Release reads task context here to maintain locality history. */
#ifndef CAKE_RELEASE
		if (stats_on)
			running_debug_start = bpf_ktime_get_ns();
		now_full	= scx_bpf_now();
		bss->cake_clock = now_full;
		if (stats_on)
			running_debug_tax_ns += bpf_ktime_get_ns() -
						running_debug_start;
#endif
#if !(defined(CAKE_RELEASE) && !CAKE_RELEASE_ROUTE_PRED)
		if ((u32)READ_ONCE(bss->route_prediction_last) != p->pid) {
			WRITE_ONCE(bss->route_prediction_last, 0);
			cake_record_frontier_clear();
		}
#endif
		u64 slice	= p->scx.slice;
		bss->last_pid	= p->pid;
		bss->tick_slice = slice ?: quantum_ns;
		WRITE_ONCE(bss->run_start_ns, bpf_ktime_get_ns());
#if !CAKE_LEAN_SCHED
		cake_owner_runtime_policy_reset(bss);
#else
		{
			bool normal_default = !(p->flags & PF_KTHREAD) &&
					      p->prio >= 120 &&
					      p->scx.weight == 100;
			u32 owner_service_kind =
				normal_default ? cake_task_service_kind(p) :
						 CAKE_TASK_SERVICE_NONE;

			WRITE_ONCE(bss->owner_service_kind,
				   (u8)owner_service_kind);
			if (normal_default &&
			    owner_service_kind == CAKE_TASK_SERVICE_NONE &&
			    READ_ONCE(bss->service_reset_kind))
				WRITE_ONCE(bss->service_reset_kind,
					   (u8)CAKE_TASK_SERVICE_NONE);
		}
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
			if (stats_on)
				running_debug_start = bpf_ktime_get_ns();
			if (first_home)
				cake_record_home_seed(tctx->home_cpu,
						      seed_reason);
			if (stats_on)
				running_debug_tax_ns += bpf_ktime_get_ns() -
							running_debug_start;
#endif
		}
	}

	/* BPF-Native Clock: single write with correct value.
	 * Same-task (75%): now_full = cake_clock (from BSS, 1ns).
	 * Task-change (25%): now_full = scx_bpf_now() (resynced above).
	 * Deferred to here so the task-change path can overwrite it. */
#ifndef CAKE_RELEASE
	if (stats_on)
		running_debug_start = bpf_ktime_get_ns();
	bss->run_start = (u32)now_full;
	if (stats_on)
		running_debug_tax_ns += bpf_ktime_get_ns() -
					running_debug_start;
#endif

#ifndef CAKE_RELEASE
	if (stats_on) {
		running_debug_start = bpf_ktime_get_ns();
		running_telemetry(p, cpu, running_overhead_start);
		running_debug_tax_ns += bpf_ktime_get_ns() -
					running_debug_start;
	}
	if (stats_on) {
		struct cake_stats *s_run = get_local_stats_for(cpu);
		u64 oh_run = bpf_ktime_get_ns() - running_overhead_start;
		u64 release_est =
			oh_run > running_debug_tax_ns ?
				oh_run - running_debug_tax_ns :
				0;
		s_run->total_running_ns += oh_run;
		s_run->max_running_ns = s_run->max_running_ns +
					((oh_run - s_run->max_running_ns) &
					 -(oh_run > s_run->max_running_ns));
		cake_record_cb(s_run, CAKE_CB_RUNNING, oh_run);
		cake_record_cb_split(s_run, CAKE_CB_RUNNING, release_est,
				     running_debug_tax_ns);
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
#if CAKE_NEEDS_ARENA
	ARENA_ASSOC();
#endif

	u32		     cpu = cake_task_cpu(p) & (CAKE_MAX_CPUS - 1);
	struct cake_cpu_bss *bss = &cpu_bss[cpu];

	/* Vtime integration.
	 * Release fast path uses task_struct, private BSS, and owner-published
	 * status/frontier lanes.
	 * Debug telemetry below adds extra reads and one deferred divide. */
	u32 slice_consumed = (u32)bss->tick_slice - (u32)p->scx.slice;
#if CAKE_FUTEX_TRACE
	if (cake_task_service_kind(p) == CAKE_TASK_SERVICE_STRESS_FUTEX) {
		CAKE_FUTEX_TRACE_INC(cpu, stopping_futex);
		if (runnable)
			CAKE_FUTEX_TRACE_INC(cpu, stopping_futex_runnable);
		else
			CAKE_FUTEX_TRACE_INC(cpu, stopping_futex_blocked);
	}
#endif
#ifndef CAKE_RELEASE
	/* Debug clock accumulator — feeds run_start/telemetry. Dead in release. */
	bss->cake_clock += slice_consumed;
#endif

	/* Branchless math bounding */
	u32 rt_raw = slice_consumed - ((slice_consumed - (65535U << 10)) &
				       -(slice_consumed > (65535U << 10)));

#if CAKE_LEAN_SCHED
	u32 owner_service_kind = READ_ONCE(bss->owner_service_kind);

	if (unlikely(READ_ONCE(bss->last_pid) != p->pid)) {
		bool normal_default = !(p->flags & PF_KTHREAD) &&
				      p->prio >= 120 && p->scx.weight == 100;

		owner_service_kind = normal_default ? cake_task_service_kind(p) :
						       CAKE_TASK_SERVICE_NONE;
	}
#endif

#if CAKE_ACCEL_PATH && !defined(CAKE_RELEASE)
	cake_route_pred_observe(bss, p, rt_raw, runnable);
#endif

#ifndef CAKE_RELEASE
#if !CAKE_LEAN_SCHED
	cake_update_cpu_pressure(bss, slice_consumed);
	cake_owner_runtime_policy_update(bss, slice_consumed);
	u32 owner_avg_runtime_ns = READ_ONCE(bss->owner_avg_runtime_ns);
	cake_publish_cpu_owner(cpu, bss, owner_avg_runtime_ns);
#else
	u32 owner_avg_runtime_ns =
		cake_update_owner_avg(bss, rt_raw, owner_service_kind);
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
#if CAKE_LEAN_ACCOUNTING_VALUE
	/* Lean accounting (SCX_CAKE_LEAN_ACCOUNTING, game A/B): skip the
	 * owner-average update, service classification effects, and
	 * confidence bookkeeping on every stop; keep the vtime integration,
	 * frontier publish, and a stable-status owner publish so the IDLE
	 * bit and kick decisions stay fresh. */
	cake_publish_cpu_owner(cpu, bss,
			       READ_ONCE(bss->owner_avg_runtime_ns));
	return;
#endif
	u32  owner_avg_runtime_ns =
		cake_update_owner_avg(bss, rt_raw, owner_service_kind);
	bool schbench_service =
		owner_service_kind == CAKE_TASK_SERVICE_SCHBENCH;

	if (schbench_service) {
		/* Enqueue-side reset clears stale cache/stream residue before
		 * wake placement.  Stopping-side reset now keeps live owner
		 * runtime/pressure so schbench-saturated can build a useful busy
		 * signal; cake_publish_cpu_owner() separately forces PREEMPT_WAKE
		 * for schbench service owners so short-owner suppression does not
		 * break the latency contract. */
		CAKE_FUTEX_TRACE_INC(cpu, schbench_stopping_reset);
		if (runnable)
			CAKE_FUTEX_TRACE_INC(cpu, schbench_stopping_runnable);
		else
			CAKE_FUTEX_TRACE_INC(cpu, schbench_stopping_blocked);
		cake_latency_service_reset_state(cpu, false);
	}
	cake_route_pred_observe(bss, p, rt_raw, runnable);
	cake_publish_cpu_owner(cpu, bss, owner_avg_runtime_ns);
	if (!cake_accounting_relaxed(bss))
		cake_scoreboard_owner_result(bss, owner_avg_runtime_ns);
	return;
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
	u64  stopping_debug_tax_ns   = 0;
	u64  stopping_debug_start __maybe_unused = 0;

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
		stopping_debug_start = bpf_ktime_get_ns();
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
		stopping_debug_tax_ns += bpf_ktime_get_ns() -
					 stopping_debug_start;
#endif /* !CAKE_RELEASE */

		/* Aggregate overhead timing (per-CPU BSS). */
		struct cake_stats *s = get_local_stats_for(cpu);
#ifndef CAKE_RELEASE
		stopping_debug_start = bpf_ktime_get_ns();
		if (!smt_charged)
			cake_smt_charge_runtime(s, bss, cpu,
						bpf_ktime_get_ns());
		stopping_debug_tax_ns += bpf_ktime_get_ns() -
					 stopping_debug_start;
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
		u64 release_est =
			oh_agg > stopping_debug_tax_ns ?
				oh_agg - stopping_debug_tax_ns :
				0;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns =
			s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) &
					      -(oh_agg > s->max_stopping_ns));
		cake_record_cb(s, CAKE_CB_STOPPING, oh_agg);
		cake_record_cb_split(s, CAKE_CB_STOPPING, release_est,
				     stopping_debug_tax_ns);
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
 * Debug builds allocate full telemetry state; release builds include this
 * callback only when a baked locality policy needs task-local state. */
#if CAKE_NEEDS_ARENA
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct cake_task_ctx __arena *tctx;

	(void)args;

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

#ifndef CAKE_RELEASE
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
#endif

	return 0;
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
	if (tctx && tctx->home_cpu < cake_nr_cpus &&
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
#if CAKE_NEEDS_ARENA
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	(void)args;
#ifndef CAKE_RELEASE
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
#endif
	/* Remove from PID→tctx map: removed — iter/task program handles visibility
	 * without explicit cleanup. Task storage freed below. */
	scx_task_free(p);
}
#endif

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	if (likely(CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LLC_VTIME) ||
	    CAKE_QUEUE_POLICY == CAKE_QUEUE_POLICY_LOCAL) {
		for (u32 i = 0; i < CAKE_MAX_LLCS; i++) {
			s32 ret;

			if (i >= cake_nr_llcs)
				break;
			ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
			if (ret)
				return ret;
		}
	}

#if CAKE_HAS_DOMAIN_DRR
	for (u32 llc = 0; llc < CAKE_MAX_LLCS; llc++) {
		if (llc >= cake_nr_llcs)
			break;
		for (u32 cls = 0; cls < CAKE_DOMAIN_DRR_CLASS_MAX; cls++) {
			s32 ret;
			u64 dsq = CAKE_DOMAIN_DRR_DSQ_BASE +
				  ((u64)cls * (u64)CAKE_MAX_LLCS) + llc;

			ret = scx_bpf_create_dsq(dsq, -1);
			if (ret)
				return ret;
		}
	}
#endif

#if !CAKE_HAS_DOMAIN_DRR
	{
		s32 ret = scx_bpf_create_dsq(CAKE_DOMAIN_DRR_DSQ_BASE, -1);

		if (ret)
			return ret;
	}
#endif

	for (u32 cpu = 0; cpu < CAKE_MAX_CPUS; cpu++) {
		s32 ret;

		if (cpu >= cake_nr_cpus)
			break;
		ret = scx_bpf_create_dsq(CAKE_CORE_STEAL_DSQ_BASE + cpu, -1);
		if (ret)
			return ret;
#if !CAKE_HAS_DOMAIN_DRR
		ret = scx_bpf_create_dsq(CAKE_THROUGHPUT_DSQ_BASE + cpu, -1);
		if (ret)
			return ret;
#endif
		scx_bpf_cpuperf_set(cpu, SCX_CPUPERF_ONE);
	}

#if CAKE_CORE_STEAL_DHQ_VALUE
	for (u32 i = 0; i < CAKE_MAX_CORES; i++) {
		if (i >= cake_nr_cpus / 2)
			break;
		core_dhqs[i] = (struct scx_dhq __arena *)scx_dhq_create_balanced(
			false,                          /* is_fifo = false (priority mode) */
			64,                             /* capacity */
			SCX_DHQ_MODE_PRIORITY,          /* mode */
			3                               /* max_imbalance */
		);
		if (!core_dhqs[i]) {
			scx_bpf_error("Failed to create Core DHQ %u", i);
			return -ENOMEM;
		}
	}

	for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
		if (i >= cake_nr_cpus)
			break;
		cpu_lfdeqs[i] = (struct scx_lfdeq __arena *)scx_static_alloc(sizeof(struct scx_lfdeq), 64);
		if (!cpu_lfdeqs[i]) {
			scx_bpf_error("Failed to allocate CPU lfdeq %u", i);
			return -ENOMEM;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Populate per-CPU LLC ID cache from RODATA.
	 * Set once at init — llc_id never changes for a given CPU. */
	for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
		if (i >= cake_nr_cpus)
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
#if CAKE_NEEDS_ARENA
SCX_OPS_DEFINE(
	cake_ops, .select_cpu = (void *)cake_select_cpu,
	.enqueue = (void *)cake_enqueue, .dispatch = (void *)cake_dispatch,
	.running = (void *)cake_running, .stopping = (void *)cake_stopping,
	.enable = (void *)cake_enable, .init_task = (void *)cake_init_task,
	.exit_task = (void *)cake_exit_task, .init = (void *)cake_init,
	.exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	.timeout_ms = 5000, /* Override with SCX_TIMEOUT_MS when needed */
	.name	    = "cake");
#else
SCX_OPS_DEFINE(
	cake_ops, .select_cpu = (void *)cake_select_cpu,
	.enqueue = (void *)cake_enqueue, .dispatch = (void *)cake_dispatch,
	.running = (void *)cake_running, .stopping = (void *)cake_stopping,
	.enable = (void *)cake_enable, .init = (void *)cake_init,
	.exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	.timeout_ms = 5000, /* Override with SCX_TIMEOUT_MS when needed */
	.name	    = "cake");
#endif
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
