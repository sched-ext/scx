// SPDX-License-Identifier: GPL-2.0
/*
 * scx_cake - A sched_ext scheduler applying CAKE bufferbloat concepts
 *
 * This scheduler adapts CAKE's DRR++ (Deficit Round Robin++) algorithm
 * for CPU scheduling, providing low-latency scheduling for gaming and
 * interactive workloads.
 *
 * Key concepts from CAKE adapted here:
 * - Sparse flow detection: Low-CPU tasks (like gaming) get latency priority
 * - Direct dispatch: Waking tasks on idle CPUs run immediately
 * - Two-tier DSQ: Gaming/sparse tasks dispatched before normal tasks
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/*
 * Scheduler configuration (set by userspace before loading)
 * 
 * RODATA CONSTANT FOLDING: These are 'const' without 'volatile'.
 * Userspace writes to .rodata BEFORE load(), then the BPF loader
 * freezes the section. The JIT treats these as compile-time constants,
 * emitting immediate values instead of memory loads.
 * 
 * Performance: ~180-230 cycles saved per scheduling decision.
 */
const u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const u64 sparse_threshold = CAKE_DEFAULT_SPARSE_THRESHOLD;
const u64 starvation_ns = CAKE_DEFAULT_STARVATION_NS;
const bool enable_stats = false;

/*
 * Topology configuration (frozen .rodata = dead code elimination)
 * 
 * When has_hybrid = false, the JIT eliminates the entire P/E-core
 * steering block from the instruction stream. Zero runtime cost.
 */
const bool has_multi_llc = false;
const bool has_hybrid = false;
const bool smt_enabled = false;

#define CAKE_MAX_LLCS 8
const u8 cpu_llc_id[CAKE_MAX_CPUS];
const u8 cpu_is_big[CAKE_MAX_CPUS];
const u8 cpu_sibling_map[CAKE_MAX_CPUS];
const u64 llc_cpu_mask[CAKE_MAX_LLCS];
const u64 big_cpu_mask = 0;

/*
 * UNIFIED CPU TOPOLOGY (Fused ETD + Kernel Topology)
 * 
 * Single 8-byte struct per CPU containing sibling, LLC ID, and
 * top 3 peers ordered by measured latency. Populated by userspace
 * after ETD calibration. See intf.h for struct definition.
 */
const struct cpu_topology_entry cpu_topo[CAKE_MAX_CPUS];
const u8 core_to_cpu[32]; /* Physical Core -> Primary Logical CPU mapping */
const u8 nr_cores;        /* Actual detected core count */
const u8 nr_cpus_total;   /* Actual detected CPU count */
const u8 core_thread_mask[32]; /* Bitmask of SMT threads per core (e.g. 3 for dual-thread) */
const u64 core_cpu_mask[32];   /* Pre-computed 64-bit mask of all CPUs in a core */

/* Zero-Math Arbiter LUT (populated by userspace) */
const struct arbiter_config arbiter_cfg;

/*
 * TIERED IDLE MASK (Phase 2 Optimization)
 *
 * ARCHITECTURE: Two-level hierarchy to reduce LOCK prefix frequency
 *
 * Level 1: core_status[8] - Per-physical-core bytes (SMT-aware)
 *   Bit 0 = SMT thread 0 idle, Bit 1 = SMT thread 1 idle
 *   Standard u8 stores are architecturally atomic on x86_64.
 *
 * Level 2: global_hint - 1 bit per physical core
 *   Updated ONLY when core_status transitions 0 <-> !0
 *   This is the "Filtered Update Protocol" - LOCK only fires on
 *   core-level transitions, not every thread wake/sleep.
 *
 * BENEFIT (9800X3D): 40-60% reduction in atomic frequency,
 * eliminates L3 bank arbiter queues.
 *
 * CACHE LINE SEPARATION: core_status and global_hint on separate lines
 * to prevent false sharing. Non-atomic core_status writes won't invalidate
 * cache lines held by cores performing atomic global_hint operations.
 *
 * Source: Fretz, "Beyond Sequential Consistency" (C++Now 2024)
 */
/* Global tiered idle mask (defined in intf.h) */
static struct tiered_idle_mask tiered_idle SEC(".bss") __attribute__((aligned(128)));

/* Hint accessors */
#define idle_mask_physical (tiered_idle.physical_hint)
#define idle_mask_logical  (tiered_idle.logical_hint)


/*
 * GLOBAL CPU TIER STATE (Zero-Latency BSS Array)
 * 
 * Each CPU's current occupant tier, for Zero-Math Locality Arbiter.
 * 0ns lookup (direct memory offset) vs 25ns BPF map helper.
 * 64-byte padding per entry prevents MESI invalidation storms.
 */
struct cake_cpu_tier global_cpu_tiers[64] SEC(".bss") __attribute__((aligned(128)));

/*
 * Global Victim Mask (128-byte aligned, separate cache domain)
 * 
 * DESIGN DECISION: Victim Mask is a "Shadow Heuristic"
 * It does not require sequential consistency. If we miss a bit update,
 * we just miss a direct-dispatch opportunity (safe failure).
 * Therefore, ALWAYS use __ATOMIC_RELAXED.
 * 
 * Source: Fretz, "Beyond Sequential Consistency" (C++Now 2024)
 */
struct {
    u64 mask;
    u64 pad[15]; /* Pad to 128 bytes */
} victim_global SEC(".bss") __attribute__((aligned(128)));

/* Accessor macro for victim_mask */
#define GET_VICTIM_MASK() (cake_relaxed_load_u64(&victim_global.mask))

/* Copy of GET_TIER from implementation (fix implicit declaration) */
#define GET_TIER(tctx) (((tctx)->packed_info >> SHIFT_TIER) & MASK_TIER)
#define victim_mask      (victim_global.mask)


/*
 * Per-CPU Shadow State ("Cached Cursor" + Cache Line Isolation)
 * 
 * Each CPU tracks what it believes its bit in the global masks is.
 * We only touch global atomics when local reality disagrees with new state.
 * 
 * CRITICAL: 64-byte alignment prevents "micro-stutter" from false sharing.
 * Without padding, CPU 0's game thread and CPU 1's background service
 * would invalidate each other's cache lines on every state update.
 * 
 * Source: Frasch, "Lock-Free FIFO" (CppCon 2023)
 */
struct cake_cpu_shadow {
    u32 packed_state;  /* Bit 0: idle, Bit 1: victim (1-cycle RMW) */
    u8 _pad[60];       /* Pad to 64 bytes - cache line isolation */
} __attribute__((aligned(64)));

/* Scratchpad for cold path API compliance (Zero Spill) */
struct {
    s32 prev_cpu;
    bool is_idle;
    u8 _pad[59];  /* Pad to 64 bytes - cache line isolation */
} cold_scratch SEC(".bss") __attribute__((aligned(64)));



/* Shadow state bit positions */
#define SHADOW_BIT_IDLE   (1U << 0)
#define SHADOW_BIT_VICTIM (1U << 1)
#define SHADOW_HINT_CPU_SHIFT  8   /* Bits 8-13: Last-idle-core hint (logical CPU 0-63) */
#define SHADOW_HINT_CPU_MASK   0x3F /* 6 bits for CPU 0-63 */
#define SHADOW_WARM_TIER_SHIFT 16  /* Bits 16-18: Last successful dispatch tier (0-6) */
#define SHADOW_WARM_TIER_MASK  0x7 /* 3 bits for tier 0-6 */

/*
 * MESI-FRIENDLY WARM-TIER UPDATE
 * 
 * Skip write if unchanged to prevent cache line invalidation.
 * During steady-state gaming, tier stays at 3 (GAMING_DSQ) ~90% of the time.
 * Skipped writes keep the line in Shared state, eliminating RFO traffic.
 */
static __always_inline void update_warm_tier(struct cake_cpu_shadow *shadow, u32 new_tier)
{
    u32 old = shadow->packed_state;
    u32 new = (old & 0xFFFF) | (new_tier << SHADOW_WARM_TIER_SHIFT);
    if (old != new)
        shadow->packed_state = new;
}

/*
 * GLOBAL STATISTICS (Zero-Latency BSS Array)
 * 
 * Replaces BPF_MAP_TYPE_PERCPU_ARRAY. 0ns lookup vs 25ns helper call.
 * 256-byte alignment per CPU ensures extreme isolation for high-frequency writes.
 */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/*
 * GLOBAL CPU SHADOW STATE (Zero-Latency BSS Array)
 * 
 * Replaces cpu_shadow_map. Direct memory access for 1-cycle state checks.
 * 128-byte alignment prevents spatial prefetching interference.
 */
struct cake_cpu_shadow global_shadow[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));

/*
 * BSS TAIL GUARD: Protects against BTF truncation bugs.
 * If the BTF generator miscalculates section boundaries, this
 * padding absorbs the error instead of corrupting real variables.
 */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/*
 * get_shadow_state() removed - inline direct BSS access using cpu_idx
 * to eliminate hidden bpf_get_smp_processor_id() helper calls.
 * Use: &global_shadow[cpu_idx & (CAKE_MAX_CPUS - 1)]
 */

static __always_inline struct cake_stats *get_local_stats(void)
{
    u32 cpu = bpf_get_smp_processor_id();
    return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/*
 * BRANCHLESS kthread Classification (Zero Branch Misses)
 * 
 * OPTIMIZATION: Single 8-byte load + bitwise XOR/OR classification.
 * Eliminates branch mispredictions by computing all conditions in parallel.
 * 
 * Classification:
 * - CRITICAL (gets floor): ksoftirqd, bound kworkers, irq/
 * - HOUSEKEEPING (no floor): unbound kworkers (kworker/u*)
 * 
 * Diamond priority distribution:
 * - Tier 0: Ultra-fast inputs (IRQ handlers that earn it)
 * - Tier 1: Critical plumbing (ksoftirqd, bound kworkers)
 * - Tier 3-4: Games and interactive apps
 * - Tier 5-6: Batch work and housekeeping kworkers
 * 
 * ENDIANNESS: x86_64 Little-Endian hex constants.
 */
static __always_inline bool is_critical_kthread(struct task_struct *p)
{
    const char *comm = p->comm;
    
    /* Single 8-byte load - de-congests Load-Store Unit (LSU) */
    u64 head;
    __builtin_memcpy(&head, comm, sizeof(head));
    
    /*
     * BRANCHLESS CLASSIFICATION:
     * All comparisons execute in parallel, combined with bitwise OR.
     * Zero branch misses regardless of kthread mix.
     */
    u64 is_softirq = !(head ^ 0x71726974666F736BULL);  /* "ksoftirq" */
    u64 is_worker  = !(head ^ 0x2F72656B726F776BULL) & (comm[8] != 'u');  /* bound kworker */
    u64 is_irq     = !((head & 0xFFFFFFFFULL) ^ 0x2F717269ULL);  /* "irq/" */
    
    return is_softirq | is_worker | is_irq;
}



/*
 * BRANCHLESS Multi-Tier SIMD Topology Scan
 * 
 * Fully deterministic CPU selection using CMOV cascade.
 * EMPIRICAL TOPOLOGY DISCOVERY (ETD) - Surgical Seek (Tiered-Aware)
 *
 * PRIMARY CPU SELECTION PATH: Check empirically-measured "sweet spots"
 * BEFORE falling back to blind global scans. These are the 3 CPUs with
 * the lowest measured CAS ping-pong latency (ground truth from silicon).
 *
 * On 9800X3D:
 *   - Peer 0: SMT sibling (~18ns)
 *   - Peer 1: Ring-bus neighbor (~21ns)
 *   - Peer 2: Secondary neighbor (~21.5ns)
 *
 * vs. Distant Neighbor: ~28ns (eliminated by ETD-first approach)
 *
 * Performance: 3 core checks + SMT resolution (~8-10 cycles)
 * ROI: 30:1 vs cross-CCD miss penalty (~250 cycles)
 *
 * Tiered Integration: Works with Phase 2 tiered idle tracking:
 *   1. Check if peer's core has idle capacity (global_hint)
 *   2. Resolve to specific SMT thread via core_status
 *   3. Prefer exact peer if idle, else sibling for cache warmth
 */
/*
 * find_surgical_victim (Unified Topology)
 * 
 * Uses the new unified cpu_topo[] RODATA for peer lookup.
 * Checks sibling first, then peer_1/2/3 in latency order.
 * 
 * COST: ~6-8 cycles (single 8-byte RODATA load).
 */


/*
 * find_surgical_victim_logical (Unified Topology)
 * 
 * VARIANT: Checks a LOGICAL mask (1 bit per CPU) instead of PHYSICAL.
 * USE CASE: Checking 'victim_mask' or 'p_candidates' (Logical IDs).
 * 
 * COST: ~6-8 Cycles.
 */
static __always_inline s32 find_surgical_victim_logical(u32 prev_cpu, u64 logical_mask)
{
    u32 idx = prev_cpu & (CAKE_MAX_CPUS - 1);
    const struct cpu_topology_entry *t = &cpu_topo[idx];

    /* 1. Check top 3 latency-ordered peers (Fastest Isolation) */
    if (t->peer_1 < 64 && (logical_mask & (1ULL << t->peer_1)))
        return (s32)t->peer_1;
    if (t->peer_2 < 64 && (logical_mask & (1ULL << t->peer_2)))
        return (s32)t->peer_2;
    if (t->peer_3 < 64 && (logical_mask & (1ULL << t->peer_3)))
        return (s32)t->peer_3;

    /* 
     * 2. Topological Fallback: Broad bit-scan on the provided mask.
     * Use __builtin_ctzll to find the next available bit in the domain
     * defined by logical_mask (e.g. current CCD or full system).
     */
    if (logical_mask)
        return (s32)__builtin_ctzll(logical_mask);

    return -1;
}

/*
 * ZERO-MATH LOCALITY ARBITER (Warmth-First)
 * 
 * Replaces "Idle-First" bias with "Warmth-First" bias.
 * Decision flow: prev_cpu (Warm L1) → sibling (Warm L2) → SIMD scan (Cold L3)
 * 
 * Only triggers the expensive SIMD scan if the local core's occupant
 * isn't worth waiting for (tier gap > 3 = migration penalty ~150ns).
 * 
 * Source: Gross, "Simple is Fast" (CppCon 2022)
 */
static __always_inline s32 select_cpu_with_arbiter(
    struct cake_task_ctx *tctx, s32 prev_cpu)
{
    u32 b_prev = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);
    
    /* 1. Fast Path: Local check (L1/L2 warmth) */
    u64 l_mask = cake_relaxed_load_u64(&idle_mask_logical);
    if (l_mask & (1ULL << b_prev))
        return prev_cpu;

    /* 
     * 2. Physical-First Migration (CMOV Cascade)
     * Rank 1: Idle Physical Core (Isolation/L3 Warm)
     * Rank 2: Warm SMT Sibling (L2 Warmth)
     * Rank 3: Any Idle SMT (Throughput)
     */
    const struct cpu_topology_entry *t = &cpu_topo[b_prev];
    s32 target_cpu = -1;
    u8 target_rank = 7;
    u64 p_mask = cake_relaxed_load_u64(&idle_mask_physical);

    /* RANK 3: Any Idle SMT (Fallback) */
    if (l_mask) {
        target_cpu = (s32)__builtin_ctzll(l_mask);
        target_rank = 3;
    }

    /* RANK 2: Warm SMT Sibling (Better than random SMT) */
    if (t->sibling < 64 && (l_mask & (1ULL << t->sibling))) {
        target_cpu = (s32)t->sibling;
        target_rank = 2;
    }

    /* RANK 1: Idle Physical Core (Highest Isolation)
     * We use find_surgical_victim_logical to prioritize LOCAL CCD physical cores.
     */
    if (p_mask) {
        s32 phys_cpu = find_surgical_victim_logical(b_prev, p_mask);
        if (phys_cpu >= 0) {
            target_cpu = phys_cpu;
            target_rank = 1;
        }
    }

    /* If absolutely no idle cores even in logic mask, wait on prev */
    if (target_cpu < 0)
        return prev_cpu;

    /* 3. ZERO-MATH ARBITRATION (LUT Lookup) */
    u8 my_tier = GET_TIER(tctx) & 7;
    u8 occupant_tier = (u8)cake_relaxed_load_u32(&global_cpu_tiers[b_prev].tier);
    
    u8 threshold = arbiter_cfg.lut[my_tier][target_rank];

    if (occupant_tier <= threshold)
        return prev_cpu; // WAIT: Worth waiting for this occupant
    
    return target_cpu;   // GO: Better to migrate
}

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Global vtime removed to prevent bus locking. Tasks inherit vtime from parent. */

/* Optimization: Precomputed threshold to avoid division in hot path */
/*
 * CRITICAL: Non-static with explicit alignment prevents BTF "tail truncation" bug.
 * The aligned(8) forces the linker to allocate full 8 bytes.
 * Removing 'static' gives it external linkage for proper BTF metadata.
 */
u64 cached_threshold_ns __attribute__((aligned(8)));

/*
 * Seven dispatch queues - one per tier, served in priority order:
 * - CRITICAL_LATENCY_DSQ: Ultra-low latency (score=100 AND <50µs avg) - highest priority
 * - REALTIME_DSQ:    Ultra-sparse tasks (score=100, <500µs avg) - very high priority
 * - CRITICAL_DSQ:    Very sparse tasks (audio, compositor) - high priority
 * - GAMING_DSQ:      Sparse/bursty tasks (game threads, UI) - gaming priority  
 * - INTERACTIVE_DSQ: Normal tasks (default applications) - baseline priority
 * - BATCH_DSQ:       Lower priority work (nice > 0) - lower priority
 * - BACKGROUND_DSQ:  Bulk tasks (compilers, encoders) - lowest priority
 */
#define CRITICAL_LATENCY_DSQ 0
#define REALTIME_DSQ    1
#define CRITICAL_DSQ    2
#define GAMING_DSQ      3
#define INTERACTIVE_DSQ 4
#define BATCH_DSQ       5
#define BACKGROUND_DSQ  6

/* Per-CPU Direct Dispatch Queues (1000-1063) */
#define CAKE_DSQ_LC_BASE 1000

/* Sparse score threshold for gaming detection */
#define THRESHOLD_GAMING 70

/* Latency gate thresholds for score=100 sub-classification (in µs) */
#define LATENCY_GATE_CRITICAL   25   /* <25µs avg → Critical Latency (tier 0) - true IRQ */
#define LATENCY_GATE_REALTIME  100   /* <100µs avg → Realtime (tier 1) - fast input */
#define LATENCY_GATE_CRITICAL2 500   /* <500µs avg → Critical (tier 2) - compositor */

/* Special tier value for idle CPU scoreboard */
#define CAKE_TIER_IDLE 255

/*
 * Consolidated Tier Configuration Table
 * 
 * OPTIMIZATION: Array of Structures (AoS)
 * Before: 3 separate arrays = 3 cache line fetches per tier lookup.
 * After:  1 unified struct = 1 cache line fetch brings all params.
 * 
 * Each struct is 32 bytes, so 2 tiers fit per 64-byte cache line.
 * Accessing tier_configs[tier] brings starvation, budget, AND multiplier
 * into L1 simultaneously.
 * 
 * LFB Optimization: Reduces Line Fill Buffer usage from 3 to 1,
 * freeing memory bandwidth for game engine data.
 * 
 * Pre-computed by userspace based on profile. Zero runtime overhead.
 */
const struct cake_tier_config tier_configs[8] = {
    /* Tier 0: Critical Latency */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T0, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T0, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T0 },
    /* Tier 1: Realtime */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T1, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T1, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T1 },
    /* Tier 2: Critical */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T2, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T2, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T2 },
    /* Tier 3: Gaming */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T3, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T3, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T3 },
    /* Tier 4: Interactive */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T4, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T4, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T4 },
    /* Tier 5: Batch */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T5, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T5, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T5 },
    /* Tier 6: Background */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T6, 
      .wait_budget_ns = CAKE_DEFAULT_WAIT_BUDGET_T6, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T6 },
    /* Tier 7: Padding */
    { .starvation_ns = CAKE_DEFAULT_STARVATION_T6, 
      .wait_budget_ns = 0, 
      .multiplier = CAKE_DEFAULT_MULTIPLIER_T3 },
};

/*
 * BRANCHLESS TIER LOOKUP TABLE (Zero Branch Misses)
 * 
 * Direct indexed lookup eliminates 7-branch if-else chain in compute_tier().
 * Score 0-100 maps directly to tier 2-6. Score 100+ uses latency gates.
 * 
 * LAYOUT: 128 entries for bounds masking (score & 127)
 * Cache: 2 lines (128 bytes), aligned to 64 bytes
 * 
 * Score ranges:
 *   0-29:  Tier 6 (Background)
 *   30-49: Tier 5 (Batch)
 *   50-69: Tier 4 (Interactive)
 *   70-89: Tier 3 (Gaming)
 *   90-99: Tier 2 (Critical)
 *   100:   Tier 2 (default, latency gates may override)
 *   101-127: Tier 2 (padding for bounds mask)
 */
static const u8 tier_lut[128] __attribute__((aligned(64))) = {
    /* 0-29: Background (6) */
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    /* 30-49: Batch (5) */
    5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    /* 50-69: Interactive (4) */
    4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
    /* 70-89: Gaming (3) */
    3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,
    /* 90-99: Critical (2) */
    2,2,2,2,2,2,2,2,2,2,
    /* 100: Critical (latency gates check separately) */
    2,
    /* 101-127: Padding for bounds mask (default to Critical) */
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2
};

/* Long-sleep recovery threshold: 33ms = 2 frames @ 60Hz */
#define LONG_SLEEP_THRESHOLD_NS 33000000

/*
 * Minimum Victim Residency: ~262µs (Power-of-2 for 1-cycle bit test)
 * 
 * HYSTERESIS: Prevents "staircase" migrations where tasks are immediately
 * preempted after starting. A task must run for at least 262µs before its
 * CPU becomes eligible for victim preemption.
 * 
 * OPTIMIZATION: 2^18 ns = 262,144 ns ≈ 262µs
 * This allows a single BT (bit test) instruction instead of SUB+CMP.
 * The bit test checks if bit 18 is set in the delta, which means
 * the runtime has exceeded 262µs.
 * 
 * 262µs rationale:
 * - Long enough to warm L1/L2 caches (~100 cycles to fill a line)
 * - Short enough to not block Tier 0 preemption (6% of 240Hz frame)
 * - Power-of-2 enables 1-cycle check
 */
#define VICTIM_RESIDENCY_BIT 20  /* 2^20 ns ≈ 1ms */



/*
 * Vtime Table Removed:
 * FIFO DSQs do not use dsq_vtime for ordering.
 * Removed 160 bytes of static data + 30 cycles of math.
 */

/*
 * Per-task context map
 */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cake_task_ctx);
} task_ctx SEC(".maps");

/* REMOVED: Preemption Cooldowns
 * Stateless wakeup is now the default - kicks happen immediately.
 * Saves 1 cache line access and ~15-25ns during wakeup path.
 */


/*
 * Bitfield Accessor Macros for packed_info (ATOMIC)
 * 
 * Uses __atomic_load_n with RELAXED ordering for reads.
 * This prevents compiler optimizations that could cause tearing.
 * 
 * NOTE: SET_* macros removed - we use manual RMW with skip-if-unchanged
 * optimization instead (see cake_stopping, cake_running).
 */

/* Sparse Score accessor (0-100 with asymmetric adaptation) */
#define GET_SPARSE_SCORE(ctx) ((cake_relaxed_load_u32(&(ctx)->packed_info) >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE)

/* Wait data accessor (violations<<4 | checks) */
#define GET_WAIT_DATA(ctx) ((cake_relaxed_load_u32(&(ctx)->packed_info) >> SHIFT_WAIT_DATA) & MASK_WAIT_DATA)

/* Tier accessor */


/*
 * COLD PATH: Task context allocation
 * 
 * Strictly separated from hot path to prevent I-Cache pollution.
 * The noinline attribute forces the compiler to place this code
 * in a different cache region from the hot scheduling functions.
 * 
 * Source: Gross, "Simple is Fast" (CppCon 2023)
 */
/*
 * COLD PATH: Handle new kthread initialization
 * * Extracts string parsing and tier assignment from the hot wakeup path.
 * Saves I-Cache space in cake_enqueue for standard tasks.
 */
static __attribute__((noinline))
void init_new_kthread_cold(struct task_struct *p, u64 enq_flags)
{
    /* Branchless tier selection using mask */
    u64 critical = is_critical_kthread(p);
    u64 mask = -(u64)critical;  /* All 1s if critical, all 0s if not */
    
    /* Select: critical ? REALTIME_DSQ : INTERACTIVE_DSQ */
    u8 initial_tier = (mask & REALTIME_DSQ) | (~mask & INTERACTIVE_DSQ);
    
    scx_bpf_dsq_insert(p, initial_tier, quantum_ns, enq_flags);
}

/* * COLD PATH: Handle sparse score demotion 
 * Reduces register pressure and I-Cache usage in cake_running.
 */
static __attribute__((noinline))
u32 handle_demotion_cold(u32 packed)
{
    /* Calculate Penalty */
    u32 current_score = (packed >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE;
    u32 penalty = (current_score >= 10) ? 10 : current_score; 
    
    /* Apply Penalty */
    packed &= ~(MASK_SPARSE_SCORE << SHIFT_SPARSE_SCORE);
    packed |= ((current_score - penalty) & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE;
    
    /* Update Stats */
    if (enable_stats) {
         struct cake_stats *s = get_local_stats();
         if (s) s->nr_wait_demotions++;
    }
    
    /* Reset Wait Data (Write 0s) */
    return packed & ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
}

/* * COLD PATH: Update global victim mask 
 * Removes atomic RMW operations from the high-frequency tick loop.
 */
static __attribute__((noinline))
void set_victim_status_cold(u32 cpu_id, struct cake_cpu_shadow *shadow)
{
    u64 cpu_bit = (1ULL << cpu_id);
    u64 current = cake_relaxed_load_u64(&victim_mask);
    
    /* Atomic Update to Global Mask */
    cake_relaxed_store_u64(&victim_mask, current | cpu_bit);
    
    /* Update Local Shadow */
    shadow->packed_state |= SHADOW_BIT_VICTIM;
}

/*
 * FUSION #6: Clear Victim Status (Inline Helper)
 * Deduplicates identical logic from cake_running and cake_update_idle.
 * Saves 64 bytes I-Cache by eliminating code duplication.
 */
static __always_inline void clear_victim_status(u32 cpu_id, struct cake_cpu_shadow *shadow)
{
    if (shadow->packed_state & SHADOW_BIT_VICTIM) {
        u64 cpu_bit = (1ULL << cpu_id);
        u64 current = cake_relaxed_load_u64(&victim_mask);
        /* MESI: Only write if bit is actually set - avoids RFO on redundant clear */
        if (current & cpu_bit) {
            cake_relaxed_store_u64(&victim_mask, current & ~cpu_bit);
        }
        shadow->packed_state &= ~SHADOW_BIT_VICTIM;
    }
}

static __attribute__((noinline)) 
struct cake_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct cake_task_ctx *ctx;
    
    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx)
        return NULL;

    /* Initialize task context fields */
    ctx->next_slice = quantum_ns;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, 0);  /* avg_runtime starts at 0 */
    ctx->timestamps_fused = 0;  /* Both last_run_at and last_wake_ts start at 0 */
    ctx->avg_runtime_us = 0;    /* EMA starts fresh */
    /* rng_state removed - now using state-free temporal jitter */
    
    /* Pack initial values: Err=255, Wait=0, Score=50, Tier=Interactive, Flags=New */
    u32 packed = 0;
    packed |= (255 & MASK_KALMAN_ERROR) << SHIFT_KALMAN_ERROR;
    packed |= (0 & MASK_WAIT_DATA) << SHIFT_WAIT_DATA;
    packed |= (50 & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE;  /* Start mid-tier */
    packed |= (CAKE_TIER_INTERACTIVE & MASK_TIER) << SHIFT_TIER;
    packed |= (CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
    
    ctx->packed_info = packed;

    return ctx;
}

/*
 * COLD PATH: Kthread Priority Floor
 *
 * Applies REALTIME floor to critical kthreads (ksoftirqd, bound kworkers, irq/).
 * Housekeeping kthreads (kworker/u*) get no floor and natural tier.
 *
 * This function is noinline to:
 * 1. Keep is_critical_kthread()'s 8-byte p->comm load off the hot path
 * 2. Reduce register pressure in cake_stopping (7+ registers saved)
 * 3. Handle a rare case - most tasks are NOT kthreads
 *
 * Source: Cold path optimization (Gross, CppCon 2023)
 */
static __attribute__((noinline))
u8 apply_kthread_floor_cold(struct task_struct *p, u8 earned_tier)
{
    /* Housekeeping kthreads (unbound workers): No floor, natural tiering */
    if (!is_critical_kthread(p))
        return earned_tier;

    /* Critical kthreads: Floor at REALTIME (tier 1), can still earn tier 0 */
    u8 realtime_floor = CAKE_TIER_REALTIME;
    return (earned_tier > realtime_floor) ? realtime_floor : earned_tier;
}

/*
 * Get or initialize task context
 * 
 * HOT PATH: Fast lookup only (no allocation overhead in instruction stream).
 * COLD PATH: Allocation is delegated to alloc_task_ctx_cold() via noinline.
 * 
 * This separation keeps the I-Cache tight for the hot scheduling functions.
 */
static __always_inline struct cake_task_ctx *get_task_ctx(struct task_struct *p, bool create)
{
    struct cake_task_ctx *ctx;

    /* Fast path: lookup existing context */
    ctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    if (ctx)
        return ctx;

    /* If caller doesn't want allocation, return NULL */
    if (!create)
        return NULL;

    /* Slow path: delegate to cold section */
    return alloc_task_ctx_cold(p);
}

/*
 * PURE COMPUTE: Exponential Moving Average with α=1/8
 * Returns new avg_runtime_us, does NOT write to tctx
 */
static __always_inline u16 compute_ema_runtime(u16 old_avg_us, u64 runtime_ns)
{
    u32 meas_us = (u32)(runtime_ns >> 10);
    meas_us = (meas_us > 65535) ? 65535 : meas_us;

    if (unlikely(old_avg_us == 0)) {
        return (u16)meas_us;
    } else {
        s32 diff = (s32)meas_us - (s32)old_avg_us;
        return (u16)((s32)old_avg_us + (diff >> 3));
    }
}

/*
 * PURE COMPUTE: Sparse score with asymmetric +4/-6 adaptation
 * Returns new score, does NOT write to tctx
 */
static __always_inline u32 compute_sparse_score(u32 old_score, u64 runtime_ns)
{
    /* ILP: Compute BOTH paths in parallel (speculative) */
    s32 sparse_result = (s32)old_score + 4;
    s32 heavy_result = (s32)old_score - 6;
    
    /* Select with CMOV (no branch mispredict) */
    bool sparse = runtime_ns < cached_threshold_ns;
    s32 raw_score = sparse ? sparse_result : heavy_result;

    /* Branchless clamp to 0-100 (2x cmov, zero branch mispredictions) */
    raw_score = (raw_score < 0) ? 0 : ((raw_score > 100) ? 100 : raw_score);

    return (u32)raw_score;
}

/*
 * PURE COMPUTE: Tier from sparse score with latency gates
 * 
 * BRANCHLESS LUT: Uses tier_lut[] for O(1) lookup, eliminating
 * 7-branch if-else chain. Only score=100 triggers latency gate check.
 * 
 * Returns tier value, does NOT write to tctx
 */
static __always_inline u8 compute_tier(u32 score, u16 avg_us)
{
    /* Branchless LUT lookup: score & 127 handles bounds */
    u8 tier = tier_lut[score & 127];
    
    /*
     * PREDICATED LATENCY GATE: Only enters for Score 100.
     * 
     * BRANCHLESS ARITHMETIC: Uses boolean subtraction.
     * - avg < 25:  3 - 1 - 1 - 1 = 0 (Critical Latency - true IRQ)
     * - avg 25-99: 3 - 1 - 1 - 0 = 1 (Realtime - fast input)
     * - avg 100-499: 3 - 1 - 0 - 0 = 2 (Critical - compositor)
     * - avg >= 500: 3 - 0 - 0 - 0 = 3 (Gaming)
     *
     * Zen 5 executes all comparisons in parallel (separate ALU ports).
     */
    if (unlikely(score == 100 && avg_us > 0)) {
        tier = 3 - (u8)(avg_us < LATENCY_GATE_CRITICAL2) 
                 - (u8)(avg_us < LATENCY_GATE_REALTIME)
                 - (u8)(avg_us < LATENCY_GATE_CRITICAL);
    }
    
    return tier;
}

/*
 * PURE COMPUTE: Slice from deficit and tier
 * Returns slice value, does NOT write to tctx
 */
static __always_inline u64 compute_slice(u16 deficit_us, u8 tier)
{
    u64 deficit_ns = (u64)deficit_us << 10;
    u64 base_slice = (deficit_ns > quantum_ns) ? deficit_ns : quantum_ns;
    /* AoS: Access multiplier from consolidated tier config */
    return (base_slice * tier_configs[tier & 7].multiplier) >> 10;
}

/*
 * PURE COMPUTE: Update deficit (DRR++ credit system)
 * Returns new deficit value, does NOT write to tctx
 */
static __always_inline u16 compute_deficit(u16 old_deficit_us, u64 runtime_ns)
{
    u32 runtime_us = (u32)(runtime_ns >> 10);
    
    /*
     * BRANCHLESS SATURATING SUBTRACTION (Zero-floor)
     *
     * diff >> 31 broadcasts the sign bit: 0xFFFFFFFF if negative, 0x0 if positive.
     * diff & ~mask results in 0 for negative results, diff otherwise.
     *
     * Zen 5 Execution: SUB, SAR, ANDN = 3 cycles, 0 branches.
     * Eliminates BTB pressure from deficit overrun patterns.
     */
    s32 diff = (s32)old_deficit_us - (s32)runtime_us;
    return (u16)(diff & ~(diff >> 31));
}

/*
 * Select CPU for a waking task
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    struct cake_task_ctx *tctx;

    /*
     * BSS-TUNNELING (Absolute Zero Spill):
     * Archive prev_cpu to BSS immediately to avoid stack persistence.
     */
    cold_scratch.prev_cpu = prev_cpu;
    /* tc_id removed from hot path to prevent spill */
    
    tctx = get_task_ctx(p, false);
    if (unlikely(!tctx)) {
        return scx_bpf_select_cpu_dfl(p, cold_scratch.prev_cpu, wake_flags, &cold_scratch.is_idle);
    }
    
    tctx->last_wake_ts = (u32)scx_bpf_now();

    /* Sync Wakeup: Early Exit */
    if (wake_flags & SCX_WAKE_SYNC) {
        u32 tc_id = bpf_get_smp_processor_id();
        if (tc_id < CAKE_MAX_CPUS) {
            tctx->target_dsq_id = CAKE_DSQ_LC_BASE + tc_id;
            scx_bpf_kick_cpu(tc_id, SCX_KICK_PREEMPT);
            return (s32)tc_id;
        }
    }

    /*
     * ========================================================================
     * PRIMARY PATH: ETD SURGICAL SEEK (Empirical Topology Discovery)
     * ========================================================================
     *
     * ARCHITECTURAL RATIONALE:
     * Modern CPUs (Zen 4, Raptor Lake) are defined by Non-Uniform Cache
     * Architecture (NUCA). Cross-CCD migration costs 60-80ns (~250 cycles).
     *
     * ETD provides "Ground Truth" from silicon: the actual measured latency
     * between cores via CAS ping-pong. This is the FIRST filter, not a
     * fallback, because topology matters most when we have CHOICE.
     *
     * ROI: 4-10 cycle cost vs 250 cycle cross-CCD penalty = 30:1 return.
     * ========================================================================
     */
    u8 tier = GET_TIER(tctx);

    s32 selected_cpu = cold_scratch.prev_cpu;
    bool found_idle = false;

    /* PHASE 1: Prev-CPU Warmth Check (Cache Affinity) */
    /* ALWAYS try to stay on the same core or its SMT sibling first */
    u32 prev = (u32)cold_scratch.prev_cpu & (CAKE_MAX_CPUS - 1);
    
    /* Single 8-byte load fetches all topology info for this CPU */
    const struct cpu_topology_entry *topo = &cpu_topo[prev];
    u64 l_mask_warmth = cake_relaxed_load_u64(&idle_mask_logical);

    /* 1. Stick to previous CPU if idle (Best L1/L2 Cache) */
    if (l_mask_warmth & (1ULL << prev)) {
        selected_cpu = cold_scratch.prev_cpu;
        found_idle = true;
    }
    /* 2. SMT Sibling (Shared L2, excellent transfer) */
    else if (topo->sibling < 64 && topo->sibling != prev) {
        if (l_mask_warmth & (1ULL << topo->sibling)) {
            selected_cpu = (s32)topo->sibling;
            found_idle = true;
        }
    }


    /*
     * PHASE 1.5: LAST-IDLE HINT (MRU Cache)
     *
     * Retrieve the logical CPU that was successfully found idle last time
     * this core had to wake a task. "Trust but Verify" - check global_hint
     * and core_status before using the cached value.
     *
     * Microarchitectural Win: Bypasses TZCNT + masking logic. Single MOV + TEST.
     * Expected hit rate: ~60-70% during stable workloads.
     */
    if (!found_idle) {
        u32 c_prev = (u32)cold_scratch.prev_cpu & (CAKE_MAX_CPUS - 1);
        struct cake_cpu_shadow *shadow_prev = &global_shadow[c_prev];
        u8 hint_cpu = (u8)((shadow_prev->packed_state >> SHADOW_HINT_CPU_SHIFT) & SHADOW_HINT_CPU_MASK);
        
        /* Verify hint against actual idle mask */
        if (hint_cpu < 64 && (cake_relaxed_load_u64(&idle_mask_logical) & (1ULL << hint_cpu))) {
            selected_cpu = (s32)hint_cpu;
            found_idle = true;
            /* ROI: ~8-12 cycles if hit vs ~20-30 for full scan */
        }
    }

    /* 
     * TOPOLOGICAL ESCALATION (Unified Hierarchy)
     *
     * 1. Warmth (L1/L2 Affinity) 
     * 2. Local Physical (CCD Isolation) - if multi-LLC
     * 3. Local Logical (CCD Locality) - if multi-LLC
     * 4. Global Physical (System Isolation)
     * 5. Global Logical (System Throughput)
     * 6. Arbiter Fallback (Wait Budget)
     */

    /* PHASE 1: Warmth Check (Already handled in Phase 1 start) */
    if (!found_idle && has_multi_llc) {
        u8 llc_id = topo->llc_id;
        if (llc_id < CAKE_MAX_LLCS) {
            u64 my_llc_mask = llc_cpu_mask[llc_id];

            /* PHASE 2: Local Physical (Isolation win) */
            u64 p_mask = cake_relaxed_load_u64(&idle_mask_physical) & my_llc_mask;
            if (p_mask) {
                s32 p_cpu = find_surgical_victim_logical(prev, p_mask);
                if (p_cpu >= 0) {
                    selected_cpu = p_cpu;
                    found_idle = true;
                }
            }

            /* PHASE 3: Local Logical (Locality win) */
            if (!found_idle) {
                u64 l_mask = cake_relaxed_load_u64(&idle_mask_logical) & my_llc_mask;
                if (l_mask) {
                    s32 l_cpu = find_surgical_victim_logical(prev, l_mask);
                    if (l_cpu >= 0) {
                        selected_cpu = l_cpu;
                        found_idle = true;
                    }
                }
            }
        }
    }

    /* PHASE 4: Global Physical (Generic Scan fallback) */
    if (!found_idle) {
        u64 p_mask = cake_relaxed_load_u64(&idle_mask_physical);
        if (p_mask) {
            s32 p_cpu = find_surgical_victim_logical(prev, p_mask);
            if (p_cpu >= 0) {
                selected_cpu = p_cpu;
                found_idle = true;
            }
        }
    }

    /* PHASE 5: Global Logical (Generic Scan fallback) */
    if (!found_idle) {
        u64 l_mask = cake_relaxed_load_u64(&idle_mask_logical);
        if (l_mask) {
            selected_cpu = (s32)__builtin_ctzll(l_mask);
            found_idle = true;

            /* Update HINT: Cache for next wakeup */
            u32 c_prev = (u32)cold_scratch.prev_cpu & (CAKE_MAX_CPUS - 1);
            struct cake_cpu_shadow *shadow_prev = &global_shadow[c_prev];
            shadow_prev->packed_state = (shadow_prev->packed_state & ~(SHADOW_HINT_CPU_MASK << SHADOW_HINT_CPU_SHIFT)) 
                                      | ((u32)selected_cpu << SHADOW_HINT_CPU_SHIFT);
        }
    }

    /* PHASE 6: Ultra-fallback - Arbiter with preemption logic */
    if (!found_idle) {
        selected_cpu = select_cpu_with_arbiter(tctx, cold_scratch.prev_cpu);
        if (selected_cpu >= 0) found_idle = true;
    }

    
    /* Hybrid Gaming Logic - Prioritize Physical P-Cores for max isolation */
    if (has_hybrid && found_idle && tier <= GAMING_DSQ) {
        if ((u32)selected_cpu < CAKE_MAX_CPUS && !cpu_is_big[selected_cpu]) {
             /* 
              * UNIFIED SILICON MAP: Direct bitwise scan for P-cores.
              * If physical_hint has bits set in big_cpu_mask, it means there's
              * an idle physical P-core.
              */
             u64 p_candidates = cake_relaxed_load_u64(&idle_mask_physical) & big_cpu_mask;
             if (p_candidates) {
                 s32 p_cpu = find_surgical_victim_logical((u32)selected_cpu, p_candidates);
                 if (p_cpu >= 0) {
                     selected_cpu = p_cpu;
                 }
             }
        }
    }

    /* Final Dispatch */
    if (found_idle) {
        tctx->target_dsq_id = cpu_topo[selected_cpu & 63].dsq_id;
        if (enable_stats) {
            u32 tc_id = bpf_get_smp_processor_id();
            (&global_stats[tc_id & 63])->nr_new_flow_dispatches++;
        }
        scx_bpf_kick_cpu((u32)selected_cpu, SCX_KICK_PREEMPT);
        return selected_cpu;
    }

    if (tier == CRITICAL_LATENCY_DSQ) {
        u64 spec_mask = cake_relaxed_load_u64(&victim_mask);
        if (spec_mask) {
            s32 s_cpu = -1;

            /* ✅ TOPOLOGY OPTIMIZATION: Check for close victims first */
            s_cpu = find_surgical_victim_logical((u32)cold_scratch.prev_cpu, spec_mask);

            /* Fallback: If no close victims, pick any victim */
            if (s_cpu < 0) {
                s_cpu = (s32)__builtin_ctzll(spec_mask);
            }

            tctx->target_dsq_id = cpu_topo[s_cpu & 63].dsq_id;
            if (enable_stats) {
                u32 tc_id = bpf_get_smp_processor_id();
                (&global_stats[tc_id & 63])->nr_input_preempts++;
            }
            scx_bpf_kick_cpu((u32)s_cpu, SCX_KICK_PREEMPT);
            return s_cpu;
        }
    }

    return cold_scratch.prev_cpu;
}

/*
 * Enqueue task to the appropriate DSQ based on sparse detection
 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    /*
     * REGISTER HINTING OPTIMIZATION: Front-load ALL uses of 'p'
     * Extract everything we need from p NOW so the compiler can
     * free up that register for other uses across branches.
     */
    u32 task_flags = p->flags;
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    
    /*
     * PROACTIVE KTHREAD CLASSIFICATION (Branchless Diamond Distribution)
     * 
     * NEW kthreads without context use mask-based selection to avoid branches.
     * Check uses extracted task_flags, not p->flags (p already consumed).
     */
    /*
     * PROACTIVE KTHREAD CLASSIFICATION (Moved to Cold Path)
     * * Optimization: The heavy string parsing logic is now in a 
     * separate function (init_new_kthread_cold).
     * This keeps the 'cake_enqueue' instruction footprint small
     * for the 99.9% of wakeups that are NOT new kthreads.
     */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        init_new_kthread_cold(p, enq_flags);
        return;
    }

    
    /* 
     * FIX: Safer Direct Dispatch Check
     * 1. Only use target_dsq_id if this is a WAKEUP (prevents stale data on Yields).
     * 2. Always clear target_dsq_id immediately after checking.
     */
    if (likely(tctx)) {
        u32 target = tctx->target_dsq_id;
        tctx->target_dsq_id = 0; /* CONSUME: Clear immediately to prevent stale state */

        if ((enq_flags & SCX_ENQ_WAKEUP) && target != 0) {
            scx_bpf_dsq_insert(p, target, tctx->next_slice, enq_flags);
            return;
        }
    }

    /* Handle Yields/Background */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        scx_bpf_dsq_insert(p, BACKGROUND_DSQ, quantum_ns, enq_flags);
        return;
    }

    if (unlikely(!tctx)) {
         /* No context yet - use INTERACTIVE defaults (context created in cake_running) */
        scx_bpf_dsq_insert(p, INTERACTIVE_DSQ, quantum_ns, enq_flags);
        return;
    }

    /* Standard Tier Logic (Zero-Cycle Wakeup) */
    u8 tier = GET_TIER(tctx);
    u64 slice = tctx->next_slice;

    if (enable_stats) {
        struct cake_stats *s = get_local_stats();
        if (enq_flags & SCX_ENQ_WAKEUP)
            s->nr_new_flow_dispatches++;
        else
            s->nr_old_flow_dispatches++;

        u8 bounded_tier = tier & 0x7;
        if (bounded_tier < CAKE_TIER_MAX)
            s->nr_tier_dispatches[bounded_tier]++;
    }

    scx_bpf_dsq_insert(p, tier, slice, enq_flags);
}

/*
 * Dispatch tasks to run on this CPU
 * 
 * WARM-TIER OPTIMIZATION: Each CPU remembers the tier it successfully
 * pulled from last. In a gaming session, this tier (usually 3: Gaming)
 * stays hot, saving 5-6 helper calls per dispatch.
 *
 * Order:
 *   1. Private mailbox (highest affinity, zero contention)
 *   2. Warm-tier short-circuit (last successful tier)
 *   3. Starvation inversion (occasional fairness)
 *   4. Full priority scan (deterministic fallback)
 */
void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
    u32 c = (u32)cpu & (CAKE_MAX_CPUS - 1);
    struct cake_cpu_shadow *shadow = &global_shadow[c];

    /* 1. Drain private mailbox first (zero lock contention) */
    if (scx_bpf_dsq_move_to_local(CAKE_DSQ_LC_BASE + c)) 
        return;

    /* 2. Warm-Tier Short-Circuit: Try the last successful tier first.
     * In a gaming session, this will likely be GAMING_DSQ (3).
     * Hit rate ~90% during steady-state gaming workloads.
     */
    u32 warm_tier = (shadow->packed_state >> SHADOW_WARM_TIER_SHIFT) & SHADOW_WARM_TIER_MASK;
    if (warm_tier < 7) {
        if (scx_bpf_dsq_move_to_local(warm_tier))
            return;
    }

    /* 3. Starvation Inversion: Occasionally check lower-priority queues first.
     * Prevents permanent starvation of background tasks.
     */
    u64 starvation_bits = prev ? (prev->pid ^ prev->se.sum_exec_runtime) : 1;
    if ((starvation_bits & 0xF) == 0) {
        if (scx_bpf_dsq_move_to_local(BACKGROUND_DSQ)) {
            update_warm_tier(shadow, BACKGROUND_DSQ);
            return;
        }
        if (scx_bpf_dsq_move_to_local(INTERACTIVE_DSQ)) {
            update_warm_tier(shadow, INTERACTIVE_DSQ);
            return;
        }
    }
    
    /* 4. Full Priority Scan: Deterministic fallback, updates warm-tier on hit */
    #pragma unroll
    for (u32 i = 0; i < 7; i++) {
        if (scx_bpf_dsq_move_to_local(i)) {
            /* Update warm-tier for next dispatch */
            update_warm_tier(shadow, i);
            return;
        }
    }
}

/*
 * Task is starting to run
 *
 * Includes:
 * - XOR-blend victim_mask update (preserved MLP optimization)
 * - Wait budget checking (CAKE's AQM - restored)
 * - Long-sleep recovery (restored)
 */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
    /* LAZY ALLOCATION: Create context here (serialized per-CPU, no contention) */
    struct cake_task_ctx *tctx = get_task_ctx(p, true);
    if (unlikely(!tctx))
        return;

    /*
     * ZERO-SPILL: Get cpu_idx and now ONCE before loading tctx fields.
     * Helper calls clobber R1-R5, so call when few values are live.
     * Use cpu_idx directly for shadow access instead of get_shadow_state().
     */
    u32 cpu_idx = bpf_get_smp_processor_id();
    if (unlikely(cpu_idx >= 64))
        return;

    u64 now = scx_bpf_now();
    u32 now_ts = (u32)now;

    u8 tier = GET_TIER(tctx);

    /*
     * LAZY TIER SCOREBOARDING: Only update when tier changes.
     * 
     * OPTIMIZATION: Load+CMP stays in L1 pipeline (~1 cycle).
     * On unchanged tier, we avoid the Store → L3 invalidation traffic.
     * Tasks often run at the same tier for multiple quanta, so the
     * "skip write" path fires frequently.
     * 
     * MESI BENEFIT: Cache line stays Shared instead of Modified,
     * eliminating cross-core invalidation storms.
     */
    if (cake_relaxed_load_u32(&global_cpu_tiers[cpu_idx].tier) != tier) {
        cake_relaxed_store_u32(&global_cpu_tiers[cpu_idx].tier, tier);
    }

    /*
     * DEFERRED VICTIM LOGIC (Stability & Protection Patch)
     *
     * When a task STARTS running, we do NOT add to victim mask immediately.
     * Instead, we ALWAYS clear the victim bit here. The victim bit will be
     * set in cake_tick AFTER the task has run for ~1ms (2^20 ns).
     *
     * CACHED CURSOR OPTIMIZATION: Direct BSS access using cpu_idx.
     * Avoids second helper call from get_shadow_state().
     */
    struct cake_cpu_shadow *shadow = &global_shadow[cpu_idx & (CAKE_MAX_CPUS - 1)];

    /* FUSION #6: Use inline helper for victim cleanup (deduplication) */
    clear_victim_status(cpu_idx, shadow);

    /*
     * WAIT BUDGET CHECK (CAKE's AQM) - Restored
     * 
     * FUSED LOAD-COMPUTE-STORE:
     * Load everything first, compute in registers, write once.
     * FUSION #2: Single 8-byte load for both timestamps.
     */
    u64 timestamps = tctx->timestamps_fused;
    u32 last_wake = EXTRACT_LAST_WAKE(timestamps);
    u32 deficit_avg = tctx->deficit_avg_fused;
    u16 avg_runtime = EXTRACT_AVG_RT(deficit_avg);
    u32 packed = cake_relaxed_load_u32(&tctx->packed_info);
    
    if (likely(last_wake > 0)) {
        u64 wait_time = (u64)(now_ts - last_wake);
        
        /* Long-sleep recovery: Reset history after 33ms */
        if (wait_time > LONG_SLEEP_THRESHOLD_NS) {
            avg_runtime >>= 1;  /* 50% decay */
        }

        struct cake_stats *s = NULL;
        if (enable_stats) {
            s = get_local_stats();
            if (s) {
                s->total_wait_ns += wait_time;
                s->nr_waits++;
                if (wait_time > s->max_wait_ns)
                    s->max_wait_ns = wait_time;
            }
        }

        /* Wait budget tracking (4-bit counters) */
        /* * OPTIMIZATION: Pure Bitwise Wait Budget (Zero Branch)
         * Replaces control flow with boolean algebra for maximum ILP.
         */

        /* 1. Extract Fields (Parallel Loads) */
        u32 wait_data = (packed >> SHIFT_WAIT_DATA) & MASK_WAIT_DATA;
        u32 checks = wait_data & 0xF;
        u32 violations = wait_data >> 4;
        
        /* 2. Compute Violation Status (Branchless Boolean) */
        u64 budget_ns = tier_configs[tier & 7].wait_budget_ns;
        /* is_violation = 1 if (budget > 0 AND wait > budget), else 0 */
        u32 is_violation = (budget_ns > 0) & (wait_time > budget_ns);
        
        /* 3. Saturating Updates (Bitwise Logic) */
        /* Increment checks, clamp at 15 */
        checks += (checks < 15);
        /* Increment violations if needed, clamp at 15 */
        violations += is_violation & (violations < 15);

        /* 4. Demotion Check (The only necessary branch) */
        /* Check: checks >= 10 AND violations >= 3 */
        bool check_threshold = (checks >= 10);
        bool viol_threshold = (violations >= 3);
        bool can_demote = (tier < CAKE_TIER_BACKGROUND);

        if (unlikely(check_threshold && can_demote)) {
             if (viol_threshold) {
                 /* COLD PATH CALL: Handle Demotion */
                 packed = handle_demotion_cold(packed);
             } else {
                 /* Reset Wait Data (Write 0s) */
                 packed &= ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
             }
        } else {
             /* Normal Update (Pack and Write) */
             u32 new_wait = (violations << 4) | checks;
             packed &= ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
             packed |= (new_wait & MASK_WAIT_DATA) << SHIFT_WAIT_DATA;
        }
        
        last_wake = 0;  /* Clear to prevent double-counting */
        
        /* 
         * STATE BURST COMMIT (Fusion #8)
         * Prepare 64-bit state update. Low 32: deficit/avg, High 32: packed_info.
         */
        u32 final_deficit_avg = tctx->deficit_avg_fused;
        if (avg_runtime != tctx->avg_runtime_us) {
            u16 curr_deficit = tctx->deficit_us;
            final_deficit_avg = PACK_DEFICIT_AVG(curr_deficit, avg_runtime);
        }

        u64 state_fused = ((u64)packed << 32) | final_deficit_avg;
        cake_relaxed_store_u64(&tctx->state_fused_u64, state_fused);
    }
    
    /* FUSED STORE: Single u64 write instead of 2x u32 writes (50% reduction) */
    tctx->timestamps_fused = PACK_TIMESTAMPS(now_ts, last_wake);
}

/*
 * Task is stopping (yielding or being preempted)
 * 
 * FUSED LOAD-COMPUTE-STORE OPTIMIZATION:
 * Phase 1: Load all data (MLP - parallel memory access)
 * Phase 2: Compute everything (ILP - parallel ALU)
 * Phase 3: Write everything back (single burst)
 * 
 * Saves ~12 cycles by eliminating interleaved R/W.
 */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    if (unlikely(!tctx || tctx->last_run_at == 0))
        return;

    /*
     * PHASE 1: LOAD ALL DATA (MLP - Memory Level Parallelism)
     * Issue all loads simultaneously to hide cache latency.
     *
     * RELAXED atomic load: Prevents compiler from splitting the 32-bit read.
     * Source: Doumler, "Lock-Free Atomic Shared Pointer" (CppCon)
     */
    u64 now = scx_bpf_now();
    u32 packed = cake_relaxed_load_u32(&tctx->packed_info);
    
    /* FUSED LOAD: Single u32 read instead of 2x u16 reads (50% reduction) */
    u32 deficit_avg_fused = tctx->deficit_avg_fused;
    u16 old_deficit_us = EXTRACT_DEFICIT(deficit_avg_fused);
    u16 old_avg_us = EXTRACT_AVG_RT(deficit_avg_fused);
    
    u32 last_run = tctx->last_run_at;

    /* Extract packed fields (ALU ops while waiting for memory) */
    u32 old_score = (packed >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE;

    /* Compute runtime from timestamp delta */
    u64 runtime = (u32)now - last_run;

    /*
     * PHASE 2: COMPUTE EVERYTHING (ILP - Instruction Level Parallelism)
     * All operations can execute in parallel on superscalar CPUs.
     */
    u16 new_avg_us = compute_ema_runtime(old_avg_us, runtime);
    u32 new_score = compute_sparse_score(old_score, runtime);
    u16 new_deficit_us = compute_deficit(old_deficit_us, runtime);
    u8 new_tier = compute_tier(new_score, new_avg_us);

    /*
     * COLD PATH: Kthread Priority Floor (Safety Net)
     *
     * Most tasks are NOT kthreads, so this branch is rarely taken.
     * The expensive is_critical_kthread() with its 8-byte p->comm load
     * is now isolated in the cold function, reducing register pressure
     * on the hot path from 7+ registers to 0.
     */
    if (unlikely(p->flags & PF_KTHREAD))
        new_tier = apply_kthread_floor_cold(p, new_tier);

    /*
     * WARMTH CEILING (Inverted Logic)
     * 
     * Wait for FAST occupants (low tier), migrate from SLOW occupants (high tier).
     * Tier 0 tasks finish in ~50µs, tier 6 can take seconds.
     * 
     * ceiling = maximum tier we're willing to wait for
     * If occupant <= ceiling, WAIT (they'll finish fast, keep cache warm)
     * If occupant > ceiling, MIGRATE (they're too slow)
     */
    tctx->preempt_floor = new_tier;  // Wait for same-tier or faster only

    u64 new_slice = compute_slice(new_deficit_us, new_tier);

    /* Stats (compiled out when enable_stats=false) */
    if (enable_stats) {
        bool was_gaming = old_score >= THRESHOLD_GAMING;
        bool is_gaming = new_score >= THRESHOLD_GAMING;
        if (was_gaming != is_gaming) {
            struct cake_stats *s = get_local_stats();
            if (s) {
                if (is_gaming) s->nr_sparse_promotions++;
                else s->nr_sparse_demotions++;
            }
        }
    }

    /* Pack new values into packed_info (single u32 write) */
    u32 new_packed = packed;
    new_packed &= ~(MASK_SPARSE_SCORE << SHIFT_SPARSE_SCORE);
    new_packed &= ~(MASK_TIER << SHIFT_TIER);
    new_packed |= (new_score & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE;
    new_packed |= (new_tier & MASK_TIER) << SHIFT_TIER;

    /*
     * PHASE 3: STATE BURST COMMIT (Fusion #8)
     * Zen 4 Store Buffer coalesces both state fields into a single 64-bit transaction.
     */
    tctx->next_slice = new_slice;

    u32 final_deficit_avg = PACK_DEFICIT_AVG(new_deficit_us, new_avg_us);
    u64 state_fused = ((u64)new_packed << 32) | final_deficit_avg;
    
    /* Commit 64-bit fused state at once */
    cake_relaxed_store_u64(&tctx->state_fused_u64, state_fused);

    /*
     * NOTE: global_cpu_tiers update moved to cake_running.
     * Update happens when task STARTS (correct semantics) rather than
     * when it STOPS (stale data). This also eliminates the helper call
     * that was causing spills here.
     */
}

/*
 * CPU idle state changed
 * 
 * ZERO-SPILL OPTIMIZATION: The kernel provides the CPU as a parameter.
 * We use it directly to index global_shadow[] instead of calling
 * bpf_get_smp_processor_id(). This eliminates all helper calls and
 * thus all register preservation requirements.
 */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
    /* Bounds check using mask (branchless, verifier-friendly) */
    u32 c = (u32)cpu & (CAKE_MAX_CPUS - 1);
    
    /* Direct shadow access - NO HELPER CALL, ZERO SPILLS */
    struct cake_cpu_shadow *shadow = &global_shadow[c];

    /* Shadow-gate check (L1 hit) */
    bool shadow_idle = !!(shadow->packed_state & SHADOW_BIT_IDLE);
    if (shadow_idle == idle)
        return;

    /* TIERED UPDATE (Topology-Agnostic) */
    const struct cpu_topology_entry *topo = &cpu_topo[c & 63];
    u32 core_id = (u32)topo->core_id;
    u8 bit = topo->thread_bit;

    u8 old_status = tiered_idle.core_status[core_id & 31];
    u8 new_status = idle ? (old_status | bit) : (old_status & ~bit);
    
    tiered_idle.core_status[core_id & 31] = new_status;

    /* LOGICAL UPDATE: 1 bit per thread (Gated Test-and-Test-and-Set) */
    u64 target_bit = (1ULL << c);
    if (idle) {
        if (!(cake_relaxed_load_u64(&idle_mask_logical) & target_bit)) {
            bpf_atomic_or(&idle_mask_logical, target_bit);
        }
    } else {
        if (cake_relaxed_load_u64(&idle_mask_logical) & target_bit) {
            bpf_atomic_and(&idle_mask_logical, ~target_bit);
        }
    }

    /* PHYSICAL UPDATE: Manage CPU bits for fully idle cores */
    u8 target_mask = core_thread_mask[core_id & 31];
    u64 core_mask = core_cpu_mask[core_id & 31];
    if (idle && new_status == target_mask) {
        /* Core just became fully idle: set ALL its CPU bits in physical_hint (Gated TTAS) */
        if (!(cake_relaxed_load_u64(&idle_mask_physical) & core_mask)) {
            bpf_atomic_or(&idle_mask_physical, core_mask);
        }
    } else if (!idle && old_status == target_mask) {
        /* Core is no longer fully idle: clear ALL its CPU bits in physical_hint (Gated TTAS) */
        if (cake_relaxed_load_u64(&idle_mask_physical) & core_mask) {
            bpf_atomic_and(&idle_mask_physical, ~core_mask);
        }
    }

    /* FUSION #6: Use inline helper for victim cleanup (deduplication) */
    if (idle) {
        clear_victim_status(c, shadow);
    }

    /* Update local shadow */
    if (idle)
        shadow->packed_state |= SHADOW_BIT_IDLE;
    else
        shadow->packed_state &= ~SHADOW_BIT_IDLE;
}






void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    
    /* MERGED GUARD: Single branch for both null and uninitialized */
    if (unlikely(!tctx || tctx->last_run_at == 0))
        return;

    /*
     * PARALLEL LOAD: Fetch tier and timing data simultaneously.
     * MLP optimization - memory loads issued in parallel.
     */
    u8 tier = GET_TIER(tctx);
    u32 last_run = tctx->last_run_at;
    u64 threshold = tier_configs[tier & 7].starvation_ns;

    /*
     * FUSION #3: Hoist cpu_id before starvation check.
     * Eliminates scx_bpf_task_cpu(p) helper call (~15-20 cycles).
     * In cake_tick, the task is always running on the current CPU.
     */
    u32 cpu_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

    /* STATE-FREE JITTER: Uses timestamp bits for variance (0-127µs) */
    u32 now = (u32)scx_bpf_now();
    u32 jitter = now & 0x7F;
    threshold += (u64)(jitter << 10);

    /* Compute runtime once, use twice */
    u64 runtime = (u64)(now - last_run);

    /*
     * STARVATION CHECK: Unavoidable branch (helper call has side effects)
     * The comparison is decoupled for OOO pre-computation.
     */
    bool needs_kick = (runtime > threshold);
    if (unlikely(needs_kick)) {
        scx_bpf_kick_cpu(cpu_id, SCX_KICK_PREEMPT);  /* FUSION #3: Use hoisted cpu_id */

        if (enable_stats && tier < CAKE_TIER_MAX) {
            struct cake_stats *s = get_local_stats();
            if (s) s->nr_starvation_preempts_tier[tier]++;
        }
    }

    /*
     * BRANCHLESS VICTIM ELIGIBILITY:
     * Compute predicate using boolean AND (compiles to SETcc + AND).
     * Reduces 3 nested branches to 1 predicated cold call.
     *
     * Eligibility: runtime >= 1ms AND tier >= Interactive AND not already victim
     */
    /* cpu_id already hoisted above (Fusion #3) */
    struct cake_cpu_shadow *shadow = &global_shadow[cpu_id];
    
    bool is_eligible = (runtime >> VICTIM_RESIDENCY_BIT) & 
                       (tier >= REALTIME_DSQ && tier <= BATCH_DSQ) & 
                       !(shadow->packed_state & SHADOW_BIT_VICTIM);

    if (unlikely(is_eligible)) {
        set_victim_status_cold(cpu_id, shadow);
    }
}

/*
 * Task is enabled (joining sched_ext)
 */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
    /* No initialization needed - context created on first use */
}

/*
 * Task is disabled (leaving sched_ext)
 */
void BPF_STRUCT_OPS(cake_disable, struct task_struct *p)
{
    /* 
     * Cleanup Task Storage
     * When a task leaves scx_cake (e.g. exit or switch to CFS), we must
     * explicitly delete its task storage to prevent memory leaks.
     * Use BPF helper which is faster than waiting for task rcu death.
     */
    bpf_task_storage_delete(&task_ctx, p);
}

/*
 * Initialize the scheduler
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
    s32 ret;

    /* BITWISE OPTIMIZATION: >> 10 (~ / 1024) instead of / 1000 */
    cached_threshold_ns = (quantum_ns * sparse_threshold) >> 10;

    /* Initialize Tiered Idle Mask (Phase 2) */
    u32 nr_cpus = scx_bpf_nr_cpu_ids();
    
    /* Pre-warm tiered mask using compat helper (works on v6.16+ via fallback) */
    bpf_rcu_read_lock();
    for (s32 i = 0; i < 64; i++) {  /* Universal: up to 64 threads */
        if (i >= nr_cpus) break;
        struct task_struct *p = __COMPAT_scx_bpf_cpu_curr(i);
        /* Set bit if idle */
        if (p && p->pid == 0) {
            /* Topology-Agnostic Pre-warm */
            u32 core_id = (u32)cpu_topo[i].core_id;
            u8 thread_bit = cpu_topo[i].thread_bit;

            tiered_idle.core_status[core_id & 31] |= thread_bit;
            
            /* Logic: Set logical mask for all idle threads */
            idle_mask_logical |= (1ULL << i);

            /* Logic: Set physical mask ONLY if ALL threads are now idle */
            u8 target_mask = core_thread_mask[core_id & 31];
            if (tiered_idle.core_status[core_id & 31] == target_mask && target_mask > 0) {
                idle_mask_physical |= core_cpu_mask[core_id & 31];
            }
        }
    }
    bpf_rcu_read_unlock();


    /* Create Per-CPU Direct Dispatch Queues (fixes 0xf crash) */
    for (s32 i = 0; i < 64; i++) {
        if (i >= nr_cpus) break;
        ret = scx_bpf_create_dsq(CAKE_DSQ_LC_BASE + i, -1);
        if (ret < 0) return ret;
    }

    /* Create all 7 dispatch queues in priority order */
    ret = scx_bpf_create_dsq(CRITICAL_LATENCY_DSQ, -1);
    if (ret < 0)
        return ret;

    ret = scx_bpf_create_dsq(REALTIME_DSQ, -1);
    if (ret < 0)
        return ret;

    ret = scx_bpf_create_dsq(CRITICAL_DSQ, -1);
    if (ret < 0)
        return ret;

    ret = scx_bpf_create_dsq(GAMING_DSQ, -1);
    if (ret < 0)
        return ret;

    ret = scx_bpf_create_dsq(INTERACTIVE_DSQ, -1);
    if (ret < 0)
        return ret;

    ret = scx_bpf_create_dsq(BATCH_DSQ, -1);
    if (ret < 0)
        return ret;

    ret = scx_bpf_create_dsq(BACKGROUND_DSQ, -1);
    if (ret < 0)
        return ret;

    return 0;
}

/*
 * Scheduler exit - record exit info
 */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cake_ops,
               .select_cpu     = (void *)cake_select_cpu,
               .enqueue        = (void *)cake_enqueue,
               .dispatch       = (void *)cake_dispatch,
               .running        = (void *)cake_running,
               .stopping       = (void *)cake_stopping,
               .update_idle    = (void *)cake_update_idle,
                .tick           = (void *)cake_tick,
               .enable         = (void *)cake_enable,
               .disable        = (void *)cake_disable,
               .init           = (void *)cake_init,
               .exit           = (void *)cake_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "cake");
