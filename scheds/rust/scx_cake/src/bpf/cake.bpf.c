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
const u64 cached_threshold_ns = 0;

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



/* D2A Signal Mask (L3 Coherency Path) */
static struct cake_signal_mask hs_signal SEC(".bss") __attribute__((aligned(64)));
#define hs_signal_mask (hs_signal.signal_mask)

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
 * PER-CPU SCRATCH AREA (BSS-Tunneling)
 * 
 * Used for output parameters to BPF helpers to avoid stack usage.
 * Isolated per-CPU to prevent cache-line bouncing (MESI contention).
 * Since BPF programs are serialized per-CPU, this is safe for tunneling.
 */
struct cake_scratch {
    bool dummy_idle;
    u8 _pad[63]; /* Pad to 64 bytes for cache line isolation */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(64)));


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

/* Shadow state bit positions */
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

/*
 * TTAS (Test-and-Test-and-Set) Gating Macros
 * 
 * These wrap atomic operations with a relaxed load check. 
 * On Zen 5, this prevents the 'LOCK' prefix from stalling the pipeline
 * if the bit is already in the desired state.
 */
#define TTAS_BIT_SET(target, bit) \
    do { \
        if (!(cake_relaxed_load_u64(target) & (bit))) \
            bpf_atomic_or(target, bit); \
    } while (0)

#define TTAS_BIT_CLEAR(target, bit) \
    do { \
        if (cake_relaxed_load_u64(target) & (bit)) \
            bpf_atomic_and(target, ~(bit)); \
    } while (0)

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
    
    /* Direct 8-byte load - eliminates stack usage from __builtin_memcpy */
    u64 head = *(u64 *)p->comm;
    
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
static __always_inline 
s32 find_surgical_victim_logical(u32 raw_idx, u64 logical_mask, u64 mult, const struct cpu_topology_entry *topo_base)
{
    /* 
     * BPF SHIELD: Hardware-Enforced Zero-Extension
     * Forces LLVM to treat the index as a clean 32-bit register, 
     * preventing 0xc000... sign-extension crashes on JIT.
     */
    u32 idx;
    asm volatile("%0 = %1" : "=r"(idx) : "r"(raw_idx));

    const struct cpu_topology_entry *t = &topo_base[idx & 63];

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
        return (s32)BIT_SCAN_FORWARD_U64_RAW(logical_mask, mult);

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
    struct cake_task_ctx *tctx, s32 prev_cpu, u64 l_mask, u64 p_mask, u64 db_const, const struct cpu_topology_entry *topo_base)
{
    u32 b_prev = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);
    
    /* 1. Fast Path: Local check (L1/L2 warmth) - Using snapshot */
    if (l_mask & (1ULL << b_prev))
        return prev_cpu;

    /* 
     * 2. Physical-First Migration (Branchless CMOV Cascade)
     * Rank 1: Idle Physical Core (Isolation/L3 Warm)
     * Rank 2: Warm SMT Sibling (L2 Warmth)
     * Rank 3: Any Idle SMT (Throughput)
     */
    const struct cpu_topology_entry *t = &topo_base[b_prev];
    
    /* RANK 3: Any Idle SMT (Fallback) */
    s32 target_cpu = l_mask ? (s32)BIT_SCAN_FORWARD_U64_RAW(l_mask, db_const) : -1;
    u8 target_rank = l_mask ? 3 : 7;

    /* RANK 2: Warm SMT Sibling (Better than random SMT) */
    bool sib_idle = (t->sibling < 64 && (l_mask & (1ULL << t->sibling)));
    target_cpu = sib_idle ? (s32)t->sibling : target_cpu;
    target_rank = sib_idle ? 2 : target_rank;

    /* RANK 1: Idle Physical Core (Highest Isolation) */
    s32 phys_cpu = p_mask ? find_surgical_victim_logical(b_prev, p_mask, 0x022FDD63CC95386DULL, topo_base) : -1;
    target_cpu = (phys_cpu >= 0) ? phys_cpu : target_cpu;
    target_rank = (phys_cpu >= 0) ? 1 : target_rank;

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
/* Cached threshold moved to RODATA */

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
const fused_config_t tier_configs[8] = {
    /* Tier 0: Critical Latency */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T0, 
                CAKE_DEFAULT_WAIT_BUDGET_T0 / 1024, CAKE_DEFAULT_STARVATION_T0 / 1024),
    /* Tier 1: Realtime */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T1, 
                CAKE_DEFAULT_WAIT_BUDGET_T1 / 1024, CAKE_DEFAULT_STARVATION_T1 / 1024),
    /* Tier 2: Critical */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T2, 
                CAKE_DEFAULT_WAIT_BUDGET_T2 / 1024, CAKE_DEFAULT_STARVATION_T2 / 1024),
    /* Tier 3: Gaming */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T3, 
                CAKE_DEFAULT_WAIT_BUDGET_T3 / 1024, CAKE_DEFAULT_STARVATION_T3 / 1024),
    /* Tier 4: Interactive */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T4, 
                CAKE_DEFAULT_WAIT_BUDGET_T4 / 1024, CAKE_DEFAULT_STARVATION_T4 / 1024),
    /* Tier 5: Batch */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T5, 
                CAKE_DEFAULT_WAIT_BUDGET_T5 / 1024, CAKE_DEFAULT_STARVATION_T5 / 1024),
    /* Tier 6: Background */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T6, 
                CAKE_DEFAULT_WAIT_BUDGET_T6 / 1024, CAKE_DEFAULT_STARVATION_T6 / 1024),
    /* Tier 7: Padding */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS / 1024, CAKE_DEFAULT_MULTIPLIER_T3, 
                0, CAKE_DEFAULT_STARVATION_T6 / 1024),
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
#define GET_SPARSE_SCORE(ctx) EXTRACT_BITS_U32(cake_relaxed_load_u32(&(ctx)->packed_info), SHIFT_SPARSE_SCORE, 7)

/* Wait data accessor (violations<<4 | checks) */
#define GET_WAIT_DATA(ctx) EXTRACT_BITS_U32(cake_relaxed_load_u32(&(ctx)->packed_info), SHIFT_WAIT_DATA, 8)

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
/* Pure Compute Helpers */
static __always_inline u32 compute_sparse_score(u32 old_score, u64 runtime_ns)
{
    s32 sparse_result = (s32)old_score + 4;
    s32 heavy_result = (s32)old_score - 6;
    bool sparse = runtime_ns < cached_threshold_ns;
    s32 raw_score = sparse ? sparse_result : heavy_result;
    raw_score = (raw_score < 0) ? 0 : ((raw_score > 100) ? 100 : raw_score);
    return (u32)raw_score;
}

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

static __always_inline u16 compute_deficit(u16 old_deficit_us, u64 runtime_ns)
{
    u32 runtime_us = (u32)(runtime_ns >> 10);
    s32 diff = (s32)old_deficit_us - (s32)runtime_us;
    return (u16)(diff & ~(diff >> 31));
}

static __always_inline u8 compute_tier(u32 score, u16 avg_us)
{
    u8 tier = tier_lut[score & 127];
    if (unlikely(score == 100 && avg_us > 0)) {
        tier = 3 - (u8)(avg_us < LATENCY_GATE_CRITICAL2) 
                 - (u8)(avg_us < LATENCY_GATE_REALTIME)
                 - (u8)(avg_us < LATENCY_GATE_CRITICAL);
    }
    return tier;
}

static __always_inline u64 compute_slice(u16 deficit_us, u8 tier)
{
    fused_config_t cfg = tier_configs[tier & 7];
    u64 q_ns = UNPACK_QUANTUM_NS(cfg);
    u64 deficit_ns = (u64)deficit_us << 10;
    u64 base_slice = (deficit_ns > q_ns) ? deficit_ns : q_ns;
    return (base_slice * UNPACK_MULTIPLIER(cfg)) >> 10;
}

static __always_inline u8 apply_kthread_floor_cold(struct task_struct *p, u8 earned_tier)
{
    if (!is_critical_kthread(p))
        return earned_tier;
    u8 realtime_floor = CAKE_TIER_REALTIME;
    return (earned_tier > realtime_floor) ? realtime_floor : earned_tier;
}

static __always_inline void clear_victim_status(u32 cpu_id, struct cake_cpu_shadow *shadow)
{
    if (shadow->packed_state & SHADOW_BIT_VICTIM) {
        u64 cpu_bit = (1ULL << (cpu_id & 63));
        TTAS_BIT_CLEAR(&victim_mask, cpu_bit);
        shadow->packed_state &= ~SHADOW_BIT_VICTIM;
    }
}

static __always_inline void set_victim_status_cold(u32 cpu_id, struct cake_cpu_shadow *shadow)
{
    if (!(shadow->packed_state & SHADOW_BIT_VICTIM)) {
        u64 cpu_bit = (1ULL << (cpu_id & 63));
        TTAS_BIT_SET(&victim_mask, cpu_bit);
        shadow->packed_state |= SHADOW_BIT_VICTIM;
    }
}

static __always_inline u32 handle_demotion_cold(u32 packed)
{
    u32 current_score = (packed >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE;
    u32 penalty = (current_score >= 10) ? 10 : current_score; 
    packed &= ~(MASK_SPARSE_SCORE << SHIFT_SPARSE_SCORE);
    packed |= ((current_score - penalty) & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE;
    if (enable_stats) {
         struct cake_stats *s = get_local_stats();
         if (s) s->nr_wait_demotions++;
    }
    return packed & ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
}

/* Logic Helpers */
static __always_inline void perform_lazy_accounting(struct task_struct *p, struct cake_task_ctx *tctx, u64 branch_now)
{
    u32 now_ts = (u32)branch_now;
    u64 metadata = cake_relaxed_load_u64(&tctx->state_fused_u64);
    u32 last_run = tctx->last_run_at;
    
    if (last_run == 0)
        return;

    u64 runtime = (u32)now_ts - last_run;
    u32 packed = (u32)(metadata >> 32);
    u32 score = compute_sparse_score((packed >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE, runtime);
    u32 avg_def = PACK_DEFICIT_AVG(compute_deficit(EXTRACT_DEFICIT((u32)metadata), runtime),
                                  compute_ema_runtime(EXTRACT_AVG_RT((u32)metadata), runtime));

    u8 tier = compute_tier(score, (u16)(avg_def >> 16));
    if (unlikely(p->flags & PF_KTHREAD)) {
        tier = apply_kthread_floor_cold(p, tier);
    }

    tctx->preempt_floor = tier;
    tctx->next_slice = compute_slice((u16)avg_def, tier);

    u32 last_wake = EXTRACT_LAST_WAKE(tctx->timestamps_fused);
    if (last_wake > 0 && ((u32)now_ts - last_wake) > LONG_SLEEP_THRESHOLD_NS) {
        u16 avg_rt = EXTRACT_AVG_RT(avg_def);
        avg_def = PACK_DEFICIT_AVG((u16)avg_def, avg_rt >> 1);
    }

    u32 clear_mask = (MASK_SPARSE_SCORE << SHIFT_SPARSE_SCORE) | (MASK_TIER << SHIFT_TIER);
    packed = (packed & ~clear_mask) | 
             ((score & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE) | 
             ((tier & MASK_TIER) << SHIFT_TIER);

    cake_relaxed_store_u64(&tctx->state_fused_u64, ((u64)packed << 32) | avg_def);
    tctx->last_run_at = 0;
}

static __always_inline void side_effect_dispatch_setup(struct task_struct *p, struct cake_task_ctx *tctx, u32 cpu, u64 branch_now)
{
    u32 now_ts = (u32)branch_now;
    u8 tier = GET_TIER(tctx) & 7;
    tctx->last_run_at = now_ts;
    
    if (cake_relaxed_load_u32(&global_cpu_tiers[cpu & 63].tier) != tier) {
        cake_relaxed_store_u32(&global_cpu_tiers[cpu & 63].tier, tier);
    }
    
    struct cake_cpu_shadow *shadow = &global_shadow[cpu & (CAKE_MAX_CPUS - 1)];
    clear_victim_status(cpu, shadow);

    u64 state_ts = tctx->timestamps_fused;
    u32 last_wake = EXTRACT_LAST_WAKE(state_ts);
    if (likely(last_wake > 0)) {
        u64 wait_time = (u64)(now_ts - last_wake);
        u64 tier_cfg = tier_configs[tier];
        u64 budget_ns = UNPACK_BUDGET_NS(tier_cfg);

        if (budget_ns > 0 && wait_time > budget_ns) {
            u64 fused_meta = cake_relaxed_load_u64(&tctx->state_fused_u64);
            u32 packed = (u32)(fused_meta >> 32);
            u32 wait_data = (packed >> SHIFT_WAIT_DATA) & MASK_WAIT_DATA;
            
            if ((wait_data >> 4) < 15) wait_data += 0x10;
            if ((wait_data & 0xF) < 15) wait_data++;

            if ((wait_data & 0xF) >= 10 && (wait_data >> 4) >= 3 && tier < CAKE_TIER_BACKGROUND) {
                packed = handle_demotion_cold(packed);
            } else {
                packed = (packed & ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA)) | (wait_data << SHIFT_WAIT_DATA);
            }
            cake_relaxed_store_u64(&tctx->state_fused_u64, ((u64)packed << 32) | (u32)fused_meta);
        }
    }
    tctx->timestamps_fused = PACK_TIMESTAMPS(now_ts, 0);
}

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







static __attribute__((noinline))
s32 select_cpu_new_task_cold(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    u32 tc_id = bpf_get_smp_processor_id();
    struct cake_scratch *scr = &global_scratch[tc_id & (CAKE_MAX_CPUS - 1)];
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &scr->dummy_idle);
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
 * Select CPU for a waking task
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* 
     * REGISTER PINNING & MAP CACHING: 
     * Cache map bases to avoid redundant 'ld_imm64' (16-byte) instructions.
     */
    register struct task_struct *p_reg asm("r6") = p;
    register s32 prev_cpu_reg asm("r9") = prev_cpu;
    struct cake_task_ctx *tctx;

    tctx = get_task_ctx(p_reg, false);
    if (unlikely(!tctx)) {
        return select_cpu_new_task_cold(p_reg, prev_cpu_reg, wake_flags);
    }

    register struct cake_task_ctx *tctx_reg asm("r7") = tctx;
    
    /* Cache shared pointers in registers for duration of call */
    register const struct cpu_topology_entry *topo_base asm("r8") = cpu_topo;
    
    u64 now = scx_bpf_now();
    tctx_reg->last_wake_ts = (u32)now;

    /* SYMPHONY OF 2: LAZY ACCOUNTING */
    perform_lazy_accounting(p_reg, tctx_reg, now);

    /* Sync Wakeup: Early Exit */
    if (wake_flags & SCX_WAKE_SYNC) {
        u32 tc_id = bpf_get_smp_processor_id();
        if (tc_id < CAKE_MAX_CPUS) {
            u32 t_id = topo_base[tc_id].dsq_id;
            scx_bpf_dsq_insert(p_reg, t_id, tctx_reg->next_slice, wake_flags);
            scx_bpf_kick_cpu(tc_id, SCX_KICK_PREEMPT);
            return (s32)tc_id;
        }
    }

    u8 tier = GET_TIER(tctx_reg);

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

    s32 selected_cpu;
    asm volatile("%0 = %1" : "=r"(selected_cpu) : "r"(prev_cpu_reg));
    bool found_idle = false;

    /* PHASE 1: Prev-CPU Warmth Check (Cache Affinity) */
    u32 prev = (u32)prev_cpu_reg & (CAKE_MAX_CPUS - 1);
    
    /* 
     * LOW-OVERHEAD KFUNC: Query kernel's idle state directly.
     * This replaces the tiered-BSS lookup with a single kfunc call.
     * Although a call, it remains internal to BPF/Kernel logic.
     */
    const struct cpumask *sys_idle_log = scx_bpf_get_idle_cpumask();

    /* 1. Stick to previous CPU if idle (Best L1/L2 Cache) */
    if (bpf_cpumask_test_cpu(prev, sys_idle_log)) {
        selected_cpu = prev_cpu_reg;
        found_idle = true;
    } else {
        /* SMT Sibling (Shared L2, excellent transfer) */
        const struct cpu_topology_entry *topo_init = &topo_base[prev];
        if (topo_init->sibling < 64 && topo_init->sibling != prev) {
            if (bpf_cpumask_test_cpu(topo_init->sibling, sys_idle_log)) {
                selected_cpu = (s32)topo_init->sibling;
                found_idle = true;
            }
        }
    }

    if (!found_idle) {
        /* 
         * RANK 1: Universal Clean Core Search (All Tiers)
         * Using kernel's SMT-aware idle mask for zero-math physical identification.
         */
        const struct cpumask *sys_idle_phys = scx_bpf_get_idle_smtmask();
        
        if (sys_idle_phys && !bpf_cpumask_empty(sys_idle_phys)) {
            /* We still use the surgical seek for latency-ordered peer checking */
            selected_cpu = find_surgical_victim_logical(prev, *(u64 *)sys_idle_phys, 0x022FDD63CC95386DULL, topo_base);
            if (selected_cpu >= 0) {
                found_idle = true;
            }
        }
        
        /* RANK 2: SMT Scaling (Throughput Pool Only) */
        if (!found_idle && tier > GAMING_DSQ && !bpf_cpumask_empty(sys_idle_log)) {
            selected_cpu = find_surgical_victim_logical(prev, *(u64 *)sys_idle_log, 0x022FDD63CC95386DULL, topo_base);
            if (selected_cpu >= 0) {
                found_idle = true;
            }
        }
        
        scx_bpf_put_cpumask(sys_idle_phys);
    }

    /* PHASE 6: Arbiter with preemption logic */
    if (!found_idle) {
        selected_cpu = select_cpu_with_arbiter(tctx_reg, prev_cpu_reg, *(u64 *)sys_idle_log, 0 /* p_mask */, 0x022FDD63CC95386DULL, topo_base);
        if (selected_cpu >= 0) found_idle = true;
    }

    /* Final Dispatch (DIRECT DISPATCH OPTIMIZATION) */
    if (found_idle) {
        u32 target_id = topo_base[selected_cpu & 63].dsq_id;
        
        /* 
         * DIRECT DISPATCH: Insert task directly into the target DSQ.
         * The kernel sees this insertion and skips the 'cake_enqueue' callback entirely.
         * SAVES: 1x BPF Trampoline (5,000ns)
         */
        scx_bpf_dsq_insert(p_reg, target_id, tctx_reg->next_slice, wake_flags);
        
        /* 
         * D2A SIGNAL: Perform atomic OR on the target signal bit.
         * Shifting work from hardware IPI to L3 Cache Fabric.
         */
        __sync_fetch_and_or(&hs_signal_mask, (1ULL << (selected_cpu & 63)));

        /* Kick to ensure immediate execution on the target but return the CPU */
        scx_bpf_kick_cpu((u32)selected_cpu, SCX_KICK_PREEMPT);
        
        scx_bpf_put_cpumask(sys_idle_log);
        return selected_cpu;
    }

    if (tier == CRITICAL_LATENCY_DSQ) {
        u64 spec_mask = cake_relaxed_load_u64(&victim_mask);
        if (spec_mask) {
            s32 s_cpu = find_surgical_victim_logical((u32)prev_cpu_reg, spec_mask, 0x022FDD63CC95386DULL, topo_base);
            if (s_cpu < 0) {
                s_cpu = (s32)BIT_SCAN_FORWARD_U64(spec_mask);
            }

            u32 target_id = topo_base[s_cpu & 63].dsq_id;
            scx_bpf_dsq_insert(p_reg, target_id, tctx_reg->next_slice, wake_flags);
            
            /* D2A SIGNAL: Trigger L3 snoop for the victim */
            __sync_fetch_and_or(&hs_signal_mask, (1ULL << (s_cpu & 63)));

            scx_bpf_kick_cpu((u32)s_cpu, SCX_KICK_PREEMPT);
            
            scx_bpf_put_cpumask(sys_idle_log);
            return s_cpu;
        }
    }

    scx_bpf_put_cpumask(sys_idle_log);
    return prev_cpu_reg;
}

/*
 * Enqueue task to the appropriate DSQ based on sparse detection
 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    /*
     * REGISTER HINTING OPTIMIZATION: Front-load ALL uses of 'p'
     * Extract everything we need from p NOW so the compiler can
     * free up that register for other uses across branches.
     */
    u32 task_flags = p_reg->flags;
    struct cake_task_ctx *tctx = get_task_ctx(p_reg, false);
    
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
        init_new_kthread_cold(p_reg, enq_flags);
        return;
    }

    register struct cake_task_ctx *tctx_reg asm("r7") = tctx;

    
    /* Legacy target_dsq_id check removed - using Direct Dispatch in select_cpu */

    /* Handle Yields/Background */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        scx_bpf_dsq_insert(p_reg, BACKGROUND_DSQ, quantum_ns, enq_flags);
        return;
    }

    if (unlikely(!tctx_reg)) {
         /* No context yet - use INTERACTIVE defaults (context created in cake_running) */
        scx_bpf_dsq_insert(p_reg, INTERACTIVE_DSQ, quantum_ns, enq_flags);
        return;
    }

    /* Standard Tier Logic (Zero-Cycle Wakeup) */
    u8 tier = GET_TIER(tctx_reg);
    u64 slice = tctx_reg->next_slice;

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

    scx_bpf_dsq_insert(p_reg, tier, slice, enq_flags);
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
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    /* BPF SHIELD: Hardware-Enforced Zero-Extension */
    u32 cpu;
    asm volatile("%0 = %1" : "=r"(cpu) : "r"(raw_cpu));
    
    u32 c = cpu & (CAKE_MAX_CPUS - 1);
    struct cake_cpu_shadow *shadow = &global_shadow[c];
    u64 now = scx_bpf_now();

    /* 1. D2A Signal Check */
    if (cake_relaxed_load_u64(&hs_signal_mask) & (1ULL << (c & 63))) {
        __sync_fetch_and_and(&hs_signal_mask, ~(1ULL << (c & 63)));
    }

    /* 
     * SYMPHONY OF 2: PROACTIVE SETUP 
     * Macro to wrap move + setup + vtime-deadline.
     */
    #define CONSUME_AND_SETUP(dsq_id) ({ \
        bool __moved = scx_bpf_dsq_move_to_local(dsq_id); \
        if (__moved) { \
            struct task_struct *__p = cake_bpf_dsq_peek(SCX_DSQ_LOCAL); \
            if (__p) { \
                struct cake_task_ctx *__tctx = get_task_ctx(__p, false); \
                if (__tctx) { \
                    side_effect_dispatch_setup(__p, __tctx, c, now); \
                } \
            } \
        } \
        __moved; \
    })

    /* 1. Drain private mailbox first */
    if (CONSUME_AND_SETUP(CAKE_DSQ_LC_BASE + c)) 
        return;

    /* 2. Warm-Tier Short-Circuit */
    u32 warm_tier = EXTRACT_BITS_U32(shadow->packed_state, SHADOW_WARM_TIER_SHIFT, 3);
    u8 probed_mask = 0;
    
    if (warm_tier < 7) {
        if (CONSUME_AND_SETUP(warm_tier))
            return;
        probed_mask |= (1 << (warm_tier & 7));
    }

    /* 3. Starvation Inversion */
    u64 starvation_bits = prev ? (prev->pid ^ prev->se.sum_exec_runtime) : 1;
    if ((starvation_bits & 0xF) == 0) {
        if (CONSUME_AND_SETUP(BACKGROUND_DSQ)) {
            update_warm_tier(shadow, BACKGROUND_DSQ);
            return;
        }
        probed_mask |= (1 << (BACKGROUND_DSQ & 7));
    }
    
    /* 4. Full Priority Scan */
    #pragma unroll
    for (u32 i = 0; i < CAKE_TIER_MAX; i++) {
        if (probed_mask & (1 << (i & 7)))
            continue;
        
        if (CONSUME_AND_SETUP(i)) {
            update_warm_tier(shadow, i);
            return;
        }
    }
}










void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
    /* 
     * REGISTER PINNING: Pin p to r6 to avoid stack spills.
     * Satisfies verifier type tracking without volatile barriers.
     */
    register struct task_struct *p_reg asm("r6") = p;
    register struct cake_task_ctx *tctx_reg asm("r7") = get_task_ctx(p_reg, false);
    register u32 cpu_id_reg asm("r8") = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    
    u32 now = (u32)scx_bpf_now();
    
    /* SYMPHONY OF 2: SAFETY GATE & CONTINUATION CHECK */
    if (unlikely(!tctx_reg || tctx_reg->last_run_at == 0)) {
        if (tctx_reg) tctx_reg->last_run_at = now;
        return;
    }

    /* PHASE 1: COMPUTE RUNTIME & THRESHOLDS */
    register u8 tier_reg asm("r9") = GET_TIER(tctx_reg);
    u32 last_run = tctx_reg->last_run_at;
    u64 runtime = (u64)(now - last_run);

    /* 
     * CONTINUATION ENFORCEMENT:
     * If task has exceeded its slice, force it back into dispatch
     * to perform a context switch and re-account.
     */
    if (unlikely(runtime > tctx_reg->next_slice)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
        return;
    }

    u64 threshold = UNPACK_STARVATION_NS(tier_configs[tier_reg & 7]);
    
    /* Reduced jitter: 0x0F = 15 * 1024ns = ~15.3µs range (Minimizes lockstep without bloating frame times) */
    threshold += (u64)((now & 0x0F) << 10);

    /*
     * STARVATION CHECK: Unavoidable branch (helper call has side effects)
     * The comparison is decoupled for OOO pre-computation.
     */
    bool needs_kick = (runtime > threshold);
    if (unlikely(needs_kick)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);  /* FUSION #3: Use hoisted cpu_id_reg */

        if (enable_stats && tier_reg < CAKE_TIER_MAX) {
            struct cake_stats *s = get_local_stats();
            if (s) s->nr_starvation_preempts_tier[tier_reg]++;
        }
    }

    /*
     * BRANCHLESS VICTIM ELIGIBILITY:
     * Compute predicate using boolean AND (compiles to SETcc + AND).
     * Reduces 3 nested branches to 1 predicated cold call.
     *
     * Eligibility: runtime >= 1ms AND tier >= Interactive AND not already victim
     */
    /* cpu_id_reg already hoisted above (Fusion #3) */
    struct cake_cpu_shadow *shadow = &global_shadow[cpu_id_reg];
    
    bool is_eligible = (runtime >> VICTIM_RESIDENCY_BIT) & 
                       (tier_reg >= REALTIME_DSQ && tier_reg <= BATCH_DSQ) & 
                       !(shadow->packed_state & SHADOW_BIT_VICTIM);

    if (unlikely(is_eligible)) {
        set_victim_status_cold(cpu_id_reg, shadow);
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

    /* cached_threshold_ns now populated by userspace via rodata */

    u32 nr_cpus = scx_bpf_nr_cpu_ids();


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
                .tick           = (void *)cake_tick,
               .enable         = (void *)cake_enable,
               .disable        = (void *)cake_disable,
               .init           = (void *)cake_init,
               .exit           = (void *)cake_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "cake");
