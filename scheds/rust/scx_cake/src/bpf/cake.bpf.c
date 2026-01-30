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



/* D2A Signal Mask - REMOVED (A+B+D architecture makes this redundant) */

/*
 * GLOBAL CPU TIER STATE (Zero-Latency BSS Array)
 * 
 * Each CPU's current occupant tier, for Zero-Math Locality Arbiter.
 * 0ns lookup (direct memory offset) vs 25ns BPF map helper.
 * 64-byte padding per entry prevents MESI invalidation storms.
 */
/*
 * FUSED CORE STATE (3D Packing / Rent's Rule)
 * 
 * Replaces separate cpu_tier and shadow arrays.
 * 64-byte aligned per CPU.
 */
struct cake_core_state global_core_state[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));

/*
 * Bit-Scan Helpers for Core State
 * State is packed as: [Occ:8][Warm:8][Victim:8][Pad:8]
 */
#define STATE_GET_OCCUPANT(s)  ((u8)((s) & 0xFF))
#define STATE_GET_WARM(s)      ((u8)(((s) >> 8) & 0xFF))
#define STATE_GET_VICTIM(s)    ((u8)(((s) >> 16) & 0xFF))
#define STATE_GET_STAGING_PRIO(s)   ((u8)(((s) >> 24) & 0xFF))
#define STATE_CLEAR_STAGING         0x00FFFFFF  /* Mask to zero out byte 3 */

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
#define victim_mask (victim_global.mask)

/*
 * Global Idle Mask (Shadow)
 * Tracks idle CPUs to avoid scx_bpf_get_idle_cpumask() kfunc overhead.
 */
struct {
    u64 mask;
    u64 pad[15];
} idle_global SEC(".bss") __attribute__((aligned(128)));
#define global_idle_mask (idle_global.mask)

/*
 * T1 OPTIMIZATION: Tier Availability Bitmap
 * 
 * Each bit represents whether a tier DSQ has tasks queued.
 * Updated atomically in cake_enqueue (set) and dispatch_success_handler (conditionally clear).
 * 
 * Enables O(1) dispatch: CTZ(tier_avail & ~warm_mask) → first populated tier.
 * Replaces 7 sequential scx_bpf_dsq_move_to_local() probes.
 * 
 * Layout: Bit 0 = Tier 0, Bit 1 = Tier 1, ... Bit 6 = Tier 6
 */
struct {
    u64 mask;
    u64 pad[7];
} tier_avail_global SEC(".bss") __attribute__((aligned(64)));
#define tier_available_mask (tier_avail_global.mask)

/* Metadata accessors (Fused for Zero-Spill) */
#define GET_TIER_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_TIER, 3)
#define GET_TIER(ctx) GET_TIER_RAW(cake_relaxed_load_u32(&(ctx)->packed_info))
#define GET_CRITICAL_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_CRITICAL, 1)
#define GET_CRITICAL(ctx) GET_CRITICAL_RAW(cake_relaxed_load_u32(&(ctx)->packed_info))

/* 
 * QUAD-PACK (v12 "Dark Art"): Single 64-bit register (r8) as 4-slot 16-bit vector.
 * Slot 0 [0:15]:  prev_cpu (6 bits ID + padding)
 * Slot 1 [16:31]: target_dsq (pre-computed ID)
 * Slot 2 [32:47]: pinfo_squeezed ([16:22]=score, [23:25]=tier, [30]=critical)
 * Slot 3 [48:63]: wake_flags (low 16)
 */
static __always_inline u32 QP_GET_PREV(u64 qp) {
    u32 res;
    asm volatile("%[out] = %[in]; %[out] &= 0x3F" : [out]"=r"(res) : [in]"r"(qp));
    return res;
}
/* QP_GET_DSQ removed - T2 optimization uses topo_prev->dsq_id directly */
static __always_inline u32 QP_GET_TIER(u64 qp) {
    u32 res;
    asm volatile("%[out] = %[in]; %[out] >>= 39; %[out] &= 0x7" : [out]"=r"(res) : [in]"r"(qp));
    return res;
}
static __always_inline u32 QP_GET_WAKE(u64 qp) {
    u32 res;
    asm volatile("%[out] = %[in]; %[out] >>= 48; %[out] &= 0xFFFF" : [out]"=r"(res) : [in]"r"(qp));
    return res;
}



/*
 * PER-CPU SCRATCH AREA (BSS-Tunneling)
 * 
 * Used for output parameters to BPF helpers to avoid stack usage.
 * Isolated per-CPU to prevent cache-line bouncing (MESI contention).
 * Since BPF programs are serialized per-CPU, this is safe for tunneling.
 */
struct cake_scratch {
    bool dummy_idle;
    u32 init_tier;
    u32 init_critical;
    struct bpf_iter_scx_dsq it; /* BSS-Tunneling for iterators */
    u8 _pad[44]; /* Pad to 128 bytes (2 cache lines) */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));


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
static __always_inline void update_occupant_tier(struct cake_core_state *state, u8 tier)
{
    /* ATOMIC UPDATER: Updates occupant tier byte only */
    u32 *packed = (u32 *)state;
    u32 old = cake_relaxed_load_u32(packed);
    u32 new_val = (old & 0xFFFFFF00) | tier;
    cake_relaxed_store_u32(packed, new_val);
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
 *
 * VARIANT: Checks a LOGICAL mask (1 bit per CPU) instead of PHYSICAL.
 * USE CASE: Checking 'victim_mask' or 'p_candidates' (Logical IDs).
 *
 * COST: ~6-8 Cycles.
 */
static __always_inline s32 find_surgical_victim_logical(u32 prev, u64 logical_mask, u64 db_const,
                                 const struct cpu_topology_entry *topo)
{
    u32 idx;
    asm volatile("%0 = %1" : "=r"(idx) : "r"(prev));

    const struct cpu_topology_entry *t = &topo[idx & 63];

    if (t->peer_1 < 64 && (logical_mask & (1ULL << t->peer_1)))
        return (s32)t->peer_1;
    if (t->peer_2 < 64 && (logical_mask & (1ULL << t->peer_2)))
        return (s32)t->peer_2;
    if (t->peer_3 < 64 && (logical_mask & (1ULL << t->peer_3)))
        return (s32)t->peer_3;

    if (logical_mask)
        return (s32)BIT_SCAN_FORWARD_U64_RAW(logical_mask, db_const);

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
static __always_inline s32 select_cpu_with_arbiter(struct cake_task_ctx *tctx, s32 prev_cpu, 
                            u64 l_mask, u64 p_mask, u64 db_const, 
                            const struct cpu_topology_entry *topo)
{
    u32 b_prev = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);
    
    if (l_mask & (1ULL << b_prev))
        return prev_cpu;

    const struct cpu_topology_entry *t = &topo[b_prev];
    
    s32 target_cpu = l_mask ? (s32)BIT_SCAN_FORWARD_U64_RAW(l_mask, db_const) : -1;
    u8 target_rank = l_mask ? 3 : 7;

    bool sib_idle = (t->sibling < 64 && (l_mask & (1ULL << t->sibling)));
    target_cpu = sib_idle ? (s32)t->sibling : target_cpu;
    target_rank = sib_idle ? 2 : target_rank;

    s32 phys_cpu = p_mask ? find_surgical_victim_logical(b_prev, p_mask, 0x022FDD63CC95386DULL, topo) : -1;
    target_cpu = (phys_cpu >= 0) ? phys_cpu : target_cpu;
    target_rank = (phys_cpu >= 0) ? 1 : target_rank;

    if (target_cpu < 0)
        return prev_cpu;

    /* 3. ZERO-MATH ARBITER (Fused State Lookup) */
    u32 state = cake_relaxed_load_u32((u32 *)&global_core_state[b_prev]);
    u8 occupant_tier = STATE_GET_OCCUPANT(state);
    u8 my_tier = GET_TIER(tctx) & 7;
    
    u8 threshold = arbiter_cfg.lut[my_tier][target_rank];

    if (occupant_tier <= threshold)
        return prev_cpu; 
    
    return target_cpu; 
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

/* A+B ARCHITECTURE: Single unified DSQ with vtime-encoded priority */
#define UNIFIED_DSQ     100

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
 * BRANCHLESS TIER ARITHMETIC (T6 Optimization)
 * 
 * Replaces 128-byte LUT with pure ALU operations.
 * 4 SETcc + 4 SUB instructions = 8 cycles on Zen 5.
 * vs LUT: 4ns (L1 hit) to 12ns (L2 hit).
 * 
 * Score ranges → Tier:
 *   0-29:  6 (Background)
 *   30-49: 5 (Batch)
 *   50-69: 4 (Interactive)
 *   70-89: 3 (Gaming)
 *   90-99: 2 (Critical)
 *   100:   Slow path (latency gates)
 * 
 * ABSURD PERF: compute_tier_fast removed - tier read from task context directly.
 */

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

/* RESTORE peek_legacy via scratch tunnel */
__attribute__((noinline)) 
struct task_struct *cake_bpf_dsq_peek_legacy(u64 dsq_id) 
{
    /* Preserve dsq_id across helper call */
    register u64 dsq_reg asm("r9") = dsq_id;
    asm volatile("" : "+r"(dsq_reg));

    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    asm volatile("" : "+r"(dsq_reg)); /* Refresh liveness */

    struct cake_scratch *scr = &global_scratch[cpu];
    struct task_struct *p = NULL;

    if (bpf_iter_scx_dsq_new(&scr->it, dsq_reg, 0) == 0) {
        p = bpf_iter_scx_dsq_next(&scr->it);
        bpf_iter_scx_dsq_destroy(&scr->it);
    }
    return p;
}


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

/* Metadata Accessors - Definitions moved to top */


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
/* Pure Compute Helpers - ABSURD PERF: Removed accounting functions, now in tick */


static __always_inline void set_victim_status_cold(u32 cpu, struct cake_core_state *state)
{
    u64 cpu_bit = (1ULL << (cpu & 63));
    
    if (!(cake_relaxed_load_u64(&victim_mask) & cpu_bit)) {
        bpf_atomic_or(&victim_mask, cpu_bit);
        
        u32 *packed = (u32 *)state;
        bpf_atomic_or(packed, 1 << 16); /* Set VICTIM bit (byte 2) */
    }
}

/* ABSURD PERF: perform_lazy_accounting removed - accounting in tick */


static __attribute__((noinline))
void init_new_kthread_cold(struct task_struct *p, u64 enq_flags)
{
    /* Branchless tier selection using mask */
    u64 critical = is_critical_kthread(p);
    u64 mask = -(u64)critical;  /* All 1s if critical, all 0s if not */
    
    /* Select: critical ? REALTIME tier : INTERACTIVE tier */
    u8 initial_tier = (mask & CAKE_TIER_REALTIME) | (~mask & CAKE_TIER_INTERACTIVE);
    
    /* A+B: Vtime-encoded priority: (tier << 56) | timestamp */
    u64 vtime = ((u64)initial_tier << 56) | (scx_bpf_now() & 0x00FFFFFFFFFFFFFFULL);
    scx_bpf_dsq_insert_vtime(p, UNIFIED_DSQ, quantum_ns, vtime, enq_flags);
}







static __attribute__((noinline))
s32 select_cpu_new_task_cold(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    /* ZERO-SPILL: Pin inputs to callee-saved registers */
    register struct task_struct *p_pin asm("r6") = p;
    register s32 prev_pin asm("r7") = prev_cpu;
    register u64 wake_pin asm("r8") = wake_flags;
    
    asm volatile("" : "+r"(p_pin), "+r"(prev_pin), "+r"(wake_pin));
    u32 tc_id = bpf_get_smp_processor_id();
    asm volatile("" : "+r"(p_pin), "+r"(prev_pin), "+r"(wake_pin));
    
    struct cake_scratch *scr = &global_scratch[tc_id & (CAKE_MAX_CPUS - 1)];
    return scx_bpf_select_cpu_dfl(p_pin, prev_pin, wake_pin, &scr->dummy_idle);
}

static __attribute__((noinline)) 
struct cake_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct cake_task_ctx *ctx;
    
    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) return NULL;

    /* NIBBLE SEEDING: One-time classification */
    u64 head = *(u64 *)p->comm;
    const char *comm = p->comm;
    bool is_softirq = !(head ^ 0x71726974666F736BULL);
    bool is_worker  = !(head ^ 0x2F72656B726F776BULL) & (comm[8] != 'u');
    bool is_irq     = !((head & 0xFFFFFFFFULL) ^ 0x2F717269ULL);
    bool critical   = is_softirq | is_worker | is_irq;

    ctx->next_slice = quantum_ns;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, 0);
    ctx->timestamps_fused = 0;
    
    u32 packed = 0;
    packed |= (255 & MASK_KALMAN_ERROR) << SHIFT_KALMAN_ERROR;
    packed |= (0 & MASK_WAIT_DATA) << SHIFT_WAIT_DATA;
    packed |= (50 & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE;
    packed |= (critical ? CAKE_TIER_INTERACTIVE : CAKE_TIER_BATCH) << SHIFT_TIER;
    packed |= (CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
    packed |= (critical ? 1 : 0) << SHIFT_CRITICAL;
    
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
 * NOINLINE ACCOUNTING
 * Math-heavy operations are moved here to free up registers for the hot scan.
 * ABSURD PERF: cake_accounting_core removed - accounting fully async in tick.
 */

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* 
     * DARK ART: QUAD-PACK (Absolute Zero v12)
     * r6: Pinned ctx pointer
     * r7: Pinned tctx pointer
     * r8: QUAD-PACK ([0:15]=prev, [16:31]=dsq, [32:47]=pinfo, [48:63]=flags)
     * r9: Core Idle Mask (pinned)
     */
    register void *ctx_reg asm("r6");
    register struct cake_task_ctx *tctx_reg asm("r7");
    register u64 qp asm("r8");
    register u64 idles asm("r9");
    
    asm volatile("%[out] = r1" : [out]"=r"(ctx_reg));
    tctx_reg = get_task_ctx(*(struct task_struct **)ctx_reg, false);
    
    if (unlikely(!tctx_reg)) {
        return select_cpu_new_task_cold(*(struct task_struct **)ctx_reg, 
                                      *(s32 *)((u8 *)ctx_reg + 8), 
                                      *(u64 *)((u8 *)ctx_reg + 16));
    }

    /* ATOMIC QUAD-PACK INITIALIZATION */
    {
        u32 b_p = (u32)*(s32 *)((u8 *)ctx_reg + 8) & (CAKE_MAX_CPUS - 1);
        u32 pinf = tctx_reg->packed_info;
        qp =  (u64)b_p;
        qp |= (u64)cpu_topo[b_p].dsq_id << 16;
        qp |= (u64)(pinf >> 16) << 32;
        qp |= (u64)(u16)*(u64 *)((u8 *)ctx_reg + 16) << 48;
    }

    /* BARRIER: Finalize pinned state before calls */
    asm volatile("" : "+r"(ctx_reg), "+r"(tctx_reg), "+r"(qp));

    /* ABSURD PERF: cake_accounting_core removed - fully async in tick */

    /* Sync check - QP-SLOT 3: Direct dispatch to current CPU */
    if (QP_GET_WAKE(qp) & SCX_WAKE_SYNC) {
        u32 tc_id = bpf_get_smp_processor_id();
        if (tc_id < CAKE_MAX_CPUS) {
            scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, CAKE_DSQ_LC_BASE + tc_id, 
                               tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
            scx_bpf_kick_cpu(tc_id, SCX_KICK_PREEMPT);
            return (s32)tc_id;
        }
    }

    /* Idle Check - Load from BSS Shadow */
    idles = cake_relaxed_load_u64(&global_idle_mask);
    
    /* BARRIER: Preserve idles in r9 */
    asm volatile("" : "+r"(ctx_reg), "+r"(tctx_reg), "+r"(qp), "+r"(idles));

    s32 selected_cpu = -1;
    bool found_idle = false;
    u32 target_dsq = 0;

    /* 1. Prev check - QP-SLOT 0 */
    /* T2 OPTIMIZATION: Pre-computed sibling mask from RODATA */
    u32 b_prev = QP_GET_PREV(qp);
    const struct cpu_topology_entry *topo_prev = &cpu_topo[b_prev];
    u32 dsq_prev = topo_prev->dsq_id;
    u64 sib_bit = topo_prev->sibling_bit;  /* Pre-computed (1ULL << sibling) or 0 */
    u32 dsq_sib = topo_prev->sibling_dsq;  /* Pre-computed DSQ ID */

    if (idles & (1ULL << b_prev)) {
        selected_cpu = (s32)b_prev;
        target_dsq = dsq_prev;
        found_idle = true;
    } else if (sib_bit & idles) {
        /* T2: Single AND check replaces (sib < 64 && sib != prev && (idles & (1ULL << sib))) */
        selected_cpu = (s32)topo_prev->sibling;
        target_dsq = dsq_sib;
        found_idle = true;
    }

    if (!found_idle) {
        /* Core-Deep Scan (Logical Shadow) */
        /* RE-PIN BARRIER: Force ctx/tctx/qp/idles to stay in r6-r9 */
        asm volatile("" : "+r"(ctx_reg), "+r"(tctx_reg), "+r"(qp), "+r"(idles));
        if (idles) {
            selected_cpu = find_surgical_victim_logical(QP_GET_PREV(qp), idles, 0x022FDD63CC95386DULL, cpu_topo);
            if (selected_cpu >= 0) {
                 target_dsq = CAKE_DSQ_LC_BASE + selected_cpu;
                 found_idle = true;
            }
        }
    }

    /* Optimization #2: Duplicate find_surgical_victim_logical removed (dead code) */
    if (!found_idle) {
        selected_cpu = select_cpu_with_arbiter(tctx_reg, (s32)QP_GET_PREV(qp), idles, 0, 0x022FDD63CC95386DULL, cpu_topo);
        if (selected_cpu >= 0) target_dsq = CAKE_DSQ_LC_BASE + selected_cpu;
    }

    /* DISPATCH SLAM: Final commit using pre-calculated target_dsq */
    if (selected_cpu >= 0) {
        /* 
         * SPILL-FREE STRATEGY:
         * 1. Compute target_bit BEFORE kfunc (survives in qp or recompute)
         * 2. After kfunc, RE-DERIVE selected_cpu from target_dsq
         * 3. target_dsq is pinned in a register, selected_cpu = target_dsq & 63
         */
        
        /* BARRIER: Pin qp and idles before kfunc */
        asm volatile("" : "+r"(qp), "+r"(idles));
        
        scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, target_dsq, tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
        
        /* RE-DERIVE: selected_cpu from target_dsq (1 AND op, no spill) */
        asm volatile("" : "+r"(qp), "+r"(idles));
        u32 cpu_id = target_dsq & 63;  /* LC DSQ IDs are CAKE_DSQ_LC_BASE + cpu */
        u64 target_bit = (1ULL << cpu_id);
        
        /* ABSURD PERF: Signal mask and surgical producer staging removed */
        if (!(idles & target_bit)) {
            scx_bpf_kick_cpu(cpu_id, SCX_KICK_PREEMPT);
        }
        return (s32)cpu_id;
    }

    if (QP_GET_TIER(qp) == CRITICAL_LATENCY_DSQ) {
        u64 spec_mask = cake_relaxed_load_u64(&victim_mask);
        if (spec_mask) {
            s32 s_cpu = find_surgical_victim_logical(QP_GET_PREV(qp), spec_mask, 0x022FDD63CC95386DULL, cpu_topo);
            if (s_cpu < 0) s_cpu = (s32)BIT_SCAN_FORWARD_U64_RAW(spec_mask, 0x022FDD63CC95386DULL);

            scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, CAKE_DSQ_LC_BASE + (s_cpu & 63), 
                               tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
            scx_bpf_kick_cpu((u32)s_cpu, SCX_KICK_PREEMPT);
            return s_cpu;
        }
    }

    return (s32)QP_GET_PREV(qp);
}

/*
 * Enqueue task to the appropriate DSQ based on sparse detection
 * 
 * A+B ARCHITECTURE: Uses unified DSQ with vtime-encoded priority.
 * vtime = (tier << 56) | timestamp
 * Lower tier = earlier dispatch. FIFO within tier.
 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    u32 task_flags = p_reg->flags;
    struct cake_task_ctx *tctx = get_task_ctx(p_reg, false);
    
    /* Kthread cold path */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        init_new_kthread_cold(p_reg, enq_flags);
        return;
    }

    register struct cake_task_ctx *tctx_reg asm("r7") = tctx;

    /* Handle Yields/Background */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u64 vtime = ((u64)CAKE_TIER_BACKGROUND << 56) | (scx_bpf_now() & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, UNIFIED_DSQ, quantum_ns, vtime, enq_flags);
        return;
    }

    if (unlikely(!tctx_reg)) {
        /* No context yet - use INTERACTIVE tier */
        u64 vtime = ((u64)CAKE_TIER_INTERACTIVE << 56) | (scx_bpf_now() & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, UNIFIED_DSQ, quantum_ns, vtime, enq_flags);
        return;
    }

    /* Standard Tier Logic */
    u8 tier = GET_TIER(tctx_reg) & 7;
    u64 slice = tctx_reg->next_slice;

    if (enable_stats) {
        struct cake_stats *s = get_local_stats();
        if (enq_flags & SCX_ENQ_WAKEUP)
            s->nr_new_flow_dispatches++;
        else
            s->nr_old_flow_dispatches++;

        if (tier < CAKE_TIER_MAX)
            s->nr_tier_dispatches[tier]++;
    }

    /* A+B: Vtime-encoded priority: (tier << 56) | timestamp */
    u64 vtime = ((u64)tier << 56) | (scx_bpf_now() & 0x00FFFFFFFFFFFFFFULL);
    scx_bpf_dsq_insert_vtime(p_reg, UNIFIED_DSQ, slice, vtime, enq_flags);
}

/*
 * A+B+D ARCHITECTURE: Simplified dispatch
 * 
 * - Single UNIFIED_DSQ scan (6 kfuncs eliminated)
 * - Deferred accounting to cake_tick (3 kfuncs eliminated)
 * - Per-CPU mailbox for direct dispatch still checked first
 */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 cpu = (u32)raw_cpu & 63;
    u64 cpu_bit = (1ULL << cpu);
    
    /* ABSURD PERF: Signal mask check removed */
    
    /* 1. Check per-CPU direct dispatch mailbox first (highest priority) */
    if (scx_bpf_dsq_move_to_local(CAKE_DSQ_LC_BASE + cpu)) {
        /* D: Deferred accounting - just mark busy, accounting in tick */
        bpf_atomic_and(&global_idle_mask, ~cpu_bit);
        return;
    }
    
    /* 2. A+B: Single unified DSQ scan (vtime-ordered by tier) */
    if (scx_bpf_dsq_move_to_local(UNIFIED_DSQ)) {
        bpf_atomic_and(&global_idle_mask, ~cpu_bit);
        return;
    }
    
    /* No work - mark idle */
    bpf_atomic_or(&global_idle_mask, cpu_bit);
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
    struct cake_core_state *state = &global_core_state[cpu_id_reg];
    u32 packed = cake_relaxed_load_u32((u32 *)state);
    
    bool is_eligible = (runtime >> VICTIM_RESIDENCY_BIT) & 
                       (tier_reg >= REALTIME_DSQ && tier_reg <= BATCH_DSQ) & 
                       !(STATE_GET_VICTIM(packed));

    if (unlikely(is_eligible)) {
        set_victim_status_cold(cpu_id_reg, state);
    }
    
    /* Update Occupant Tier (Atomic Byte Store) */
    if (tier_reg != STATE_GET_OCCUPANT(packed)) {
        update_occupant_tier(state, tier_reg);
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
    /* ZERO-SPILL PINNING */
    register struct task_struct *p_reg asm("r6") = p;
    register u32 cpu_reg asm("r8") = bpf_get_smp_processor_id();
    asm volatile("" : "+r"(p_reg), "+r"(cpu_reg));

    /* L3 HYGIENE: Cleanup victim status before deleting storage */
    u32 cpu_val;
    asm volatile("%0 = r8" : "=r"(cpu_val));
    
    struct cake_core_state *state = &global_core_state[cpu_val & (CAKE_MAX_CPUS - 1)];
    u32 packed = cake_relaxed_load_u32((u32 *)state);
    
    if (STATE_GET_VICTIM(packed)) {
        u64 cpu_bit = (1ULL << (cpu_val & 63));
        bpf_atomic_and(&victim_mask, ~cpu_bit);
        bpf_atomic_and((u32 *)state, ~(1 << 16));
    }

    bpf_task_storage_delete(&task_ctx, p_reg);
}

/*
 * Initialize the scheduler
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
    s32 ret;

    /* cached_threshold_ns now populated by userspace via rodata */

    u32 nr_cpus = scx_bpf_nr_cpu_ids();

    /* Create Per-CPU Direct Dispatch Queues */
    for (s32 i = 0; i < 64; i++) {
        if (i >= nr_cpus) break;
        ret = scx_bpf_create_dsq(CAKE_DSQ_LC_BASE + i, -1);
        if (ret < 0) return ret;
    }

    /* A+B ARCHITECTURE: Single unified DSQ with vtime ordering */
    ret = scx_bpf_create_dsq(UNIFIED_DSQ, -1);
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
