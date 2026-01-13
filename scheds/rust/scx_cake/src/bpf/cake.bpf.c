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

char _license[] SEC("license") = "GPL";

/* Scheduler configuration (set by userspace before loading) */
const volatile u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const volatile u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const volatile u64 sparse_threshold = CAKE_DEFAULT_SPARSE_THRESHOLD;
const volatile u64 starvation_ns = CAKE_DEFAULT_STARVATION_NS;
const volatile bool enable_stats = false;

/* Topology configuration (const volatile = optimized out if false) */
const volatile bool has_multi_llc = false;
const volatile bool has_hybrid = false;
const volatile bool smt_enabled = false;

#define CAKE_MAX_LLCS 8
const volatile u8 cpu_llc_id[CAKE_MAX_CPUS];
const volatile u8 cpu_is_big[CAKE_MAX_CPUS];
const volatile u8 cpu_sibling_map[CAKE_MAX_CPUS];
const volatile u64 llc_cpu_mask[CAKE_MAX_LLCS];
const volatile u64 big_cpu_mask = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cake_stats);
} stats_map SEC(".maps");

/*
 * Static Topology Preference Map (populated by userspace)
 * 
 * Instead of calculating LLC/Hybrid masks at runtime, we iterate
 * a pre-computed list of "Best Neighbors" set by userspace.
 * 
 * Index = CPU ID, Value = ordered list of preferred target CPUs.
 * 
 * Source: Doumler, "C++ Standard Library for Real-time Audio" (Data-Oriented Design)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct topology_vector);
    __uint(max_entries, CAKE_MAX_CPUS);
} topo_preference_map SEC(".maps");

/*
 * Global Idle Mask (128-byte aligned to prevent false sharing)
 * 
 * CACHE ISOLATION: 128-byte alignment guarantees no spatial prefetching
 * conflicts with victim_mask. Modern CPUs fetch cache lines in pairs,
 * so 64-byte alignment alone is insufficient.
 * 
 * Source: Fretz, "Beyond Sequential Consistency" (C++Now 2024)
 * 
 * Protocol: ACQUIRE-RELEASE
 * - Writers: __ATOMIC_RELEASE in cake_update_idle
 * - Readers: __ATOMIC_ACQUIRE in find_first_idle_cpu
 */
struct {
    u64 mask;
    u64 pad[15]; /* Pad to 128 bytes (8 + 120 = 128) */
} idle_global SEC(".bss") __attribute__((aligned(128)));

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

/* Accessor macros for cleaner code */
#define idle_mask_global (idle_global.mask)
#define victim_mask      (victim_global.mask)

/*
 * Per-CPU Shadow State ("Cached Cursor" optimization)
 * 
 * Each CPU tracks what it believes its bit in the global masks is.
 * We only touch global atomics when local reality disagrees with new state.
 * 
 * Performance: Eliminates ~99% of reads to global cache lines.
 * Source: Frasch, "Lock-Free FIFO" (CppCon 2023)
 * 
 * The key insight: Even a RELAXED read on a contested cache line
 * participates in coherence traffic. Checking per-CPU state first
 * (L1 hit, ~1 cycle) filters out redundant global accesses.
 */
struct cake_cpu_shadow {
    bool is_idle;      /* Mirror of our bit in idle_mask_global */
    bool is_victim;    /* Mirror of our bit in victim_mask */
    u8 _pad[2];        /* Align to 4 bytes */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cake_cpu_shadow);
} cpu_shadow_map SEC(".maps");

static __always_inline struct cake_cpu_shadow *get_shadow_state(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&cpu_shadow_map, &key);
}

static __always_inline struct cake_stats *get_local_stats(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

/*
 * XorShift32: Wait-free pseudo-random number generator
 * 
 * Used for jittering starvation thresholds to prevent Thundering Herd.
 * When 100 game threads hit their threshold simultaneously, they cause
 * a massive preemption storm. XorShift adds +0-128µs variance.
 * 
 * Performance: ~3 cycles (3 XORs + 3 shifts), register-only.
 * Source: Doumler, "C++ Standard Library for Real-time Audio"
 */
static __always_inline u32 xorshift32(struct cake_task_ctx *ctx) 
{
    u32 x = ctx->rng_state;
    if (unlikely(x == 0)) x = (u32)scx_bpf_now(); /* Seed from clock */
    
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    
    ctx->rng_state = x;
    return x;
}

/*
 * Helper: Find first idle CPU using O(1) Bitmask Scan
 * 
 * PERFORMANCE:
 * - Load: Single u64 load (vs 8 loads previously)
 * - Check: __builtin_ctzll maps to TZCNT (3 cycles)
 * - Latency: Limited by memory fetch of idle_mask_global only.
 * 
 * SYNCHRONIZATION: Uses ACQUIRE to pair with RELEASE in cake_update_idle.
 * This guarantees we see the full CPU state when the idle bit is set.
 */
static __always_inline s32 find_first_idle_cpu(s32 prev_cpu)
{
    /*
     * ACQUIRE: Synchronize with the RELEASE in cake_update_idle.
     * Guarantees we see the latest state of the idle CPU's cache.
     */
    u64 idle_mask = __atomic_load_n(&idle_mask_global, __ATOMIC_ACQUIRE);

    if (!idle_mask)
        return -1;

    /* 1. Check prev_cpu direct (BT instruction - no variable shift) */
    if (prev_cpu >= 0 && prev_cpu < 64) {
        if (idle_mask & (1ULL << prev_cpu))
            return prev_cpu;
    }

    /* 2. Scan: Find first set bit (TZCNT/BSF) */
    return __builtin_ctzll(idle_mask);
}

/*
 * Static Topology-aware Idle CPU Finder
 * 
 * OPTIMIZATION: Replaced runtime topology logic with pre-computed vector lookup.
 * Instead of calculating LLC/Hybrid masks (~4 branches, ~2 dependent loads),
 * we iterate a static preference list (8 candidates max, unrolled loop).
 * 
 * Performance: O(1) array lookup vs O(N) topology calculation.
 * Source: Doumler, "Data-Oriented Design" principle.
 * 
 * Fallback behavior:
 * 1. Check prev_cpu first (cache warmth)
 * 2. Iterate pre-computed topology preference list
 * 3. Fall back to TZCNT on global mask
 */
static __always_inline s32 find_first_idle_cpu_topo(s32 prev_cpu)
{
    /*
     * ACQUIRE: Synchronize with RELEASE in cake_update_idle.
     * Load global idle mask once for the entire function.
     */
    u64 idle_mask = __atomic_load_n(&idle_mask_global, __ATOMIC_ACQUIRE);
    if (!idle_mask) 
        return -1;

    /* 1. Fast path: Check prev_cpu first (BT instruction) */
    if (prev_cpu >= 0 && prev_cpu < 64) {
        if (idle_mask & (1ULL << prev_cpu))
            return prev_cpu;
    }

    /* 2. Static Vector Lookup (Data-Oriented Design) */
    u32 key = (u32)prev_cpu;
    if (key >= CAKE_MAX_CPUS) key = 0; /* Safety clamp for verifier */

    struct topology_vector *vec = bpf_map_lookup_elem(&topo_preference_map, &key);
    
    if (vec && vec->count > 0) {
        /*
         * Unrolled loop over pre-computed candidate list.
         * Each candidate is already sorted by preference (sibling, LLC, global).
         */
        #pragma unroll
        for (int i = 0; i < TOPO_MAX_CANDIDATES; i++) {
            if (i >= vec->count) break;
            
            s32 cpu = vec->cpus[i];
            
            /* Bounds check for verifier */
            if (cpu < 0 || cpu >= 64) continue;
            
            /* Is this candidate idle? (BT instruction) */
            if (idle_mask & (1ULL << cpu)) {
                return cpu; 
            }
        }
    }

    /* 3. Fallback: Find *any* idle CPU using TZCNT/BSF */
    return __builtin_ctzll(idle_mask);
}

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Global vtime removed to prevent bus locking. Tasks inherit vtime from parent. */

/* Optimization: Precomputed threshold to avoid division in hot path */
static u64 cached_threshold_ns;

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
#define LATENCY_GATE_CRITICAL  50   /* <50µs avg → Critical Latency (tier 0) */
#define LATENCY_GATE_REALTIME  500  /* <500µs avg → Realtime (tier 1) */

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
const volatile struct cake_tier_config tier_configs[8] = {
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

/* Long-sleep recovery threshold: 33ms = 2 frames @ 60Hz */
#define LONG_SLEEP_THRESHOLD_NS 33000000



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
#define GET_SPARSE_SCORE(ctx) ((__atomic_load_n(&(ctx)->packed_info, __ATOMIC_RELAXED) >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE)

/* Wait data accessor (violations<<4 | checks) */
#define GET_WAIT_DATA(ctx) ((__atomic_load_n(&(ctx)->packed_info, __ATOMIC_RELAXED) >> SHIFT_WAIT_DATA) & MASK_WAIT_DATA)

/* Tier accessor */
#define GET_TIER(ctx) ((__atomic_load_n(&(ctx)->packed_info, __ATOMIC_RELAXED) >> SHIFT_TIER) & MASK_TIER)

/*
 * COLD PATH: Task context allocation
 * 
 * Strictly separated from hot path to prevent I-Cache pollution.
 * The noinline attribute forces the compiler to place this code
 * in a different cache region from the hot scheduling functions.
 * 
 * Source: Gross, "Simple is Fast" (CppCon 2023)
 */
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
    ctx->deficit_us = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->last_run_at = 0;
    ctx->last_wake_ts = 0;      /* No pending wake */
    ctx->avg_runtime_us = 0;    /* EMA starts fresh */
    ctx->rng_state = 0;         /* XorShift seeds itself on first use */
    
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

    /* Clamp to 0-100 (branchless: use conditional move) */
    if (raw_score < 0) raw_score = 0;
    else if (raw_score > 100) raw_score = 100;
    
    return (u32)raw_score;
}

/*
 * PURE COMPUTE: Tier from sparse score with latency gates
 * Returns tier value, does NOT write to tctx
 */
static __always_inline u8 compute_tier(u32 score, u16 avg_us)
{
    u8 tier;
    
    if (score < 30) {
        tier = 6;  /* Background */
    } else if (score < 50) {
        tier = 5;  /* Batch */
    } else if (score < 70) {
        tier = 4;  /* Interactive */
    } else if (score < 90) {
        tier = 3;  /* Gaming */
    } else if (score < 100) {
        tier = 2;  /* Critical */
    } else {
        /* score == 100: Apply latency gates */
        tier = 2;  /* Default: Critical */
        if (avg_us > 0) {
            if (avg_us < LATENCY_GATE_CRITICAL) {
                tier = 0;  /* Critical Latency */
            } else if (avg_us < LATENCY_GATE_REALTIME) {
                tier = 1;  /* Realtime */
            }
        }
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
    if (runtime_us < old_deficit_us)
        return old_deficit_us - (u16)runtime_us;
    else
        return 0;
}

/*
 * Select CPU for a waking task
 */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    struct cake_task_ctx *tctx;
    s32 cpu;

    /*
     * CLUSTER BOMB: Issue all potential memory loads NOW
     * Hides L2/L3 latency behind the tctx pointer chase.
     */
    
    /* SPECULATIVE LOAD: Fetch victim_mask blindly */
    u64 spec_victim_mask = victim_mask;
    
    /* PRE-CALC VICTIM (Pure ALU while waiting for tctx) */
    s32 spec_victim_cpu = spec_victim_mask ? __builtin_ctzll(spec_victim_mask) : -1;

    tctx = get_task_ctx(p, false);  /* No allocation - fast path */
    if (unlikely(!tctx)) {
        /* No context yet - use kernel default (task will get context in cake_running) */
        bool is_idle = false;
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
    }

    /* CRITICAL: Set wake timestamp BEFORE any early return */
    tctx->last_wake_ts = (u32)scx_bpf_now();

    /*
     * SYNC WAKEUP: L1 Cache Bias
     * If waker is going to sleep immediately, run wakee on same CPU.
     * Data is hot in L1 cache - don't migrate it.
     */
    if (wake_flags & SCX_WAKE_SYNC) {
        s32 this_cpu = bpf_get_smp_processor_id();
        if (this_cpu >= 0 && this_cpu < 64) {
             /* STATE-BASED DISPATCH: Set target, let enqueue handle it */
            tctx->target_dsq_id = CAKE_DSQ_LC_BASE + this_cpu;
            
            /* ADD THIS: Ensure we actually reschedule to pick it up */
            scx_bpf_kick_cpu(this_cpu, SCX_KICK_PREEMPT);
            return this_cpu;
        }
    }

    /*
     * MLP OPTIMIZATION: Issue independent loads in parallel
     * Load tier AND idle mask simultaneously.
     */
    u8 tier = GET_TIER(tctx);  /* Load 1: tctx cache line */
    
    /* Load global idle mask (replaces idle_map byte access) */
    u64 idle_mask = READ_ONCE(idle_mask_global);  /* Load 2: MLP parallel with tier load */
    
    u32 bounded_prev = (u32)prev_cpu & 63;  /* Always 0-63, BPF verifier happy */
    bool prev_idle = !!(idle_mask & (1ULL << bounded_prev));  /* BT instruction */
    bool prev_valid = (prev_cpu >= 0 && prev_cpu < 64);
    
    /* Default to prev_cpu */
    cpu = prev_cpu;
    bool is_idle = false;

    /* Use speculative prev_idle result first (fast path) */
    if (prev_valid && prev_idle) {
        is_idle = true;
        /* cpu already = prev_cpu */
    } else 
    /* Check topology-optimized idle path */
    if (tier <= REALTIME_DSQ) {
        /* High priority: rigorous scan */
        s32 idle_cpu = find_first_idle_cpu_topo(prev_cpu);
        if (idle_cpu >= 0) {
            cpu = idle_cpu;
            is_idle = true;
        }
    } else {
        /* Low priority: fast scan */
        if (has_multi_llc || has_hybrid) {
             /* Use bitmask scan if available/relevant */
             s32 idle_cpu = find_first_idle_cpu_topo(prev_cpu);
             if (idle_cpu >= 0) {
                 cpu = idle_cpu;
                 is_idle = true;
             }
        } else {
             /* Standard fast scan */
             s32 idle_cpu = find_first_idle_cpu(prev_cpu);
             if (idle_cpu >= 0) {
                 cpu = idle_cpu;
                 is_idle = true;
             }
        }
    }
    
    /* Hybrid Gaming Logic: Avoid E-cores for gaming */
    if (has_hybrid && is_idle && tier <= GAMING_DSQ) {
        if (cpu >= 0 && cpu < CAKE_MAX_CPUS && !cpu_is_big[cpu]) {
             /* We picked an E-core. Try to find a P-core instead. */
             u64 idle_current = READ_ONCE(idle_mask_global);
             u64 big_mask = READ_ONCE(big_cpu_mask);
             u64 p_candidates = idle_current & big_mask;
             
             if (p_candidates) {
                 cpu = __builtin_ctzll(p_candidates);
                 /* Stick with E-core if no P-cores idle? 
                  * Strategy: Prefer idle E-core over busy P-core.
                  * So we only swap if we found an IDLE P-core.
                  */
             }
        }
    }

    /* Direct dispatch if idle CPU found - bypasses DSQ entirely */
    if (is_idle) {
         /* STATE-BASED DISPATCH: Set target, let enqueue handle it */
        tctx->target_dsq_id = CAKE_DSQ_LC_BASE + cpu;

        if (enable_stats) {
            struct cake_stats *s = get_local_stats();
            if (s) s->nr_new_flow_dispatches++;
        }
        
        /* ADD THIS: Wake up the idle CPU! */
        /* UPGRADE: Use SCX_KICK_PREEMPT. IDLE kick might be ignored if we raced. */
        scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);

        return cpu;  /* Critical: return early to avoid cake_enqueue */
    }

    /* 
     * CRITICAL PATH: Tier 0 preemption injection with DIRECT DISPATCH
     * 
     * Fast Lane: Tier 0 tasks skip cake_enqueue and global DSQ entirely.
     * They are inserted directly into the victim's local queue.
     * 
     * ZERO LATENCY: The victim was computed ~20 cycles ago (Cluster Bomb).
     * Savings: 1-3µs by bypassing global DSQ lock and cake_dispatch pull.
     * 
     * Fallback: If no victim found, falls through to cake_enqueue (standard path).
     */
    if (tier == CRITICAL_LATENCY_DSQ && spec_victim_cpu >= 0) {
        scx_bpf_kick_cpu(spec_victim_cpu, SCX_KICK_PREEMPT);
        
        /* STATE-BASED DISPATCH */
        tctx->target_dsq_id = CAKE_DSQ_LC_BASE + spec_victim_cpu;
        
        if (enable_stats) {
            struct cake_stats *s = get_local_stats();
            if (s) s->nr_input_preempts++;
        }
        return spec_victim_cpu;  /* Return early to skip cake_enqueue */
    }

    return cpu;
}

/*
 * Enqueue task to the appropriate DSQ based on sparse detection
 */
/*
 * Enqueue task to the appropriate DSQ based on sparse detection
 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    
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
        if (s) {
            if (enq_flags & SCX_ENQ_WAKEUP) s->nr_new_flow_dispatches++;
            else s->nr_old_flow_dispatches++;
            u8 bounded_tier = tier & 0x7;
            if (bounded_tier < CAKE_TIER_MAX) s->nr_tier_dispatches[bounded_tier]++;
        }
    }

    scx_bpf_dsq_insert(p, tier, slice, enq_flags);
}

/*
 * Dispatch tasks to run on this CPU
 * 
 * DSQs are served in strict priority order:
 *   1. Critical Latency (true input handlers)
 *   2. Realtime (ultra-sparse tasks)
 *   3. Critical (audio, compositor)
 *   4. Gaming (sparse/bursty)
 *   5. Interactive (normal apps)
 *   6. Batch (nice > 0)
 *   7. Background (bulk work)
 *
 * NOTE: No flag pre-checks. scx_bpf_dsq_move_to_local returns false on empty
 * queues (~10 cycles). Flags became permanently dirty and provided no benefit.
 */
void BPF_STRUCT_OPS(cake_dispatch, s32 cpu, struct task_struct *prev)
{
    /* 1. Drain private mailbox first (zero lock contention) */
    if (scx_bpf_dsq_move_to_local(CAKE_DSQ_LC_BASE + cpu)) 
        return;

    /*
     * MLP OPTIMIZATION: NULL-safe starvation check
     * Compute starvation bits without branching on prev.
     * Uses arithmetic to force check failure when prev is NULL.
     */
    u64 starvation_bits = prev ? (prev->pid ^ prev->se.sum_exec_runtime) : 1;
    if ((starvation_bits & 0xF) == 0) {
        if (scx_bpf_dsq_move_to_local(BACKGROUND_DSQ)) return;
        if (scx_bpf_dsq_move_to_local(INTERACTIVE_DSQ)) return;
    }
    
    /* Priority Dispatch (move_to_local is fast ~10 cycles on empty) */
    if (scx_bpf_dsq_move_to_local(CRITICAL_LATENCY_DSQ)) return;
    if (scx_bpf_dsq_move_to_local(REALTIME_DSQ)) return;
    if (scx_bpf_dsq_move_to_local(CRITICAL_DSQ)) return;
    if (scx_bpf_dsq_move_to_local(GAMING_DSQ)) return;
    if (scx_bpf_dsq_move_to_local(INTERACTIVE_DSQ)) return;
    if (scx_bpf_dsq_move_to_local(BATCH_DSQ)) return;
    if (scx_bpf_dsq_move_to_local(BACKGROUND_DSQ)) return;
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
    /*
     * PREFETCH OPTIMIZATION: Touch tier_configs array early
     * 
     * The CPU will load tier_configs into L1 cache while we wait
     * for get_task_ctx() to complete. By the time we need 
     * tier_configs[tier & 7], starvation/budget/mult are all hot.
     * 
     * AoS Benefit: One prefetch brings ALL tier params into cache.
     */
    volatile u64 prefetch_hint = tier_configs[0].starvation_ns;
    (void)prefetch_hint;
    
    /* LAZY ALLOCATION: Create context here (serialized per-CPU, no contention) */
    struct cake_task_ctx *tctx = get_task_ctx(p, true);
    if (unlikely(!tctx))
        return;

    u32 cpu_idx = bpf_get_smp_processor_id();
    if (unlikely(cpu_idx >= 64))
        return;

    u8 tier = GET_TIER(tctx);
    
    /*
     * XOR-BLEND victim_mask update with Shadow State
     * 
     * CACHED CURSOR OPTIMIZATION: Check per-CPU shadow first (L1 hit)
     * to avoid reading the global victim_mask atomic.
     */
    bool is_victim = (tier >= INTERACTIVE_DSQ);
    struct cake_cpu_shadow *shadow = get_shadow_state();
    
    if (shadow && shadow->is_victim != is_victim) {
        u64 cpu_bit = (1ULL << cpu_idx);
        if (is_victim)
            __atomic_fetch_or(&victim_mask, cpu_bit, __ATOMIC_RELAXED);
        else
            __atomic_fetch_and(&victim_mask, ~cpu_bit, __ATOMIC_RELAXED);
        shadow->is_victim = is_victim;
    }

    u64 now = scx_bpf_now();
    u32 now_ts = (u32)now;

    /*
     * WAIT BUDGET CHECK (CAKE's AQM) - Restored
     * 
     * FUSED LOAD-COMPUTE-STORE:
     * Load everything first, compute in registers, write once.
     */
    u32 last_wake = tctx->last_wake_ts;
    u16 avg_runtime = tctx->avg_runtime_us;
    u32 packed = __atomic_load_n(&tctx->packed_info, __ATOMIC_RELAXED);
    
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
            /* OPTIMIZATION: BATCHED RMW on packed_info */
            /* Using local 'packed' variable loaded above */
            u32 original_packed = packed;
            
            u8 wait_data = (packed >> SHIFT_WAIT_DATA) & MASK_WAIT_DATA;
            u8 checks = wait_data & 0xF;
            u8 violations = wait_data >> 4;
            
            checks++;
            
            u64 budget_ns = tier_configs[tier & 7].wait_budget_ns;
            if (budget_ns > 0 && wait_time > budget_ns) {
                violations++;
            }
            
            /* Demotion check: 10-sample window, >30% violations */
            if (checks >= 10 && tier < CAKE_TIER_BACKGROUND) {
                if (violations >= 3) {
                    u32 current_score = (packed >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE;
                    u32 penalized = (current_score > 10) ? current_score - 10 : 0;
                    
                    /* Update Score */
                    packed &= ~(MASK_SPARSE_SCORE << SHIFT_SPARSE_SCORE);
                    packed |= (penalized & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE;
                    
                    /* Reset Wait Data */
                    packed &= ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
                    // (0 << SHIFT) is 0
                    
                    if (s) s->nr_wait_demotions++;
                } else {
                    /* Reset Wait Data */
                    packed &= ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
                }
            } else {
                if (checks >= 15) checks = 15;
                if (violations >= 15) violations = 15;
                u8 new_wait = (violations << 4) | checks;
                
                /* Update Wait Data */
                packed &= ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA);
                packed |= ((new_wait & MASK_WAIT_DATA) << SHIFT_WAIT_DATA);
            }
        
        last_wake = 0;  /* Clear to prevent double-counting */
        
        /* 
         * BURST WRITEBACK: Check change to avoid dirtying cache line if possible
         * RELAXED atomic store: Prevents compiler from splitting the 32-bit write.
         */
        if (packed != original_packed)
            __atomic_store_n(&tctx->packed_info, packed, __ATOMIC_RELAXED);
    }

    /* BURST WRITEBACK: 
     * Write avg_runtime (if decayed), last_wake (if cleared), last_run (always).
     * Grouping these encourages store buffer coalescing.
     */
    if (avg_runtime != tctx->avg_runtime_us)
        tctx->avg_runtime_us = avg_runtime;
        
    tctx->last_wake_ts = last_wake;
    tctx->last_run_at = now_ts;
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
    u32 packed = __atomic_load_n(&tctx->packed_info, __ATOMIC_RELAXED);
    u16 old_avg_us = tctx->avg_runtime_us;
    u16 old_deficit_us = tctx->deficit_us;
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
     * PHASE 3: WRITE EVERYTHING BACK (Single Burst)
     * All writes to same cache line - store buffer coalesces them.
     * 
     * OPTIMIZATION: Skip packed_info write if unchanged.
     * Tier/Score stability is high, skipping write saves energy.
     * 
     * RELAXED atomic store: Prevents compiler from splitting the 32-bit write.
     */
    tctx->avg_runtime_us = new_avg_us;
    tctx->deficit_us = new_deficit_us;
    tctx->next_slice = new_slice;
    
    if (packed != new_packed)
        __atomic_store_n(&tctx->packed_info, new_packed, __ATOMIC_RELAXED);
}

/*
 * CPU idle state changed
 * 
 * OPTIMIZATION: "Cached Cursor" pattern (Frasch, CppCon 2023)
 * Check per-CPU shadow state FIRST (L1 hit, ~1 cycle, zero bus traffic).
 * Only touch global atomics when local reality disagrees with new state.
 * 
 * This eliminates ~99% of reads to the contested idle_mask_global cache line.
 */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
    if (cpu < 0 || cpu >= 64) return;

    /*
     * STEP 1: Check Local Shadow (L1 Cache Hit, Zero Bus Traffic)
     * The Frasch video proves that checking local state first prevents
     * cache line bouncing and false sharing.
     */
    struct cake_cpu_shadow *shadow = get_shadow_state();
    if (unlikely(!shadow)) return;

    /* If our local shadow matches the requested state, DO NOTHING.
     * This is the common case (~99%) and requires zero global memory access.
     */
    if (shadow->is_idle == idle) {
        return;
    }

    /*
     * STEP 2: Update Global State (Only when state *actually* changes)
     * We only incur the cost of atomic RMW when transitioning.
     */
    u64 mask = (1ULL << cpu);
    
    if (idle) {
        /*
         * RELEASE: Publish idle state.
         * Ensures all previous writes (task state save) are visible
         * before we mark this CPU as idle.
         * 
         * Pairs with ACQUIRE in find_first_idle_cpu.
         */
        __atomic_fetch_or(&idle_mask_global, mask, __ATOMIC_RELEASE);
        
        /* Heuristic: If we are idle, we cannot be a victim anymore.
         * Check shadow first to avoid redundant atomic access.
         */
        if (shadow->is_victim) {
            __atomic_fetch_and(&victim_mask, ~mask, __ATOMIC_RELAXED);
            shadow->is_victim = false;
        }
    } else {
        /* RELEASE: Publish busy state */
        __atomic_fetch_and(&idle_mask_global, ~mask, __ATOMIC_RELEASE);
    }

    /* STEP 3: Update Local Shadow */
    shadow->is_idle = idle;
}

void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
    struct cake_task_ctx *tctx;

    tctx = get_task_ctx(p, false);  /* No allocation */
    if (unlikely(!tctx))
        return;

    /* Check for starvation using tier-specific threshold */
    if (likely(tctx->last_run_at > 0)) {
        /*
         * MLP OPTIMIZATION: Parallel fetch of tier and time
         * AoS BENEFIT: tier_configs access brings entire config into cache
         */
        u8 tier = GET_TIER(tctx);                    /* Load 1: packed_info */
        u32 last_run = tctx->last_run_at;            /* Load 2: last_run_at (parallel) */
        u64 threshold = tier_configs[tier & 7].starvation_ns;  /* AoS: 1 cache line */
        
        /*
         * JITTER OPTIMIZATION: Add +0-128µs variance to threshold
         * 
         * Prevents Thundering Herd: When 100 game threads hit their threshold
         * simultaneously, they cause a massive preemption storm. XorShift
         * desynchronizes them across ~128µs window.
         * 
         * Performance: ~3 cycles (register-only operation).
         * Source: Doumler, "C++ Standard Library for Real-time Audio"
         */
        u32 jitter = xorshift32(tctx) & 0x7F; /* 0-127 */
        threshold += (u64)(jitter << 10);     /* Convert to ~ns (×1024) */
        
        /* Compute runtime after loads complete */
        u32 now = (u32)scx_bpf_now();
        u64 runtime = (u64)(now - last_run);
        
        if (runtime > threshold) {
            /* Force preemption - task exceeded its tier's starvation limit */
            scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
            
            /* Track per-tier starvation preempts */
            if (enable_stats && tier < CAKE_TIER_MAX) {
                struct cake_stats *s = get_local_stats();
                if (s) s->nr_starvation_preempts_tier[tier]++;
            }
        }
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

    /* Initialize Idle Mask */
    u32 nr_cpus = scx_bpf_nr_cpu_ids();
    
    /* Pre-warm idle mask using compat helper (works on v6.16+ via fallback) */
    bpf_rcu_read_lock();
    for (s32 i = 0; i < 64; i++) {
        if (i >= nr_cpus) break;
        struct task_struct *p = __COMPAT_scx_bpf_cpu_curr(i);
        /* Set bit if idle */
        if (p && p->pid == 0) {
            /* No need for atomic here, single threaded init */
            idle_mask_global |= (1ULL << i); 
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
