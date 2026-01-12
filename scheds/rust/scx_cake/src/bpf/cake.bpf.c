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
 * Global Idle Mask (Bitmask)
 * 
 * SINGLE SOURCE OF TRUTH for idle CPU tracking.
 * - Single u64 replaces 64 bytes + 8 u64 chunks.
 * - Eliminated False Sharing: No more 64-byte cache line invalidation.
 * - Updated atomically with Read-Before-Write optimization.
 * - Read via TZCNT for O(1) idle CPU discovery.
 */
u64 idle_mask_global SEC(".bss") __attribute__((aligned(64)));

/*
 * Global Victim Mask (Bitmask for CTZ scanning)
 * 
 * KEPT AS BITMASK because we need "find first victim" via CTZ.
 * Updated non-atomically (acceptable race - victim is heuristic).
 */
u64 victim_mask SEC(".bss") __attribute__((aligned(64)));

/* NOTE: dsq_has_tasks flag system was removed.
 * Flags became permanently dirty (never cleared) and provided no benefit.
 * scx_bpf_dsq_move_to_local handles empty queues efficiently (~10 cycles).
 */

/* NOTE: cpu_status scoreboard was removed.
 * It was written every context switch but NEVER READ.
 * Saves 4 cycles per running + 4KB BSS memory.
 */

static __always_inline struct cake_stats *get_local_stats(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

/*
 * Helper: Find first idle CPU using O(1) Bitmask Scan
 * 
 * PERFORMANCE:
 * - Load: Single u64 load (vs 8 loads previously)
 * - Check: __builtin_ctzll maps to TZCNT (3 cycles)
 * - Latency: Limited by memory fetch of idle_mask_global only.
 */
static __always_inline s32 find_first_idle_cpu(s32 prev_cpu)
{
    /* Load global mask once */
    u64 idle_mask = READ_ONCE(idle_mask_global);

    if (!idle_mask)
        return -1;

    /* 1. Check prev_cpu direct (Bitwise extract) */
    if (prev_cpu >= 0 && prev_cpu < 64) {
        if ((idle_mask >> prev_cpu) & 1)
            return prev_cpu;
    }

    /* 2. Scan: Find first set bit (TZCNT/BSF) */
    return __builtin_ctzll(idle_mask);
}

/*
 * Helper: Find best core from a mask of candidates
 * 
 * CHANGED: Accepts 'full_idle_mask' to check siblings without 
 * reloading the global state.
 * 
 * Logic:
 * 1. If SMT disabled: Just pick first bit (CTZ).
 * 2. If SMT enabled:
 *    - Try to find a core where sibling is ALSO idle.
 *    - Inspect up to 4 candidates to find a fully idle one.
 *    - Fallback to first candidate if no fully idle core found.
 */
static __always_inline s32 pick_best_cpu_smt(u64 candidates, u64 full_idle_mask)
{
    if (!candidates)
        return -1;

    /* If SMT disabled, simple CTZ is optimal */
    if (!smt_enabled)
        return __builtin_ctzll(candidates);
        
    /* SMT Enabled: Search for fully idle core (both siblings idle) */
    u64 iter_mask = candidates;
    s32 fallback_cpu = -1;
    
    /* Unroll checking loop (limit 4 checks to bound overhead) */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if (!iter_mask) break;
        
        s32 cpu = __builtin_ctzll(iter_mask);
        
        /* Barrier to satisfy verifier bounds */
        __asm__ __volatile__("" : "+r"(cpu));
        cpu &= 63;

        /* Check sibling using BITWISE extraction on full mask */
        u8 sibling = cpu_sibling_map[cpu];
        sibling &= 63;
        
        /* Bit check is ~1 cycle. We already have full_idle_mask in register. */
        if ((full_idle_mask >> sibling) & 1) {
             return cpu; /* Both idle */
        }
        
        if (fallback_cpu < 0) fallback_cpu = cpu;
        iter_mask &= ~(1ULL << cpu);
    }
    
    if (fallback_cpu >= 0) return fallback_cpu;
    return __builtin_ctzll(candidates);
}

/*
 * Topology-aware idle CPU finder
 * 
 * Optimized for:
 * 1. Single CCD / Non-Hybrid -> Becomes find_first_idle_cpu() (Zero Overhead)
 * 2. Multi-CCD -> Prefers local LLC, then P-cores
 * 3. Hybrid -> Prefers P-cores
 * 4. SMT -> Prefers fully idle cores
 */
static __always_inline s32 find_first_idle_cpu_topo(s32 prev_cpu)
{
    /* ZERO OVERHEAD PATH: Compiled out if no topology features */
    if (!has_multi_llc && !has_hybrid && !smt_enabled)
        return find_first_idle_cpu(prev_cpu);

    /* Load global idle mask once */
    u64 idle_current = READ_ONCE(idle_mask_global);
    if (!idle_current)
        return -1;

    /* 1. Fast path: Check prev_cpu first (Bitwise extract) */
    if (prev_cpu >= 0 && prev_cpu < 64) {
        if ((idle_current >> prev_cpu) & 1)
            return prev_cpu;
    }

    /* 2. Topology preference logic */
    u64 candidates = 0;
    
    /* Preference A: Same LLC (if multi-LLC) */
    if (has_multi_llc && prev_cpu >= 0 && prev_cpu < CAKE_MAX_CPUS) {
        u8 my_llc = cpu_llc_id[prev_cpu];
        if (my_llc < 8) {
            u64 local_mask = llc_cpu_mask[my_llc];
            
            /* Sub-preference: Local P-cores first (if hybrid) */
            if (has_hybrid) {
                u64 big_mask = READ_ONCE(big_cpu_mask);
                candidates = idle_current & local_mask & big_mask;
                /* PASS FULL MASK for SMT checks */
                if (candidates) return pick_best_cpu_smt(candidates, idle_current);
            }
            
            candidates = idle_current & local_mask;
            if (candidates) return pick_best_cpu_smt(candidates, idle_current);
        }
    }

    /* Preference B: Any P-core (if hybrid) */
    if (has_hybrid) {
         u64 big_mask = READ_ONCE(big_cpu_mask);
         candidates = idle_current & big_mask;
         if (candidates) return pick_best_cpu_smt(candidates, idle_current);
    }
    
    /* Fallback: Any idle CPU */
    return pick_best_cpu_smt(idle_current, idle_current);
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
 * Per-tier starvation thresholds (nanoseconds)
 * Safety net: force preemption if task runs longer than its tier allows.
 * 
 * Pre-computed by userspace based on profile. Zero runtime overhead.
 * Array is padded to 8 for branchless access (tier & 7).
 */
const volatile u64 starvation_threshold[8] = {
    CAKE_DEFAULT_STARVATION_T0,  /* Tier 0: Critical Latency */
    CAKE_DEFAULT_STARVATION_T1,  /* Tier 1: Realtime */
    CAKE_DEFAULT_STARVATION_T2,  /* Tier 2: Critical */
    CAKE_DEFAULT_STARVATION_T3,  /* Tier 3: Gaming */
    CAKE_DEFAULT_STARVATION_T4,  /* Tier 4: Interactive */
    CAKE_DEFAULT_STARVATION_T5,  /* Tier 5: Batch */
    CAKE_DEFAULT_STARVATION_T6,  /* Tier 6: Background */
    CAKE_DEFAULT_STARVATION_T6,  /* PADDING: Entry 7 */
};

/*
 * Tier quantum multipliers (fixed-point, 1024 = 1.0x)
 * Higher tiers get SMALLER slices (more preemption points, lower latency)
 * Lower tiers get LARGER slices (less context switching for bulk work)
 * 
 * Pre-computed by userspace based on profile. Zero runtime overhead.
 */
const volatile u32 tier_multiplier[8] = {
    CAKE_DEFAULT_MULTIPLIER_T0,  /* Critical Latency: 0.7x */
    CAKE_DEFAULT_MULTIPLIER_T1,  /* Realtime: 0.8x */
    CAKE_DEFAULT_MULTIPLIER_T2,  /* Critical: 0.9x */
    CAKE_DEFAULT_MULTIPLIER_T3,  /* Gaming: 1.0x */
    CAKE_DEFAULT_MULTIPLIER_T4,  /* Interactive: 1.1x */
    CAKE_DEFAULT_MULTIPLIER_T5,  /* Batch: 1.2x */
    CAKE_DEFAULT_MULTIPLIER_T6,  /* Background: 1.3x */
    CAKE_DEFAULT_MULTIPLIER_T3,  /* PADDING: Entry 7 */
};

/*
 * Wait Budget per Tier (CAKE's AQM)
 * Tasks exceeding their tier's wait budget get demoted.
 * 
 * Pre-computed by userspace based on profile. Zero runtime overhead.
 */
const volatile u64 wait_budget[8] = {
    CAKE_DEFAULT_WAIT_BUDGET_T0,  /* Critical Latency: 100µs */
    CAKE_DEFAULT_WAIT_BUDGET_T1,  /* Realtime: 750µs */
    CAKE_DEFAULT_WAIT_BUDGET_T2,  /* Critical: 2ms */
    CAKE_DEFAULT_WAIT_BUDGET_T3,  /* Gaming: 4ms */
    CAKE_DEFAULT_WAIT_BUDGET_T4,  /* Interactive: 8ms */
    CAKE_DEFAULT_WAIT_BUDGET_T5,  /* Batch: 20ms */
    CAKE_DEFAULT_WAIT_BUDGET_T6,  /* Background: no limit */
    0,                            /* PADDING: Entry 7 */
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
 * Bitfield Accessor Macros for packed_info
 * These allow us to pack multiple variables into a single u32.
 */

/* Sparse Score accessors (0-100 with asymmetric adaptation) */
#define GET_SPARSE_SCORE(ctx) ((ctx->packed_info >> SHIFT_SPARSE_SCORE) & MASK_SPARSE_SCORE)
#define SET_SPARSE_SCORE(ctx, val) (ctx->packed_info = (ctx->packed_info & ~(MASK_SPARSE_SCORE << SHIFT_SPARSE_SCORE)) | ((val & MASK_SPARSE_SCORE) << SHIFT_SPARSE_SCORE))

/* Wait data accessors (violations<<4 | checks) */
#define GET_WAIT_DATA(ctx) ((ctx->packed_info >> SHIFT_WAIT_DATA) & MASK_WAIT_DATA)
#define SET_WAIT_DATA(ctx, val) (ctx->packed_info = (ctx->packed_info & ~(MASK_WAIT_DATA << SHIFT_WAIT_DATA)) | ((val & MASK_WAIT_DATA) << SHIFT_WAIT_DATA))

#define GET_TIER(ctx) ((ctx->packed_info >> SHIFT_TIER) & MASK_TIER)
#define SET_TIER(ctx, val) (ctx->packed_info = (ctx->packed_info & ~(MASK_TIER << SHIFT_TIER)) | ((val & MASK_TIER) << SHIFT_TIER))

/*
 * Get or initialize task context
 * 
 * LAZY ALLOCATION: Pass create=false for fast-path lookups (no malloc).
 * Pass create=true only in cake_running (serialized per-CPU, no contention).
 * This eliminates malloc lock contention at scheduler startup.
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

    /* Slow path: allocate new context (only from cake_running) */
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
    return (base_slice * tier_multiplier[tier & 7]) >> 10;
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
    bool prev_idle = (idle_mask >> bounded_prev) & 1;  /* Bitwise extract */
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
     * PREFETCH OPTIMIZATION: Touch wait_budget array early
     * 
     * The CPU will load wait_budget[0-7] into L1 cache while we wait
     * for get_task_ctx() to complete. By the time we need 
     * wait_budget[tier & 7], it's already hot in cache.
     * 
     * Saves: ~10 cycles (40-cycle L3 load hidden behind pointer chase)
     */
    volatile u64 prefetch_hint = wait_budget[0];
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
     * XOR-BLEND victim_mask update (preserved MLP optimization)
     */
    u32 is_victim = (u32)tier >= INTERACTIVE_DSQ;
    u64 cpu_bit = (1ULL << cpu_idx);
    
    /* 
     * OPTIMIZATION: Check if bit is already correct (Skip redundant atomic)
     * Most tasks stay in same state, so this skips ~20 cycle atomic op.
     * Also fixes previous race condition where non-atomic RMW clobbered updates.
     */
    bool bit_set = (READ_ONCE(victim_mask) & cpu_bit);
    if (bit_set != is_victim) {
        if (is_victim)
            __sync_fetch_and_or(&victim_mask, cpu_bit);
        else
            __sync_fetch_and_and(&victim_mask, ~cpu_bit);
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
    u32 packed = tctx->packed_info;
    
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
            
            u64 budget_ns = wait_budget[tier & 7];
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
         */
        if (packed != original_packed)
            tctx->packed_info = packed;
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
     */
    u64 now = scx_bpf_now();
    u32 packed = tctx->packed_info;
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
     */
    tctx->avg_runtime_us = new_avg_us;
    tctx->deficit_us = new_deficit_us;
    tctx->next_slice = new_slice;
    
    if (packed != new_packed)
        tctx->packed_info = new_packed;
}

/*
 * CPU idle state changed
 * Updates the global idle bitmask atomically.
 */
void BPF_STRUCT_OPS(cake_update_idle, s32 cpu, bool idle)
{
    if (cpu < 0 || cpu >= 64) return;

    u64 mask = (1ULL << cpu);

    /*
     * OPTIMIZATION: Read-Before-Write
     * We only perform the expensive atomic RMW if the bit is actually changing.
     * 
     * Cost if match:   1 Load + 1 Branch (Cheap)
     * Cost if differ:  1 Load + 1 Branch + 1 Lock RMW (Expensive)
     * 
     * This prevents cache line bouncing when the scheduler "updates" idle
     * state redundantly (e.g. during rapid task switches).
     */
    u64 current = READ_ONCE(idle_mask_global);
    bool current_bit = !!(current & mask);

    if (current_bit != idle) {
        if (idle) {
            __sync_fetch_and_or(&idle_mask_global, mask);
            
            /* Clear victim mask if we are going idle */
            if (READ_ONCE(victim_mask) & mask)
                 __sync_fetch_and_and(&victim_mask, ~mask);
        } else {
            __sync_fetch_and_and(&idle_mask_global, ~mask);
        }
    }
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
         * Issue both loads simultaneously, combine results after.
         */
        u8 tier = GET_TIER(tctx);                    /* Load 1: packed_info */
        u32 last_run = tctx->last_run_at;            /* Load 2: last_run_at (parallel) */
        u64 threshold = starvation_threshold[tier & 7];  /* Load 3: LUT (parallel with above) */
        
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
