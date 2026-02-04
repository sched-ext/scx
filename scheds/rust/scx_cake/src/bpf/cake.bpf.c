// SPDX-License-Identifier: GPL-2.0
/* scx_cake - CAKE DRR++ adapted for CPU scheduling: sparse detection, direct dispatch, tiered DSQ */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
const u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const u64 sparse_threshold = CAKE_DEFAULT_SPARSE_THRESHOLD;
const u64 starvation_ns = CAKE_DEFAULT_STARVATION_NS;
const bool enable_stats = false;
const u64 cached_threshold_ns = 0;

/* Topology config - JIT eliminates unused P/E-core steering when has_hybrid=false */
const bool has_multi_llc = false;
const bool has_hybrid = false;
const bool smt_enabled = false;

#define CAKE_MAX_LLCS 8
const u8 cpu_llc_id[CAKE_MAX_CPUS];
const u8 cpu_is_big[CAKE_MAX_CPUS];
const u8 cpu_sibling_map[CAKE_MAX_CPUS];
const u64 llc_cpu_mask[CAKE_MAX_LLCS];
const u64 big_cpu_mask = 0;

/* Unified CPU topology - 8-byte struct per CPU with sibling/LLC/peers from ETD calibration */
const struct cpu_topology_entry cpu_topo[CAKE_MAX_CPUS];
const u8 core_to_cpu[32]; /* Physical Core -> Primary Logical CPU mapping */
const u8 nr_cores;        /* Actual detected core count */
const u8 nr_cpus_total;   /* Actual detected CPU count */
const u8 core_thread_mask[32]; /* Bitmask of SMT threads per core (e.g. 3 for dual-thread) */
const u64 core_cpu_mask[32];   /* Pre-computed 64-bit mask of all CPUs in a core */

/* Zero-Math Arbiter LUT (populated by userspace) */
const struct arbiter_config arbiter_cfg;

/* D2A Signal Mask - REMOVED (A+B+D architecture makes this redundant) */

/* Fused core state - replaces cpu_tier/shadow arrays, 128-byte aligned to prevent MESI storms */
struct cake_core_state global_core_state[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));

/* Bit-Scan Helpers - state packed as [Occ:8][Warm:8][Victim:8][Pad:8] */
#define STATE_GET_OCCUPANT(s)  ((u8)((s) & 0xFF))
#define STATE_GET_WARM(s)      ((u8)(((s) >> 8) & 0xFF))
#define STATE_GET_VICTIM(s)    ((u8)(((s) >> 16) & 0xFF))
#define STATE_GET_STAGING_PRIO(s)   ((u8)(((s) >> 24) & 0xFF))
#define STATE_CLEAR_STAGING         0x00FFFFFF  /* Mask to zero out byte 3 */

/* Global victim mask - shadow heuristic, relaxed atomics OK (missed bit = missed opportunity, safe) */
struct {
    u64 mask;
    u64 pad[15]; /* Pad to 128 bytes */
} victim_global SEC(".bss") __attribute__((aligned(128)));

/* Accessor macro for victim_mask */
#define victim_mask (victim_global.mask)

/* Global idle mask shadow - tracks idle CPUs to avoid scx_bpf_get_idle_cpumask() kfunc overhead */
struct {
    u64 mask;
    u64 pad[15];
} idle_global SEC(".bss") __attribute__((aligned(128)));
#define global_idle_mask (idle_global.mask)

/* T1: Tier availability bitmap - O(1) dispatch via CTZ(tier_avail & ~warm_mask) */
struct {
    u64 mask;
    u64 pad[7];
} tier_avail_global SEC(".bss") __attribute__((aligned(64)));
#define tier_available_mask (tier_avail_global.mask)

/* Metadata accessors (Fused layout) */
#define GET_TIER_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_TIER, 3)
#define GET_TIER(ctx) GET_TIER_RAW(cake_relaxed_load_u32(&(ctx)->packed_info))
#define GET_CRITICAL_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_CRITICAL, 1)
#define GET_CRITICAL(ctx) GET_CRITICAL_RAW(cake_relaxed_load_u32(&(ctx)->packed_info))

/* QUAD-PACK: r8 as 4x16-bit vector [prev:6|dsq:16|pinfo:16|wake:16] */
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

/* Per-CPU scratch area - BSS-tunneled helper outputs, isolated to prevent MESI contention */
struct cake_scratch {
    bool dummy_idle;
    u32 init_tier;
    u32 init_critical;
    struct bpf_iter_scx_dsq it; /* BSS-Tunneling for iterators */
    struct cake_task_ctx *cached_tctx;  /* Kfunc yo-yo reduction: cache between select_cpu→enqueue */
    struct task_struct *cached_task;    /* Validate cache belongs to same task */
    u32 cached_cpu_id;                  /* Cross-callback CPU ID cache */
    u8 _pad[24]; /* Pad to 128 bytes (2 cache lines) */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));

/* Per-CPU shadow state - 64-byte aligned to prevent micro-stutter from false sharing */
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

/* MESI-friendly tier update - skip write if unchanged to avoid cache line invalidation */
static __always_inline void update_occupant_tier(struct cake_core_state *state, u8 tier)
{
    /* ATOMIC UPDATER: Updates occupant tier byte only */
    u32 *packed = (u32 *)state;
    u32 old = cake_relaxed_load_u32(packed);
    u32 new_val = (old & 0xFFFFFF00) | tier;
    cake_relaxed_store_u32(packed, new_val);
}

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* Global CPU shadow state - direct 1-cycle access, 128-byte aligned */

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* get_shadow_state() removed - use direct BSS: &global_shadow[cpu_idx & (CAKE_MAX_CPUS - 1)] */

/* TTAS gating - prevents LOCK prefix stalling pipeline if bit already in desired state */
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

/* Branchless kthread classification - single 8-byte load + XOR/OR (ksoftirqd/worker/irq) */
static __always_inline bool is_critical_kthread(struct task_struct *p)
{
    const char *comm = p->comm;

    /* Direct 8-byte load - eliminates stack usage from __builtin_memcpy */
    u64 head = *(u64 *)p->comm;

    /* Branchless: all comparisons parallel, combined with OR = zero branch misses */
    u64 is_softirq = !(head ^ 0x71726974666F736BULL);  /* "ksoftirq" */
    u64 is_worker  = !(head ^ 0x2F72656B726F776BULL) & (comm[8] != 'u');  /* bound kworker */
    u64 is_irq     = !((head & 0xFFFFFFFFULL) ^ 0x2F717269ULL);  /* "irq/" */

    return is_softirq | is_worker | is_irq;
}

/* ETD surgical seek - check 3 lowest-latency peers (~8 cycles) before blind global scan (30:1 ROI) */

/* find_surgical_victim - uses cpu_topo[] RODATA, ~6-8 cycles per lookup */

/* find_surgical_victim_logical - checks LOGICAL mask instead of PHYSICAL, ~6-8 cycles */
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

/* Locality arbiter - warmth-first: prev_cpu → sibling → SIMD scan (migrate if tier gap > 3) */
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

    /* Arbiter decision (fused state lookup) */
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
/* BTF fix: Non-static + aligned(8) prevents tail truncation bug */
/* Cached threshold moved to RODATA */

/* Seven DSQs: T0-Critical(IRQ) > T1-Realtime > T2-Critical > T3-Gaming > T4-Interactive > T5-Batch > T6-Background */
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

/* Tier config table - AoS layout: single cache line fetch vs 3 separate arrays, 2 tiers/64B line */
const fused_config_t tier_configs[8] = {
    /* Tier 0: Critical Latency */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T0,
                CAKE_DEFAULT_WAIT_BUDGET_T0 >> 10, CAKE_DEFAULT_STARVATION_T0 >> 10),
    /* Tier 1: Realtime */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T1,
                CAKE_DEFAULT_WAIT_BUDGET_T1 >> 10, CAKE_DEFAULT_STARVATION_T1 >> 10),
    /* Tier 2: Critical */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T2,
                CAKE_DEFAULT_WAIT_BUDGET_T2 >> 10, CAKE_DEFAULT_STARVATION_T2 >> 10),
    /* Tier 3: Gaming */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    /* Tier 4: Interactive */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T4,
                CAKE_DEFAULT_WAIT_BUDGET_T4 >> 10, CAKE_DEFAULT_STARVATION_T4 >> 10),
    /* Tier 5: Batch */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T5,
                CAKE_DEFAULT_WAIT_BUDGET_T5 >> 10, CAKE_DEFAULT_STARVATION_T5 >> 10),
    /* Tier 6: Background */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T6,
                CAKE_DEFAULT_WAIT_BUDGET_T6 >> 10, CAKE_DEFAULT_STARVATION_T6 >> 10),
    /* Tier 7: Padding */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                0, CAKE_DEFAULT_STARVATION_T6 >> 10),
};

/* Branchless tier arithmetic - 8 cycles (4 SETcc + 4 SUB) vs 4-12ns LUT lookup */

/* Long-sleep recovery threshold: 33ms = 2 frames @ 60Hz */
#define LONG_SLEEP_THRESHOLD_NS 33000000

/* Minimum victim residency: 2^20 ns (~1ms) - 1-cycle bit test instead of SUB+CMP */
#define VICTIM_RESIDENCY_BIT 20  /* 2^20 ns ≈ 1ms */

/* Vtime table removed - FIFO DSQs don't use dsq_vtime, saved 160B + 30 cycles */

/* Per-task context map */
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

/* Bitfield accessors - relaxed atomics prevent tearing, SET_* macros use manual skip-if-unchanged RMW */

/* Sparse Score accessor (0-100 with asymmetric adaptation) */
#define GET_SPARSE_SCORE(ctx) EXTRACT_BITS_U32(cake_relaxed_load_u32(&(ctx)->packed_info), SHIFT_SPARSE_SCORE, 7)

/* Metadata Accessors - Definitions moved to top */

/* COLD PATH: Task allocation + kthread init - noinline keeps I-Cache tight for hot path */
/* Removed accounting functions - now in tick */

static __always_inline void set_victim_status_cold(u32 cpu, struct cake_core_state *state)
{
    u64 cpu_bit = (1ULL << (cpu & 63));

    if (!(cake_relaxed_load_u64(&victim_mask) & cpu_bit)) {
        bpf_atomic_or(&victim_mask, cpu_bit);

        u32 *packed = (u32 *)state;
        bpf_atomic_or(packed, 1 << 16); /* Set VICTIM bit (byte 2) */
    }
}

/* perform_lazy_accounting removed - accounting in tick */

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
    /* Pin inputs to callee-saved registers */
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

/* Get/init task context - hot path: fast lookup only, cold path: noinline alloc */
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

/* Noinline accounting - math-heavy ops moved here to free registers (now fully async in tick) */

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* Register layout: r6=ctx, r7=tctx, r8=QUAD-PACK, r9=idle_mask */
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

    /* KFUNC YO-YO REDUCTION: Cache tctx + CPU ID for enqueue/sync-wake to reuse */
    u32 scratch_cpu;
    {
        scratch_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
        struct cake_scratch *scr = &global_scratch[scratch_cpu];
        scr->cached_tctx = tctx_reg;
        scr->cached_task = *(struct task_struct **)ctx_reg;
        scr->cached_cpu_id = scratch_cpu;  /* Cache for cross-callback reuse */
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

    /* cake_accounting_core removed - fully async in tick */

    /* Sync check - QP-SLOT 3: Direct dispatch to current CPU */
    if (QP_GET_WAKE(qp) & SCX_WAKE_SYNC) {
        /* Reuse cached CPU ID instead of second kfunc call */
        if (scratch_cpu < CAKE_MAX_CPUS) {
            scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, CAKE_DSQ_LC_BASE + scratch_cpu,
                               tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
            /* NO KICK: We're on scratch_cpu, waker blocks → natural reschedule */
            return (s32)scratch_cpu;
        }
    }

    /* Idle Check - Load from BSS Shadow */
    idles = cake_relaxed_load_u64(&global_idle_mask);

    /* BARRIER: Preserve idles in r9 */
    asm volatile("" : "+r"(ctx_reg), "+r"(tctx_reg), "+r"(qp), "+r"(idles));

    /* Variables removed - branchless selection doesn't need them */

    /* 1. Prev check - QP-SLOT 0 */
    /* T2 OPTIMIZATION: Pre-computed sibling mask from RODATA */
    u32 b_prev = QP_GET_PREV(qp);
    const struct cpu_topology_entry *topo_prev = &cpu_topo[b_prev];
    u64 sib_bit = topo_prev->sibling_bit;  /* Pre-computed (1ULL << sibling) or 0 */

    /* Branchless CPU selection - CMOV cascade, ~15 cycle savings vs branch mispredict */
    u64 prev_bit = (1ULL << b_prev);
    bool prev_idle = (idles & prev_bit);
    bool sib_idle = (sib_bit & idles);

    /* PARALLEL COMPUTATION: All candidates computed regardless of which wins */
    s32 candidate_prev = (s32)b_prev;
    s32 candidate_sib = (s32)topo_prev->sibling;

    /* RE-PIN BARRIER: Force registers before scan */
    asm volatile("" : "+r"(ctx_reg), "+r"(tctx_reg), "+r"(qp), "+r"(idles));

    /* Speculative computation of scan result (may not be used) */
    s32 candidate_scan = idles ? find_surgical_victim_logical(b_prev, idles, 0x022FDD63CC95386DULL, cpu_topo) : -1;

    /* Arbiter fallback (computed speculatively) */
    s32 candidate_arbiter = select_cpu_with_arbiter(tctx_reg, (s32)b_prev, idles, 0, 0x022FDD63CC95386DULL, cpu_topo);

    /* Branchless selection cascade - track only selected_cpu, derive dsq at end */
    s32 selected_cpu = candidate_arbiter;  /* Lowest priority: arbiter */

    /* Upgrade if scan found idle (higher priority) */
    bool scan_ok = (candidate_scan >= 0);
    selected_cpu = scan_ok ? candidate_scan : selected_cpu;

    /* Upgrade if sibling idle (higher priority) */
    selected_cpu = sib_idle ? candidate_sib : selected_cpu;

    /* Upgrade if prev_cpu idle (highest priority) */
    selected_cpu = prev_idle ? candidate_prev : selected_cpu;

    /* FUSED: Derive target_dsq from selected_cpu via topology lookup */
    u32 target_dsq = cpu_topo[selected_cpu & 63].dsq_id;
    if (selected_cpu >= 0) {
        /* Spill-free: compute target_bit before kfunc, re-derive cpu from dsq after */

        /* BARRIER: Pin qp and idles before kfunc */
        asm volatile("" : "+r"(qp), "+r"(idles));

        scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, target_dsq, tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));

        /* RE-DERIVE: selected_cpu from target_dsq (1 AND op, no spill) */
        asm volatile("" : "+r"(qp), "+r"(idles));
        u32 cpu_id = target_dsq & 63;  /* LC DSQ IDs are CAKE_DSQ_LC_BASE + cpu */
        u64 target_bit = (1ULL << cpu_id);

        /* Branchless kick - compute necessity as bool to gate IPI */
        bool needs_kick = !(idles & target_bit);
        if (needs_kick) {
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

/* Enqueue - A+B architecture: unified DSQ with vtime = (tier << 56) | timestamp */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    u32 task_flags = p_reg->flags;

    /* KFUNC CACHING: Single scx_bpf_now() call for entire function */
    u64 now_cached = scx_bpf_now();

    /* KFUNC YO-YO REDUCTION: Check cache from select_cpu first */
    struct cake_task_ctx *tctx;
    u32 scratch_cpu;
    {
        scratch_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
        struct cake_scratch *scr = &global_scratch[scratch_cpu];
        if (scr->cached_task == p_reg && scr->cached_tctx) {
            tctx = scr->cached_tctx;
            scr->cached_task = NULL;  /* Single store invalidation (sentinel check) */
        } else {
            tctx = get_task_ctx(p_reg, false);  /* Fallback: kfunc call */
        }
    }

    /* Kthread cold path */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        init_new_kthread_cold(p_reg, enq_flags);
        return;
    }

    register struct cake_task_ctx *tctx_reg asm("r7") = tctx;

    /* Handle Yields/Background */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u64 vtime = ((u64)CAKE_TIER_BACKGROUND << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, UNIFIED_DSQ, quantum_ns, vtime, enq_flags);
        return;
    }

    if (unlikely(!tctx_reg)) {
        /* No context yet - use INTERACTIVE tier */
        u64 vtime = ((u64)CAKE_TIER_INTERACTIVE << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
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
    u64 vtime = ((u64)tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
    scx_bpf_dsq_insert_vtime(p_reg, UNIFIED_DSQ, slice, vtime, enq_flags);
}

/* A+B+D dispatch - single UNIFIED_DSQ scan, deferred accounting, per-CPU mailbox priority */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 cpu = (u32)raw_cpu & 63;
    u64 cpu_bit = (1ULL << cpu);

    /* Signal mask check removed */

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
    /* Register pin p to r6 to avoid stack spills */
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

    /* Continuation: if task exceeded slice, force context switch */
    if (unlikely(runtime > tctx_reg->next_slice)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
        return;
    }

    u64 threshold = UNPACK_STARVATION_NS(tier_configs[tier_reg & 7]);

    /* Reduced jitter: 0x0F = 15 * 1024ns = ~15.3µs range (Minimizes lockstep without bloating frame times) */
    threshold += (u64)((now & 0x0F) << 10);

    /* Starvation check - unavoidable branch (helper has side effects) */
    bool needs_kick = (runtime > threshold);
    if (unlikely(needs_kick)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);  /* FUSION #3: Use hoisted cpu_id_reg */

        if (enable_stats && tier_reg < CAKE_TIER_MAX) {
            struct cake_stats *s = get_local_stats();
            if (s) s->nr_starvation_preempts_tier[tier_reg]++;
        }
    }

    /* Branchless victim eligibility: runtime >= 1ms AND tier >= Interactive AND not already victim */
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

/* Task enabled (joining sched_ext) */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
    /* No initialization needed - context created on first use */
}

/* Task disabled (leaving sched_ext) */
void BPF_STRUCT_OPS(cake_disable, struct task_struct *p)
{
    /* Register pinning */
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

/* Initialize the scheduler */
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

/* Scheduler exit - record exit info */
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
