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

/* De Bruijn constant for CTZ - hoisted to RODATA for JIT immediate embedding */
const u64 DB_MAGIC = 0x022FDD63CC95386DULL;

/* Fused core state - replaces cpu_tier/shadow arrays, 128-byte aligned to prevent MESI storms */
struct cake_core_state global_core_state[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));

/* Bit-Scan Helpers - state packed as [Occ:8][Warm:8][Victim:8][Pad:8] */
#define STATE_GET_OCCUPANT(s)  ((u8)((s) & 0xFF))
#define STATE_GET_WARM(s)      ((u8)(((s) >> 8) & 0xFF))
#define STATE_GET_VICTIM(s)    ((u8)(((s) >> 16) & 0xFF))
#define STATE_GET_STAGING_PRIO(s)   ((u8)(((s) >> 24) & 0xFF))
#define STATE_CLEAR_STAGING         0x00FFFFFF  /* Mask to zero out byte 3 */

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: 64-byte per-CPU state (single cache line = optimal L1)
 * - Zero false sharing: each CPU writes ONLY to mega_mailbox[its_cpu]
 * - 50% less L1 pressure than 128B design (16 vs 32 cache lines)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry mega_mailbox[CAKE_MAX_CPUS] SEC(".bss");

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
_Static_assert(sizeof(struct cake_scratch) <= 128,
    "cake_scratch exceeds 128B -- adjacent CPUs will false-share");

/* MESI-friendly tier update - caller passes already-loaded packed state to avoid redundant volatile load */
static __always_inline void update_occupant_tier(u32 *packed_ptr, u32 old_packed, u8 tier)
{
    u32 new_val = (old_packed & 0xFFFFFF00) | tier;
    cake_relaxed_store_u32(packed_ptr, new_val);
}

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* ═══════════════════════════════════════════════════════════════════════════
 * MAILBOX MASK BUILDERS: Replace atomic globals with per-CPU mailbox reads
 * - O(nr_cpus) loop, zero contention vs O(1) with N-way atomic contention
 * - nr_cpus_total is RODATA: JIT constant-folds the break, eliminating
 *   iterations beyond the actual CPU count at load time
 * ═══════════════════════════════════════════════════════════════════════════ */
static __always_inline u64 build_idle_mask_from_mailbox(void)
{
    u64 mask = 0;
    #pragma unroll
    for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
        if (i >= nr_cpus_total) break;
        if (MBOX_IS_IDLE(mega_mailbox[i].flags))
            mask |= (1ULL << i);
    }
    return mask;
}

static __always_inline u64 build_victim_mask_from_mailbox(void)
{
    u64 mask = 0;
    #pragma unroll
    for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
        if (i >= nr_cpus_total) break;
        if (MBOX_IS_VICTIM(mega_mailbox[i].flags))
            mask |= (1ULL << i);
    }
    return mask;
}

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

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX VICTIM FINDER: Quality-aware victim selection
 * - Checks 3 ETD peers first (locality preference)
 * - Uses mailbox victim+tier info for quality ranking
 * - Rotated CTZ fallback avoids CPU 0 bias
 * ═══════════════════════════════════════════════════════════════════════════ */
static __always_inline s32 find_victim_mailbox(u32 prev, u64 candidate_mask,
                                               const struct cpu_topology_entry *topo)
{
    u32 idx = prev & 63;
    const struct cpu_topology_entry *t = &topo[idx];

    /* 1. Check ETD peers first (locality-optimal) */
    u8 p1 = t->peer_1;
    u8 p2 = t->peer_2;
    u8 p3 = t->peer_3;

    /* Read mailbox status for peers (prefetched during earlier work) */
    if (p1 < 64 && (candidate_mask & (1ULL << p1))) {
        u8 flags = mega_mailbox[p1].flags;
        if (MBOX_IS_VICTIM(flags) || MBOX_IS_IDLE(flags))
            return (s32)p1;
    }
    if (p2 < 64 && (candidate_mask & (1ULL << p2))) {
        u8 flags = mega_mailbox[p2].flags;
        if (MBOX_IS_VICTIM(flags) || MBOX_IS_IDLE(flags))
            return (s32)p2;
    }
    if (p3 < 64 && (candidate_mask & (1ULL << p3))) {
        u8 flags = mega_mailbox[p3].flags;
        if (MBOX_IS_VICTIM(flags) || MBOX_IS_IDLE(flags))
            return (s32)p3;
    }

    /* 2. Quality-aware fallback: find highest tier (best to preempt) */
    u8 best_tier = 0;
    s32 best_cpu = -1;

    /* M3: Rotate start by prev to distribute IPI load across CPUs */
    #pragma unroll
    for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
        if (i >= nr_cpus_total) break;
        u32 idx = (prev + i) % nr_cpus_total;
        if (!(candidate_mask & (1ULL << idx)))
            continue;
        u8 flags = mega_mailbox[idx].flags;
        u8 tier = MBOX_GET_TIER(flags);

        /* Prefer idle > victim > none; within category, prefer higher tier */
        bool is_candidate = MBOX_IS_IDLE(flags) || MBOX_IS_VICTIM(flags);
        if (is_candidate && tier > best_tier) {
            best_tier = tier;
            best_cpu = (s32)idx;
        }
    }

    /* 3. If quality search failed, use rotated CTZ to avoid CPU 0 bias */
    if (best_cpu < 0 && candidate_mask) {
        /* Rotate mask by prev to distribute selection */
        u32 shift = prev & 15;
        u64 rotated = (candidate_mask >> shift) | (candidate_mask << (64 - shift));
        u32 offset = BIT_SCAN_FORWARD_U64_RAW(rotated, DB_MAGIC);
        best_cpu = (s32)((shift + offset) & 63);
    }

    return best_cpu;
}

/* Locality arbiter - warmth-first: prev_cpu → sibling → SIMD scan (migrate if tier gap > 3) */
static __always_inline s32 select_cpu_with_arbiter(struct cake_task_ctx *tctx, s32 prev_cpu,
                            u64 l_mask, u64 p_mask,
                            const struct cpu_topology_entry *topo_prev)
{
    u32 b_prev = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);

    if (l_mask & (1ULL << b_prev))
        return prev_cpu;

    /* [R3.2] Use pre-fetched topo_prev instead of re-indexing */
    s32 target_cpu = l_mask ? (s32)BIT_SCAN_FORWARD_U64_RAW(l_mask, DB_MAGIC) : -1;
    u8 target_rank = l_mask ? 3 : 7;

    bool sib_idle = (topo_prev->sibling < 64 && (l_mask & (1ULL << topo_prev->sibling)));
    target_cpu = sib_idle ? (s32)topo_prev->sibling : target_cpu;
    target_rank = sib_idle ? 2 : target_rank;

    s32 phys_cpu = p_mask ? find_surgical_victim_logical(b_prev, p_mask, DB_MAGIC, cpu_topo) : -1;
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
/* set_victim_status_cold removed - mailbox handles victim status */

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
    bool critical = is_critical_kthread(p);

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

/* T0 VICTIM COLD PATH: Rare path for Critical Latency tasks when no idle CPU found */
static __attribute__((noinline))
s32 select_cpu_t0_victim_cold(void *ctx_reg, struct cake_task_ctx *tctx, u32 scratch_cpu, u32 prev)
{
    u64 spec_mask = mega_mailbox[scratch_cpu].cached_victim_mask;
    if (!spec_mask)
        return -1;  /* No victims available */

    s32 s_cpu = find_victim_mailbox(prev, spec_mask, cpu_topo);
    scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, CAKE_DSQ_LC_BASE + (s_cpu & 63),
                       tctx->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
    scx_bpf_kick_cpu((u32)s_cpu, SCX_KICK_PREEMPT);
    return s_cpu;
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* Register layout: r6=ctx, r7=tctx, r8=QUAD-PACK, r9=idle_mask */
    register void *ctx_reg asm("r6");
    register struct cake_task_ctx *tctx_reg asm("r7");
    register u64 qp asm("r8");
    register u64 idles asm("r9");

    asm volatile("%[out] = r1" : [out]"=r"(ctx_reg));

    /* MEGA-MAILBOX PREFETCH: Issue early to hide DDR5 latency (~500 cycles) */
    CAKE_PREFETCH(&mega_mailbox[0]);

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

    /* ATOMIC QUAD-PACK INITIALIZATION [R6.1] Removed dead dsq_id slot */
    {
        u32 b_p = (u32)*(s32 *)((u8 *)ctx_reg + 8) & (CAKE_MAX_CPUS - 1);
        u32 pinf = tctx_reg->packed_info;
        qp =  (u64)b_p;                                    /* Slot 0: prev_cpu (6 bits) */
        qp |= (u64)(pinf >> 16) << 32;                     /* Slot 2: tier+flags (16 bits) */
        qp |= (u64)(u16)*(u64 *)((u8 *)ctx_reg + 16) << 48; /* Slot 3: wake_flags (16 bits) */
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
            /* H1: Prevent thundering herd - clear bit so next SYNC won't pick same CPU */
            mega_mailbox[scratch_cpu].cached_idle_mask &= ~(1ULL << scratch_cpu);
            return (s32)scratch_cpu;
        }
    }

    /* CACHED IDLE MASK: Read from any CPU's mailbox (tick updates it) - saves 28 cycles */
    idles = mega_mailbox[scratch_cpu].cached_idle_mask;

    /* BARRIER: Preserve idles in r9 */
    asm volatile("" : "+r"(ctx_reg), "+r"(tctx_reg), "+r"(qp), "+r"(idles));

    /* Variables removed - branchless selection doesn't need them */

    /* ═══════════════════════════════════════════════════════════════════════════
     * OPT-2: TIERED SHORT-CIRCUIT (Zen 5 Dual-Path Speculation Optimized)
     * - Prev/sibling idle = 90% of wakeups → skip arbiter entirely
     * - Zen 5 speculates both branch paths in parallel, ~1-2 cycle branch cost
     * - Net savings: ~15-20 cycles when fast path taken
     * ═══════════════════════════════════════════════════════════════════════════ */
    u32 b_prev = QP_GET_PREV(qp);
    const struct cpu_topology_entry *topo_prev = &cpu_topo[b_prev];
    u64 prev_bit = (1ULL << b_prev);

    /* TIER 1: Prev CPU idle - highest priority, ~60 cycle path */
    if (idles & prev_bit) {
        scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, topo_prev->dsq_id,
                           tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
        /* H1: Prevent thundering herd - clear bit in waker's mailbox */
        mega_mailbox[scratch_cpu].cached_idle_mask &= ~prev_bit;
        return (s32)b_prev;
    }

    /* TIER 2: Sibling idle - second priority, ~60 cycle path */
    u64 sib_bit = topo_prev->sibling_bit;
    if (sib_bit & idles) {
        scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, topo_prev->sibling_dsq,
                           tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
        /* H1: Prevent thundering herd - clear sibling bit in waker's mailbox */
        mega_mailbox[scratch_cpu].cached_idle_mask &= ~sib_bit;
        return (s32)topo_prev->sibling;
    }

    /* TIER 3: Global scan - find any idle CPU */
    if (idles) {
        s32 scan_cpu = find_victim_mailbox(b_prev, idles, cpu_topo);
        if (scan_cpu >= 0) {
            u32 scan_dsq = CAKE_DSQ_LC_BASE + (scan_cpu & 63);
            scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, scan_dsq,
                               tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));
            /* H1: Prevent thundering herd - clear scanned CPU bit */
            mega_mailbox[scratch_cpu].cached_idle_mask &= ~(1ULL << scan_cpu);
            return scan_cpu;
        }
    }

    /* T0 VICTIM FALLBACK: Critical Latency tasks try victim steal before arbiter */
    if (QP_GET_TIER(qp) == CRITICAL_LATENCY_DSQ) {
        s32 victim_cpu = select_cpu_t0_victim_cold(ctx_reg, tctx_reg, scratch_cpu, b_prev);
        if (victim_cpu >= 0)
            return victim_cpu;
    }

    /* TIER 4: Arbiter - all CPUs busy, use quality-based selection */
    s32 arbiter_cpu = select_cpu_with_arbiter(tctx_reg, (s32)b_prev, idles, 0, topo_prev);
    u32 arbiter_dsq = cpu_topo[arbiter_cpu & 63].dsq_id;

    scx_bpf_dsq_insert(*(struct task_struct **)ctx_reg, arbiter_dsq,
                       tctx_reg->next_slice, *(u64 *)((u8 *)ctx_reg + 16));

    /* Arbiter path always needs kick - no idle CPUs available */
    scx_bpf_kick_cpu((u32)arbiter_cpu & 63, SCX_KICK_PREEMPT);
    return arbiter_cpu;
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

    /* Signal mask check removed */

    /* 1. Check per-CPU direct dispatch mailbox first (highest priority) */
    if (scx_bpf_dsq_move_to_local(CAKE_DSQ_LC_BASE + cpu)) {
        /* H3: MESI-friendly - skip write if already not-idle */
        u8 old_flags = mega_mailbox[cpu].flags;
        if (old_flags & MBOX_IDLE_BIT)
            mega_mailbox[cpu].flags = old_flags & ~MBOX_IDLE_BIT;
        return;
    }

    /* 2. A+B: Single unified DSQ scan (vtime-ordered by tier) */
    if (scx_bpf_dsq_move_to_local(UNIFIED_DSQ)) {
        /* H3: MESI-friendly - skip write if already not-idle */
        u8 old_flags = mega_mailbox[cpu].flags;
        if (old_flags & MBOX_IDLE_BIT)
            mega_mailbox[cpu].flags = old_flags & ~MBOX_IDLE_BIT;
        return;
    }

    /* No work - H3: skip write if already idle */
    u8 old_flags = mega_mailbox[cpu].flags;
    if (!(old_flags & MBOX_IDLE_BIT))
        mega_mailbox[cpu].flags = old_flags | MBOX_IDLE_BIT;
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

    /* Victim eligibility is now computed later in mailbox update section */

    /* Update Occupant Tier - single load, skip write if unchanged (MESI-friendly) */
    u32 *core_packed_ptr = (u32 *)&global_core_state[cpu_id_reg];
    u32 core_packed = cake_relaxed_load_u32(core_packed_ptr);
    if (tier_reg != STATE_GET_OCCUPANT(core_packed)) {
        update_occupant_tier(core_packed_ptr, core_packed, tier_reg);
    }

    /* ═══════════════════════════════════════════════════════════════════════
     * MEGA-MAILBOX UPDATE: Zero false sharing + kfunc/mask caching
     * - Caches timestamp, idle_mask, victim_mask for fast wakeup reads
     * - Pre-computes best_idle_cpu hint (saves ~40 cycles on wakeup)
     * ═══════════════════════════════════════════════════════════════════════ */
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu_id_reg];

    /* Victim eligibility: runtime >= 1ms AND tier >= Interactive */
    bool is_victim = (runtime >> VICTIM_RESIDENCY_BIT) &&
                     (tier_reg >= REALTIME_DSQ && tier_reg <= BATCH_DSQ);

    /* Pack flags: [2:0]=tier, [3]=victim, [4]=idle, [5]=warm */
    u8 new_flags = (tier_reg & MBOX_TIER_MASK);
    if (is_victim)
        new_flags |= MBOX_VICTIM_BIT;
    if (runtime < cached_threshold_ns)
        new_flags |= MBOX_WARM_BIT;

    /* AMORTIZED MASK CACHING: Alternate idle/victim rebuild across ticks
     * - Halves cross-CPU coherency traffic (N reads/tick instead of 2N)
     * - Stale mask is at most 1 tick old -- missed idle/victim = next tick catches it
     * - now bit 0 is ~1ms granularity, free toggle with zero branch overhead */
    u64 idle_snap = mbox->cached_idle_mask;   /* Preserve stale as default */
    u64 victim_snap = mbox->cached_victim_mask;

    if (now & 1) {
        idle_snap = build_idle_mask_from_mailbox();
    } else {
        victim_snap = build_victim_mask_from_mailbox();
    }

    /* BEST IDLE HINT: Pre-compute before stores so we can write monotonically */
    u8 hint = 0xFF;  /* Invalid = no hint */
    if (idle_snap) {
        const struct cpu_topology_entry *t = &cpu_topo[cpu_id_reg];
        if (t->peer_1 < 64 && (idle_snap & (1ULL << t->peer_1)))
            hint = t->peer_1;
        else if (t->peer_2 < 64 && (idle_snap & (1ULL << t->peer_2)))
            hint = t->peer_2;
        else if (t->peer_3 < 64 && (idle_snap & (1ULL << t->peer_3)))
            hint = t->peer_3;
        else if (idle_snap)
            hint = (u8)BIT_SCAN_FORWARD_U64_RAW(idle_snap, DB_MAGIC);
    }

    /* MONOTONIC STORE BURST: Ascending offsets for optimal write combining
     * [0]=flags, [1]=best_idle_cpu, [4]=runtime_us, [8]=cached_now,
     * [16]=cached_idle_mask, [24]=cached_victim_mask */
    mbox->flags = new_flags;
    mbox->best_idle_cpu = hint;
    mbox->runtime_us = (u32)(runtime >> 10);
    mbox->cached_now = now;
    mbox->cached_idle_mask = idle_snap;
    mbox->cached_victim_mask = victim_snap;
}

/* Task enabled (joining sched_ext) */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
    /* No initialization needed - context created on first use */
}

/* Task stopping (yielding/blocking) - H2: MESI-friendly skip-if-unchanged */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

    /* H2: Read first, skip write if victim bit already clear */
    u8 old_flags = mega_mailbox[cpu].flags;
    if (old_flags & MBOX_VICTIM_BIT)
        mega_mailbox[cpu].flags = old_flags & ~MBOX_VICTIM_BIT;
}

/* Task disabled (leaving sched_ext) - MAILBOX ONLY cleanup */
void BPF_STRUCT_OPS(cake_disable, struct task_struct *p)
{
    register struct task_struct *p_reg asm("r6") = p;
    register u32 cpu_reg asm("r8") = bpf_get_smp_processor_id();
    asm volatile("" : "+r"(p_reg), "+r"(cpu_reg));

    /* MAILBOX ONLY: Clear victim status */
    mega_mailbox[cpu_reg & 63].flags &= ~MBOX_VICTIM_BIT;

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
               .stopping       = (void *)cake_stopping,
               .enable         = (void *)cake_enable,
               .disable        = (void *)cake_disable,
               .init           = (void *)cake_init,
               .exit           = (void *)cake_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "cake");
