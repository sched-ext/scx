// SPDX-License-Identifier: GPL-2.0
/* scx_cake - CAKE DRR++ adapted for CPU scheduling: avg_runtime classification, direct dispatch, tiered DSQ */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
const u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const bool enable_stats = false;
const bool enable_dvfs = false;  /* RODATA — JIT eliminates DVFS block when false (default gaming) */

/* Topology config - JIT eliminates unused P/E-core steering when has_hybrid=false */
const bool has_hybrid = false;

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
const u32 nr_llcs = 1;
const u32 nr_cpus = 8;  /* Set by loader — bounds kick scan loop (Rule 39) */
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: 64-byte per-CPU state (single cache line = optimal L1)
 * - Zero false sharing: each CPU writes ONLY to mega_mailbox[its_cpu]
 * - 50% less L1 pressure than 128B design (16 vs 32 cache lines)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry mega_mailbox[CAKE_MAX_CPUS] SEC(".bss");

/* Metadata accessors (Fused layout) */
#define GET_TIER_RAW(packed) EXTRACT_BITS_U32(packed, SHIFT_TIER, 2)
#define GET_TIER(ctx) GET_TIER_RAW(cake_relaxed_load_u32(&(ctx)->packed_info))

/* Per-CPU scratch area - BSS-tunneled helper outputs, isolated to prevent MESI contention */
struct cake_scratch {
    bool dummy_idle;
    u32 cached_llc;            /* LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u64 cached_now;            /* scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u8 _pad[111]; /* Pad to 128 bytes (2 cache lines) */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));
_Static_assert(sizeof(struct cake_scratch) <= 128,
    "cake_scratch exceeds 128B -- adjacent CPUs will false-share");

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* ═══ TIER SNAPSHOT (A4: tick-assembled, zero false sharing) ═══
 * Built by CPU 0's cake_tick from per-CPU mbox->tick_tier (1kHz, ~150ns).
 * Read by cake_select_cpu Gate 2 — single L1-hot u64 load + CTZ scan.
 *
 * Architecture (sim-verified: unified_tier_sim.c):
 *   Writer: CPU 0 tick only (single writer = zero MESI contention)
 *   Reader: Gate 2 in select_cpu (~9% of wakeups)
 *   Staleness: ~1ms (tick period). Tiers stable for seconds → <0.2% stale hits.
 *   Incorrect match → kfunc test fails → next candidate (no correctness issue).
 *
 * Cacheline-padded: each tier mask on its own 64B line.
 * Zero false sharing between tiers, zero contention from writes.
 * Sim results: 31ns/wakeup (vs 40ns mailbox scan, vs 126ns global packed). */
struct tier_snap {
    u64 mask;
    u8 _pad[56];
} __attribute__((aligned(64)));
struct tier_snap tier_snapshot[4] SEC(".bss") __attribute__((aligned(64)));

static __always_inline struct cake_stats *get_local_stats(void)
{
    u32 cpu = bpf_get_smp_processor_id();
    return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* ETD surgical seek / find_surgical_victim_logical removed — select_cpu
 * now delegates idle selection to scx_bpf_select_cpu_dfl() which does
 * prev → sibling → LLC cascade internally with kernel-native topology. */

/* Victim finder / arbiter removed — select_cpu now uses kernel-delegated
 * idle selection. When all CPUs are busy, enqueue handles placement via
 * per-LLC DSQs with vtime-encoded tier priority. */

/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);

/* Global vtime removed to prevent bus locking. Tasks inherit vtime from parent. */

/* Optimization: Precomputed threshold to avoid division in hot path */
/* BTF fix: Non-static + aligned(8) prevents tail truncation bug */
/* Cached threshold moved to RODATA */

/* A+B ARCHITECTURE: Per-LLC DSQs with vtime-encoded priority.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */

/* Tier config table - 4 tiers + padding, AoS layout: single cache line fetch */
const fused_config_t tier_configs[8] = {
    /* T0: Critical (<100µs) — IRQ, input, audio */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T0,
                CAKE_DEFAULT_WAIT_BUDGET_T0 >> 10, CAKE_DEFAULT_STARVATION_T0 >> 10),
    /* T1: Interactive (<2ms) — compositor, physics */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T1,
                CAKE_DEFAULT_WAIT_BUDGET_T1 >> 10, CAKE_DEFAULT_STARVATION_T1 >> 10),
    /* T2: Frame Producer (<8ms) — game render, encoding */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T2,
                CAKE_DEFAULT_WAIT_BUDGET_T2 >> 10, CAKE_DEFAULT_STARVATION_T2 >> 10),
    /* T3: Bulk (≥8ms) — compilation, background */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    /* Padding (copies of T3 for safe & 7 access) */
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
    PACK_CONFIG(CAKE_DEFAULT_QUANTUM_NS >> 10, CAKE_DEFAULT_MULTIPLIER_T3,
                CAKE_DEFAULT_WAIT_BUDGET_T3 >> 10, CAKE_DEFAULT_STARVATION_T3 >> 10),
};

/* Vtime prefix LUT: 8 entries = 64B = 1 cache line.
 * Index = (tier << 1) | new_flow. Replaces 3 shifts + 2 ORs with 1 load.
 * (Pattern bench P7: 0.3664ns vs 0.5456ns, 10/10 wins on 9800X3D) */
static const u64 vtime_prefix[8] = {
    (1ULL << 63) | (0ULL << 56),                  /* T0, nf=0 */
    (1ULL << 63) | (0ULL << 56) | (1ULL << 48),   /* T0, nf=1 */
    (1ULL << 63) | (1ULL << 56),                  /* T1, nf=0 */
    (1ULL << 63) | (1ULL << 56) | (1ULL << 48),   /* T1, nf=1 */
    (1ULL << 63) | (2ULL << 56),                  /* T2, nf=0 */
    (1ULL << 63) | (2ULL << 56) | (1ULL << 48),   /* T2, nf=1 */
    (1ULL << 63) | (3ULL << 56),                  /* T3, nf=0 */
    (1ULL << 63) | (3ULL << 56) | (1ULL << 48),   /* T3, nf=1 */
};

/* tick skip_mask LUT: 256B = 4 cache lines, permanently L1-hot at 1kHz.
 * Replaces 3-branch ternary chain with single byte load.
 * (Pattern bench P8: 0.1834ns vs 0.3656ns, 10/10 wins on 9800X3D)
 *
 * Extended ceiling: mask 15 at counter ≥64 (every 16th tick, 16ms worst
 * response).  Bench: gaming heavy 23,243→95 checks/100K ticks (97.4%
 * reduction, 64.48µs/s saved across 8 cores).  Mask 31+ gives <0.15µs/s
 * additional savings — diminishing returns cliff confirmed at mask 15.
 * 16ms worst-case ≤ 1 frame at 60fps, safe for starvation detection. */
static const u8 skip_mask_lut[256] = {
    [0 ... 7]    = 0,   /* settling: check every tick */
    [8 ... 15]   = 1,   /* warming: check every 2nd tick */
    [16 ... 31]  = 3,   /* confident: check every 4th tick */
    [32 ... 63]  = 7,   /* high confidence: check every 8th tick */
    [64 ... 255] = 15,  /* max confidence: check every 16th tick */
};

/* Pre-computed tier slices: 8 entries = 64B = 1 cache line.
 * Replaces RODATA load + AND + multiply + shift with single load.
 * Populated by Rust loader from quantum_ns × tier_multiplier.
 * (Pattern bench P16: 0.2100ns vs 0.3136ns, 10/10 wins on 9800X3D) */
const u64 tier_slice_ns[8] = { 0 };

/* Per-tier graduated backoff recheck masks (RODATA)
 * Lower tiers (more stable) recheck less often.
 * T0 IRQs almost never change behavior → every 1024th stop.
 * T3 bulk tasks may transition → every 16th stop. */
static const u16 tier_recheck_mask[] = {
    1023,  /* T0: every 1024th stop */
    127,   /* T1: every 128th  */
    31,    /* T2: every 32nd   */
    15,    /* T3: every 16th   */
    15, 15, 15, 15,  /* padding */
};

/* M5 hysteresis gate LUT: 4 tiers × 4 entries = 32B RODATA (1 cache line).
 * Pre-computes tier boundaries with 10% promote-only hysteresis.
 * Replaces 9 instructions (3 cmp + 3 imul + 3 sub) with 3 L1d loads.
 * [4][4] layout: power-of-2 stride → single LEA for indexing.
 * (cake_math_bench M5: 2.66 cyc vs 13.4 cyc, 80.1% faster on 9800X3D) */
static const u16 tier_gates[4][4] = {
    /* old_tier=0: standard gates (no hysteresis — already at lowest relevant) */
    { TIER_GATE_T0,                    TIER_GATE_T1,                    TIER_GATE_T2,                    0 },
    /* old_tier=1: g0 lowered 10% (harder to promote T1→T0) */
    { TIER_GATE_T0 - TIER_GATE_T0/10, TIER_GATE_T1,                    TIER_GATE_T2,                    0 },
    /* old_tier=2: g0,g1 lowered 10% */
    { TIER_GATE_T0 - TIER_GATE_T0/10, TIER_GATE_T1 - TIER_GATE_T1/10, TIER_GATE_T2,                    0 },
    /* old_tier=3: all gates lowered 10% */
    { TIER_GATE_T0 - TIER_GATE_T0/10, TIER_GATE_T1 - TIER_GATE_T1/10, TIER_GATE_T2 - TIER_GATE_T2/10, 0 },
};

/* Vtime table removed - FIFO DSQs don't use dsq_vtime, saved 160B + 30 cycles */

/* Per-task context map */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cake_task_ctx);
} task_ctx SEC(".maps");



/* Bitfield accessors - relaxed atomics prevent tearing */

/* Metadata Accessors - Definitions moved to top */

/* COLD PATH: Task allocation + kthread init - noinline keeps I-Cache tight for hot path */
/* Removed accounting functions - now in tick */
/* set_victim_status_cold removed - mailbox handles victim status */

/* perform_lazy_accounting removed - accounting in tick */

/* init_new_kthread_cold inlined into cake_enqueue — reuses hoisted
 * now_cached + enq_llc, saving 2 kfunc calls per kthread enqueue. */

/* select_cpu_new_task_cold removed — new tasks go through the same
 * scx_bpf_select_cpu_dfl path as all other tasks. */

static __attribute__((noinline))
struct cake_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct cake_task_ctx *ctx;

    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) return NULL;

    ctx->next_slice = quantum_ns;
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    ctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, 0);
    ctx->last_run_at = 0;
    ctx->reclass_counter = 0;

    /* MULTI-SIGNAL INITIAL CLASSIFICATION
     *
     * Two cheap signals set the starting point; avg_runtime classification
     * takes over after the first few execution bouts and is authoritative.
     *
     * Signal 1: Nice value (u32 field read, ~2 cycles)
     *   - nice < 0 (prio < 120): OS/user explicitly prioritized
     *     System services (-20), pipewire (-11), games with nice (-5)
     *     → T0 initially, avg_runtime reclassifies after first runs
     *   - nice > 10 (prio > 130): explicitly deprioritized
     *     Background builds, indexers → T3, stays if bulk
     *   - nice 0-10: default → T1, avg_runtime adjusts naturally
     *
     * Signal 2: PF_KTHREAD flag (1 bit test, already known by caller)
     *   Kthreads with nice < 0 get T0 from Signal 1 automatically.
     *   Kthreads with nice 0 start at T1 like all other nice-0 tasks.
     *   No pin — reclassify based on actual avg_runtime behavior:
     *   - ksoftirqd: ~10μs bursts → T0 within 3 stops
     *   - kcompactd: long runs → T2-T3 naturally
     *
     * Signal 3: Runtime behavior (ongoing, ~15ns/stop — authoritative)
     *   Pure avg_runtime → tier mapping in reclassify_task_cold(). */

    /* Nice value: static_prio 100 = nice -20, 120 = nice 0, 139 = nice 19
     *
     * R1 sum-of-cmp: branchless non-monotonic mapping.
     * (prio >= 120) = 0 for negative nice (→ CRITICAL=0), 1 for default (→ INTERACT=1)
     * (prio > 130) * 2 = 0 for normal, 2 for high nice (1+2 = BULK=3)
     * 10/10 wins, 0.34 cyc vs 3.69 cyc on 9800x3d. */
    u32 prio = p->static_prio;
    u8 init_tier = (prio >= 120) + (prio > 130) * 2;

    u32 packed = 0;
    /* Fused TIER+FLAGS: bits [29:24] = [tier:2][flags:4] (Rule 37 coalescing) */
    packed |= (((u32)(init_tier & MASK_TIER) << 4) | (CAKE_FLOW_NEW & MASK_FLAGS)) << SHIFT_FLAGS;
    /* stable=0: implicit from packed=0 */

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

/* T0 victim cold path removed — when all CPUs are busy, tasks go through
 * enqueue → per-LLC DSQ where vtime ordering ensures T0 tasks get pulled
 * first. Preemption handled by cake_tick starvation checks. */

/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU: PREV-CPU GATE + TIER-MATCHED FALLBACK
 *
 * Architecture (benchmark-validated — see bench/core_packing_sim.c):
 *   1. Strip SYNC flag to prevent waker-core migration (cache-destructive)
 *   2. Try prev_cpu first: if idle, claim it atomically → direct dispatch
 *   3. If prev_cpu busy: scan tier_cpu_mask[tier] for a same-tier idle core
 *   4. Last resort: fall through to scx_bpf_select_cpu_dfl() kernel cascade
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
    u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch *scr = &global_scratch[tc_id];
    bool is_idle = false;

    /* ── SYNC STRIP: prevent waker-core migration ──
     * Bench: 0.20ns cost, saves 1.6-3.5µs per prevented migration.
     * Without this, scx_bpf_select_cpu_dfl prefers waker CPU over prev_cpu
     * when WF_SYNC is set, destroying cache warmth. */
    wake_flags &= ~SCX_WAKE_SYNC;

    /* ── GATE 1: Try prev_cpu — task's L1/L2 cache is hot there ──
     * Atomically claims the idle CPU. If idle, we get direct dispatch.
     * This is the fast path (~91% hit rate in gaming workloads).
     * Cost: ~15ns (single kfunc). */
    if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        u64 slice = p->scx.slice ?: quantum_ns;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice, wake_flags);
        return prev_cpu;
    }

    /* ── GATE 2: Tier-matched idle core via tick snapshot (A4) ──
     * Read the task's tier from staged dsq_vtime (set by cake_stopping).
     * tier_snapshot[tier].mask built by CPU 0's tick from per-CPU mailboxes.
     * Single L1 read (~1.3ns) + CTZ scan — zero cross-CPU cache line reads.
     *
     * MESI: zero contention. Single writer (CPU 0 tick, 1kHz).
     * Staleness: ~1ms. Tiers stable for seconds → stale hit causes kfunc
     * test to fail → next candidate. No correctness issue.
     * Sim: 31ns/wakeup amortized (vs 40ns mailbox scan). */
    u64 staged = p->scx.dsq_vtime;
    if (staged & (1ULL << 63)) {
        u8 tier = (staged >> 56) & 3;
        u64 tmask = tier_snapshot[tier].mask;

        u32 scan;
        for (scan = 0; tmask && scan < nr_cpus; scan++) {
            s32 candidate = __builtin_ctzll(tmask);
            tmask &= tmask - 1;  /* clear lowest set bit */
            if ((u32)candidate >= CAKE_MAX_CPUS)
                break;
            if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
                u64 slice = p->scx.slice ?: quantum_ns;
                scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | candidate, slice, wake_flags);
                return candidate;
            }
        }
    }

    /* ── GATE 3: Kernel fallback — let kernel find any idle CPU ──
     * Only reached when prev_cpu is busy AND no tier-matched cores are idle.
     * This is the cold path (~2-5% of wakeups in gaming). */
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle) {
        u64 slice = p->scx.slice ?: quantum_ns;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);
        return cpu;
    }

    /* ALL BUSY: tunnel LLC ID + timestamp for enqueue.
     * select_cpu runs on same CPU as enqueue — safe to tunnel. */
    scr->cached_llc = cpu_llc_id[tc_id];
    scr->cached_now = scx_bpf_now();
    return prev_cpu;
}

/* ENQUEUE-TIME KICK: DISABLED.
 * A/B testing confirmed kicks cause 16fps 1% low regression in Arc Raiders
 * (252fps without kick, 236fps with T3-only kick). Even T3-only kicks create
 * cache pollution and GPU pipeline bubbles. Tick-based starvation detection
 * is sufficient for gaming workloads. */

/* Enqueue - A+B architecture: per-LLC DSQ with vtime = (tier << 56) | timestamp
 *
 * ZERO bpf_task_storage_get: tier + CAKE_FLOW_NEW flag are pre-staged in
 * p->scx.dsq_vtime by cake_stopping (Rule 41: locality promotion). Slice is
 * pre-staged in p->scx.slice. Both are direct task_struct field reads (~3ns)
 * vs the 30-80ns cold-memory lookup under heavy load. The kernel does not
 * read p->scx.dsq_vtime for sleeping tasks (not on any DSQ), so the staging
 * bits are inert until we consume them here. */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
    register struct task_struct *p_reg asm("r6") = p;
    u32 task_flags = p_reg->flags;

    /* KFUNC TUNNELING: Reuse LLC ID + timestamp cached by select_cpu in scratch.
     * Eliminates 2 kfunc trampolines (~40-60ns) — select_cpu always runs on
     * the same CPU immediately before enqueue, so values are fresh. */
    u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch *scr = &global_scratch[enq_cpu];
    u64 now_cached = scr->cached_now;
    u32 enq_llc = scr->cached_llc;

    /* Read staged context from task_struct fields (~3ns each, always L1).
     * Bit 63 = sentinel: set by cake_stopping = context exists.
     * Clear = first dispatch or kthread without context → fallback. */
    u64 staged = p_reg->scx.dsq_vtime;

    if (unlikely(!(staged & (1ULL << 63)))) {
        /* No staged context: first dispatch or kthread without alloc */
        u8 fallback_tier = (task_flags & PF_KTHREAD) ?
            CAKE_TIER_CRITICAL : CAKE_TIER_FRAME;
        u64 vtime = ((u64)fallback_tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc,
                                 quantum_ns, vtime, enq_flags);
        return;
    }

    /* Handle Yields/Background — check before extracting tier */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u64 vtime = ((u64)CAKE_TIER_BULK << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        return;
    }

    /* Extract staged fields — zero bpf_task_storage_get */
    u8 tier = (staged >> 56) & 3;
    u8 new_flow = (staged >> 48) & 1;
    u64 slice = p_reg->scx.slice ?: quantum_ns;

    if (enable_stats) {
        struct cake_stats *s = get_local_stats();
        if (enq_flags & SCX_ENQ_WAKEUP)
            s->nr_new_flow_dispatches++;
        else
            s->nr_old_flow_dispatches++;

        if (tier < CAKE_TIER_MAX)
            s->nr_tier_dispatches[tier]++;
    }

    /* A+B: Vtime-encoded priority: (tier << 56) | timestamp
     * DRR++ NEW FLOW BONUS: Tasks with CAKE_FLOW_NEW get a vtime reduction,
     * making them drain before established same-tier tasks. This gives
     * newly spawned threads instant responsiveness (e.g., game launching a
     * new worker). Cleared by reclassify_task_cold when deficit exhausts. */
    u64 vtime = ((u64)tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
    if (new_flow)
        vtime -= new_flow_bonus_ns;
    scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, slice, vtime, enq_flags);
}

/* Dispatch: per-LLC DSQ scan with cross-LLC stealing fallback.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];

    /* Local LLC first — zero cross-CCD contention in steady state */
    if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + my_llc))
        return;

    /* Steal from other LLCs (only when local is empty).
     * RODATA gate: Clang doesn't constant-fold RODATA globals, so without
     * this check, single-LLC systems (9800X3D) execute 7 unrolled
     * load+branch pairs that always break immediately. (Rule 5) */
    if (nr_llcs <= 1)
        return;

    for (u32 i = 1; i < CAKE_MAX_LLCS; i++) {
        if (i >= nr_llcs)
            break;
        u32 victim = my_llc + i;
        if (victim >= nr_llcs)
            victim -= nr_llcs;
        if (scx_bpf_dsq_move_to_local(LLC_DSQ_BASE + victim))
            return;
    }
}

/* DVFS RODATA LUT: Tier → CPU performance target (branchless via array index)
 * SCX_CPUPERF_ONE = 1024 = max hardware frequency. JIT constant-folds the array.
 * ALL tiers can contain gaming workloads — tiers control latency priority, not
 * execution speed. Conservative targets: never below 75% to avoid starving
 * game-critical work. */
const u32 tier_perf_target[8] = {
    1024,  /* T0 Critical: 100% — IRQ, input, audio, network (<100µs) */
    1024,  /* T1 Interactive: 100% — compositor, physics, AI (<2ms) */
    1024,  /* T2 Frame: 100% — game render, encoding (<8ms) */
    768,   /* T3 Bulk: 75% — compilation, background (≥8ms) */
    768, 768, 768, 768,  /* padding */
};

/* ZERO bpf_task_storage_get: tier, last_run_at, and slice are pre-staged
 * in mega_mailbox by cake_running (Rule 41: locality promotion). All reads
 * hit the SAME cache line as tick_counter — zero extra cache line loads.
 * Saves ~22ns/tick (kfunc overhead eliminated). */
void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
    register u32 cpu_id_reg asm("r8") = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu_id_reg];

    /* SAFETY GATE: running must have stamped this CPU's mailbox */
    if (unlikely(!mbox->tick_ctx_valid))
        return;

    /* PHASE 1: COMPUTE RUNTIME — all data from mailbox (same cache line) */
    u32 now = (u32)scx_bpf_now();
    register u8 tier_reg asm("r9") = mbox->tick_tier;
    u32 last_run = mbox->tick_last_run_at;
    u64 runtime = (u64)(now - last_run);

    /* Slice exceeded: force context switch */
    if (unlikely(runtime > mbox->tick_slice)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
        return;
    }

    /* PHASE 2: STARVATION CHECK — graduated confidence backoff.
     * tick_counter tracks consecutive ticks without contention (nr_running <= 1).
     * As confidence grows, check frequency drops:
     *   counter < 8:  check every tick     (settling, ~8ms)
     *   counter < 16: check every 2nd tick (warming, max 1ms delay)
     *   counter < 32: check every 4th tick (confident, max 3ms delay)
     *   counter < 64: check every 8th tick (high confidence, max 7ms delay)
     *   counter >= 64: check every 16th tick (max confidence, max 15ms delay)
     * Any contention (nr_running > 1) resets to 0 → full alertness.
     * Core ideology: good scheduling earns reduced overhead. */
    u8 tc = mbox->tick_counter;
    u8 skip_mask = skip_mask_lut[tc];  /* P8 LUT: 0.18ns vs 0.37ns ternary */

    if (!(tc & skip_mask)) {
        struct rq *rq = cake_get_rq(cpu_id_reg);
        if (rq && rq->scx.nr_running > 1) {
            /* Contention detected — reset confidence immediately */
            mbox->tick_counter = 0;

            u64 threshold = UNPACK_STARVATION_NS(tier_configs[tier_reg & 7]);
            if (unlikely(runtime > threshold)) {
                scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);

                if (enable_stats && tier_reg < CAKE_TIER_MAX) {
                    struct cake_stats *s = get_local_stats();
                    if (s) s->nr_starvation_preempts_tier[tier_reg]++;
                }
                return;  /* Already kicked — skip mailbox/DVFS */
            }
        } else {
            /* No contention — grow confidence (saturate at 255) */
            if (tc < 255) mbox->tick_counter = tc + 1;
        }
    } else {
        /* Skipped check — still increment counter for next mask eval */
        if (tc < 255) mbox->tick_counter = tc + 1;
    }


    /* DVFS: Tier-proportional CPU frequency steering (default OFF for gaming).
     * Disabled by default: (1) T3 at 75% makes bulk tasks run 33% longer on-core,
     * competing with game threads. (2) performance governor makes cpuperf_set a no-op.
     * (3) CPPC2 beats cake's 1ms tick granularity. (4) Per-tick overhead wasted.
     * JIT eliminates this entire block when enable_dvfs = false. */
    if (enable_dvfs) {
        u32 target = tier_perf_target[tier_reg & 7];
        if (has_hybrid) {
            u32 cap = scx_bpf_cpuperf_cap(cpu_id_reg);
            target = (target * cap) >> 10;
        }
        u8 cached_perf = mbox->dsq_hint;
        u8 target_cached = (u8)(target >> 3);  /* 1024>>3=128, fits u8 (was >>2=256 overflow) */
        if (cached_perf != target_cached) {
            scx_bpf_cpuperf_set(cpu_id_reg, target);
            mbox->dsq_hint = target_cached;
        }
    }

    /* ── A4: Tick-assembled tier snapshot (CPU 0 only) ──
     * Build tier bitmask from per-CPU mailboxes for select_cpu Gate 2.
     * Single writer (CPU 0) = zero MESI contention. 1kHz = ~1ms staleness.
     * Cost: nr_cpus L3 reads + 4 writes = ~150ns (0.15µs/sec at 1kHz).
     * Branchless accumulation: multiply-select avoids branch misprediction. */
    if (cpu_id_reg == 0) {
        u64 t0 = 0, t1 = 0, t2 = 0, t3 = 0;
        u32 c;
        for (c = 0; c < nr_cpus; c++) {
            if (c >= CAKE_MAX_CPUS)
                break;
            u8 t = mega_mailbox[c].tick_tier;
            u64 bit = 1ULL << c;
            /* Branchless: each tier accumulates its matching CPUs.
             * Comparison returns 0 or 1, multiply by bit = 0 or bit. */
            t0 |= (u64)(t == 0) * bit;
            t1 |= (u64)(t == 1) * bit;
            t2 |= (u64)(t == 2) * bit;
            t3 |= (u64)(t == 3) * bit;
        }
        tier_snapshot[0].mask = t0;
        tier_snapshot[1].mask = t1;
        tier_snapshot[2].mask = t2;
        tier_snapshot[3].mask = t3;
    }
}

/* ZERO bpf_task_storage_get: stamp the currently-running task's data into
 * the per-CPU mega_mailbox. cake_tick reads from the SAME cache line.
 * Tier extracted from p->scx.dsq_vtime — bits [57:56] contain tier in
 * both staging format (set by stopping) and vtime-encoding format (set by
 * scx_bpf_dsq_insert_vtime). cake_stopping syncs last_run_at back to tctx. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu];
    u32 now = (u32)scx_bpf_now();
    u8 tier;

    mbox->tick_last_run_at = now;

    u64 v = p->scx.dsq_vtime;
    if (unlikely(!v)) {
        /* First-ever dispatch — defaults until reclassify builds history */
        tier = CAKE_TIER_FRAME;
        mbox->tick_slice = quantum_ns;
    } else {
        /* Tier at bits [57:56] in both staging and vtime-encoding formats */
        tier = (v >> 56) & 3;
        mbox->tick_slice = p->scx.slice ?: quantum_ns;
    }
    mbox->tick_tier = tier;
    mbox->tick_ctx_valid = 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AVG_RUNTIME CLASSIFICATION + DRR++: Dynamic tier reclassification on every stop.
 * CPU analog of network CAKE's flow classification:
 * - Sparse flows (audio, input) → short bursts + yield → settle at T0-T1
 * - Bulk flows (compilation, renders) → run until preempted → demote to T2-T3
 * - Mixed flows (game logic) → medium bursts → settle at T1-T2
 *
 * This is the engine that makes tier-encoded vtime and per-tier starvation
 * actually differentiate traffic. Without it, all userspace tasks compete
 * at the same tier.
 * ═══════════════════════════════════════════════════════════════════════════ */
static __attribute__((noinline))
void reclassify_task_cold(struct cake_task_ctx *tctx)
{
    u32 packed = cake_relaxed_load_u32(&tctx->packed_info);

    /* ── RUNTIME MEASUREMENT ── */
    u32 now = (u32)scx_bpf_now();
    u32 last_run = tctx->last_run_at;
    if (!last_run)
        return;  /* Never ran — skip (safety gate) */

    u32 runtime_raw = now - last_run;
    u32 runtime_us = runtime_raw >> 10;  /* ns → ~μs (÷1024 ≈ ÷1000) */

    /* Clamp to u16 max for EWMA field (65ms max, more than any reasonable burst) */
    u16 rt_clamped = runtime_us > 0xFFFF ? 0xFFFF : (u16)runtime_us;

    /* ── GRADUATED BACKOFF ──
     * When tier has been stable for 3+ consecutive stops, throttle reclassify
     * frequency based on current tier. T0 tasks (IRQ/input) almost never
     * change → recheck every 1024th stop. T3 tasks (bulk) may transition
     * → recheck every 16th stop. Uses per-task counter + RODATA masks. */
    u8 stable = (packed >> SHIFT_STABLE) & 3;
    if (stable == 3) {
        /* Fast path: update EWMA + deficit without full tier mapping */
        u32 old_fused = tctx->deficit_avg_fused;
        u16 avg_rt = EXTRACT_AVG_RT(old_fused);
        u16 deficit = EXTRACT_DEFICIT(old_fused);  /* M11 ILP: extract both before compute */
        u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_clamped >> 3);
        u16 _d = deficit - rt_clamped;
        deficit = (deficit > rt_clamped) ? _d : 0;  /* P4 cmov: 0.38ns vs 0.55ns */
        u32 new_fused = PACK_DEFICIT_AVG(deficit, new_avg);
        if (new_fused != old_fused)
            tctx->deficit_avg_fused = new_fused;

        /* Per-tier recheck: increment counter, check against tier mask */
        u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;
        u16 mask = tier_recheck_mask[tier & 3];
        u16 counter = tctx->reclass_counter + 1;
        tctx->reclass_counter = counter;
        if (counter & mask) {
            /* Not time for full recheck — spot-check: would new EWMA
             * classify to a different tier? Uses hysteresis-adjusted gates
             * so spot-check agrees exactly with full reclassify logic.
             * Only resets stability when a genuine tier change is imminent.
             * Zero false triggers from normal frame variance. */
            const u16 *tg = tier_gates[tier & 3];  /* M5 LUT: 2.66 vs 13.4 cyc */
            u16 g0 = tg[0], g1 = tg[1], g2 = tg[2];
            /* M6 sum-of-cmp: 3 independent branches vs 3 chained.
             * 10/10 wins, 0.21 cyc vs 6.15 cyc on 9800x3d.
             * BPF codegen: 3 parallel 1-insn skips vs 3 serial jumps. */
            u8 spot_tier = (new_avg >= g0) + (new_avg >= g1) + (new_avg >= g2);

            if (spot_tier != tier) {
                u32 reset = packed & ~((u32)3 << SHIFT_STABLE);
                cake_relaxed_store_u32(&tctx->packed_info, reset);
                tctx->reclass_counter = 0;
            }
            return;
        }
        /* Fall through → periodic full reclassify */
    }

    /* ── FULL RECLASSIFICATION ── */

    /* ── EWMA + DEFICIT UPDATE (M11 ILP interleaved) ── */
    /* Extract both fields before computing either chain → OoO executes in parallel.
     * (cake_math_bench M11: 2.76 cyc vs 3.57 cyc, 22.6% faster on 9800X3D) */
    u32 old_fused = tctx->deficit_avg_fused;
    u16 avg_rt = EXTRACT_AVG_RT(old_fused);
    u16 deficit = EXTRACT_DEFICIT(old_fused);
    /* EWMA 7/8 decay: responds in ~8 bouts, ignores single outliers */
    u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_clamped >> 3);
    /* DRR++ deficit: each bout consumes credit, clear new-flow on exhaust */
    u16 _d2 = deficit - rt_clamped;
    deficit = (deficit > rt_clamped) ? _d2 : 0;  /* P4 cmov: 0.38ns vs 0.55ns */

    /* Pre-compute deficit_exhausted before rt_clamped/deficit die (Rule 36) */
    bool deficit_exhausted = (deficit == 0 && (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)));

    /* Write fused deficit + avg_runtime (MESI-friendly: skip if unchanged) */
    u32 new_fused = PACK_DEFICIT_AVG(deficit, new_avg);
    if (new_fused != old_fused)
        tctx->deficit_avg_fused = new_fused;

    /* ── HYSTERESIS TIER CLASSIFICATION ──
     * Promote-only deadband prevents oscillation at tier boundaries.
     * To PROMOTE (lower tier): avg must be 10% below the gate.
     * To DEMOTE  (higher tier): standard gate (no barrier — fast demotion).
     * Asymmetric by design: give more CPU time quickly, take it back cautiously.
     *
     * Example at T1/T2 gate (2000µs):
     *   Current T1, avg=2100 → demotes to T2 (standard gate)
     *   Current T2, avg=1900 → stays T2 (promote needs <1800)
     *   Current T2, avg=1750 → promotes to T1 */
    u8 old_tier = (packed >> SHIFT_TIER) & MASK_TIER;
    u8 new_tier;

    /* Gate values with 10% hysteresis applied per-direction.
     * Promote gates (10% below): task must clearly be in the faster tier.
     * Demote gates  (10% above): task must clearly be in the slower tier. */
    const u16 *tg = tier_gates[old_tier & 3];  /* M5 LUT: 2.66 vs 13.4 cyc */
    u16 g0 = tg[0], g1 = tg[1], g2 = tg[2];

    /* M6 sum-of-cmp: 3 independent branches vs 3 chained.
     * 10/10 wins, 0.21 cyc vs 6.15 cyc on 9800x3d.
     * BPF codegen: 3 parallel 1-insn skips vs 3 serial jumps. */
    new_tier = (new_avg >= g0) + (new_avg >= g1) + (new_avg >= g2);

    /* ── TIER-CHANGE DAMPENING ──
     * Suppress tier change when stability == 0 (zero prior agreement).
     * Prevents single-sample EWMA fluctuations near gate boundaries from
     * causing vtime priority whiplash (1<<56 jump) → scheduling feedback
     * loop.  Confirmed fix for vsync'd games (Elden Ring bimodal 40ms/5ms
     * frametime oscillation).
     *
     * Mechanism: first divergence at stable==0 keeps old tier, lets
     * stability increment to 1.  If next cycle still computes the same
     * new tier (stable >= 1), the change is allowed through.
     * Cost: 1 extra reclassify cycle (~1-4ms) delay for legitimate
     * tier transitions.  Zero cost for stable tasks.
     *
     * Branchless: cmov keeps old_tier when dampen==1 (Rule 16). */
    bool tier_changed = (new_tier != old_tier);
    u8 dampen = tier_changed & (!stable);
    new_tier = dampen ? old_tier : new_tier;  /* cmov: suppress on first divergence */
    tier_changed = (new_tier != old_tier);     /* recompute after dampening */

    /* M8 branchless stability: (!changed) * (stable + (stable < 3)).
     * 10/10 wins, 0.27 cyc vs 1.03 cyc on 9800x3d.
     * Eliminates nested ternary → flat branchless arithmetic. */
    u8 new_stable = (!tier_changed) * (stable + (stable < 3));

    if (tier_changed || deficit_exhausted || new_stable != stable) {
        u32 new_packed = packed;
        /* Fused tier+stable: bits [31:28] = [stable:2][tier:2]
         * Bitfield coalescing — 2 ops instead of 4 (Rule 24 mask fusion) */
        new_packed &= ~((u32)0xF << 28);
        new_packed |= (((u32)new_stable << 2) | (u32)new_tier) << 28;
        /* DRR++: Clear new-flow flag when deficit exhausted */
        if (deficit_exhausted)
            new_packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);

        cake_relaxed_store_u32(&tctx->packed_info, new_packed);
    }

    /* ── SLICE RECALCULATION on tier change ── */
    /* When tier changes, the quantum multiplier changes (T0=0.75x → T3=1.4x).
     * Update next_slice so the next execution bout uses the correct quantum. */
    if (tier_changed) {
        tctx->next_slice = tier_slice_ns[new_tier & 7];  /* P16 LUT: 0.21ns vs 0.31ns */
        tctx->reclass_counter = 0;
    }
}

/* Task stopping — confidence-gated kfunc elimination (Rule 40 + Rule 41).
 *
 * FAST PATH (stable task, same CPU): inline EWMA+deficit from mailbox cache.
 * Zero bpf_task_storage_get — saves ~38ns/stop. Task pointer identity check
 * uses p already in register (zero task_struct loads vs PID comparison).
 *
 * FULL PATH (unstable, recheck, or cache miss): authoritative kfunc reclassify.
 * Populates/refreshes the mailbox cache for future fast-path hits.
 *
 * Periodic tctx sync every 16th fast-path stop prevents migration staleness —
 * ensures tctx is at most 16 bouts stale if task moves to a different CPU. */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu];

    /* ═══ FAST PATH: confidence-gated kfunc skip ═══
     * Task pointer in register → 1 load + 1 cmp (vs PID: 2 loads + 1 cmp) */
    if (likely((u64)p == mbox->rc_task_ptr)) {
        u64 fused = mbox->rc_state_fused;
        u32 packed = (u32)(fused >> 32);
        u8 stable = (packed >> SHIFT_STABLE) & 3;

        if (stable == 3) {
            u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;
            u16 mask = tier_recheck_mask[tier & 3];
            u16 counter = mbox->rc_counter + 1;
            mbox->rc_counter = counter;

            if (counter & mask) {
                /* ── INLINE EWMA+DEFICIT UPDATE ── */
                u32 now = (u32)scx_bpf_now();
                u32 last_run = mbox->tick_last_run_at;
                u32 rt_raw = now - last_run;
                u16 rt_us = (rt_raw >> 10) > 0xFFFF ?
                    0xFFFF : (u16)(rt_raw >> 10);

                u32 deficit_avg = (u32)fused;
                u16 avg_rt = EXTRACT_AVG_RT(deficit_avg);
                u16 deficit = EXTRACT_DEFICIT(deficit_avg);  /* M11 ILP: extract both before compute */
                u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_us >> 3);
                u16 _d3 = deficit - rt_us;
                deficit = (deficit > rt_us) ? _d3 : 0;  /* P4 cmov: 0.38ns vs 0.55ns */

                /* SPOT-CHECK: would new EWMA change the tier? */
                const u16 *tg = tier_gates[tier & 3];  /* M5 LUT: 2.66 vs 13.4 cyc */
                u16 g0 = tg[0], g1 = tg[1], g2 = tg[2];
                /* M6 sum-of-cmp: 3 independent branches (see M6 bench) */
                u8 spot = (new_avg >= g0) + (new_avg >= g1) + (new_avg >= g2);

                if (unlikely(spot != tier)) {
                    /* Tier WOULD change: reset stability → full path
                     * fires on next stop for authoritative reclassify */
                    packed &= ~((u32)3 << SHIFT_STABLE);
                } else {
                    /* DRR++ deficit exhaustion */
                    if (deficit == 0 &&
                        (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)))
                        packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);
                }

                /* Write updated cache */
                mbox->rc_state_fused = ((u64)packed << 32) |
                    PACK_DEFICIT_AVG(deficit, new_avg);

                /* PERIODIC TCTX SYNC: every 16th fast-path stop.
                 * Prevents unlimited staleness on migration. */
                u16 sync = mbox->rc_sync_counter + 1;
                mbox->rc_sync_counter = sync;
                if (unlikely(!(sync & 15))) {
                    struct cake_task_ctx *tctx =
                        get_task_ctx(p, false);
                    if (tctx) {
                        u64 f = mbox->rc_state_fused;
                        tctx->packed_info = (u32)(f >> 32);
                        tctx->deficit_avg_fused = (u32)f;
                        tctx->reclass_counter = mbox->rc_counter;
                        tctx->next_slice = mbox->rc_slice;
                        tctx->last_run_at = mbox->tick_last_run_at;
                    }
                }

                /* Stage for next wakeup from cached values */
                u8 nf = (packed >> SHIFT_FLAGS) & 1;
                p->scx.slice = mbox->rc_slice;
                p->scx.dsq_vtime = vtime_prefix[(tier << 1) | nf];  /* P7 LUT: 0.37ns vs 0.55ns */
                mbox->tick_ctx_valid = 0;
                return;  /* ZERO kfunc stopping ✅ */
            }
            /* Fall through: at recheck boundary → full path */
        }
        /* Fall through: not stable → full path */
    }

    /* ═══ FULL PATH: authoritative kfunc reclassify ═══ */
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    if (tctx) {
        tctx->last_run_at = mbox->tick_last_run_at;
        reclassify_task_cold(tctx);

        /* Stage for next wakeup */
        p->scx.slice = tctx->next_slice;
        u32 packed = tctx->packed_info;
        u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;
        u8 nf = (packed >> SHIFT_FLAGS) & 1;
        p->scx.dsq_vtime = vtime_prefix[(tier << 1) | nf];  /* P7 LUT: 0.37ns vs 0.55ns */

        /* Update cache for future fast-path hits */
        mbox->rc_task_ptr = (u64)p;
        mbox->rc_state_fused =
            ((u64)packed << 32) | tctx->deficit_avg_fused;
        mbox->rc_counter = tctx->reclass_counter;
        mbox->rc_slice = tctx->next_slice;
        mbox->rc_sync_counter = 0;
    }

    mbox->tick_ctx_valid = 0;
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
    /* Per-CPU DSQs eliminated — SCX_DSQ_LOCAL_ON dispatches directly to
     * the kernel's built-in local DSQ, skipping dispatch callback entirely.
     * Per-LLC DSQs used for enqueue → dispatch path. */
    /* Create per-LLC DSQs — one per cache domain.
     * Single-CCD: 1 DSQ (single per-LLC DSQ).
     * Multi-CCD: N DSQs (eliminates cross-CCD lock contention). */
    for (u32 i = 0; i < CAKE_MAX_LLCS; i++) {
        if (i >= nr_llcs)
            break;
        s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
        if (ret < 0)
            return ret;
    }

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
               .running        = (void *)cake_running,
               .stopping       = (void *)cake_stopping,
               .init           = (void *)cake_init,
               .exit           = (void *)cake_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "cake");
