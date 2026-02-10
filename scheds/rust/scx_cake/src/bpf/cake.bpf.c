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
    u32 init_tier;
    u32 cached_llc;            /* LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u64 cached_now;            /* scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
    struct bpf_iter_scx_dsq it; /* BSS-Tunneling for iterators */
    u8 _pad[36]; /* Pad to 128 bytes (2 cache lines) */
} global_scratch[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(128)));
_Static_assert(sizeof(struct cake_scratch) <= 128,
    "cake_scratch exceeds 128B -- adjacent CPUs will false-share");

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* Mailbox mask builders removed — select_cpu now delegates idle detection
 * to scx_bpf_select_cpu_dfl() which uses the kernel's authoritative idle
 * tracking (zero staleness, atomic claiming). */

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

/* Per-CPU Direct Dispatch Queues (1000-1063) */
#define CAKE_DSQ_LC_BASE 1000

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

    /* Nice value: static_prio 100 = nice -20, 120 = nice 0, 139 = nice 19 */
    u32 prio = p->static_prio;
    u8 init_tier;

    if (prio < 120) {
        /* Negative nice: OS or user explicitly prioritized.
         * avg_runtime=0 at init → T0 until first reclassify. */
        init_tier = CAKE_TIER_CRITICAL;
    } else if (prio > 130) {
        /* High nice (>10): explicitly deprioritized.
         * Background builds, indexers, low-priority daemons. */
        init_tier = CAKE_TIER_BULK;
    } else {
        /* Default (nice 0-10): start at Interactive.
         * avg_runtime reclassifies to correct tier within ~3 stops. */
        init_tier = CAKE_TIER_INTERACT;
    }

    u32 packed = 0;
    packed |= (255 & MASK_KALMAN_ERROR) << SHIFT_KALMAN_ERROR;
    /* Fused TIER+FLAGS: bits [29:24] = [tier:2][flags:4] (Rule 37 coalescing) */
    packed |= (((u32)(init_tier & MASK_TIER) << 4) | (CAKE_FLOW_NEW & MASK_FLAGS)) << SHIFT_FLAGS;
    /* stable=0, wait_data=0: implicit from packed=0 */

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
 * KERNEL-FIRST FLAT SELECT_CPU: ~20 instructions vs ~200+ in the old cascade.
 *
 * Architecture: delegate idle detection to the kernel's authoritative
 * scx_bpf_select_cpu_dfl() which does prev → sibling → LLC cascade internally
 * with zero staleness and atomic claiming. When all CPUs are busy, return
 * prev_cpu and let cake_enqueue handle via per-LLC DSQ with vtime ordering.
 *
 * Benefits (tier-agnostic by design — all tiers equally important):
 * - All tiers 0-3 take the same placement path (tiers define latency, not affinity)
 * - Zero bpf_task_storage_get in select_cpu (no tier/slice needed)
 * - Zero mailbox reads (kernel has authoritative idle data)
 * - Zero stale mask cascades (kernel idle bitmap is real-time)
 * - ~90-110 cycles vs ~200-500 cycles (~20-40ns p50 improvement)
 * ═══════════════════════════════════════════════════════════════════════════ */
/* SYNC fast-path dispatch: waker's CPU is by definition running.
 * Noinline: only 2 args (p, wake_flags) → r1→r6, r2→r7 saves
 * leave r8,r9 free. Single kfunc call (get_smp_id) + dispatch.
 * Splitting this out lets the main function avoid hoisting
 * bpf_get_smp_processor_id above the SYNC branch, which was the
 * root cause of Spill A (p had to survive across the shared call).
 *
 * CPUMASK GUARD: Check inside cold path (Rule 5/13: no extra work on
 * inline hot path). Wine/Proton threadpools use sched_setaffinity —
 * waker's CPU may not be in woken task's cpumask. Returns -1 to signal
 * fallthrough to kernel path which handles cpumask correctly. */
static __attribute__((noinline))
s32 dispatch_sync_cold(struct task_struct *p, u64 wake_flags)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
        return -1;

    /* Use tier-adjusted slice, not raw quantum. Without this, the kernel's
     * slice countdown preempts at 2ms before cake_tick can check the
     * tier-adjusted threshold — making multipliers dead code for SYNC. */
    struct cake_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
    u64 slice = tctx ? tctx->next_slice : quantum_ns;

    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);
    return (s32)cpu;
}

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    /* SYNC FAST PATH: Direct dispatch to waker's CPU.
     * Cold helper checks cpumask internally (Rule 5: zero extra hot-path
     * instructions). Returns -1 if cpumask disallows → fall through. */
    if (wake_flags & SCX_WAKE_SYNC) {
        s32 sync_cpu = dispatch_sync_cold(p, wake_flags);
        if (sync_cpu >= 0)
            return sync_cpu;
    }

    u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch *scr = &global_scratch[tc_id];
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &scr->dummy_idle);

    if (scr->dummy_idle) {
        /* Kernel found & claimed an idle CPU — direct dispatch.
         * Use tier-adjusted slice so kernel preemption matches tick's check.
         * Falls back to raw quantum for unclassified tasks (first wakeup).
         * No tunnel needed — enqueue never runs on this path. */
        struct cake_task_ctx *tctx = bpf_task_storage_get(&task_ctx, p, 0, 0);
        u64 slice = tctx ? tctx->next_slice : quantum_ns;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);
        return cpu;
    }

    /* ALL BUSY: tunnel LLC ID + timestamp for enqueue (~22ns saved on
     * the 90% idle path above where these were previously wasted).
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

/* Enqueue - A+B architecture: per-LLC DSQ with vtime = (tier << 56) | timestamp */
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

    struct cake_task_ctx *tctx = get_task_ctx(p_reg, false);

    /* Kthread cold path (inlined — reuses now_cached + enq_llc) */
    if (unlikely((task_flags & PF_KTHREAD) && !tctx)) {
        u64 vtime = ((u64)CAKE_TIER_CRITICAL << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        return;
    }

    register struct cake_task_ctx *tctx_reg asm("r7") = tctx;

    /* Handle Yields/Background */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u64 vtime = ((u64)CAKE_TIER_BULK << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        return;
    }

    if (unlikely(!tctx_reg)) {
        /* No context yet - use Frame tier */
        u64 vtime = ((u64)CAKE_TIER_FRAME << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc, quantum_ns, vtime, enq_flags);
        return;
    }

    /* Standard Tier Logic */
    u8 tier = GET_TIER(tctx_reg) & 3;
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

    /* A+B: Vtime-encoded priority: (tier << 56) | timestamp
     * DRR++ NEW FLOW BONUS: Tasks with CAKE_FLOW_NEW get a vtime reduction,
     * making them drain before established same-tier tasks. This gives
     * newly spawned threads instant responsiveness (e.g., game launching a
     * new worker). Cleared by reclassify_task_cold when deficit exhausts. */
    u64 vtime = ((u64)tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
    u32 task_packed = cake_relaxed_load_u32(&tctx_reg->packed_info);
    if (task_packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS))
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

void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
    /* Register pin p to r6 to avoid stack spills */
    register struct task_struct *p_reg asm("r6") = p;
    register struct cake_task_ctx *tctx_reg asm("r7") = get_task_ctx(p_reg, false);
    register u32 cpu_id_reg asm("r8") = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

    u32 now = (u32)scx_bpf_now();

    /* SAFETY GATE: tctx must exist and have been stamped */
    if (unlikely(!tctx_reg || tctx_reg->last_run_at == 0)) {
        if (tctx_reg) tctx_reg->last_run_at = now;
        return;
    }

    /* PHASE 1: COMPUTE RUNTIME */
    register u8 tier_reg asm("r9") = GET_TIER(tctx_reg);
    u32 last_run = tctx_reg->last_run_at;
    u64 runtime = (u64)(now - last_run);

    /* Slice exceeded: force context switch */
    if (unlikely(runtime > tctx_reg->next_slice)) {
        scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
        return;
    }

    /* PHASE 2: STARVATION CHECK — graduated confidence backoff.
     * tick_counter tracks consecutive ticks without contention (nr_running <= 1).
     * As confidence grows, check frequency drops:
     *   counter < 8:  check every tick     (settling, ~8ms)
     *   counter < 16: check every 2nd tick (warming, max 1ms delay)
     *   counter < 32: check every 4th tick (confident, max 3ms delay)
     *   counter >= 32: check every 8th tick (high confidence, max 7ms delay)
     * Any contention (nr_running > 1) resets to 0 → full alertness.
     * Core ideology: good scheduling earns reduced overhead. */
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu_id_reg];
    u8 tc = mbox->tick_counter;
    u8 skip_mask = tc < 8 ? 0 : tc < 16 ? 1 : tc < 32 ? 3 : 7;

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

    /* MEGA-MAILBOX UPDATE: tier for dispatch to consume (MESI-guarded) */
    u8 new_flags = (tier_reg & MBOX_TIER_MASK);
    if (mbox->flags != new_flags)
        mbox->flags = new_flags;

    /* DVFS: Tier-proportional CPU frequency steering.
     * Runs in tick (rq-locked) = ~15-20ns vs ~30-80ns unlocked in running.
     * Hysteresis: skip kfunc if perf target unchanged (MESI-friendly).
     *
     * Hybrid scaling: on Intel P/E-core systems, scale target by each core's
     * cpuperf_cap so E-cores don't get over-requested. JIT eliminates this
     * branch entirely on non-hybrid CPUs (has_hybrid = false in RODATA). */
    u32 target = tier_perf_target[tier_reg & 7];
    if (has_hybrid) {
        u32 cap = scx_bpf_cpuperf_cap(cpu_id_reg);
        target = (target * cap) >> 10;  /* scale by capability (1024 = 100%) */
    }
    u8 cached_perf = mbox->dsq_hint;
    u8 target_cached = (u8)(target >> 2);
    if (cached_perf != target_cached) {
        scx_bpf_cpuperf_set(cpu_id_reg, target);
        mbox->dsq_hint = target_cached;
    }
}

/* Task started running - stamp last_run_at for runtime measurement.
 * DVFS moved to cake_tick where rq lock is held (cpuperf_set ~15-20ns vs
 * ~30-80ns unlocked here). Saves ~44-84 cycles per context switch. */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    if (!tctx)
        return;
    tctx->last_run_at = (u32)scx_bpf_now();
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
        u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_clamped >> 3);
        u16 deficit = EXTRACT_DEFICIT(old_fused);
        deficit = (rt_clamped >= deficit) ? 0 : deficit - rt_clamped;
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
            u16 g0 = tier <= 0 ? TIER_GATE_T0 : TIER_GATE_T0 - TIER_GATE_T0 / 10;
            u16 g1 = tier <= 1 ? TIER_GATE_T1 : TIER_GATE_T1 - TIER_GATE_T1 / 10;
            u16 g2 = tier <= 2 ? TIER_GATE_T2 : TIER_GATE_T2 - TIER_GATE_T2 / 10;
            u8 spot_tier;
            if      (new_avg < g0) spot_tier = 0;
            else if (new_avg < g1) spot_tier = 1;
            else if (new_avg < g2) spot_tier = 2;
            else                   spot_tier = 3;

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

    /* ── EWMA RUNTIME UPDATE ── */
    /* Decay 7/8: responds in ~8 execution bouts. Smooth enough to ignore
     * single outliers, fast enough to detect behavior changes within 50ms. */
    u32 old_fused = tctx->deficit_avg_fused;
    u16 avg_rt = EXTRACT_AVG_RT(old_fused);
    u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_clamped >> 3);

    /* ── DRR++ DEFICIT TRACKING ── */
    /* Each execution bout consumes deficit. When deficit exhausts, clear the
     * new-flow flag → task loses its priority bonus within the tier.
     * Initial deficit = quantum + new_flow_bonus ≈ 10ms of credit. */
    u16 deficit = EXTRACT_DEFICIT(old_fused);
    deficit = (rt_clamped >= deficit) ? 0 : deficit - rt_clamped;

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
    u16 g0 = old_tier <= 0 ? TIER_GATE_T0 : TIER_GATE_T0 - TIER_GATE_T0 / 10;  /* 100 or 90 */
    u16 g1 = old_tier <= 1 ? TIER_GATE_T1 : TIER_GATE_T1 - TIER_GATE_T1 / 10;  /* 2000 or 1800 */
    u16 g2 = old_tier <= 2 ? TIER_GATE_T2 : TIER_GATE_T2 - TIER_GATE_T2 / 10;  /* 8000 or 7200 */

    if      (new_avg < g0) new_tier = 0;
    else if (new_avg < g1) new_tier = 1;
    else if (new_avg < g2) new_tier = 2;
    else                   new_tier = 3;

    /* ── WRITE PACKED_INFO (MESI-friendly: skip if unchanged) ── */
    bool tier_changed = (new_tier != old_tier);

    /* Tier-stability counter: increment toward 3 if tier held, reset on change.
     * When stable==3, subsequent calls take the graduated backoff path. */
    u8 new_stable = tier_changed ? 0 : ((stable < 3) ? stable + 1 : 3);

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
        u64 cfg = tier_configs[new_tier & 7];
        u64 mult = UNPACK_MULTIPLIER(cfg);
        tctx->next_slice = (quantum_ns * mult) >> 10;
        tctx->reclass_counter = 0;
    }
}

/* Task stopping — avg_runtime reclassification + DRR++ deficit tracking */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
    struct cake_task_ctx *tctx = get_task_ctx(p, false);
    if (tctx)
        reclassify_task_cold(tctx);
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
