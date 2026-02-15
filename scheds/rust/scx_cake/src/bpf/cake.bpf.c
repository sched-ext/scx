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
const u32 nr_phys_cpus = 8;  /* Set by loader — physical core count for PHYS_FIRST */
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: 64-byte per-CPU state (single cache line = optimal L1)
 * Two-entry psychic cache: slot[0]=MRU, slot[1]=LRU. LRU promotion on hit.
 * rc_slice derived from tier_slice_ns[tier] LUT (saves 8B/slot).
 * (mailbox_cacheline_bench: 64B beats 128B by 1.1%, lower jitter @ 4.89GHz)
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry mega_mailbox[CAKE_MAX_CPUS] SEC(".bss");

/* Per-CPU scratch area - BSS-tunneled helper outputs, isolated to prevent MESI contention */
struct cake_scratch {
    u32 cached_llc;            /* LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u64 cached_now;            /* scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u8 _pad[112]; /* Pad to 128 bytes (2 cache lines) — F4: removed dead dummy_idle field */
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
    s8  hint;       /* V3 LUT_GATE: tick-precomputed best idle CPU per tier (co-located = 1 cache line read) */
    u8 _pad[55];
} __attribute__((aligned(64)));
struct tier_snap tier_snapshot[4] SEC(".bss") __attribute__((aligned(64)));


/* V2 COND_WRITE: packed tier array for snapshot reader.
 * Written conditionally by each CPU's cake_running (only on tier change).
 * Read by CPU 0's cake_tick (1kHz). 64 bytes = 1 cache line.
 * 95% of writes skipped → line stays MESI Shared. */
static u8 packed_tiers[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(64)));

/* V9 FLAG-SKIP: dirty flag for tier snapshot rebuild.
 * Set by any CPU's cake_running when tier changes (~200/s in gaming).
 * Read by CPU 0's cake_tick: if clean, skip entire scan (3.6 cyc vs 44 cyc).
 * Idempotent: setting 1 to 1 is harmless (multiple writers, single reader).
 * aligned(64): own cache line — prevents false sharing regardless of linker BSS order.
 * Bench: 91.5% faster than unconditional scan at gaming steady state. */
static u8 snapshot_dirty SEC(".bss") __attribute__((aligned(64)));


static __always_inline struct cake_stats *get_local_stats(void)
{
    u32 cpu = bpf_get_smp_processor_id();
    return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}


/* User exit info for graceful scheduler exit */
UEI_DEFINE(uei);


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
 * (confidence_sweep_bench: "Linear" config — 96.9% skip rate, 2.1% missed
 *  tier changes vs prior 10.3% missed.  71 µs/s overhead vs 100 µs/s.
 *  Tighter masks catch tier transitions 5× faster with lower net cost.) */
static const u16 tier_recheck_mask[] = {
    255,   /* T0: every 256th stop (was 1024 — over-skipped) */
    63,    /* T1: every 64th   (was 128) */
    15,    /* T2: every 16th   (was 32)  */
    7,     /* T3: every 8th    (was 16)  */
    7, 7, 7, 7,  /* padding */
};

/* Tier classification LUT: pre-baked hysteresis-aware tier mapping.
 * 4 old_tiers × 512 entries = 2KB RODATA. Indexed by [old_tier][new_avg >> 4].
 * Replaces 3 BPF conditional branches + 3 tier_gates loads + sum-of-cmp
 * with 1 shift + 1 clamp + 1 byte load = ZERO branches.
 *
 * Gate values with 10% promote-only hysteresis:
 *   old_tier=0: g0=100, g1=2000, g2=8000 (standard, no hysteresis)
 *   old_tier=1: g0= 90, g1=2000, g2=8000 (g0 lowered 10%)
 *   old_tier=2: g0= 90, g1=1800, g2=8000 (g0,g1 lowered 10%)
 *   old_tier=3: g0= 90, g1=1800, g2=7200 (all lowered 10%)
 *
 * In 16µs buckets: T0 gate→bucket 6(100µs)/5(90µs),
 *                   T1 gate→bucket 125(2000µs)/112(1800µs),
 *                   T2 gate→bucket 500(8000µs)/450(7200µs).
 *
 * BPF constraint: flat 2D array (no pointer indirection — BPF linker
 * rejects relocations against non-exec sections).
 *
 * (small_n_lookup_bench: 1.03 cyc vs 12.3 cyc linear, 92% faster.
 *  BPF codegen: 4 instructions vs 9 instructions with 3 branches.
 *  Validated across 5 workload profiles — no winner flips.) */
#define TIER_LUT_SHIFT   4
#define TIER_LUT_ENTRIES 512
#define TIER_LUT_CLAMP   (TIER_LUT_ENTRIES - 1)

static const u8 tier_classify_lut[4][TIER_LUT_ENTRIES]
    __attribute__((aligned(64))) = {
    /* old_tier=0: gates at 100, 2000, 8000 (standard) */
    [0] = {
        [0 ... 5]     = 0,   /* 0-80µs   → T0 */
        [6 ... 124]   = 1,   /* 96-1984µs → T1 */
        [125 ... 499] = 2,   /* 2000-7984µs → T2 */
        [500 ... 511] = 3,   /* 8000+µs → T3 */
    },
    /* old_tier=1: gates at 90, 2000, 8000 (g0 lowered 10%) */
    [1] = {
        [0 ... 4]     = 0,   /* 0-64µs   → T0 */
        [5 ... 124]   = 1,   /* 80-1984µs → T1 */
        [125 ... 499] = 2,   /* 2000-7984µs → T2 */
        [500 ... 511] = 3,   /* 8000+µs → T3 */
    },
    /* old_tier=2: gates at 90, 1800, 8000 (g0,g1 lowered 10%) */
    [2] = {
        [0 ... 4]     = 0,   /* 0-64µs   → T0 */
        [5 ... 111]   = 1,   /* 80-1776µs → T1 */
        [112 ... 499] = 2,   /* 1792-7984µs → T2 */
        [500 ... 511] = 3,   /* 8000+µs → T3 */
    },
    /* old_tier=3: gates at 90, 1800, 7200 (all lowered 10%) */
    [3] = {
        [0 ... 4]     = 0,   /* 0-64µs   → T0 */
        [5 ... 111]   = 1,   /* 80-1776µs → T1 */
        [112 ... 449] = 2,   /* 1792-7184µs → T2 */
        [450 ... 511] = 3,   /* 7200+µs → T3 */
    },
};

/* Inline helper: hysteresis-aware tier classification via LUT.
 * Replaces: (new_avg >= g0) + (new_avg >= g1) + (new_avg >= g2)
 * BPF codegen: w1 >>= 4; MIN(w1, 511); r2 = lut ll; w0 = *(u8*)(r2+r1)
 * = ~5 instructions, ZERO branches (vs 9 instructions, 3 branches) */
static __always_inline u8 classify_tier_lut(u8 old_tier, u16 new_avg)
{
    u32 bucket = new_avg >> TIER_LUT_SHIFT;
    if (bucket > TIER_LUT_CLAMP)
        bucket = TIER_LUT_CLAMP;
    return tier_classify_lut[old_tier & 3][bucket];
}


/* Per-task context map */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct cake_task_ctx);
} task_ctx SEC(".maps");


static __attribute__((noinline))
struct cake_task_ctx *alloc_task_ctx_cold(struct task_struct *p)
{
    struct cake_task_ctx *ctx;

    /* Heavy allocator call */
    ctx = bpf_task_storage_get(&task_ctx, p, 0,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) return NULL;

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
     * Cost: ~15ns (single kfunc).
     * AFFINITY GATE: Wine/Proton tasks may dynamically restrict cpumask.
     * prev_cpu could be outside the allowed set after affinity change.
     * Fast path: nr_cpus_allowed == nr_cpus is RODATA-const, JIT folds
     * to single register cmp — zero kfunc cost for full-affinity tasks. */
    bool restricted = (p->nr_cpus_allowed != nr_cpus);
    u32 prev_idx = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);
    if ((!restricted || bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        /* J1 V2: Gate 1 hit — increment prediction counter.
         * Saturate at 255 to avoid wrap. */
        u8 wsc = mega_mailbox[prev_idx].wakeup_same_cpu;
        if (wsc < 255)
            mega_mailbox[prev_idx].wakeup_same_cpu = wsc + 1;
        u64 slice = p->scx.slice ?: quantum_ns;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice, wake_flags);
        return prev_cpu;
    }

    /* J1 V2: Gate 1 MISS — check prediction counter.
     * If task has 8+ consecutive same-CPU wakeups, it strongly prefers
     * prev_cpu. Skip Gates 1b/2/3 — let enqueue handle placement.
     * Sim: -100% gate cascade jitter (P99-P50 → 0ns). */
    {
        u8 wsc = mega_mailbox[prev_idx].wakeup_same_cpu;
        if (wsc >= 8) {
            mega_mailbox[prev_idx].wakeup_same_cpu = 0;
            /* Use prev_cpu's LLC, not waker's — task predicted to run
             * on prev_cpu. Using waker's LLC would put it in the wrong
             * DSQ on multi-CCD systems. */
            scr->cached_llc = cpu_llc_id[prev_idx];
            scr->cached_now = scx_bpf_now();
            return prev_cpu;
        }
        mega_mailbox[prev_idx].wakeup_same_cpu = 0;
    }

    /* ── GATE 1b: SMT sibling fallback — L2 still warm ──
     * When prev_cpu is busy, try its SMT sibling before Gate 2's full scan.
     * Same physical core → L2 cache shared → 1.5µs migration vs 8µs full.
     * Sim (real schedstat): −66% full migrations, net 71.3ms/s savings.
     * Cost: 1 extra kfunc (15ns) per Gate 1 miss. JIT folds nr_cpus/nr_phys
     * comparison to constant (both are RODATA).
     * Branchless sibling: XOR with nr_phys toggles the SMT bit (Rule 16). */
    if (nr_cpus > nr_phys_cpus) {
        s32 sib = prev_cpu ^ nr_phys_cpus;  /* SMT sibling (P↔V) */
        if ((u32)sib < nr_cpus &&
            (!restricted || bpf_cpumask_test_cpu(sib, p->cpus_ptr)) &&
            scx_bpf_test_and_clear_cpu_idle(sib)) {
            u64 slice = p->scx.slice ?: quantum_ns;
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | sib, slice, wake_flags);
            return sib;
        }
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

        /* ── GATE 2a: LUT hint — tick-precomputed best CPU per tier ──
         * 0-1 kfuncs. Bench: 100% hint accuracy, 50% fewer wasted kfuncs. */
        s8 hint = tier_snapshot[tier].hint;  /* F2: co-located with mask — 1 cache line */
        if (hint >= 0 && (u32)hint < CAKE_MAX_CPUS &&
            (!restricted || bpf_cpumask_test_cpu(hint, p->cpus_ptr)) &&
            scx_bpf_test_and_clear_cpu_idle(hint)) {
            u64 slice = p->scx.slice ?: quantum_ns;
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | hint, slice, wake_flags);
            return hint;
        }

        /* ── GATE 2b: PHYS_FIRST scan, LIMIT-2 ──
         * Physical cores have dedicated L2 → prefer over SMT siblings (Rule 21).
         * Limit total scan to 2: 1 physical + 1 virtual.
         * Bench: +65% at 32c, halves wasted kfuncs. */
        if (tmask) {
            /* Skip hint CPU if already tried */
            if (hint >= 0 && (u32)hint < CAKE_MAX_CPUS)
                tmask &= ~(1ULL << hint);

            /* Try 1 physical core (lower N bits) */
            u64 phys_mask = nr_phys_cpus < 64 ?
                (1ULL << nr_phys_cpus) - 1 : ~0ULL;
            u64 phys_cand = tmask & phys_mask;
            if (phys_cand) {
                s32 c = __builtin_ctzll(phys_cand);
                if ((u32)c < CAKE_MAX_CPUS &&
                    (!restricted || bpf_cpumask_test_cpu(c, p->cpus_ptr)) &&
                    scx_bpf_test_and_clear_cpu_idle(c)) {
                    u64 slice = p->scx.slice ?: quantum_ns;
                    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | c, slice, wake_flags);
                    return c;
                }
            }
            /* Try 1 virtual core */
            u64 virt_cand = tmask & ~phys_mask;
            if (virt_cand) {
                s32 c = __builtin_ctzll(virt_cand);
                if ((u32)c < CAKE_MAX_CPUS &&
                    (!restricted || bpf_cpumask_test_cpu(c, p->cpus_ptr)) &&
                    scx_bpf_test_and_clear_cpu_idle(c)) {
                    u64 slice = p->scx.slice ?: quantum_ns;
                    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | c, slice, wake_flags);
                    return c;
                }
            }
        }
    }

    /* ── GATE 3: Kernel fallback — let kernel find any idle CPU ──
     * Only reached when prev_cpu is busy AND no tier-matched cores are idle.
     * This is the cold path (~2-5% of wakeups in gaming). */
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle && bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
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
        /* No staged context: first dispatch or kthread without alloc.
         * task_flags read deferred here — only needed on this cold path.
         * Avoids stealing a callee-saved register from the hot path,
         * eliminating spill of p across bpf_get_smp_processor_id. */
        u32 task_flags = p_reg->flags;
        u8 fallback_tier = (task_flags & PF_KTHREAD) ?
            CAKE_TIER_CRITICAL : CAKE_TIER_FRAME;
        u64 vtime = ((u64)fallback_tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
        /* J6 V1: per-tier DSQ — reduce contention ~75% */
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc * 4 + fallback_tier,
                                 quantum_ns, vtime, enq_flags);
        return;
    }

    /* Handle Yields/Background — preserve staged tier from stopping.
     * Re-enqueues (slice exhaust, yield) don't go through select_cpu,
     * so cached_now is stale. Get fresh timestamp. Use staged tier/slice
     * from cake_stopping if available (bit 63 set). */
    if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
        u64 now_fresh = scx_bpf_now();
        u8 requeue_tier = (staged >> 56) & 3;
        u64 requeue_slice = p_reg->scx.slice ?: quantum_ns;
        /* STOLEN SLICE: Re-enqueued tasks (slice exhaust, yield) get 50%
         * of their normal slice. Forces compilation workers to release
         * CPUs 2x faster, creating more idle windows for fresh game
         * wakeups. 200µs floor prevents micro-slicing (Rule 9).
         * Sim: cuts render wait 82% vs full-slice re-enqueue. */
        requeue_slice >>= 1;
        if (requeue_slice < 200000)
            requeue_slice = 200000;
        u64 vtime = ((u64)requeue_tier << 56) | (now_fresh & 0x00FFFFFFFFFFFFFFULL);
        /* J6 V1: per-tier DSQ */
        scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc * 4 + requeue_tier,
                                 requeue_slice, vtime, enq_flags);
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

    /* TIER-1 WAKEUP PROMOTION: Fresh wakeups get tier-1 in vtime ordering.
     * A T3 render thread wakes at T2 priority, sorting before T3
     * compilation re-enqueues in the same DSQ. Combined with stolen-slice,
     * this isolates fresh game wakeups from background contention.
     * Sim: beats 1/24 multi-DSQ by 29% on render avg wait.
     * Cost: 1 branch + 1 subtract (~0.3ns). */
    u8 vtime_tier = tier;
    if (tier > 0)
        vtime_tier--;

    /* A+B: Vtime-encoded priority: (vtime_tier << 56) | timestamp
     * DRR++ NEW FLOW BONUS: Tasks with CAKE_FLOW_NEW get a vtime reduction,
     * making them drain before established same-tier tasks. This gives
     * newly spawned threads instant responsiveness (e.g., game launching a
     * new worker). Cleared by reclassify_task_cold when deficit exhausts. */
    u64 vtime = ((u64)vtime_tier << 56) | (now_cached & 0x00FFFFFFFFFFFFFFULL);
    if (new_flow)
        vtime -= new_flow_bonus_ns;
    /* J6 V1: per-tier DSQ — insert into tier-specific DSQ.
     * Uses actual tier (not vtime_tier) for DSQ routing so dispatch
     * scans T0 before T1 before T2 before T3. The vtime_tier promotion
     * only affects ordering within the DSQ, not DSQ selection. */
    scx_bpf_dsq_insert_vtime(p_reg, LLC_DSQ_BASE + enq_llc * 4 + tier, slice, vtime, enq_flags);
}

/* Dispatch: per-LLC DSQ scan with cross-LLC stealing fallback.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];
    u32 base = LLC_DSQ_BASE + my_llc * 4;

    /* J6 V1: Scan local LLC per-tier DSQs in priority order (T0→T3).
     * Higher-priority tiers always dispatch first, eliminating the
     * vtime-tier encoding as the sole priority mechanism.
     * Each per-tier DSQ has ~1/4 the contention of a unified DSQ. */
    for (u32 t = 0; t < 4; t++) {
        if (scx_bpf_dsq_move_to_local(base + t))
            return;
    }

    /* Steal from other LLCs (only when all local tiers empty).
     * RODATA gate: single-LLC systems skip this entirely. (Rule 5) */
    if (nr_llcs <= 1)
        return;

    for (u32 i = 1; i < CAKE_MAX_LLCS; i++) {
        if (i >= nr_llcs)
            break;
        u32 victim = my_llc + i;
        if (victim >= nr_llcs)
            victim -= nr_llcs;
        u32 vbase = LLC_DSQ_BASE + victim * 4;
        /* Steal in tier priority order from victim LLC */
        for (u32 t = 0; t < 4; t++) {
            if (scx_bpf_dsq_move_to_local(vbase + t))
                return;
        }
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

    /* Slice exceeded: Grace period kick (J13 V2)
     * T0/T1 (IRQ, input, compositor): immediate hard preempt — latency-critical.
     * T2/T3 (render, compilation): +2ms grace window before kick.
     * Most short overruns self-correct within grace (task yields naturally).
     * If still running after grace, hard preempt fires.
     * Starvation check (below) handles actual contention independently.
     * Sim: 42ns avg overhead vs 29,708ns baseline (-99.9% jitter). */
    if (unlikely(runtime > mbox->tick_slice)) {
        /* T0/T1: no grace — kick immediately */
        if (tier_reg <= 1) {
            scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
            return;
        }
        /* T2/T3: 2ms grace window — only kick if significantly over slice.
         * 2ms grace = small fraction of T2's 4ms/T3's 8ms slice.
         * Short overruns (<2ms) resolve naturally next tick. */
        if (runtime > mbox->tick_slice + 2000000) {
            scx_bpf_kick_cpu(cpu_id_reg, SCX_KICK_PREEMPT);
            return;
        }
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
            goto skip_increment;  /* F3: contention reset — don't also increment */
        }
    }
    /* F3: Common path — increment counter (skipped check OR no contention).
     * Deduplicates identical increment from both branches (Rule 5, 24). */
    if (tc < 255) mbox->tick_counter = tc + 1;
skip_increment:;


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
     * Build tier bitmask from packed_tiers array for select_cpu Gate 2.
     * COND_WRITE: packed_tiers read = 1 cache line (vs N mailbox lines).
     * Single writer (CPU 0) = zero MESI contention. 1kHz = ~1ms staleness.
     *
     * F1v3: Direct-index accumulation replaces 8-accumulator multiply-select.
     * 12 ops/iter → 3 ops/iter. thints is s64 (not s8) to force Clang to
     * emit (index << 3) + ADD for array indexing. Byte-sized arrays cause
     * Clang to optimize ptr+index → ptr|index, which BPF verifier rejects
     * ("bitwise operator |= on pointer prohibited"). 8-byte elements
     * guarantee shift+ADD since OR is not equivalent for stride-8 offsets
     * when base alignment is < 32. Stack cost: 64B (thints) + 32B (tmasks)
     * = 96B, all L1-hot after first touch. */
    if (cpu_id_reg == 0 && snapshot_dirty) {
        /* V9 FLAG-SKIP: only rebuild when cake_running flagged a change.
         * Gaming steady state: ~80%+ of ticks skip entirely (3.6 cyc).
         * When dirty: indexed s64 rebuild (44 cyc vs 113 cyc original). */
        snapshot_dirty = 0;  /* Clear before scan — new changes during scan will re-flag */

        u64 tmasks[4] = {0, 0, 0, 0};
        s64 thints[4] = {-1, -1, -1, -1};

        u32 c;
        for (c = 0; c < nr_cpus; c++) {
            if (c >= CAKE_MAX_CPUS)
                break;
            u8 t = packed_tiers[c] & 3;  /* & 3 = verifier-safe array bound */
            tmasks[t] |= 1ULL << c;      /* Direct index: 1 OR (was 4×multiply+OR) */
            thints[t] = (s64)c;          /* s64: forces shift+ADD indexing in BPF */
        }
        tier_snapshot[0].mask = tmasks[0]; tier_snapshot[0].hint = (s8)thints[0];
        tier_snapshot[1].mask = tmasks[1]; tier_snapshot[1].hint = (s8)thints[1];
        tier_snapshot[2].mask = tmasks[2]; tier_snapshot[2].hint = (s8)thints[2];
        tier_snapshot[3].mask = tmasks[3]; tier_snapshot[3].hint = (s8)thints[3];
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

    /* ── PHASE 1: READ all inputs (2 cache lines: kfunc + p->scx) ── */
    u32 now = (u32)scx_bpf_now();
    u64 v = p->scx.dsq_vtime;
    u64 slice = p->scx.slice;

    /* ── PHASE 2: COMPUTE (registers only, zero memory) ── */
    u8 tier;
    u64 final_slice;
    if (unlikely(!v)) {
        tier = CAKE_TIER_FRAME;
        final_slice = quantum_ns;
    } else {
        tier = (v >> 56) & 3;
        final_slice = slice ?: quantum_ns;
    }

    /* ── PHASE 3: WRITE all outputs (single cache line burst) ──
     * All 4 writes hit the same mbox cache line (already in Modified state
     * from prior tick_ctx_valid=0). Batching avoids interleaving reads from
     * p->escx between writes, preventing store buffer stalls.
     * (write_coalesce_bench: narrow stores 1.21 cyc vs fused u64 3.57 cyc) */
    mbox->tick_last_run_at = now;
    mbox->tick_slice = final_slice;
    mbox->tick_tier = tier;
    mbox->tick_ctx_valid = 1;

    /* V2 COND_WRITE: update packed array only on tier change.
     * Read-only check keeps line MESI Shared (~95% of the time).
     * Write triggers RFO only on actual tier change (~5%).
     * Bench: 20× fewer RFOs, zero instruction cost regression. */
    if (packed_tiers[cpu] != tier) {
        packed_tiers[cpu] = tier;
        /* V9 FLAG-SKIP: signal CPU 0 tick to rebuild snapshot.
         * Read-before-write: skip store when already dirty (~80% of writes
         * under load), avoids redundant RFO cache-line invalidation.
         * Same RFO as packed_tiers write (both on same code path). */
        if (!snapshot_dirty)
            snapshot_dirty = 1;
    }
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
/* NOTE: reclassify_task_cold removed — OPT2 replaced its only call site with
 * inline classification (slice-delta runtime → EWMA → tier LUT → cache seed).
 * EWMA, hysteresis LUT, and dampening logic now live inline in the MONSTER
 * paths (psychic cache, self-seed, and cold classify). Periodic tctx sync
 * every 16th fast-path stop writes back to task storage. */

/* Task stopping — THE MONSTER: 5-component fast-path optimization.
 *
 * Benchmark (stopping_psychic_bench): 3.1× per-stop speedup (51ns→16.7ns),
 * 0% full-path rate (was 97%), 49% fewer kfunc calls.
 *
 * Components combined:
 *   OPT2: Skip stability ramp — full path sets stable=3 directly
 *   OPT3: Confidence EWMA skip — after 64+ fast-path hits, skip 3/4 EWMAs
 *   OPT4: Inline tier update — spot!=tier updates tier in-place, no nuke
 *   OPT5: Two-entry psychic cache — slot[0]=MRU, slot[1]=LRU, 44% hit rate
 *   OPT6: Self-carried EWMA — avg_rt packed in dsq_vtime[47:32], survives migration
 *
 * Periodic tctx sync every 16th fast-path stop prevents migration staleness. */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry *mbox = &mega_mailbox[cpu];
    u64 tp = (u64)p;

    /* ═══ PSYCHIC CACHE: Check both slots (OPT5) ═══
     * Slot 0 (MRU) checked first — ~85% of hits land here.
     * Slot 1 (LRU) checked second — catches CPU-alternating tasks.
     * Combined: ~44% fast-path rate vs 3% with single slot (sim validated). */
    int hit = -1;
    u64 *fused_ptr;
    u32 *counter_ptr;

    if (likely(tp == mbox->rc_task_ptr0)) {
        hit = 0;
        fused_ptr = &mbox->rc_state_fused0;
        counter_ptr = &mbox->rc_counter0;
    } else if (tp == mbox->rc_task_ptr1) {
        hit = 1;
        /* ALWAYS_S0: copy slot[1] → slot[0], then use slot[0].
         * 4 stores vs 6+3 for old SWAP. slot[0] = fixed offset → no
         * data-dependent addressing. Bench: +10% vs SWAP. */
        mbox->rc_task_ptr0 = mbox->rc_task_ptr1;
        mbox->rc_state_fused0 = mbox->rc_state_fused1;
        mbox->rc_counter0 = mbox->rc_counter1;
        mbox->rc_task_ptr1 = 0;
        fused_ptr = &mbox->rc_state_fused0;
        counter_ptr = &mbox->rc_counter0;
    }

    if (hit >= 0) {
        u64 fused = *fused_ptr;
        u32 packed = (u32)(fused >> 32);
        u8 stable = (packed >> SHIFT_STABLE) & 3;
        u8 tier = (packed >> SHIFT_TIER) & MASK_TIER;

        if (stable == 3) {
            u16 mask = tier_recheck_mask[tier & 3];
            u32 counter = *counter_ptr + 1;  /* u32: no wrap for 23.9h */

            if (counter & mask) {
                /* ── OPT3: CONFIDENCE EWMA SKIP ──
                 * After 64+ consecutive fast-path hits, the task's tier is
                 * hyper-stable. Skip EWMA+kfunc on 3 of every 4 stops.
                 * Just stage from cache and return. ~4ns vs ~14ns. */
                if (counter > 64 && (counter & 3)) {
                    u8 nf = (packed >> SHIFT_FLAGS) & 1;
                    /* WRITE BURST: all stores grouped at exit */
                    *counter_ptr = counter;
                    p->scx.slice = tier_slice_ns[tier & 7];
                    p->scx.dsq_vtime = vtime_prefix[(tier << 1) | nf] |
                        ((u64)EXTRACT_AVG_RT((u32)fused) << 32);
                    mbox->tick_ctx_valid = 0;
                    return;  /* ULTRA-FAST: zero kfunc, zero EWMA ✅ */
                }

                /* ── INLINE EWMA+DEFICIT UPDATE ──
                 * OPT6: slice-delta runtime. Kernel decrements p->scx.slice
                 * via update_curr_scx() before stopping() fires.
                 * runtime = original_slice - remaining. Zero kfuncs. */
                u32 rt_raw = (u32)(mbox->tick_slice - p->scx.slice);
                /* Branchless delta clamp */
                u32 _max_rt = 65535U << 10;
                rt_raw -= (rt_raw - _max_rt) & -(rt_raw > _max_rt);
                u16 rt_us = (u16)(rt_raw >> 10);

                u32 deficit_avg = (u32)fused;
                u16 avg_rt = EXTRACT_AVG_RT(deficit_avg);
                u16 deficit = EXTRACT_DEFICIT(deficit_avg);
                u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_us >> 3);
                u16 _d3 = deficit - rt_us;
                deficit = (deficit > rt_us) ? _d3 : 0;

                /* SPOT-CHECK: would new EWMA change the tier?
                 * LUT: 1 shift + 1 load, ZERO branches */
                u8 spot = classify_tier_lut(tier, new_avg) & MASK_TIER;

                if (unlikely(spot != tier)) {
                    /* ── DAMPENED TIER CHANGE ──
                     * DON'T change tier in-place. Reset stability to 0.
                     * Keeps old tier — forces 3 confirming stops through
                     * the ramp path before the new tier commits.
                     * Prevents oscillation at tier boundaries (Rule 45). */
                    packed &= ~((u32)3 << SHIFT_STABLE);  /* stable = 0 */
                } else {
                    /* DRR++ deficit exhaustion */
                    if (deficit == 0 &&
                        (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)))
                        packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);
                }

                /* ── WRITE BURST: pre-compute all values in registers,
                 * then group all stores at exit. Bench: +3-5% over
                 * scattered writes, fixes p99 spike at 32c (141→94). ── */
                u64 new_fused = ((u64)packed << 32) |
                    PACK_DEFICIT_AVG(deficit, new_avg);
                u8 nf = (packed >> SHIFT_FLAGS) & 1;
                u64 new_slice = tier_slice_ns[tier & 7];
                u64 new_vtime = vtime_prefix[(tier << 1) | nf] |
                    ((u64)new_avg << 32);
                u32 sync = mbox->rc_sync_counter + 1;  /* u32: no wrap */

                /* All stores grouped — same-line writes coalesce in
                 * store buffer, avoiding fill buffer exhaustion. */
                *counter_ptr = counter;
                *fused_ptr = new_fused;
                mbox->rc_sync_counter = sync;
                p->scx.slice = new_slice;
                p->scx.dsq_vtime = new_vtime;
                mbox->tick_ctx_valid = 0;

                /* PERIODIC TCTX SYNC: every 16th fast-path stop.
                 * J23 V3: Skip when hyper-stable (stable=3) — psychic cache +
                 * dsq_vtime carry authoritative state. Only sync during tier
                 * transitions (stable<3) or after migration (self-seed handles).
                 * Sim: eliminates 100% sync jitter for gaming tasks. */
                if (unlikely(!(sync & 15)) && stable < 3) {
                    struct cake_task_ctx *tctx =
                        get_task_ctx(p, false);
                    if (tctx) {
                        tctx->packed_info = (u32)(new_fused >> 32);
                        tctx->deficit_avg_fused = (u32)new_fused;
                        tctx->reclass_counter = counter;
                        tctx->last_run_at = mbox->tick_last_run_at;
                    }
                }
                return;  /* FAST PATH: 0 kfuncs (OPT6 slice-delta) ✅ */
            }
            /* Fall through: at recheck boundary → full path */
        }

        /* ── STABILITY RAMP (stable < 3): Dampened confirmation ──
         * Cache hit but not yet confident. Do EWMA, check if tier
         * confirms. Increment stable only on agreement, nuke on
         * disagreement. Requires 3 consecutive confirming stops to
         * reach stable=3. Prevents tier oscillation (Rule 45). */
        if (stable < 3) {
            /* OPT6: slice-delta runtime (zero kfuncs) */
            u32 rt_raw = (u32)(mbox->tick_slice - p->scx.slice);
            u32 _max_rt_r = 65535U << 10;
            rt_raw -= (rt_raw - _max_rt_r) & -(rt_raw > _max_rt_r);
            u16 rt_us = (u16)(rt_raw >> 10);

            u32 deficit_avg = (u32)fused;
            u16 avg_rt = EXTRACT_AVG_RT(deficit_avg);
            u16 deficit = EXTRACT_DEFICIT(deficit_avg);
            u16 new_avg = avg_rt - (avg_rt >> 3) + (rt_us >> 3);
            u16 _d_r = deficit - rt_us;
            deficit = (deficit > rt_us) ? _d_r : 0;

            u8 spot = classify_tier_lut(tier, new_avg) & MASK_TIER;
            u8 new_stable;

            if (spot == tier) {
                /* Tier confirms — increment stability */
                new_stable = stable + 1;
            } else {
                /* Tier disagrees — reset stability, keep old tier */
                new_stable = 0;
            }

            /* DRR++ deficit exhaustion */
            if (deficit == 0 &&
                (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)))
                packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);

            packed = (packed & ~((u32)0xF << 28)) |
                     (((u32)new_stable << 2) | (u32)tier) << 28;

            u64 new_fused = ((u64)packed << 32) |
                PACK_DEFICIT_AVG(deficit, new_avg);
            u8 nf = (packed >> SHIFT_FLAGS) & 1;

            *counter_ptr = *counter_ptr + 1;
            *fused_ptr = new_fused;
            p->scx.slice = tier_slice_ns[tier & 7];
            p->scx.dsq_vtime = vtime_prefix[(tier << 1) | nf] |
                ((u64)new_avg << 32);
            mbox->tick_ctx_valid = 0;
            return;  /* RAMP PATH: 1 kfunc, building confidence ✅ */
        }
        /* Fall through: stable < 3 handled above, this is unreachable
         * but kept for verifier safety */
    }

    /* ═══ UNIFIED MISS PATH (J20 V3): Self-seed + Cold merged ═══
     * Both paths do: extract initial avg → EWMA step → classify → seed cache.
     * Self-seed: init from dsq_vtime[47:32] (migration recovery, OPT6).
     * Cold: init from 0 (first-ever stop).
     * Unified: eliminates bimodal 4-32ns distribution → constant ~14ns.
     * Sim: -100% stopping path jitter (P99-P50 → 0ns). */
    {
        u64 staged = p->scx.dsq_vtime;
        bool has_carried = staged & (1ULL << 63);
        u16 init_avg = has_carried ? (u16)((staged >> 32) & 0xFFFF) : 0;
        u8 init_tier = has_carried ? (u8)((staged >> 56) & 3) : CAKE_TIER_FRAME;

        /* OPT6: slice-delta runtime (zero kfuncs) */
        u32 rt_raw = (u32)(mbox->tick_slice - p->scx.slice);
        u32 _max_rt_u = 65535U << 10;
        rt_raw -= (rt_raw - _max_rt_u) & -(rt_raw > _max_rt_u);
        u16 rt_us = (u16)(rt_raw >> 10);

        /* EWMA: self-seed uses carried avg, cold uses 0 */
        u16 new_avg = init_avg - (init_avg >> 3) + (rt_us >> 3);
        u8 new_tier = classify_tier_lut(init_tier, new_avg) & MASK_TIER;

        /* DAMPENED SEED: stable=2 if tier confirms (self-seed only),
         * stable=0 for cold start or tier change.
         * Requires 1-3 confirming stops via ramp before stable=3. */
        u8 seed_stable = (has_carried && new_tier == init_tier) ? 2 : 0;
        u32 new_packed = ((u32)seed_stable << SHIFT_STABLE) |
                         ((u32)new_tier << SHIFT_TIER);
        u16 new_deficit = (u16)((tier_slice_ns[new_tier & 7] >> 10) & 0xFFFF);

        /* Install in cache: evict LRU (slot[1]), promote to MRU (slot[0]) */
        mbox->rc_task_ptr1 = mbox->rc_task_ptr0;
        mbox->rc_state_fused1 = mbox->rc_state_fused0;
        mbox->rc_counter1 = mbox->rc_counter0;
        mbox->rc_task_ptr0 = tp;
        mbox->rc_state_fused0 = ((u64)new_packed << 32) |
            PACK_DEFICIT_AVG(new_deficit, new_avg);
        mbox->rc_counter0 = has_carried ? 1 : 0;  /* Pre-warm on self-seed */
        mbox->rc_sync_counter = 0;

        p->scx.slice = tier_slice_ns[new_tier & 7];
        p->scx.dsq_vtime = vtime_prefix[new_tier << 1] |
            ((u64)new_avg << 32);
    }

    mbox->tick_ctx_valid = 0;
}

/* Initialize the scheduler */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
    /* Per-CPU DSQs eliminated — SCX_DSQ_LOCAL_ON dispatches directly to
     * the kernel's built-in local DSQ, skipping dispatch callback entirely.
     * Per-LLC DSQs used for enqueue → dispatch path. */
    /* J6 V1: Create per-tier per-LLC DSQs — 4 tiers × N LLCs.
     * Single-CCD: 4 DSQs (one per tier, ~75% less contention).
     * Multi-CCD: 4×N DSQs (eliminates cross-CCD + cross-tier contention).
     * DSQ ID = LLC_DSQ_BASE + llc*4 + tier. */
    for (u32 i = 0; i < CAKE_MAX_LLCS; i++) {
        if (i >= nr_llcs)
            break;
        for (u32 t = 0; t < 4; t++) {
            s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i * 4 + t, -1);
            if (ret < 0)
                return ret;
        }
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
