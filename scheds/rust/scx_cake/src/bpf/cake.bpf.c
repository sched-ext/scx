// SPDX-License-Identifier: GPL-2.0
/* scx_cake - CAKE DRR++ adapted for CPU scheduling: avg_runtime classification, direct dispatch, tiered DSQ */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/arena_map.h>        /* BPF_MAP_TYPE_ARENA definition */
#include <lib/sdt_task.h>         /* scx_task_data, scx_task_alloc, scx_task_free */
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
const u64 quantum_ns = CAKE_DEFAULT_QUANTUM_NS;
const u64 new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;
const bool enable_stats = false;
const bool enable_dvfs = false;  /* RODATA — loader-compat only (tick removed, DVFS dead) */

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
 * MEGA-MAILBOX: Arena per-CPU state (Phase 2 arena migration).
 * 128-byte per CPU: psychic cache (3-slot), tick staging, tier snapshot.
 * Arena pointer eliminates verifier bounds checks (~12ns/cycle savings).
 * Allocated contiguously in cake_init via bpf_arena_alloc_pages.
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry __arena *arena_mailbox;

/* Per-CPU scratch area — arena-backed (Phase 3).
 * Tunnels select_cpu → enqueue outputs (LLC ID, timestamp). */
struct cake_scratch {
    u32 cached_llc;            /* LLC ID tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u64 cached_now;            /* scx_bpf_now() tunneled from select_cpu → enqueue (saves 1 kfunc) */
    u8 _pad[112]; /* Pad to 128 bytes (2 cache lines) — F4: removed dead dummy_idle field */
};
_Static_assert(sizeof(struct cake_scratch) <= 128,
    "cake_scratch exceeds 128B -- adjacent CPUs will false-share");
struct cake_scratch __arena *arena_scratch;

/* Per-LLC tier-occupancy bitmask — arena-backed (2nd pass item C).
 * 4 bits per LLC (bit 0 = T0, bit 3 = T3). Set in cake_enqueue when
 * inserting to a tier DSQ. Read by cake_dispatch to skip empty tiers,
 * avoiding ~25ns kfunc trampoline per skipped tier. Cleared after
 * successful dsq_move_to_local. Racy but safe: worst case is one
 * extra dsq_move_to_local that returns false instantly. */
u8 __arena *arena_tier_occupied;

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss") __attribute__((aligned(256)));

/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* ═══ TIER SNAPSHOT (A4: tick-assembled, zero false sharing) ═══
 * Built by CPU 0's cake_tick from per-CPU mbox->tick_tier (1kHz, ~150ns).
 * Read by cake_select_cpu Gate 2 — single L1-hot u64 load + CTZ scan.
 *
 * Architecture: INCREMENTAL ATOMIC UPDATES (tick-less)
 *   Writer: any CPU's cake_running, only on tier change (~200/s total)
 *   Reader: Gate 2 in select_cpu (~9% of wakeups)
 *   Staleness: ZERO — updated atomically at the instant a tier changes.
 *   Each CPU owns exactly 1 bit position → no cross-bit contention.
 *   2 atomics per tier change vs old 16-CPU polling loop at 200/s.
 *
 * Cacheline-padded: each tier mask on its own 64B line.
 * Zero false sharing between tiers. Atomic contention negligible
 * at ~200 tier changes/s across 16 CPUs. */
struct tier_snap {
    u64 mask;
    u8 _pad[56];
} __attribute__((aligned(64)));
struct tier_snap tier_snapshot[4] SEC(".bss") __attribute__((aligned(64)));


/* packed_tiers[]/packed_wsc[]/snapshot_dirty REMOVED:
 * packed arrays were redundant copies causing false sharing (100K+ RFOs/s).
 * snapshot_dirty was the tick-based rebuild flag — no longer needed.
 * Tier snapshot now updated incrementally via atomics in cake_running. */

/* Force BPF arena map association for struct_ops programs.
 * BSS-stored __arena pointers generate addr_space_cast instructions, but the
 * verifier only allows these in programs with an associated arena map.
 * BSS loads don't create arena map relocations — only direct &arena references do.
 * volatile prevents dead-code elimination. Cost: 2 insns (~0.4ns). */
#define ARENA_ASSOC() do { void *volatile __p = (void *)&arena; (void)__p; } while (0)

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
 * (Pattern bench P8: 0.1834ns vs 0.3656ns, 10/10 wins on 9800X3D) */

/* skip_mask_lut REMOVED: was tick confidence backoff LUT.
 * No longer needed — tick eliminated. Starvation detection
 * now handled by kernel timer (slice = base + grace). */

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

/* ═══ EWMA + CLASSIFICATION HELPER ═══
 * Extracted from 3 identical copies in cake_stopping (fast-path, ramp-path,
 * miss-path). __always_inline produces identical codegen to copy-paste
 * but single source of truth eliminates maintenance fragility. */
struct ewma_result {
    u16 rt_us;
    u16 new_avg;
    u16 deficit;
    u8  new_tier;
};

static __always_inline struct ewma_result
compute_ewma_classify(u64 tick_slice, u64 remaining_slice,
                      u16 old_avg, u16 old_deficit, u8 old_tier)
{
    struct ewma_result r;
    /* OPT6: slice-delta runtime (zero kfuncs) */
    u32 rt_raw = (u32)(tick_slice - remaining_slice);
    u32 _max_rt = 65535U << 10;
    rt_raw -= (rt_raw - _max_rt) & -(rt_raw > _max_rt);
    r.rt_us = (u16)(rt_raw >> 10);
    /* EWMA: 7/8 old + 1/8 new */
    r.new_avg = old_avg - (old_avg >> 3) + (r.rt_us >> 3);
    /* Deficit drain */
    u16 _d = old_deficit - r.rt_us;
    r.deficit = (old_deficit > r.rt_us) ? _d : 0;
    /* Classification via hysteresis LUT */
    r.new_tier = classify_tier_lut(old_tier, r.new_avg) & MASK_TIER;
    return r;
}

/* C2 DUAL_PHASE: bimodal runtime detection helper.
 * If THIS run's actual runtime > 2× EWMA average, dispatch with
 * one-tier-higher slice to avoid preemption on long physics batches. */
static __always_inline u8
compute_dispatch_tier(u8 tier, u16 rt_us, u16 new_avg)
{
    if (rt_us > (new_avg << 1))
        return (tier < 3) ? tier + 1 : 3;
    return tier;
}


/* Per-task context: arena-backed direct pointer dereference.
 * Replaces BPF_MAP_TYPE_TASK_STORAGE (hash lookup, ~25-40ns cold)
 * with scx_task_data() arena pointer (single load, ~4-8ns).
 * Benchmark: cold P99 355ns → 86ns, contended P99 19ns → 9.6ns.
 * Storage allocated in cake_init_task (sleepable), freed in cake_exit_task. */


/* Get task context — arena direct pointer dereference.
 * Arena storage allocated upfront in cake_init_task (sleepable).
 * No null check needed in hot paths: init_task guarantees allocation
 * before any scheduling callbacks fire for this task.
 * __arena qualifier: verifier knows this pointer is arena-backed. */
static __always_inline struct cake_task_ctx __arena *get_task_ctx(struct task_struct *p)
{
    return (struct cake_task_ctx __arena *)scx_task_data(p);
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

/* ── Confidence gate recording macro (Rule 40) ──
 * Updates predicted_gate + gate_confidence on the mailbox for prev_cpu.
 * Called at each miss-path gate exit. Gate 1 hits and WSC bypass do NOT
 * update confidence — Gate 1 depends on system idle state, not task behavior.
 * CL1 write: mailbox[prev_idx] already hot from WSC + migration_cooldown. */
#define CAKE_GATE_RECORD(idx, gate_id) do {                     \
    u8 _pg = arena_mailbox[(idx)].predicted_gate;               \
    if (_pg == (gate_id)) {                                     \
        u8 _gc = arena_mailbox[(idx)].gate_confidence;          \
        if (_gc < CAKE_GATE_CONF_MAX)                           \
            arena_mailbox[(idx)].gate_confidence = _gc + 1;     \
    } else {                                                    \
        arena_mailbox[(idx)].predicted_gate = (gate_id);        \
        arena_mailbox[(idx)].gate_confidence = 1;               \
    }                                                           \
} while (0)

s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags)
{
    bool is_idle = false;
    ARENA_ASSOC();

    /* ── SYNC STRIP: prevent waker-core migration ──
     * Bench: 0.20ns cost, saves 1.6-3.5µs per prevented migration.
     * Without this, scx_bpf_select_cpu_dfl prefers waker CPU over prev_cpu
     * when WF_SYNC is set, destroying cache warmth. */
    wake_flags &= ~SCX_WAKE_SYNC;

    /* ── GATE 1: Try prev_cpu — task's L1/L2 cache is hot there ──
     * Atomically claims the idle CPU. If idle, we get direct dispatch.
     * This is the fast path (~91% hit rate in gaming workloads).
     * Cost: ~15ns (single kfunc).
     *
     * KFUNC DEFERRAL: bpf_get_smp_processor_id() deferred to after Gate 1.
     * Gate 1 hit (91%) never uses tc_id/scr — saves 15ns kfunc trampoline
     * on the hottest path. ~1,365µs/s returned to game threads.
     *
     * AFFINITY GATE: Wine/Proton tasks may dynamically restrict cpumask.
     * prev_cpu could be outside the allowed set after affinity change.
     * Fast path: nr_cpus_allowed == nr_cpus is RODATA-const, JIT folds
     * to single register cmp — zero kfunc cost for full-affinity tasks. */
    bool restricted = (p->nr_cpus_allowed != nr_cpus);
    u32 prev_idx = (u32)prev_cpu & (CAKE_MAX_CPUS - 1);
    if ((!restricted || bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr)) &&
        scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
        /* MLP: load slice FIRST — independent cache line from mailbox CL1.
         * CPU issues both loads in parallel: p->scx (scx entity CL) and
         * mailbox CL1 (remote) overlap → max(3ns, 8ns) vs serial 11ns. */
        u64 slice = p->scx.slice ?: quantum_ns;

        /* J1 V2: Gate 1 hit — increment prediction counter.
         * Saturate at 255 to avoid wrap. */
        u8 wsc = arena_mailbox[prev_idx].wakeup_same_cpu;
        if (wsc < 255) {
            u8 new_wsc = wsc + 1;
            arena_mailbox[prev_idx].wakeup_same_cpu = new_wsc;
        }
        /* NEAR_PREF: Gate 1 hit — same CPU, cooldown decrement.
         * CL1 read: mailbox[prev_idx] already hot from WSC read above.
         * CL1 write: conditional-only, no spurious invalidation (Rule 11). */
        u8 mcd = arena_mailbox[prev_idx].migration_cooldown;
        if (mcd > 0)
            arena_mailbox[prev_idx].migration_cooldown = mcd - 1;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, slice, wake_flags);
        return prev_cpu;
    }

    /* ── DEFERRED KFUNC: bpf_get_smp_processor_id() ──
     * Only reached on Gate 1 miss (~9%). WSC bypass, Gate 1c, Gate 2-4,
     * and the enqueue tunnel all need tc_id/scr. */
    u32 tc_id = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch __arena *scr = &arena_scratch[tc_id];

    /* J1 V2: Gate 1 MISS — check prediction counter.
     * If task has 8+ consecutive same-CPU wakeups, it strongly prefers
     * prev_cpu. Skip Gates 1b/2/3 — let enqueue handle placement.
     * Sim: -100% gate cascade jitter (P99-P50 → 0ns). */
    {
        u8 wsc = arena_mailbox[prev_idx].wakeup_same_cpu;
        if (wsc >= 8) {
            arena_mailbox[prev_idx].wakeup_same_cpu = 0;
            /* Use prev_cpu's LLC, not waker's — task predicted to run
             * on prev_cpu. Using waker's LLC would put it in the wrong
             * DSQ on multi-CCD systems. */
            scr->cached_llc = cpu_llc_id[prev_idx];
            scr->cached_now = scx_bpf_now();
            return prev_cpu;
        }
        arena_mailbox[prev_idx].wakeup_same_cpu = 0;
    }

    /* Hoist staged/tier extraction above confidence check.
     * Gate 4, Gate 2, and tunnel all need these values. If confidence
     * routing jumps past Gate 2, they must already be initialized.
     * p->scx.dsq_vtime is on the same cache line as p->scx.slice
     * (already pulled by Gate 1 MLP) — zero new cache line fetch. */
    u64 staged = p->scx.dsq_vtime;
    u8 tier = (staged >> 56) & 3;

    /* ── CONFIDENCE ROUTING: skip intermediate gates if predictable ──
     * After WSC miss, if this CPU's wakeups consistently exit through
     * the same gate, jump directly to that gate (forward goto).
     * Saves ~2-6 kfunc calls per skipped gate (15-40ns each).
     * CL1 read: mailbox[prev_idx] already hot from WSC access above.
     * BPF: forward goto only — verifier traces both paths. */
    u8 _pred_gate = arena_mailbox[prev_idx].predicted_gate;
    u8 _gate_conf = arena_mailbox[prev_idx].gate_confidence;
    if (_gate_conf >= CAKE_GATE_CONF_THRESH) {
        switch (_pred_gate) {
        case CAKE_GATE_2:   goto gate_2_entry;
        case CAKE_GATE_3:   goto gate_3_entry;
        case CAKE_GATE_4:   goto gate_4_entry;
        case CAKE_GATE_TUN: goto gate_tunnel_entry;
        default:            break;  /* GATE_1B, GATE_1C: fall through */
        }
    }

    /* NEAR_PREF: Gate 1 MISS — task is about to migrate.
     * Set cooldown = 4: for the next 4 Gate 1 hits, the cooldown
     * decrements and Gate 1c will try nearby CPUs before Gate 2.
     * CL1 of mailbox[prev_idx] already hot from WSC access above. */
    /* MESI GUARD (Rule 11): skip write if already at target value.
     * Avoids ~4.5K unnecessary RFOs/s on CL1 when cooldown is already 4. */
    if (arena_mailbox[prev_idx].migration_cooldown != 4)
        arena_mailbox[prev_idx].migration_cooldown = 4;

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
            CAKE_GATE_RECORD(prev_idx, CAKE_GATE_1B);
            return sib;
        }
    }

    /* ── GATE 1c: NEAR_PREF — nearby idle scan on migration cooldown ──
     * When prev_cpu AND its SMT sibling are busy, try CPUs on the same
     * CCD half (±3 physical cores) before falling to Gate 2's tier scan.
     * This converts far migrations (1.2µs X3D / 4.8µs non-X3D cache cost)
     * into nearby ones (0.8µs / 2.5µs) — same L3 slice, partial cache warm.
     *
     * Only active during cooldown (4 wakeups after last migration).
     * For sticky workloads (Arc Raiders: 91% Gate 1 hit), cooldown is rarely
     * active so this gate is nearly never reached (<1% overhead).
     * For bouncy workloads (FF16: ~25% Gate 1 hit), this catches ~20% of
     * wakeups and converts far→near, reducing jitter 8.5× (sim validated).
     *
     * Scan order: physical cores first (Rule 21), then their SMT siblings.
     * CCD half = prev_cpu's physical core rounded to 4-core boundary.
     * 9800X3D: all 8 cores on 1 CCD, so half = P0-P3 or P4-P7.
     * Cost: 0-4 kfuncs (avg 1-2). Only on Gate 1+1b miss + cooldown active. */
    {
        u8 mcd = arena_mailbox[prev_idx].migration_cooldown;
        if (mcd > 0) {
            u32 prev_phys = (u32)prev_cpu % nr_phys_cpus;
            u32 half_base = prev_phys & ~3u;  /* 0 or 4 — single AND, no division */
            /* Scan physical cores in same half */
            #pragma unroll
            for (u32 off = 0; off < 4 && off < nr_phys_cpus; off++) {
                s32 c = (s32)(half_base + off);
                if (c == prev_cpu) continue;  /* already tried in Gate 1 */
                if ((u32)c < nr_cpus &&
                    (!restricted || bpf_cpumask_test_cpu(c, p->cpus_ptr)) &&
                    scx_bpf_test_and_clear_cpu_idle(c)) {
                    u64 slice = p->scx.slice ?: quantum_ns;
                    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | c, slice, wake_flags);
                    CAKE_GATE_RECORD(prev_idx, CAKE_GATE_1C);
                    return c;
                }
            }
            /* Scan SMT siblings of same half */
            if (nr_cpus > nr_phys_cpus) {
                #pragma unroll
                for (u32 off = 0; off < 4 && off < nr_phys_cpus; off++) {
                    s32 c = (s32)(half_base + off + nr_phys_cpus);
                    /* Skip prev_cpu's sibling — already tried in Gate 1b */
                    if (c == (prev_cpu ^ (s32)nr_phys_cpus)) continue;
                    if ((u32)c < nr_cpus &&
                        (!restricted || bpf_cpumask_test_cpu(c, p->cpus_ptr)) &&
                        scx_bpf_test_and_clear_cpu_idle(c)) {
                        u64 slice = p->scx.slice ?: quantum_ns;
                        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | c, slice, wake_flags);
                        CAKE_GATE_RECORD(prev_idx, CAKE_GATE_1C);
                        return c;
                    }
                }
            }
        }
    }

gate_2_entry: __attribute__((unused));
    /* ── GATE 2: Tier-matched idle core via tick snapshot (A4) ──
     * Read the task's tier from staged dsq_vtime (set by cake_stopping).
     * tier_snapshot[tier].mask updated atomically by cake_running.
     * Single L1 read (~1.3ns) + CTZ scan — zero cross-CPU cache line reads.
     *
     * MESI: negligible contention (~200 atomic ops/s from tier changes).
     * Staleness: ZERO — updated at the instant a tier changes.
     * Sim: 31ns/wakeup amortized (vs 40ns mailbox scan). */
    /* staged + tier already extracted above confidence check */
    if (staged & (1ULL << 63)) {
        u64 tmask = tier_snapshot[tier].mask;

        /* ── GATE 2: PHYS_FIRST scan, LIMIT-2 (tick-less) ──
         * tier_snapshot updated atomically by cake_running — always current.
         * Physical cores have dedicated L2 → prefer over SMT siblings (Rule 21).
         * Limit total scan to 2: 1 physical + 1 virtual.
         * Bench: +65% at 32c, halves wasted kfuncs. */
        if (tmask) {

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
                    CAKE_GATE_RECORD(prev_idx, CAKE_GATE_2);
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
                    CAKE_GATE_RECORD(prev_idx, CAKE_GATE_2);
                    return c;
                }
            }
        }
    }

gate_3_entry: __attribute__((unused));
    /* ── GATE 3: Kernel fallback — let kernel find any idle CPU ──
     * Only reached when prev_cpu is busy AND no tier-matched cores are idle.
     * This is the cold path (~2-5% of wakeups in gaming). */
    s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle && bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
        u64 slice = p->scx.slice ?: quantum_ns;
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, wake_flags);
        CAKE_GATE_RECORD(prev_idx, CAKE_GATE_3);
        return cpu;
    }

gate_4_entry: __attribute__((unused));
    /* ── GATE 4: Lazy preempt — T0/T1 urgent task, all CPUs busy ──
     * All idle gates missed. If the waking task is T0/T1 (latency-critical),
     * find the worst-tier CPU via tier_snapshot bitmask (pre-built by tick,
     * 1.14ns V3 CTZ scan) and dispatch to its LOCAL queue.
     *
     * NO IPI, NO kick — victim discovers pending task on next natural
     * yield (50-200µs for game threads) or tick starvation check (1-3ms).
     * Bench: 1.71ns total (scan+LOCAL_ON) — CHEAPER than DSQ fallback (2.45ns).
     * Sim (real Arc Raiders data): -99% composite score, zero oscillation.
     *
     * T0+T1 gating: +0.4µs/s overhead, saves 6-25ms/s for GPU pipeline.
     * Unlike enqueue-time kicks (DISABLED above — 16fps regression in A/B test),
     * this uses LOCAL_ON dispatch: zero cache pollution, zero pipeline bubbles. */
    if ((staged & (1ULL << 63)) && tier <= 1) {
        /* tier already extracted above — zero redundant shift+AND */
        s32 victim = -1;

        /* V3 bitmask scan: tier_snapshot[].mask updated atomically by cake_running.
         * Scan worst tier first: T3 → T2 → (T1 if waker is T0).
         * CTZ = first set bit = one victim CPU. 1.14ns on 9800X3D.
         * ~1ms staleness is fine: if CPU went idle since snapshot,
         * LOCAL_ON task gets dispatched immediately (even better). */
        for (int t = 3; t > (int)tier; t--) {
            u64 tmask = tier_snapshot[t].mask;
            if (tmask) {
                victim = __builtin_ctzll(tmask);
                break;
            }
        }

        if (victim >= 0 && (u32)victim < CAKE_MAX_CPUS &&
            (!restricted || bpf_cpumask_test_cpu(victim, p->cpus_ptr))) {
            u64 slice = p->scx.slice ?: quantum_ns;
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | victim, slice, wake_flags);
            CAKE_GATE_RECORD(prev_idx, CAKE_GATE_4);
            return victim;
        }
    }

gate_tunnel_entry: __attribute__((unused));
    /* ALL BUSY + NO VICTIM: tunnel LLC ID + timestamp for enqueue.
     * select_cpu runs on same CPU as enqueue — safe to tunnel.
     * Reached when: all T0/T1 (no higher-tier victim exists),
     * or task is T2/T3 (no preemption needed), or new task (no staged ctx). */
    scr->cached_llc = cpu_llc_id[tc_id];
    scr->cached_now = scx_bpf_now();
    CAKE_GATE_RECORD(prev_idx, CAKE_GATE_TUN);
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
    ARENA_ASSOC();

    /* PRE-LOAD: staged context before kfunc trampoline.
     * p_reg->scx.dsq_vtime doesn't depend on enq_cpu — load executes
     * in parallel with the ~15ns bpf_get_smp_processor_id trampoline.
     * Saves ~3ns dependent load on the hot path. */
    u64 staged = p_reg->scx.dsq_vtime;

    /* KFUNC TUNNELING: Reuse LLC ID + timestamp cached by select_cpu in scratch.
     * Eliminates 2 kfunc trampolines (~40-60ns) — select_cpu always runs on
     * the same CPU immediately before enqueue, so values are fresh. */
    u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct cake_scratch __arena *scr = &arena_scratch[enq_cpu];
    u64 now_cached = scr->cached_now;
    u32 enq_llc = scr->cached_llc;

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
        arena_tier_occupied[enq_llc & (CAKE_MAX_LLCS - 1)] |= (1 << fallback_tier);
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
        arena_tier_occupied[enq_llc & (CAKE_MAX_LLCS - 1)] |= (1 << requeue_tier);
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
    /* Mark tier as occupied for dispatch skip optimization */
    arena_tier_occupied[enq_llc & (CAKE_MAX_LLCS - 1)] |= (1 << tier);
}

/* Dispatch: per-LLC DSQ scan with cross-LLC stealing fallback.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here. */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
    u32 my_llc = cpu_llc_id[raw_cpu & (CAKE_MAX_CPUS - 1)];
    u32 base = LLC_DSQ_BASE + my_llc * 4;
    ARENA_ASSOC();

    /* J6 V2: Arena-filtered local LLC dispatch.
     * Read arena_tier_occupied to skip tiers known-empty.
     * Each skipped tier avoids a ~25ns dsq_move_to_local kfunc trampoline.
     * Racy: bit may be stale (another CPU consumed last task), but
     * dsq_move_to_local returns false instantly in that case. */
    u8 occ = arena_tier_occupied[my_llc & (CAKE_MAX_LLCS - 1)];
    for (u32 t = 0; t < 4; t++) {
        if (!(occ & (1 << t)))
            continue;  /* Skip empty tier — save ~25ns kfunc trampoline */
        if (scx_bpf_dsq_move_to_local(base + t)) {
            /* Clear bit: we consumed from this tier. Racy but safe —
             * worst case: another enqueue re-sets it next cycle. */
            arena_tier_occupied[my_llc & (CAKE_MAX_LLCS - 1)] &= ~(1 << t);
            return;
        }
        /* dsq_move_to_local returned false: tier actually empty.
         * Clear the stale bit so future dispatches skip it. */
        arena_tier_occupied[my_llc & (CAKE_MAX_LLCS - 1)] &= ~(1 << t);
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
        u8 vocc = arena_tier_occupied[victim & (CAKE_MAX_LLCS - 1)];
        u32 vbase = LLC_DSQ_BASE + victim * 4;
        /* Steal in tier priority order from victim LLC */
        for (u32 t = 0; t < 4; t++) {
            if (!(vocc & (1 << t)))
                continue;
            if (scx_bpf_dsq_move_to_local(vbase + t))
                return;
        }
    }
}

/* cake_tick REMOVED: tick-less architecture.
 * All tick responsibilities relocated to always-warm callbacks:
 *
 * 1. Slice enforcement → baked into p->scx.slice (base + grace).
 *    Kernel timer fires at expiration, no polling needed.
 *
 * 2. Starvation detection → kernel timer guarantees preemption at slice
 *    boundary. Max wait for queued tasks = one slice. Gate 4 handles
 *    urgent T0/T1 dispatch to busy CPUs via LOCAL_ON.
 *
 * 3. Tier snapshot → incremental atomics in cake_running (below).
 *    Each CPU owns 1 bit position, 2 atomics per tier change (~200/s).
 *    Always current — zero staleness vs old 1ms polling.
 *
 * 4. DVFS → removed (JIT-eliminated for gaming, CPPC2 is faster).
 *
 * Savings: eliminates 16K kfunc calls/s, ~1.6M cycles/s stolen from
 * game threads, CPU 0 jitter spikes from snapshot rebuild.
 * tier_perf_target/enable_dvfs/has_hybrid RODATA kept for loader compat. */

/* DVFS RODATA: unused by BPF (tick removed) but written by Rust loader.
 * Kept to prevent loader panic on missing RODATA symbol. JIT dead-code eliminates. */
const u32 tier_perf_target[8] = {
    1024, 1024, 1024, 768, 768, 768, 768, 768,
};

/* ZERO bpf_task_storage_get: stamp the currently-running task's data into
 * the per-CPU mega_mailbox. cake_stopping reads from the SAME cache line.
 * Tier extracted from p->scx.dsq_vtime — bits [57:56] contain tier in
 * both staging format (set by stopping) and vtime-encoding format (set by
 * scx_bpf_dsq_insert_vtime). cake_stopping syncs last_run_at back to tctx.
 *
 * TICK-LESS: also maintains tier_snapshot incrementally via atomics.
 * Each CPU owns bit position [cpu] in tier_snapshot[tier].mask.
 * On tier change: clear old bit, set new bit (2 atomics, ~200/s total). */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
    /* PRE-LOAD: dsq_vtime before kfunc trampoline.
     * Doesn't depend on any kfunc result. Lands in r8 callee-saved
     * (confirmed by codegen audit — zero spill). Saves ~3ns.
     * NOTE: p->scx.slice NOT pre-loaded — codegen audit showed it
     * spills to stack (4ns) > gain (3ns). Loaded after kfuncs instead. */
    u64 v = p->scx.dsq_vtime;
    ARENA_ASSOC();

    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    struct mega_mailbox_entry __arena *mbox = &arena_mailbox[cpu];

    /* ── PHASE 1: READ timestamp + slice (kfunc + task field) ── */
    u32 now = (u32)scx_bpf_now();
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

    /* ── PHASE 2b: READ old tier for incremental snapshot update ──
     * CL0 already in Modified state — this read is free. */
    u8 old_tier = mbox->tick_tier;

    /* ── PHASE 3: WRITE all outputs (single cache line burst) ──
     * All stores hit the same mbox cache line (already Modified).
     * Batching avoids interleaving reads from p->scx between writes.
     * (write_coalesce_bench: narrow stores 1.21 cyc vs fused u64 3.57 cyc) */
    mbox->tick_last_run_at = now;
    mbox->tick_slice = final_slice;
    mbox->tick_tier = tier;

    /* ── PHASE 4: INCREMENTAL TIER SNAPSHOT (tick-less) ──
     * On tier change: atomically move this CPU's bit from old tier to new.
     * Each CPU owns exactly 1 bit → zero cross-bit contention.
     * ~200 tier changes/s total → negligible atomic contention.
     * Always current: zero staleness vs old 1ms tick polling. */
    if (old_tier != tier) {
        u64 cpu_bit = 1ULL << cpu;
        __sync_fetch_and_and(&tier_snapshot[old_tier & 3].mask, ~cpu_bit);
        __sync_fetch_and_or(&tier_snapshot[tier & 3].mask, cpu_bit);
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
    /* NOTE: p->scx.slice NOT pre-loaded here — codegen audit showed it
     * spills to stack (4ns cost) since all callee-saved registers are
     * occupied. Only 29% of paths use it (compute_ewma_classify calls).
     * Net: 4ns spill > 0.87ns weighted gain. Read inline instead. */
    u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
    ARENA_ASSOC();
    struct mega_mailbox_entry __arena *mbox = &arena_mailbox[cpu];
    u64 tp = (u64)p;

    /* ═══ PSYCHIC CACHE: Check all 3 slots (R2 3-slot) ═══
     * Slot 0 (MRU) checked first — ~58% of hits (Arc Raiders sim).
     * Slot 1 checked second — ~30% of hits.
     * Slot 2 (LRU, cache line 2) checked last — ~7% of hits.
     * Combined: 95.4% fast-path rate (was 78% with 2-slot).
     * Slot 2 on CL1: only accessed on s0+s1 miss, ALP-prefetched. */
    int hit = -1;
    u64 __arena *fused_ptr;
    u32 __arena *counter_ptr;

    if (likely(tp == mbox->rc_task_ptr0)) {
        hit = 0;
        fused_ptr = &mbox->rc_state_fused0;
        counter_ptr = &mbox->rc_counter0;
        if (mbox->s1_hot_flag)  /* J3: skip-if-unchanged — 58% of stops write 0 to already-0 */
            mbox->s1_hot_flag = 0;
    } else if (tp == mbox->rc_task_ptr1) {
        hit = 1;
        /* C2: DEFERRED PROMOTION — avoid swap churn for occasional s1 hits.
         * Bench: +5.1% throughput (29.4 vs 28.0 Mops/s), same hit rate.
         * 1st hit: work in-place on slot 1 (3 stores), set hot flag.
         * 2nd consecutive: full swap s0↔s1 (6 stores), clear hot flag.
         * Gaming: most s1 hits are one-off (task briefly revisits CPU),
         * so deferred skips ~70% of swaps while preserving MRU accuracy. */
        if (mbox->s1_hot_flag) {
            /* 2nd consecutive s1 hit — promote via full swap */
            u64 tmp_ptr = mbox->rc_task_ptr0;
            u64 tmp_fused = mbox->rc_state_fused0;
            u32 tmp_counter = mbox->rc_counter0;
            mbox->rc_task_ptr0 = mbox->rc_task_ptr1;
            mbox->rc_state_fused0 = mbox->rc_state_fused1;
            mbox->rc_counter0 = mbox->rc_counter1;
            mbox->rc_task_ptr1 = tmp_ptr;
            mbox->rc_state_fused1 = tmp_fused;
            mbox->rc_counter1 = tmp_counter;
            fused_ptr = &mbox->rc_state_fused0;
            counter_ptr = &mbox->rc_counter0;
            mbox->s1_hot_flag = 0;
        } else {
            /* 1st s1 hit — work in-place, defer promotion decision */
            fused_ptr = &mbox->rc_state_fused1;
            counter_ptr = &mbox->rc_counter1;
            mbox->s1_hot_flag = 1;
        }
    } else if (tp == mbox->rc_task_ptr2) {
        hit = 2;
        /* PROMOTE s2→s0: cascade s0→s1→s2, then install s2 at s0.
         * Touches CL1 (slot 2 read), but this is only ~7% of stops.
         * 9 stores total for full 3-way rotation. */
        u64 s2_ptr = mbox->rc_task_ptr2;
        u64 s2_fused = mbox->rc_state_fused2;
        u32 s2_counter = mbox->rc_counter2;
        mbox->rc_task_ptr2 = mbox->rc_task_ptr1;
        mbox->rc_state_fused2 = mbox->rc_state_fused1;
        mbox->rc_counter2 = mbox->rc_counter1;
        mbox->rc_task_ptr1 = mbox->rc_task_ptr0;
        mbox->rc_state_fused1 = mbox->rc_state_fused0;
        mbox->rc_counter1 = mbox->rc_counter0;
        mbox->rc_task_ptr0 = s2_ptr;
        mbox->rc_state_fused0 = s2_fused;
        mbox->rc_counter0 = s2_counter;
        fused_ptr = &mbox->rc_state_fused0;
        counter_ptr = &mbox->rc_counter0;
        mbox->s1_hot_flag = 0;  /* C2: s2 hit resets s1 tracking */
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
                    return;  /* ULTRA-FAST: zero kfunc, zero EWMA ✅ */
                }

                /* ── INLINE EWMA+DEFICIT UPDATE via helper ──
                 * OPT6: slice-delta runtime + EWMA + deficit + classify.
                 * Single source of truth (was copy-pasted 3×). */
                u32 deficit_avg = (u32)fused;
                struct ewma_result er = compute_ewma_classify(
                    mbox->tick_slice, p->scx.slice,
                    EXTRACT_AVG_RT(deficit_avg),
                    EXTRACT_DEFICIT(deficit_avg), tier);

                if (unlikely(er.new_tier != tier)) {
                    /* ── DAMPENED TIER CHANGE ──
                     * DON'T change tier in-place. Reset stability to 0.
                     * Keeps old tier — forces 3 confirming stops through
                     * the ramp path before the new tier commits.
                     * Prevents oscillation at tier boundaries (Rule 45). */
                    packed &= ~((u32)3 << SHIFT_STABLE);  /* stable = 0 */
                } else {
                    /* DRR++ deficit exhaustion */
                    if (er.deficit == 0 &&
                        (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)))
                        packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);
                }

                u8 dispatch_tier = compute_dispatch_tier(tier, er.rt_us, er.new_avg);

                /* ── WRITE BURST: pre-compute all values in registers,
                 * then group all stores at exit. Bench: +3-5% over
                 * scattered writes, fixes p99 spike at 32c (141→94). ── */
                u64 new_fused = ((u64)packed << 32) |
                    PACK_DEFICIT_AVG(er.deficit, er.new_avg);
                u8 nf = (packed >> SHIFT_FLAGS) & 1;
                u64 new_slice = tier_slice_ns[dispatch_tier & 7];
                u64 new_vtime = vtime_prefix[(tier << 1) | nf] |
                    ((u64)er.new_avg << 32);
                u32 sync = mbox->rc_sync_counter + 1;  /* u32: no wrap */

                /* All stores grouped — same-line writes coalesce in
                 * store buffer, avoiding fill buffer exhaustion. */
                *counter_ptr = counter;
                *fused_ptr = new_fused;
                mbox->rc_sync_counter = sync;
                p->scx.slice = new_slice;
                p->scx.dsq_vtime = new_vtime;

                /* PERIODIC TCTX SYNC: every 16th fast-path stop.
                 * J23 V3: Skip when hyper-stable (stable=3) — psychic cache +
                 * dsq_vtime carry authoritative state. Only sync during tier
                 * transitions (stable<3) or after migration (self-seed handles).
                 * Sim: eliminates 100% sync jitter for gaming tasks.
                 * ARENA: direct pointer dereference, no hash lookup.
                 * Cold P99: 355ns (hash) → 86ns (arena), 4.1× jitter reduction. */
                if (unlikely(!(sync & 15)) && stable < 3) {
                    struct cake_task_ctx __arena *tctx = get_task_ctx(p);
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
            /* EWMA + classify via helper */
            u32 deficit_avg_r = (u32)fused;
            struct ewma_result er_r = compute_ewma_classify(
                mbox->tick_slice, p->scx.slice,
                EXTRACT_AVG_RT(deficit_avg_r),
                EXTRACT_DEFICIT(deficit_avg_r), tier);

            u8 new_stable;

            if (er_r.new_tier == tier) {
                /* Tier confirms — increment stability */
                new_stable = stable + 1;
            } else {
                /* Tier disagrees — reset stability, keep old tier */
                new_stable = 0;
            }

            /* DRR++ deficit exhaustion */
            if (er_r.deficit == 0 &&
                (packed & ((u32)CAKE_FLOW_NEW << SHIFT_FLAGS)))
                packed &= ~((u32)CAKE_FLOW_NEW << SHIFT_FLAGS);

            packed = (packed & ~((u32)0xF << 28)) |
                     (((u32)new_stable << 2) | (u32)tier) << 28;

            u64 new_fused = ((u64)packed << 32) |
                PACK_DEFICIT_AVG(er_r.deficit, er_r.new_avg);
            u8 nf = (packed >> SHIFT_FLAGS) & 1;

            /* C2 DUAL_PHASE: bimodal slice boost (same as fast path) */
            u8 dispatch_tier_r = compute_dispatch_tier(tier, er_r.rt_us, er_r.new_avg);

            *counter_ptr = *counter_ptr + 1;
            *fused_ptr = new_fused;
            p->scx.slice = tier_slice_ns[dispatch_tier_r & 7];
            p->scx.dsq_vtime = vtime_prefix[(tier << 1) | nf] |
                ((u64)er_r.new_avg << 32);
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

        /* EWMA + classify via helper */
        struct ewma_result er_m = compute_ewma_classify(
            mbox->tick_slice, p->scx.slice,
            init_avg, 0, init_tier);

        /* C2 DUAL_PHASE: bimodal slice boost for miss/seed path */
        u8 dispatch_tier_m = compute_dispatch_tier(er_m.new_tier, er_m.rt_us, er_m.new_avg);

        /* DAMPENED SEED: stable=2 if tier confirms (self-seed only),
         * stable=0 for cold start or tier change.
         * Requires 1-3 confirming stops via ramp before stable=3. */
        u8 seed_stable = (has_carried && er_m.new_tier == init_tier) ? 2 : 0;
        u32 new_packed = ((u32)seed_stable << SHIFT_STABLE) |
                         ((u32)er_m.new_tier << SHIFT_TIER);
        u16 new_deficit = (u16)((tier_slice_ns[dispatch_tier_m & 7] >> 10) & 0xFFFF);

        /* Install in cache: cascade evict s1→s2, s0→s1, new→s0 (R2 3-slot) */
        mbox->rc_task_ptr2 = mbox->rc_task_ptr1;
        mbox->rc_state_fused2 = mbox->rc_state_fused1;
        mbox->rc_counter2 = mbox->rc_counter1;
        mbox->rc_task_ptr1 = mbox->rc_task_ptr0;
        mbox->rc_state_fused1 = mbox->rc_state_fused0;
        mbox->rc_counter1 = mbox->rc_counter0;
        mbox->rc_task_ptr0 = tp;
        mbox->rc_state_fused0 = ((u64)new_packed << 32) |
            PACK_DEFICIT_AVG(new_deficit, er_m.new_avg);
        mbox->rc_counter0 = has_carried ? 1 : 0;  /* Pre-warm on self-seed */
        mbox->rc_sync_counter = 0;

        p->scx.slice = tier_slice_ns[dispatch_tier_m & 7];
        p->scx.dsq_vtime = vtime_prefix[er_m.new_tier << 1] |
            ((u64)er_m.new_avg << 32);
    }

}

/* Initialize per-task arena storage.
 * Sleepable: bpf_arena_alloc_pages is sleepable-only, so all arena
 * allocation must happen here, not in hot paths.
 * Called before any scheduling ops fire for this task. */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init_task, struct task_struct *p,
                              struct scx_init_task_args *args)
{
    struct cake_task_ctx __arena *tctx;

    tctx = (struct cake_task_ctx __arena *)scx_task_alloc(p);
    if (!tctx)
        return -ENOMEM;

    /* MULTI-SIGNAL INITIAL CLASSIFICATION (moved from alloc_task_ctx_cold)
     *
     * Signal 1: Nice value (u32 field read, ~2 cycles)
     *   - nice < 0 (prio < 120): OS/user explicitly prioritized → T0
     *   - nice > 10 (prio > 130): explicitly deprioritized → T3
     *   - nice 0-10: default → T1, avg_runtime adjusts naturally
     *
     * R1 sum-of-cmp: branchless non-monotonic mapping.
     * (prio >= 120) = 0 for negative nice (→ CRITICAL=0), 1 for default (→ INTERACT=1)
     * (prio > 130) * 2 = 0 for normal, 2 for high nice (1+2 = BULK=3) */
    u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);
    tctx->deficit_avg_fused = PACK_DEFICIT_AVG(init_deficit, 0);
    tctx->last_run_at = 0;
    tctx->reclass_counter = 0;

    u32 prio = p->static_prio;
    u8 init_tier = (prio >= 120) + (prio > 130) * 2;

    u32 packed = 0;
    /* Fused TIER+FLAGS: bits [29:24] = [tier:2][flags:4] (Rule 37 coalescing) */
    packed |= (((u32)(init_tier & MASK_TIER) << 4) | (CAKE_FLOW_NEW & MASK_FLAGS)) << SHIFT_FLAGS;
    tctx->packed_info = packed;

    return 0;
}

/* Free per-task arena storage on task exit. */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
                    struct scx_exit_task_args *args)
{
    scx_task_free(p);
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

    /* Phase 2+3: Allocate arena per-CPU arrays.
     * bpf_arena_alloc_pages returns page-aligned memory from the arena map.
     * mega_mailbox: 128B × 64 = 8KB = 2 pages
     * scratch: 128B × 64 = 8KB = 2 pages */
    arena_mailbox = (struct mega_mailbox_entry __arena *)
        bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
    if (!arena_mailbox)
        return -ENOMEM;

    arena_scratch = (struct cake_scratch __arena *)
        bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
    if (!arena_scratch)
        return -ENOMEM;

    /* 2nd pass item C: per-LLC tier-occupancy bitmask.
     * CAKE_MAX_LLCS bytes (4 bits per LLC), 1 page is overkill but minimum. */
    arena_tier_occupied = (u8 __arena *)
        bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
    if (!arena_tier_occupied)
        return -ENOMEM;

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
               /* .tick removed: tick-less architecture (see cake_running) */
               .running        = (void *)cake_running,
               .stopping       = (void *)cake_stopping,
               .init_task      = (void *)cake_init_task,
               .exit_task      = (void *)cake_exit_task,
               .init           = (void *)cake_init,
               .exit           = (void *)cake_exit,
               .flags          = SCX_OPS_KEEP_BUILTIN_IDLE,
               .name           = "cake");
