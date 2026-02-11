/* SPDX-License-Identifier: GPL-2.0 */
/* scx_cake BPF/userspace interface - shared data structures and constants */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

/* Type defs for BPF/userspace compat - defined when vmlinux.h is not included */
#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
#endif

/* CAKE TIER SYSTEM — 4-tier classification by avg_runtime
 *
 * Tiers group tasks with similar scheduling needs. Classification is
 * purely by EWMA avg_runtime — shorter runtime = more latency-sensitive.
 * DRR++ deficit handles intra-tier fairness (yield vs preempt). */
enum cake_tier {
    CAKE_TIER_CRITICAL  = 0,  /* <100µs:  IRQ, input, audio, network */
    CAKE_TIER_INTERACT  = 1,  /* <2ms:    compositor, physics, AI */
    CAKE_TIER_FRAME     = 2,  /* <8ms:    game render, encoding */
    CAKE_TIER_BULK      = 3,  /* ≥8ms:    compilation, background */
    CAKE_TIER_IDLE      = 255,
    CAKE_TIER_MAX       = 4,
};

#define CAKE_MAX_CPUS 64
#define CAKE_MAX_LLCS 8

/* Per-LLC DSQ base — DSQ IDs are LLC_DSQ_BASE + llc_index (0..nr_llcs-1) */
#define LLC_DSQ_BASE 200

/* Flow state flags (only CAKE_FLOW_NEW currently used) */
enum cake_flow_flags {
    CAKE_FLOW_NEW = 1 << 0,  /* Task is newly created */
};

/* Per-task flow state - 64B aligned, first 16B coalesced for cake_stopping writes */
struct cake_task_ctx {
    /* --- Hot Write Group (cake_stopping) [Bytes 0-15] --- */
    u64 next_slice;        /* 8B: Pre-computed slice (ns) */

    /* STATE FUSION: Union allows atomic u64 access to both state fields */
    union {
        struct {
            union {
                struct {
                    u16 deficit_us;        /* 2B: Deficit (us) */
                    u16 avg_runtime_us;    /* 2B: EMA runtime estimate */
                };
                u32 deficit_avg_fused;     /* 4B: Fused access */
            };
            u32 packed_info;               /* 4B: Bitfield */
        };
        u64 state_fused_u64;               /* 8B: Direct burst commit */
    };

    /* --- Timestamp (cake_running) [Bytes 16-19] --- */
    u32 last_run_at;       /* 4B: Last run timestamp (ns), wraps 4.2s */

    /* --- Graduated backoff counter [Bytes 20-21] --- */
    u16 reclass_counter;   /* 2B: Per-task stop counter for per-tier backoff */

    u8 __pad[42];          /* Pad to 64 bytes: 8+8+4+2+42 = 64 */
} __attribute__((aligned(64)));

/* Bitfield layout for packed_info (write-set co-located, Rule 24 mask fusion):
 * [Stable:2][Tier:2][Flags:4][Rsvd:16][Rsvd:8]
 *  31-30     29-28   27-24    23-8      7-0
 * TIER+STABLE adjacent → fused 4-bit clear/set in reclassify (2 ops vs 4)
 * Bits [15:0] reserved for future use (Kalman error + wait data removed). */
#define SHIFT_FLAGS         24  /* 4 bits: flow flags */
#define SHIFT_TIER          28  /* 2 bits: tier 0-3 (coalesced with STABLE) */
#define SHIFT_STABLE        30  /* 2 bits: tier-stability counter (0-3) */

#define MASK_TIER           0x03  /* 2 bits: 0-3 */
#define MASK_FLAGS          0x0F  /* 4 bits */

/* Load fusing helpers for deficit_avg_fused */
#define EXTRACT_DEFICIT(fused)  ((u16)((fused) & 0xFFFF))
#define EXTRACT_AVG_RT(fused)   ((u16)((fused) >> 16))
#define PACK_DEFICIT_AVG(deficit, avg)  (((u32)(deficit) & 0xFFFF) | ((u32)(avg) << 16))

/* Pure avg_runtime tier gates (µs) */
#define TIER_GATE_T0   100   /* < 100µs  → T0 Critical: IRQ, input, audio */
#define TIER_GATE_T1   2000  /* < 2000µs → T1 Interact: compositor, physics */
#define TIER_GATE_T2   8000  /* < 8000µs → T2 Frame:    game render, encode */
                             /* ≥ 8000µs → T3 Bulk:     compilation, bg */

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: Per-CPU state (64 bytes = single cache line)
 * - Zero false sharing: each CPU writes only to its own entry
 * - Prefetch-accelerated reads: one prefetch loads entire CPU state
 * ═══════════════════════════════════════════════════════════════════════════ */

/* 64-byte mega-mailbox entry (single cache line = optimal L1 efficiency)
 * Per-CPU write isolation: each CPU writes ONLY its own entry.
 *
 * TICK DATA STAGING (Rule 41): cake_running writes the currently-running
 * task's tier, last_run_at, and slice. cake_tick reads from SAME cache line.
 *
 * RECLASSIFY CACHE (Rule 40): cake_stopping caches reclassify outputs here.
 * Next stopping on SAME CPU reads cached state if task pointer matches AND
 * tier is stable — skips bpf_task_storage_get entirely (~25ns kfunc saved).
 * Periodic tctx sync every 16th fast-path stop prevents stale migration. */
struct mega_mailbox_entry {
    /* --- Tick staging (bytes 0-16) --- */
    u8 flags;              /* Reserved */
    u8 dsq_hint;           /* DVFS perf target cache */
    u8 tick_counter;       /* Confidence-based starvation skip mask counter */
    u8 tick_tier;          /* Tier of currently-running task (set by running) */
    u32 tick_last_run_at;  /* Timestamp when task started (set by running) */
    u64 tick_slice;        /* Slice of currently-running task (set by running) */
    u8 tick_ctx_valid;     /* 1 = running stamped, 0 = cleared by stopping */
    u8 _pad1;              /* alignment */

    /* --- Reclassify cache (bytes 18-41) --- */
    u16 rc_counter;        /* reclass_counter snapshot (2B-aligned) */
    u32 _pad2;             /* alignment for rc_task_ptr */
    u64 rc_task_ptr;       /* Task pointer for identity (8B-aligned, in reg) */
    u64 rc_state_fused;    /* [63:32]=packed_info, [31:0]=deficit_avg_fused */
    u64 rc_slice;          /* next_slice snapshot */
    u16 rc_sync_counter;   /* Periodic tctx writeback counter */
    u8 __reserved[6];      /* Pad to 64B */
} __attribute__((aligned(64)));

/* Statistics shared with userspace */
struct cake_stats {
    u64 nr_new_flow_dispatches;    /* Tasks dispatched from new-flow */
    u64 nr_old_flow_dispatches;    /* Tasks dispatched from old-flow */
    u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Per-tier dispatch counts */
    u64 nr_starvation_preempts_tier[CAKE_TIER_MAX]; /* Per-tier starvation preempts */
    u64 _pad[22];                  /* Pad to 256 bytes: (2+4+4+22)*8 = 256 */
} __attribute__((aligned(64)));

/* Topology flags - enables zero-cost specialization (false = code path eliminated by verifier) */

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS         (2 * 1000 * 1000)   /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)   /* 8ms */
#define CAKE_DEFAULT_STARVATION_NS      (100 * 1000 * 1000) /* 100ms */

/* Default tier arrays (Gaming profile) — 4 tiers */

/* Per-tier starvation thresholds (nanoseconds) */
#define CAKE_DEFAULT_STARVATION_T0  3000000    /* Critical: 3ms */
#define CAKE_DEFAULT_STARVATION_T1  8000000    /* Interact: 8ms */
#define CAKE_DEFAULT_STARVATION_T2  40000000   /* Frame: 40ms */
#define CAKE_DEFAULT_STARVATION_T3  100000000  /* Bulk: 100ms */

/* Tier quantum multipliers (fixed-point, 1024 = 1.0x)
 * Power-of-4 progression: each tier gets 4x the quantum of the tier above.
 * T2 at 4ms lets 300fps+ render threads complete entire frames without preemption.
 * T0 at 0.5ms releases cores to game work faster (T0 runs <100µs anyway). */
#define CAKE_DEFAULT_MULTIPLIER_T0  256    /* Critical: 0.25x = 0.5ms */
#define CAKE_DEFAULT_MULTIPLIER_T1  1024   /* Interact: 1.0x  = 2.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T2  2048   /* Frame:    2.0x  = 4.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T3  4095   /* Bulk:     ~4.0x = 8.0ms (12-bit max = 4095) */

/* Wait budget per tier (nanoseconds) */
#define CAKE_DEFAULT_WAIT_BUDGET_T0 100000     /* Critical: 100µs */
#define CAKE_DEFAULT_WAIT_BUDGET_T1 2000000    /* Interact: 2ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T2 8000000    /* Frame: 8ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T3 0          /* Bulk: no limit */

/* Fused tier config - packs 4 params into 64-bit: [Mult:12][Quantum:16][Budget:16][Starve:20] */
typedef u64 fused_config_t;

#define CFG_SHIFT_MULTIPLIER  0
#define CFG_SHIFT_QUANTUM     12
#define CFG_SHIFT_BUDGET      28
#define CFG_SHIFT_STARVATION  44

#define CFG_MASK_MULTIPLIER   0x0FFFULL
#define CFG_MASK_QUANTUM      0xFFFFULL
#define CFG_MASK_BUDGET       0xFFFFULL
#define CFG_MASK_STARVATION   0xFFFFFULL

/* Extraction Macros (BPF Side) */
/* Multiplier: bits 0-11. AND only. */
#define UNPACK_MULTIPLIER(cfg)    ((cfg) & CFG_MASK_MULTIPLIER)
/* Quantum: bits 12-27. SHR; AND; SHL. */
#define UNPACK_QUANTUM_NS(cfg)    ((((cfg) >> CFG_SHIFT_QUANTUM) & CFG_MASK_QUANTUM) << 10)
/* Budget: bits 28-43. SHR; AND; SHL. */
#define UNPACK_BUDGET_NS(cfg)     ((((cfg) >> CFG_SHIFT_BUDGET) & CFG_MASK_BUDGET) << 10)
/* Starvation: bits 44-63. SHR; SHL. (Mask redundant) */
#define UNPACK_STARVATION_NS(cfg) (((cfg) >> CFG_SHIFT_STARVATION) << 10)

/* Packing Macro (Userspace/Helper) */
#define PACK_CONFIG(q_us, mult, budget_us, starv_us) \
    ((((u64)(mult) & CFG_MASK_MULTIPLIER) << CFG_SHIFT_MULTIPLIER) | \
     (((u64)(q_us) & CFG_MASK_QUANTUM) << CFG_SHIFT_QUANTUM) | \
     (((u64)(budget_us) & CFG_MASK_BUDGET) << CFG_SHIFT_BUDGET) | \
     (((u64)(starv_us) & CFG_MASK_STARVATION) << CFG_SHIFT_STARVATION))

#endif /* __CAKE_INTF_H */
