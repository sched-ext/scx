/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cake BPF/userspace interface definitions
 *
 * Shared data structures and constants between BPF and Rust userspace.
 */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

/*
 * Type definitions for BPF and userspace compatibility.
 * When vmlinux.h is included (BPF context), __VMLINUX_H__ is defined
 * and types come from there. Otherwise define them here.
 */
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

/*
 * Priority tiers with quantum multipliers (7-tier system)
 * * Higher tiers get SMALLER slices (more responsive)
 * Lower tiers get LARGER slices (better throughput)
 */
enum cake_tier {
    CAKE_TIER_CRITICAL_LATENCY = 0,  /* Ultra-low latency: score=100 AND <250µs avg runtime */
    CAKE_TIER_REALTIME    = 1,  /* Ultra-sparse: score=100 but >=250µs avg runtime */
    CAKE_TIER_CRITICAL    = 2,  /* Very sparse: audio, compositor */
    CAKE_TIER_GAMING      = 3,  /* Sparse/bursty: game threads, UI */
    CAKE_TIER_INTERACTIVE = 4,  /* Baseline: default applications */
    CAKE_TIER_BATCH       = 5,  /* Lower priority: nice > 0, heavy apps */
    CAKE_TIER_BACKGROUND  = 6,  /* Bulk work: compilers, encoders */
    CAKE_TIER_MAX         = 7,
};

/*
 * Flow state flags (only CAKE_FLOW_NEW currently used)
 */
enum cake_flow_flags {
    CAKE_FLOW_NEW = 1 << 0,  /* Task is newly created */
};

/*
 * Per-task flow state tracked in BPF (24 bytes used)
 * Padded to 64B to prevent False Sharing.
 * 
 * COMPRESSION:
 * - Timestamps: u32 (Wraps every 4.2s) - Acceptable for active gaming.
 * - Info: Packed into single u32 bitfield.
 */
struct cake_task_ctx {
    u64 next_slice;        /* 8B: Pre-computed slice (ns) */
    u32 last_run_at;       /* 4B: Last run timestamp (ns), wraps 4.2s */
    u32 last_wake_ts;      /* 4B: Wake timestamp for wait budget */
    u32 packed_info;       /* 4B: Bitfield (Err, Wait, Score, Tier, Flags) */
    u16 deficit_us;        /* 2B: Deficit (us), max 65ms */
    u16 avg_runtime_us;    /* 2B: EMA runtime estimate */
    u8 __pad[40];          /* Pad to 64 bytes (Cache Line Size) */
};

/* 
 * Bitfield Offsets for packed_info
 * Layout: [Flags:4][Tier:3][Score:7][Wait:8][Error:8]
 */
#define SHIFT_KALMAN_ERROR  0
#define SHIFT_WAIT_DATA     8
#define SHIFT_SPARSE_SCORE  16
#define SHIFT_TIER          23
#define SHIFT_FLAGS         26
/* 30-31 Reserved */

#define MASK_KALMAN_ERROR   0xFF  /* 8 bits: 0-255 */
#define MASK_WAIT_DATA      0xFF  /* 8 bits: violations<<4 | checks */
#define MASK_SPARSE_SCORE   0x7F  /* 7 bits: 0-127, clamped to 0-100 */
#define MASK_TIER           0x07  /* 3 bits: 0-7 */
#define MASK_FLAGS          0x0F  /* 4 bits */

/* Sparse score thresholds (0-100 scale) */
#define THRESHOLD_BACKGROUND    0    /* score < 30 = Background */
#define THRESHOLD_BATCH        30    /* score >= 30 = Batch */
#define THRESHOLD_INTERACTIVE  50    /* score >= 50 = Interactive */
#define THRESHOLD_GAMING       70    /* score >= 70 = Gaming */
#define THRESHOLD_CRITICAL     90    /* score >= 90 = Critical */
#define THRESHOLD_REALTIME    100    /* score == 100 = Realtime+ */

/* Latency gates for score=100 tasks */
#define LATENCY_GATE_CRITICAL   50   /* < 50µs avg → Critical Latency (tier 0) */
#define LATENCY_GATE_REALTIME  500   /* < 500µs avg → Realtime (tier 1) */

/*
 * Statistics shared with userspace
 */
struct cake_stats {
    u64 nr_new_flow_dispatches;    /* Tasks dispatched from new-flow */
    u64 nr_old_flow_dispatches;    /* Tasks dispatched from old-flow */
    u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Per-tier dispatch counts */
    u64 nr_sparse_promotions;      /* Sparse flow promotions */
    u64 nr_sparse_demotions;       /* Sparse flow demotions */
    /* Wait budget stats (CAKE's AQM) */
    u64 nr_wait_demotions;         /* Demotions due to wait budget violation */
    u64 total_wait_ns;             /* Total wait time accumulated */
    u64 nr_waits;                  /* Number of waits tracked */
    u64 max_wait_ns;               /* Maximum observed wait time */
    u64 nr_starvation_preempts_tier[CAKE_TIER_MAX]; /* Per-tier starvation preempts */
    u64 nr_input_preempts;         /* Preemptions injected for input/latency */
};

/*
 * Topology flags - set by userspace at load time
 * * These enable zero-cost specialization. When a flag is false,
 * the BPF verifier eliminates the corresponding code path entirely.
 * * Example: On 9800X3D (single CCD, no hybrid):
 * has_dual_ccd = false      → CCD selection code eliminated
 * has_hybrid_cores = false  → P-core preference code eliminated
 * Result: Zero overhead compared to no topology support
 */

/* Default values */
#define CAKE_DEFAULT_QUANTUM_NS         (4 * 1000 * 1000)   /* 4ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)   /* 8ms */
#define CAKE_DEFAULT_SPARSE_THRESHOLD   100                  /* 10% = 100 permille */
#define CAKE_DEFAULT_INIT_COUNT         20                   /* Initial sparse count */
#define CAKE_DEFAULT_STARVATION_NS      (100 * 1000 * 1000) /* 100ms */

#endif /* __CAKE_INTF_H */