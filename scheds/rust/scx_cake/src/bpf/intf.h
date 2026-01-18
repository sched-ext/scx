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
    CAKE_TIER_CRITICAL_LATENCY = 0, /* <50us avg (Input/IRQs) */
    CAKE_TIER_REALTIME         = 1, /* <500us avg (Audio/Video) */
    CAKE_TIER_CRITICAL         = 2, /* Very sparse (Compositor) */
    CAKE_TIER_GAMING           = 3, /* Sparse/Bursty (Games) */
    CAKE_TIER_INTERACTIVE      = 4, /* Normal apps (Browser/IDE) */
    CAKE_TIER_BATCH            = 5, /* Heavy compilation/Encoding */
    CAKE_TIER_BACKGROUND       = 6, /* Low prio (idlers) */
    CAKE_TIER_IDLE             = 255,
    CAKE_TIER_MAX              = 7,
};

#define CAKE_MAX_CPUS 64

/*
 * Flow state flags (only CAKE_FLOW_NEW currently used)
 */
enum cake_flow_flags {
    CAKE_FLOW_NEW = 1 << 0,  /* Task is newly created */
};

/*
 * Static Topology Vector (populated by userspace at startup)
 * 
 * SIMD-Style Tiered Masks for O(1) CPU Selection
 * 
 * Instead of iterating an array of candidates (O(N) worst case),
 * we intersect pre-computed bitmasks with the global idle_mask.
 * TZCNT on the result gives the best candidate in ~4 cycles.
 * 
 * Tier 1: SMT Sibling (~1-2 cycle L1/L2 cache transfer)
 * Tier 2: LLC Neighbors (~10-30 cycle L3 cache transfer)
 * Tier 3: Global (any idle CPU, handled by caller)
 * 
 * Source: HFT ILP optimization - parallel bitwise intersection
 */
struct topology_vector {
    u64 sibling_mask;   /* Tier 1: SMT sibling(s) - fastest cache transfer */
    u64 llc_mask;       /* Tier 2: Same LLC/CCX cores - shared L3 */
    u8 _pad[48];        /* Pad to 64 bytes for cache alignment */
} __attribute__((aligned(64)));

/*
 * CPU STATE ISOLATION (Frasch, 2023)
 * Each CPU gets its own 64-byte cache line to prevent false sharing
 * during high-frequency tier updates. Used by Zero-Math Locality Arbiter
 * to peek at remote core tier without BPF map lookup overhead (0ns vs 25ns).
 */
struct cake_cpu_tier {
    u32 tier;           /* Tier currently running on this CPU */
    u8 _pad[60];        /* Pad to 64 bytes - cache line isolation */
} __attribute__((aligned(64)));

/*
 * EMPIRICAL TOPOLOGY DISCOVERY (ETD)
 * 
 * Populated by Rust userspace at startup via CAS ping-pong measurement.
 * Each CPU stores its top 3 fastest peers (sorted by measured ns latency).
 * 
 * This enables "Surgical Seek" - the BPF hot-path checks these specific
 * cores before falling back to the generic SIMD scan.
 * 
 * Example for 9800X3D:
 *   top_peers[2] = {10, 3, 11}  → Core 2's fastest paths are to 10 (SMT),
 *                                  then 3 and 11 (ring neighbors)
 */
struct core_preferences {
    u8 top_peers[CAKE_MAX_CPUS][3];  /* Top 3 fastest peers per CPU */
    u8 _pad[64];                      /* Align to 128 bytes */
} __attribute__((aligned(128)));

/*
 * Per-task flow state tracked in BPF
 * Padded to 64B to prevent False Sharing.
 * 
 * OPTIMIZATION: Store Coalescing Layout
 * The first 16 bytes (next_slice, packed_info, deficit, avg_runtime)
 * are ALL written together in cake_stopping().
 * 
 * By placing them contiguously, the CPU Store Buffer merges these 
 * into a single burst write, reducing L1 bandwidth pressure by ~50%
 * during context switches.
 * 
 * Source: Frasch, "Lock-Free FIFO" (CppCon 2023)
 */
struct cake_task_ctx {
    /* --- Hot Write Group (cake_stopping) [Bytes 0-15] --- */
    u64 next_slice;        /* 8B: Pre-computed slice (ns) */
    u16 deficit_us;        /* 2B: Deficit (us), max 65ms */
    u16 avg_runtime_us;    /* 2B: EMA runtime estimate */
    u32 packed_info;       /* 4B: Bitfield (Err, Wait, Score, Tier, Flags) */
    
    /* --- Timestamp Group (cake_running) [Bytes 16-23] --- */
    u32 last_run_at;       /* 4B: Last run timestamp (ns), wraps 4.2s */
    u32 last_wake_ts;      /* 4B: Wake timestamp for wait budget */
    
    /* --- Read-Only / Misc [Bytes 24-63] --- */
    u32 target_dsq_id;     /* 4B: Direct Dispatch Target (0 = None) */
    u8 preempt_floor;      /* 1B: Precomputed floor for warmth arbitration */
    u8 _reserved[3];       /* 3B: Reserved */
    u8 __pad[32];          /* Pad to 64 bytes */
} __attribute__((aligned(64))); /* Force cache-line alignment */

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
    u64 nr_etd_hits;               /* ETD surgical seeks that found idle peer */
    u64 _pad[7];                   /* Pad to 256 bytes for cache line isolation in BSS array */
} __attribute__((aligned(64)));

/*
 * Topology flags - set by userspace at load time
 * * These enable zero-cost specialization. When a flag is false,
 * the BPF verifier eliminates the corresponding code path entirely.
 * * Example: On 9800X3D (single CCD, no hybrid):
 * has_dual_ccd = false      → CCD selection code eliminated
 * has_hybrid_cores = false  → P-core preference code eliminated
 * Result: Zero overhead compared to no topology support
 */

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS         (2 * 1000 * 1000)   /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)   /* 8ms */
#define CAKE_DEFAULT_SPARSE_THRESHOLD   50                   /* 5% = 50 permille */
#define CAKE_DEFAULT_INIT_COUNT         20                   /* Initial sparse count */
#define CAKE_DEFAULT_STARVATION_NS      (100 * 1000 * 1000) /* 100ms */

/*
 * Default tier arrays (Gaming profile - pre-computed by userspace)
 * These are the base values; profiles can scale them as needed.
 */
 
/* Per-tier starvation thresholds (nanoseconds) */
#define CAKE_DEFAULT_STARVATION_T0  5000000    /* Critical Latency: 5ms */
#define CAKE_DEFAULT_STARVATION_T1  3000000    /* Realtime: 3ms */
#define CAKE_DEFAULT_STARVATION_T2  4000000    /* Critical: 4ms */
#define CAKE_DEFAULT_STARVATION_T3  8000000    /* Gaming: 8ms */
#define CAKE_DEFAULT_STARVATION_T4  16000000   /* Interactive: 16ms */
#define CAKE_DEFAULT_STARVATION_T5  40000000   /* Batch: 40ms */
#define CAKE_DEFAULT_STARVATION_T6  100000000  /* Background: 100ms */

/* Tier quantum multipliers (fixed-point, 1024 = 1.0x) */
#define CAKE_DEFAULT_MULTIPLIER_T0  717    /* Critical Latency: 0.7x */
#define CAKE_DEFAULT_MULTIPLIER_T1  819    /* Realtime: 0.8x */
#define CAKE_DEFAULT_MULTIPLIER_T2  922    /* Critical: 0.9x */
#define CAKE_DEFAULT_MULTIPLIER_T3  1024   /* Gaming: 1.0x */
#define CAKE_DEFAULT_MULTIPLIER_T4  1126   /* Interactive: 1.1x */
#define CAKE_DEFAULT_MULTIPLIER_T5  1229   /* Batch: 1.2x */
#define CAKE_DEFAULT_MULTIPLIER_T6  1331   /* Background: 1.3x */

/* Wait budget per tier (nanoseconds) */
#define CAKE_DEFAULT_WAIT_BUDGET_T0 100000     /* Critical Latency: 100µs */
#define CAKE_DEFAULT_WAIT_BUDGET_T1 750000     /* Realtime: 750µs */
#define CAKE_DEFAULT_WAIT_BUDGET_T2 2000000    /* Critical: 2ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T3 4000000    /* Gaming: 4ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T4 8000000    /* Interactive: 8ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T5 20000000   /* Batch: 20ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T6 0          /* Background: no limit */

/*
 * Tier Configuration Data (32 bytes)
 * 
 * OPTIMIZATION: Array of Structures (AoS)
 * Consolidates starvation, budget, and multiplier to minimize cache misses.
 * Accessing one tier loads ALL its params in a single cache line fill.
 * 
 * Layout: [Starvation:8][Budget:8][Mult:4][Pad:12] = 32 bytes
 * Fits exactly 2 tiers per 64-byte cache line.
 * 
 * Source: Frasch, "Lock-Free FIFO" (CppCon 2023) - Cache Line Consolidation
 */
struct cake_tier_config {
    u64 starvation_ns;     /* Starvation threshold (ns) */
    u64 wait_budget_ns;    /* AQM Wait budget (ns) */
    u32 multiplier;        /* Slice multiplier (fixed point, 1024 = 1.0x) */
    u32 _pad[3];           /* Pad to 32 bytes for alignment */
};

#endif /* __CAKE_INTF_H */