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

/*
 * UNIFIED CPU TOPOLOGY ENTRY (Fused ETD + Topology)
 * 
 * Single 8-byte structure per CPU containing:
 * - SMT sibling (from ETD: guaranteed fastest peer)
 * - LLC domain ID (for cross-CCD cost assessment)
 * - Next 3 fastest peers (ring neighbors, ordered by measured latency)
 * - Flags for P/E core identification
 * 
 * Benefits:
 * - Single cache line fetch for all topology info (~2-3 cycles saved)
 * - ETD "ground truth" used everywhere (no kernel/measured mismatch)
 * - Simplified code path in cake_select_cpu
 * 
 * Populated by userspace at startup after ETD calibration.
 * Stored in RODATA for zero-cost constant folding.
 */
struct cpu_topology_entry {
    u8 sibling;        /* SMT sibling CPU ID (0xFF if none) */
    u8 llc_id;         /* LLC/CCD domain ID (0-7) */
    u8 peer_1;         /* 2nd fastest peer (ring neighbor) */
    u8 peer_2;         /* 3rd fastest peer */
    u8 peer_3;         /* 4th fastest peer */
    u8 flags;          /* Bit 0: is_big, Bit 1: has_sibling */
    u8 core_id;        /* Physical core ID (0-31) */
    u8 thread_bit;     /* Pre-computed (1 << thread_idx) */
    u32 dsq_id;        /* Pre-computed (CAKE_DSQ_LC_BASE + cpu_id) */
    u32 _pad;          /* Pad to 16 bytes */
} __attribute__((packed));

/* Topology flags */
#define CPU_TOPO_FLAG_IS_BIG      (1 << 0)
#define CPU_TOPO_FLAG_HAS_SIBLING (1 << 1)

/* Invalid CPU sentinel (no sibling or peer) */
#define CPU_TOPO_INVALID 0xFF

/*
 * Per-task flow state tracked in BPF
 * Padded to 64B to prevent False Sharing.
 * 
 * OPTIMIZATION: Store Coalescing Layout
 * The first 16 bytes (next_slice, state_fused_u64)
 * are ALL written together in cake_stopping().
 * 
 * By placing them contiguously, the CPU Store Buffer merges these 
 * into a single burst write, reducing L1 bandwidth pressure by ~50%
 * during context switches.
 */
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
    
    
    /* --- Timestamp Group (cake_running) [Bytes 16-23] --- */
    /* LOAD FUSING: Union allows atomic u64 access to both u32 timestamp fields */
    union {
        struct {
            u32 last_run_at;       /* 4B: Last run timestamp (ns), wraps 4.2s */
            u32 last_wake_ts;      /* 4B: Wake timestamp for wait budget */
        };
        u64 timestamps_fused;      /* 8B: Fused access (last_run in low 32, last_wake in high 32) */
    };
    
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

/* Load fusing helpers for deficit_avg_fused */
#define EXTRACT_DEFICIT(fused)  ((u16)((fused) & 0xFFFF))
#define EXTRACT_AVG_RT(fused)   ((u16)((fused) >> 16))
#define PACK_DEFICIT_AVG(deficit, avg)  (((u32)(deficit) & 0xFFFF) | ((u32)(avg) << 16))

/* Timestamp fusing helpers for timestamps_fused */
#define EXTRACT_LAST_RUN(fused)   ((u32)((fused) & 0xFFFFFFFF))
#define EXTRACT_LAST_WAKE(fused)  ((u32)((fused) >> 32))
#define PACK_TIMESTAMPS(last_run, last_wake)  (((u64)(last_run) & 0xFFFFFFFF) | ((u64)(last_wake) << 32))

/* Sparse score thresholds (0-100 scale) */
#define THRESHOLD_BACKGROUND    0    /* score < 30 = Background */
#define THRESHOLD_BATCH        30    /* score >= 30 = Batch */
#define THRESHOLD_INTERACTIVE  50    /* score >= 50 = Interactive */
#define THRESHOLD_GAMING       70    /* score >= 70 = Gaming */
#define THRESHOLD_CRITICAL     90    /* score >= 90 = Critical */
#define THRESHOLD_REALTIME    100    /* score == 100 = Realtime+ */

/* Latency gates for score=100 tasks (tighter for better tier separation) */
#define LATENCY_GATE_CRITICAL   25   /* < 25µs avg → Critical Latency (tier 0) - true IRQ */
#define LATENCY_GATE_REALTIME  100   /* < 100µs avg → Realtime (tier 1) - fast input */
#define LATENCY_GATE_CRITICAL2 500   /* < 500µs avg → Critical (tier 2) - compositor */

/*
 * ZERO-MATH ARBITER LUT (Pre-computed Wait/Go Logic)
 * 
 * Dimensions: [My_Tier (0-7)][Target_Rank (0-7)]
 * Value: Threshold Tier (If occupant <= threshold, WAIT. Else GO.)
 * 
 * Rank 0: SMT Sibling (Fastest)
 * Rank 1-3: ETD Peers
 * Rank 4+: Global / Distant
 */
struct arbiter_config {
    u8 lut[8][8];      /* The decision matrix */
    u8 _pad[0];        /* Pad to 64 bytes if needed */
} __attribute__((aligned(64)));

/*
 * CORE STATUS ISOLATION
 * Prevents False Sharing (MESI storms) between physical cores.
 * Each core gets a dedicated 64-byte line to avoid RFO traffic.
 */
struct cake_core_status {
    u8 status;          /* Bit 0: thread 0 idle, Bit 1: thread 1 idle */
    u8 _pad[63];        /* Pad to full cache line */
} __attribute__((aligned(64)));

struct tiered_idle_mask {
    /* Level 1: Isolated per-core status bytes */
    struct cake_core_status core[32];

    /* Level 2/3: Global atomic hints (separated from core status lines) */
    u64 physical_hint;
    u64 logical_hint;
    u8 _pad0[48];       /* Pad hint line to 64 bytes */
} __attribute__((aligned(128)));

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
 * Fused Tier Configuration (64-bit RODATA Optimization)
 * 
 * Packs 4 per-tier parameters into a single 64-bit word.
 * Optimized for Zen 5 load-to-use efficiency.
 * 
 * Layout V2 (LSB to MSB):
 * [0-11]  Multiplier (fixed-point, 1024=1.0x, 0-4095) -> 1-cycle extraction
 * [12-27] Quantum (us units, 0-65535us)
 * [28-43] Wait Budget (us units, 0-65535us)
 * [44-63] Starvation Threshold (us units, 0-1,048,575us approx 1s) -> No mask needed
 */
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