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

/* 7-tier priority - higher=smaller slices (responsive), lower=larger slices (throughput) */
enum cake_tier {
    CAKE_TIER_CRITICAL_LATENCY = 0, /* OS Input Handling / IRQs / Top-Half */
    CAKE_TIER_REALTIME         = 1, /* Game Input / Audio / Time-Sensitive */
    CAKE_TIER_CRITICAL         = 2, /* Compositor / Frame-Sync / Logic */
    CAKE_TIER_GAMING           = 3, /* Primary Burst Path (Default Gaming) */
    CAKE_TIER_INTERACTIVE      = 4, /* Game Background Workers / Asset Streaming */
    CAKE_TIER_BATCH            = 5, /* Heavy Compilation / Physics Pre-calc */
    CAKE_TIER_BACKGROUND       = 6, /* Game Main Render / Heavy Housekeeping */
    CAKE_TIER_IDLE             = 255,
    CAKE_TIER_MAX              = 7,
};

#define CAKE_MAX_CPUS 64

/* Flow state flags (only CAKE_FLOW_NEW currently used) */
enum cake_flow_flags {
    CAKE_FLOW_NEW = 1 << 0,  /* Task is newly created */
};

/* Fused core state - packs occupant/warm/victim into 32-bit for single L1 fetch (0ns vs 25ns) */
struct cake_core_state {
    u8 occupant_tier;
    u8 warm_tier;
    u8 victim_state;
    u8 staging_dsq;   /* Byte 3: Speculative DSQ ID for sibling */
    /* Pad to 64 bytes for cache line isolation */
    u8 __reserved[60];
} __attribute__((aligned(64)));

/* Helper to extract full state in one u32 load */
#define CORE_STATE_PACKED(occupant, warm, victim) \
    ((u32)(occupant) | ((u32)(warm) << 8) | ((u32)(victim) << 16))

/* ETD - populated at startup via CAS ping-pong, stores top 3 fastest peers per CPU */

/* Unified CPU topology - 8-byte struct with sibling/LLC/peers, single cache line fetch */
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
    u32 peer_dsqs;     /* SPECULATIVE MAPPING: [0-7]=sib, [8-15]=p1, [16-23]=p2, [24-31]=p3 */
    /* T2 OPTIMIZATION: Pre-computed sibling mask for O(1) idle check */
    u64 sibling_bit;   /* Pre-computed (1ULL << sibling) or 0 if no sibling */
    u32 sibling_dsq;   /* Pre-computed (CAKE_DSQ_LC_BASE + sibling) or 0 */
    u32 _pad_t2;       /* Align to 8-byte boundary */
} __attribute__((packed));

/* Topology flags */
#define CPU_TOPO_FLAG_IS_BIG      (1 << 0)
#define CPU_TOPO_FLAG_HAS_SIBLING (1 << 1)

/* Invalid CPU sentinel (no sibling or peer) */
#define CPU_TOPO_INVALID 0xFF

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

    /* --- Timestamp Group (cake_running) [Bytes 16-23] --- */
    /* LOAD FUSING: Union allows atomic u64 access to both u32 timestamp fields */
    union {
        struct {
            u32 last_run_at;       /* 4B: Last run timestamp (ns), wraps 4.2s */
            u32 last_wake_ts;      /* 4B: Wake timestamp for wait budget */
        };
        u64 timestamps_fused;      /* 8B: Fused access (last_run in low 32, last_wake in high 32) */
    };

    u8 _reserved[3];       /* 3B: Reserved */
    u8 __pad[32];          /* Pad to 64 bytes */
} __attribute__((aligned(64)));

/* Bitfield offsets for packed_info: [Flags:4][Tier:3][Score:7][Wait:8][Error:8] */
#define SHIFT_KALMAN_ERROR  0
#define SHIFT_WAIT_DATA     8
#define SHIFT_SPARSE_SCORE  16
#define SHIFT_TIER          23
#define SHIFT_FLAGS         26
#define SHIFT_CRITICAL      30
/* 31 Reserved */

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

/* Arbiter LUT - [My_Tier][Target_Rank] = threshold (if occupant <= threshold, WAIT; else GO) */
struct arbiter_config {
    u8 lut[8][8];      /* The decision matrix */
    u8 _pad[0];        /* Pad to 64 bytes if needed */
} __attribute__((aligned(64)));

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: DDR5-optimized per-CPU state (128 bytes = 1 DDR5 burst)
 * - Zero false sharing: each CPU writes only to its own entry
 * - 100% DDR5 bandwidth efficiency: 128B aligned to BL16 burst size
 * - Prefetch-accelerated reads: one prefetch loads entire CPU state
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Mailbox flags (packed in flags byte) */
#define MBOX_TIER_MASK    0x07  /* Bits [2:0] = tier (0-6) */
#define MBOX_VICTIM_BIT   0x08  /* Bit  [3]   = victim (preemptible) */
#define MBOX_IDLE_BIT     0x10  /* Bit  [4]   = idle (no task running) */
#define MBOX_WARM_BIT     0x20  /* Bit  [5]   = cache warm (recent run) */

/* Mailbox flag accessors */
#define MBOX_GET_TIER(f)   ((f) & MBOX_TIER_MASK)
#define MBOX_IS_VICTIM(f)  ((f) & MBOX_VICTIM_BIT)
#define MBOX_IS_IDLE(f)    ((f) & MBOX_IDLE_BIT)
#define MBOX_IS_WARM(f)    ((f) & MBOX_WARM_BIT)

/* 128-byte mega-mailbox entry (matches DDR5 BL16 burst size) */
struct mega_mailbox_entry {
    /* ─── HOT DATA: First 64 bytes (always read) ─── */
    u8 flags;              /* [2:0]=tier, [3]=victim, [4]=idle, [5]=warm */
    u8 best_victim_cpu;    /* Pre-computed best victim neighbor */
    u8 dsq_hint;           /* Suggested DSQ with work */
    u8 reserved1;          /* Reserved */
    u32 runtime_us;        /* Runtime in microseconds (victim quality) */
    u64 last_vtime;        /* Last dispatch vtime */
    u64 deficit;           /* DRR deficit */
    u64 peer_mask;         /* Which peers can accept work */
    u64 last_update_ns;    /* Last update timestamp */
    u8 pad1[24];           /* Pad to 64-byte cache line */
    
    /* ─── EXTENDED DATA: Second 64 bytes (prefetched free) ─── */
    u64 llc_neighbor_mask; /* Same-LLC CPUs */
    u64 thermal_budget;    /* Future: power/thermal state */
    u64 queued_tasks;      /* Tasks queued on this CPU */
    u64 cache_pressure;    /* Future: cache contention metric */
    u8 pad2[32];           /* Pad to 128 bytes total */
} __attribute__((packed, aligned(128)));

/* D2A signal line - moves signaling from IPI to L3 Cache Fabric, 64B aligned */
struct cake_signal_mask {
    u64 signal_mask;
    u8 _pad[56];
} __attribute__((aligned(64)));

/* Legacy tiered idle tracking removed - leveraging kernel idle masks via kfuncs */

/* Statistics shared with userspace */
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

/* Topology flags - enables zero-cost specialization (false = code path eliminated by verifier) */

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS         (2 * 1000 * 1000)   /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS  (8 * 1000 * 1000)   /* 8ms */
#define CAKE_DEFAULT_SPARSE_THRESHOLD   50                   /* 5% = 50 permille */
#define CAKE_DEFAULT_INIT_COUNT         20                   /* Initial sparse count */
#define CAKE_DEFAULT_STARVATION_NS      (100 * 1000 * 1000) /* 100ms */

/* Default tier arrays (Gaming profile - pre-computed by userspace) */

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