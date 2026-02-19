/* SPDX-License-Identifier: GPL-2.0 */
/* scx_cake BPF/userspace interface - shared data structures and constants */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

/* Type defs for BPF/userspace compat - defined when vmlinux.h is not included */
#ifndef __VMLINUX_H__
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;

typedef signed char    s8;
typedef signed short   s16;
typedef signed int     s32;
typedef signed long    s64;
#endif

/* CAKE TIER SYSTEM — 4-tier classification by avg_runtime
 *
 * Tiers group tasks with similar scheduling needs. Classification is
 * purely by EWMA avg_runtime — shorter runtime = more latency-sensitive.
 * DRR++ deficit handles intra-tier fairness (yield vs preempt). */
enum cake_tier {
	CAKE_TIER_CRITICAL = 0, /* <100µs:  IRQ, input, audio, network */
	CAKE_TIER_INTERACT = 1, /* <2ms:    compositor, physics, AI */
	CAKE_TIER_FRAME	   = 2, /* <8ms:    game render, encoding */
	CAKE_TIER_BULK	   = 3, /* ≥8ms:    compilation, background */
	CAKE_TIER_MAX	   = 4,
};

#define CAKE_MAX_CPUS 64
#define CAKE_MAX_LLCS 8

/* Per-LLC DSQ base — DSQ IDs are LLC_DSQ_BASE + llc_index (0..nr_llcs-1).
 * V3: Single vtime-ordered DSQ per LLC. Priority encoded in vtime:
 * (vtime_tier << 56) | timestamp. T0 always has lowest vtime → dispatches
 * first. Eliminates 3 empty-DSQ probes vs old 4-tier split. */
#define LLC_DSQ_BASE 200

/* ── Confidence-based gate routing (Rule 40) ──
 * Gate IDs for the miss-path cascade in cake_select_cpu.
 * Gate 1 (prev_cpu) and WSC bypass always run — confidence only
 * applies to gates AFTER WSC miss. IDs are sequential for comparison. */
enum cake_gate_id {
	CAKE_GATE_1B  = 0, /* SMT sibling */
	CAKE_GATE_1C  = 1, /* Nearby CCD half */
	CAKE_GATE_2   = 2, /* Tier-matched snapshot */
	CAKE_GATE_3   = 3, /* Kernel fallback */
	CAKE_GATE_4   = 4, /* Lazy preempt */
	CAKE_GATE_TUN = 5, /* Tunnel (all miss) */
};

/* Consecutive-match threshold to activate gate skipping.
 * 8 matches = ~200ms at 40 wakeups/s — stable enough to predict. */
#define CAKE_GATE_CONF_THRESH 8
#define CAKE_GATE_CONF_MAX 8 /* 3-bit saturate */

/* Flow state flags (only CAKE_FLOW_NEW currently used) */
enum cake_flow_flags {
	CAKE_FLOW_NEW = 1 << 0, /* Task is newly created */
};

/* Per-task flow state - 64B aligned, first 8B coalesced for cake_stopping writes */
struct cake_task_ctx {
	/* --- Hot Write Group (cake_stopping) [Bytes 0-7] ---
     * Union: deficit_avg_fused (4B) + packed_info (4B) = 8B */
	/* STATE FUSION: Union allows atomic u64 access to both state fields */
	union {
		struct {
			union {
				struct {
					u16 deficit_us; /* 2B: Deficit (us) */
					u16 avg_runtime_us; /* 2B: EMA runtime estimate */
				};
				u32 deficit_avg_fused; /* 4B: Fused access */
			};
			u32 packed_info; /* 4B: Bitfield */
		};
	};

	/* --- Timestamp (cake_running) [Bytes 8-11] --- */
	u32 last_run_at; /* 4B: Last run timestamp (ns), wraps 4.2s */

	/* --- Graduated backoff counter [Bytes 12-15] --- */
	u32 reclass_counter; /* 4B: Per-task stop counter for per-tier backoff
                            * Widened from u16 to prevent 21-218s wrap cascade.
                            * u32 at 50K/s wraps at 23.9 hours — effectively never. */

	/* CACHED AFFINITY MASK (Rule 41: Locality Promotion)
     * Replaces bpf_cpumask_test_cpu kfunc (~15ns) with inline bit test (~0.2ns)
     * for restricted-affinity tasks (Wine/Proton pinning, ~5% of gaming wakeups).
     * Populated in cake_init_task, updated event-driven by cake_set_cpumask.
     * Zero hot-path cost: no polling in cake_running or cake_stopping. */
	u64 cached_cpumask; /* 8B: Cached p->cpus_ptr bitmask (max 64 CPUs) */

	u8  __pad[40]; /* Pad to 64 bytes: 8+4+4+8+40 = 64 */
} __attribute__((aligned(64)));

/* Bitfield layout for packed_info (write-set co-located, Rule 24 mask fusion):
 * [Stable:2][Tier:2][Flags:4][Rsvd:16][Rsvd:8]
 *  31-30     29-28   27-24    23-8      7-0
 * TIER+STABLE adjacent → fused 4-bit clear/set in reclassify (2 ops vs 4)
 * Bits [15:0] reserved for future use (Kalman error + wait data removed). */
#define SHIFT_FLAGS 24 /* 4 bits: flow flags */
#define SHIFT_TIER 28 /* 2 bits: tier 0-3 (coalesced with STABLE) */
#define SHIFT_STABLE 30 /* 2 bits: tier-stability counter (0-3) */

#define MASK_TIER 0x03 /* 2 bits: 0-3 */
#define MASK_FLAGS 0x0F /* 4 bits */

/* Load fusing helpers for deficit_avg_fused */
#define EXTRACT_DEFICIT(fused) ((u16)((fused) & 0xFFFF))
#define EXTRACT_AVG_RT(fused) ((u16)((fused) >> 16))
#define PACK_DEFICIT_AVG(deficit, avg) \
	(((u32)(deficit) & 0xFFFF) | ((u32)(avg) << 16))

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
 * TWO-ENTRY PSYCHIC CACHE (Rule 40 + OPT5): Most CPUs alternate 2-3 tasks.
 * Two slots give ~44% fast-path rate vs 3% with one slot (sim validated).
 * Slot 0 = MRU (most-recently-used), Slot 1 = LRU. On slot[1] hit, swap
 * with slot[0] for LRU promotion. Miss evicts slot[1], installs in slot[0].
 *
 * rc_slice REMOVED: derived from tier_slice_ns[tier] LUT (saves 8B/slot).
 * Periodic tctx sync every 16th fast-path stop prevents migration staleness.
 *
 * Layout verified: 64B data = 64B. All u64 fields 8B-aligned.
 * rc_counter0/1 and rc_sync_counter widened from u16 to u32 to eliminate
 * 1.3-13s wrap cascades. u32 at 50K/s wraps at 23.9 hours — effectively never.
 * (mailbox_cacheline_bench: 64B beats 128B by 1.1% on MONSTER sim, lower jitter) */
struct mega_mailbox_entry {
	/* ═══ CACHE LINE 0 (bytes 0-63): LOCAL-CPU ONLY (HOT) ═══
     * All fields written exclusively by the CPU that owns this mailbox entry.
     * Zero cross-CPU writes → zero RFO bounces from waker CPUs. */

	/* --- Tick staging (bytes 0-15) --- */
	u8 _reserved_cl0
		[3]; /* Was: _pad_cl0, dsq_hint, tick_counter (tick/DVFS removed) */
	u8  tick_tier; /* Tier of currently-running task (set by running) */
	u32 tick_last_run_at; /* Timestamp when task started (set by running) */
	u64 tick_slice; /* Slice of currently-running task (set by running) */
	/* tick_ctx_valid REMOVED: was tick↔stopping validity flag. Tick eliminated,
     * 5 dead writes removed (~100K wasted stores/s). */
	u8 s1_hot_flag; /* C2: deferred promotion — 1 = first s1 hit seen, promote on 2nd */

	/* --- Psychic Cache Slot 0: MRU (bytes 17-43) --- */
	u8 _pad_s0[3]; /* alignment: keeps rc_counter0 at offset 20 (4B-aligned) */
	u32 rc_counter0; /* Slot 0 reclass counter (widened: u16→u32, no wrap) */
	/* rc_task_ptr0 at offset 24: 8B-aligned ✅ */
	u64 rc_task_ptr0; /* Slot 0 task pointer (8B-aligned) */
	u64 rc_state_fused0; /* Slot 0 [63:32]=packed_info, [31:0]=deficit_avg */

	/* --- Psychic Cache Slot 1 (bytes 40-59) --- */
	u64 rc_task_ptr1; /* Slot 1 task pointer (8B-aligned) */
	u64 rc_state_fused1; /* Slot 1 [63:32]=packed_info, [31:0]=deficit_avg */
	u32 rc_counter1; /* Slot 1 reclass counter (widened: u16→u32) */

	/* --- Sync (bytes 60-63) --- */
	u32 rc_sync_counter; /* Periodic tctx writeback counter (widened: u16→u32) */

	/* ═══ CACHE LINE 1 (bytes 64-127): slot 2 + CROSS-CPU fields (WARM) ═══
     * Slot 2 accessed on s0+s1 miss (~4.6% in Arc Raiders).
     * ALP prefetches this line for free on Zen 5 (128B pair).
     * Cross-CPU fields (wakeup_same_cpu, migration_cooldown) colocated here
     * to isolate waker RFOs from CL0's local-only tick/running/stopping. */

	/* --- Psychic Cache Slot 2: LRU (bytes 64-83) --- */
	u64 rc_task_ptr2; /* Slot 2 task pointer (8B-aligned) */
	u64 rc_state_fused2; /* Slot 2 [63:32]=packed_info, [31:0]=deficit_avg */
	u32 rc_counter2; /* Slot 2 reclass counter */

	/* --- Cross-CPU fields (bytes 84-85): written by waker in select_cpu --- */
	u8 migration_cooldown; /* NEAR_PREF: wakeups remaining in cooldown period.
                            * Set to 4 on migration, decremented on Gate 1 hit.
                            * While > 0, Gate 1c scans same-CCD-half idle CPUs
                            * before falling to Gate 2 (far scan).
                            * Sim: 8.5× jitter reduction for FF16, no-op for
                            * Arc Raiders (already high Gate 1 hit rate). */
	u8 wakeup_same_cpu; /* J1 V2: consecutive same-CPU wakeup counter (0-255).
                            * Written cross-CPU by waker in cake_select_cpu.
                            * Relocated from CL0→CL1 to eliminate false sharing
                            * with tick/running/stopping (all local-CPU-only). */

	/* --- Confidence routing (bytes 86-87): written by waker in select_cpu ---
     * Extends WSC pattern (Rule 40) to all gates. When a task consistently
     * exits through the same gate, skip intermediate gates on the miss path.
     * Sim: +42µs/s (Arc), +16µs/s (FF16), +915µs/s (compilation). */
	u8 predicted_gate; /* Last gate that handled prev_cpu's wakeup (0-7).
                            * Updated on every Gate 1 miss exit.
                            * Gate IDs: CAKE_GATE_1B=0, _1C=1, _2=2, _3=3, _4=4, _TUN=5 */
	u8 gate_confidence; /* Consecutive matches for predicted_gate (0-31 sat).
                            * >= CAKE_GATE_CONF_THRESH (8): skip to predicted gate. */

	/* --- V3 Quantum Guard (bytes 88-91): LOCAL writes only ---
     * run_start_cl1: duplicate of tick_last_run_at for cross-CPU reads.
     * Written by cake_running (LOCAL CPU, same CL1 already Modified).
     * Read by Gate 4 quantum guard (remote CPU, rare ~1% of wakeups).
     * Piggybacked on existing CL1 S↔M transitions from waker writes. */
	u32 run_start_cl1; /* Duplicate of tick_last_run_at for cross-CPU read.
                            * Avoids touching CL0 from remote CPUs, preserving
                            * CL0 local-only isolation. Byte 88-91. */
	u32 _reserved[9];
} __attribute__((aligned(128)));
_Static_assert(
	sizeof(struct mega_mailbox_entry) == 128,
	"mega_mailbox_entry must be exactly 128 bytes (2 cache lines — R2 3-slot)");

/* Statistics shared with userspace */
struct cake_stats {
	u64 nr_new_flow_dispatches; /* Tasks dispatched from new-flow */
	u64 nr_old_flow_dispatches; /* Tasks dispatched from old-flow */
	u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Per-tier dispatch counts */
	u64 nr_starvation_preempts_tier
		[CAKE_TIER_MAX]; /* Per-tier starvation preempts */
	u64 _pad[22]; /* Pad to 256 bytes: (2+4+4+22)*8 = 256 */
} __attribute__((aligned(64)));

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS (2 * 1000 * 1000) /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS (8 * 1000 * 1000) /* 8ms */

/* Default tier arrays (Gaming profile) — 4 tiers */

/* Per-tier starvation thresholds (nanoseconds) */
#define CAKE_DEFAULT_STARVATION_T0 3000000 /* Critical: 3ms */
#define CAKE_DEFAULT_STARVATION_T1 8000000 /* Interact: 8ms */
#define CAKE_DEFAULT_STARVATION_T2 40000000 /* Frame: 40ms */
#define CAKE_DEFAULT_STARVATION_T3 100000000 /* Bulk: 100ms */

/* Tier quantum multipliers (fixed-point, 1024 = 1.0x)
 * Power-of-4 progression: each tier gets 4x the quantum of the tier above.
 * T2 at 4ms lets 300fps+ render threads complete entire frames without preemption.
 * T0 at 0.5ms releases cores to game work faster (T0 runs <100µs anyway). */
#define CAKE_DEFAULT_MULTIPLIER_T0 256 /* Critical: 0.25x = 0.5ms */
#define CAKE_DEFAULT_MULTIPLIER_T1 1024 /* Interact: 1.0x  = 2.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T2 2048 /* Frame:    2.0x  = 4.0ms */
#define CAKE_DEFAULT_MULTIPLIER_T3 \
	4095 /* Bulk:     ~4.0x = 8.0ms (12-bit max = 4095) */

/* Wait budget per tier (nanoseconds) */
#define CAKE_DEFAULT_WAIT_BUDGET_T0 100000 /* Critical: 100µs */
#define CAKE_DEFAULT_WAIT_BUDGET_T1 2000000 /* Interact: 2ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T2 8000000 /* Frame: 8ms */
#define CAKE_DEFAULT_WAIT_BUDGET_T3 0 /* Bulk: no limit */

/* Fused tier config - packs 4 params into 64-bit: [Mult:12][Quantum:16][Budget:16][Starve:20] */
typedef u64 fused_config_t;

#define CFG_SHIFT_MULTIPLIER 0
#define CFG_SHIFT_QUANTUM 12
#define CFG_SHIFT_BUDGET 28
#define CFG_SHIFT_STARVATION 44

#define CFG_MASK_MULTIPLIER 0x0FFFULL
#define CFG_MASK_QUANTUM 0xFFFFULL
#define CFG_MASK_BUDGET 0xFFFFULL
#define CFG_MASK_STARVATION 0xFFFFFULL

/* Extraction Macro (BPF Side) — only STARVATION used in hot path */
/* Starvation: bits 44-63. SHR; SHL. (Mask redundant) */
#define UNPACK_STARVATION_NS(cfg) (((cfg) >> CFG_SHIFT_STARVATION) << 10)

/* Packing Macro (Userspace/Helper) */
#define PACK_CONFIG(q_us, mult, budget_us, starv_us)                     \
	((((u64)(mult) & CFG_MASK_MULTIPLIER) << CFG_SHIFT_MULTIPLIER) | \
	 (((u64)(q_us) & CFG_MASK_QUANTUM) << CFG_SHIFT_QUANTUM) |       \
	 (((u64)(budget_us) & CFG_MASK_BUDGET) << CFG_SHIFT_BUDGET) |    \
	 (((u64)(starv_us) & CFG_MASK_STARVATION) << CFG_SHIFT_STARVATION))

#endif /* __CAKE_INTF_H */
