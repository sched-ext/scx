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

/* ── Kfunc BenchLab: extensible per-kfunc stopwatch ──
 * Each kfunc gets a slot. Run N iterations, capture min/max/avg + return value.
 * Triggered from TUI via bench_request BSS variable. */
#define BENCH_ITERATIONS 8

enum kfunc_bench_id {
	BENCH_KTIME_GET_NS       = 0, /* bpf_ktime_get_ns() */
	BENCH_SCX_BPF_NOW        = 1, /* scx_bpf_now() */
	BENCH_GET_SMP_PROC_ID    = 2, /* bpf_get_smp_processor_id() */
	BENCH_TASK_FROM_PID      = 3, /* bpf_task_from_pid() */
	BENCH_TEST_CLEAR_IDLE    = 4, /* scx_bpf_test_and_clear_cpu_idle() */
	BENCH_NR_CPU_IDS         = 5, /* scx_bpf_nr_cpu_ids() */
	BENCH_GET_TASK_CTX       = 6, /* get_task_ctx() → bpf_task_storage_get */
	BENCH_MAX_ENTRIES        = 7,
};

struct kfunc_bench_entry {
	u64 min_ns;         /* Best-case cost */
	u64 max_ns;         /* Worst-case cost */
	u64 total_ns;       /* Sum for avg calc */
	u64 last_value;     /* Last return value from the helper */
};

struct kfunc_bench_results {
	struct kfunc_bench_entry entries[BENCH_MAX_ENTRIES];
	u32 cpu;            /* CPU that ran the bench */
	u32 iterations;     /* Iterations per helper */
	u64 bench_timestamp; /* When bench completed (ktime_ns) */
};

/* Gate enum and confidence routing removed — scheduling uses only
 * Gate 1 (prev_cpu idle), Gate 1b (SMT sibling), Gate 3 (kernel idle),
 * and tunnel (DSQ fallback). No cross-CPU gate prediction state. */

/* Flow state flags (packed_info bits 24-27) */
enum cake_flow_flags {
	CAKE_FLOW_NEW     = 1 << 0, /* Task is newly created */
	CAKE_FLOW_YIELDER = 1 << 1, /* Task voluntarily yielded since last stop */
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

	/* --- High Resolution Arena Telemetry (TUI Matrix) ---
     * Zero-cost pointer access via BPF Arena. User-space sweeps memory 
     * asynchronously to build 1% Lows and average runtimes. */
	struct {
		/* Timing Metrics */
		u64 run_start_ns;
		u64 run_duration_ns; /* Total runtime (end - begin) */
		u64 enqueue_start_ns; /* Start of DSQ sorting */
		u64 wait_duration_ns; /* Time spent in DSQ (run_start - enq_end) */
		u32 select_cpu_duration_ns; /* Total routing overhead */
		u32 enqueue_duration_ns; /* Time spent sorting DSQ */
		u32 dfl_select_cpu_ns;   /* Kernel fallback overhead */
		u32 dsq_insert_ns;       /* Insert/vtime overhead */

		/* Topographic / Cache Data */
		u32 gate_1_hits; /* Number of local cache hit wakeups */
		u32 gate_2_hits; /* SMT sibling hits */
		u32 gate_1w_hits; /* Waker affinity hits (SMT sibling or LLC) */
		u32 gate_3_hits; /* Kernel fallback hits */
		u32 gate_4_hits; /* Lazy preempt hits */
		u32 gate_tun_hits; /* Complete miss tunneling */
		u64 jitter_accum_ns; /* Mathematical running variant vs AVG */
		u32 total_runs; /* Total executions over lifetime */
		u16 core_placement; /* Physical CPU task last executed on */
		
		/* State Change Counters */
		u16 gate_confidence; /* Task Route Stability [0-8] */
		u16 migration_count; /* Inter-cpu bounces inside select_cpu */
		u16 preempt_count;   /* Task kicked/preempted */
		u16 yield_count;     /* Task willingly gave up execution */

		/* Lifecycle Counters */
		u16 direct_dispatch_count; /* SCX_DSQ_LOCAL_ON bypasses (no DSQ) */
		u16 enqueue_count;         /* Total enqueue calls */
		u16 cpumask_change_count;  /* sched_setaffinity changes */
		u16 dispatch_count;        /* Times dispatched from DSQ */

		/* Callback Overhead (last-write-wins, ns) */
		u32 stopping_duration_ns;  /* cake_stopping BPF overhead */
		u32 running_duration_ns;   /* cake_running BPF overhead */

		/* Worst-Case Tracking */
		u32 max_runtime_us;        /* Max runtime in current TUI interval */

		/* Tier Dynamics */
		u16 tier_change_count;     /* Tier reclassifications over lifetime */

		/* Scheduling Period (inter-dispatch gap) */
		u64 dispatch_gap_ns;       /* Time since previous run start */
		u64 max_dispatch_gap_ns;   /* Worst-case gap in current TUI interval */

		/* Preemption Blame */
		u32 preempted_by_pid;      /* PID of task that replaced us on CPU */

		/* Wait Latency Histogram (bucket counts, lifetime) */
		u32 wait_hist_lt10us;      /* wait < 10µs */
		u32 wait_hist_lt100us;     /* 10µs <= wait < 100µs */
		u32 wait_hist_lt1ms;       /* 100µs <= wait < 1ms */
		u32 wait_hist_ge1ms;       /* wait >= 1ms */

		/* Blind Spot Metrics (Phase B) */
		u16 slice_util_pct;        /* (actual_run / slice) * 100 */
		u16 llc_id;                /* LLC node this task last ran on */
		u16 same_cpu_streak;       /* Consecutive runs on same CPU */
		u16 __pad_align;           /* Alignment padding */
		u32 wakeup_source_pid;     /* PID that woke this task */

		/* Voluntary/involuntary context switch tracking (GPU detection) */
		u64 nvcsw_snapshot;        /* Last read of p->nvcsw (for delta) */
		u64 nivcsw_snapshot;       /* Last read of p->nivcsw (for delta) */
		u32 nvcsw_delta;           /* nvcsw delta since last TUI interval */
		u32 nivcsw_delta;          /* nivcsw delta since last TUI interval */

		u32 pid;
		u32 tgid;  /* Thread group ID (process) for TUI grouping */
		char comm[16];
		/* 208 bytes total (added 8 for nivcsw_snapshot) */
	} telemetry;

	u8  __pad[24]; /* Pad to 256 bytes: 256 - (24 + 208) = 24 bytes. */
} __attribute__((aligned(256)));

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
		[2]; /* Was: _pad_cl0, dsq_hint, tick_counter (tick/DVFS removed) */
	u8  is_yielder; /* Gate 1P: true if currently-running task is a cooperating yielder */
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

	/* --- V3 Quantum Guard (bytes 84-87): LOCAL writes only ---
     * run_start_cl1: duplicate of tick_last_run_at for cross-CPU reads.
     * Written by cake_running (LOCAL CPU, same CL1).
     * Read by Gate 4 quantum guard (remote CPU). */
	u32 run_start_cl1;

	u32 last_stopped_pid;  /* TELEMETRY: PID of last task that stopped on this CPU */
	u32 _pad_tctx;         /* padding for u64 alignment */
	u32 _reserved_cl1[6]; /* Pad to end of CL1 (byte 127) */

	/* ═══ CACHE LINE 2 (bytes 128-191): RESERVED ═══
     * Previous cross-CPU fields (migration_cooldown, wakeup_same_cpu,
     * predicted_gate, gate_confidence) removed — no longer used. */
	u32 _reserved_cl2_header;
	u32 _reserved_cl2[15]; /* Pad to byte 192 */
} __attribute__((aligned(256)));
_Static_assert(
	sizeof(struct mega_mailbox_entry) == 256,
	"mega_mailbox_entry must be exactly 256 bytes (4 cache lines)");

/* Statistics shared with userspace */
struct cake_stats {
	u64 nr_new_flow_dispatches; /* Tasks dispatched from new-flow */
	u64 nr_old_flow_dispatches; /* Tasks dispatched from old-flow */
	u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Per-tier dispatch counts */
	u64 nr_starvation_preempts_tier
		[CAKE_TIER_MAX]; /* Per-tier starvation preempts */
	u64 total_gate1_latency_ns; /* Total time spent in Gate 1 */
	u64 total_gate2_latency_ns; /* Total time spent in Gate 2 */
	u64 total_enqueue_latency_ns; /* Total time spent in enqueue */
	u64 nr_dropped_allocations; /* Count of failed scx_task_alloc requests */
	u64 nr_local_dispatches;    /* Dispatched from local LLC DSQ */
	u64 nr_stolen_dispatches;   /* Dispatched from remote LLC DSQ (steal) */
	u64 nr_dispatch_misses;     /* dispatch() found no work (all DSQs empty) */
	u64 nr_dsq_queued;          /* Per-LLC DSQ enqueue count (for depth calc) */
	u64 nr_dsq_consumed;        /* Per-LLC DSQ consume count (dispatched from DSQ) */

	/* Callback aggregate timing (cumulative ns, system-wide) */
	u64 total_select_cpu_ns;     /* Total time in cake_select_cpu */
	u64 total_stopping_ns;       /* Total time in cake_stopping */
	u64 total_running_ns;        /* Total time in cake_running */

	/* Callback max tracking (worst single invocation, ns) */
	u64 max_select_cpu_ns;       /* Worst single cake_select_cpu */
	u64 max_stopping_ns;         /* Worst single cake_stopping */
	u64 max_running_ns;          /* Worst single cake_running */

	/* Stopping path breakdown (invocation counts) */
	u64 nr_stop_confidence_skip; /* Confidence EWMA skip (~4ns) */
	u64 nr_stop_ewma;            /* EWMA+classify (~14ns) */
	u64 nr_stop_ramp;            /* Stability ramp (stable < 3) */
	u64 nr_stop_miss;            /* Cold/self-seed miss path (~30ns) */

	u64 _pad[3]; /* Pad to 256 bytes: (2+4+4+3+4+2+3+3+3+4+3)*8 = 280... recalc */
} __attribute__((aligned(64)));

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS (2 * 1000 * 1000) /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS (8 * 1000 * 1000) /* 8ms */

/* ═══ ADAPTIVE QUANTUM — YIELD-GATED (Phase 4.0) ═══
 * Per-task runtime-proportional quantum modulated by voluntary yield signal.
 * Yielders (nvcsw > 0 since last stop) get generous headroom + high ceiling.
 * Non-yielders get tight headroom + low ceiling, forcing faster CPU release.
 *
 * Quantum = clamp(EWMA_avg × HEADROOM, MIN, MAX/CEILING)
 * Yielders: game render, audio, input, network → 50ms ceiling (cooperators)
 * Non-yielders: compilation, background tasks → EWMA × 1, capped 2ms */
#define AQ_BULK_HEADROOM     1               /* 1× EWMA runtime for non-yielders */
#define AQ_MIN_NS            (50 * 1000)     /* 50µs floor — below this overhead > work */
#define AQ_YIELDER_CEILING_NS (50 * 1000000)  /* 50ms ceiling — yielders (covers 20fps+) */
#define AQ_BULK_CEILING_NS   (2 * 1000000)   /* 2ms ceiling — non-yielders (forces release) */

#endif /* __CAKE_INTF_H */
