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

/* CAKE TIER SYSTEM — 4-tier classification
 *
 * Tiers group tasks with similar scheduling needs. Classification uses
 * kernel PELT util_avg (0-1024). DRR++ deficit handles intra-tier
 * fairness (yield vs preempt). */
enum cake_tier {
	CAKE_TIER_CRITICAL = 0, /* <100µs:  IRQ, input, audio, network */
	CAKE_TIER_INTERACT = 1, /* <2ms:    compositor, physics, AI */
	CAKE_TIER_FRAME	   = 2, /* <8ms:    game render, encoding */
	CAKE_TIER_BULK	   = 3, /* ≥8ms:    compilation, background */
	CAKE_TIER_MAX	   = 4,
};

/* ═══ TASK CLASS — Pre-stamped by userspace classifier (Phase 2) ═══
 * Replaces per-stop is_game/is_hog/bg_noise computation in BPF stopping.
 * Written by Rust classifier (60Hz), read by BPF stopping+enqueue.
 * Eliminates BSS game_tgid/game_ppid MESI-S reads from hot path (~5ns). */
enum cake_class {
	CAKE_CLASS_NORMAL  = 0, /* Default: no squeeze, no boost */
	CAKE_CLASS_GAME    = 1, /* Game family: tgid/ppid match + kthread(gaming) */
	CAKE_CLASS_HOG     = 2, /* BULK + squeeze: 4× vtime penalty */
	CAKE_CLASS_BG      = 3, /* Background noise: 2× vtime penalty */
	CAKE_CLASS_MAX     = 4,
};

/* ═══ TASK HOT FIELDS — bpf_task_storage (Phase 6) ═══
 * Mirrors Arena CL0 but lives in kernel task_storage (~10ns lookup
 * vs 29ns arena TLB walk). All release-mode hot fields live here.
 * Arena CL0 is only used for telemetry (stats_on gated, dead in release).
 *
 * Accessed by: cake_running, cake_stopping, cake_select_cpu, cake_enqueue.
 * Allocated in: cake_init_task (BPF_NOEXIST → creates on first alloc). */
struct cake_task_hot {
	u64 staged_vtime_bits; /* 8B: VALID|HOME|WB|WB_DUP|NF|weight */
	u16 deficit_u16;       /* 2B: DRR deficit (drain from slice delta) */
	u16 _pad0;             /* 2B: alignment */
	u32 packed_info;       /* 4B: flags + tier + flow_id */
	u32 ppid;              /* 4B: Parent PID (game family detection) */
	u32 last_run_at;       /* 4B: (u32)scx_bpf_now() from stopping */
	u32 reclass_counter;   /* 4B: Per-task stop counter */
	u16 warm_cpus[3];      /* 6B: [0]=current, [1]=home, [2]=oldest */
	u16 waker_cpu;         /* 2B: CPU where waker last ran */
	u64 nvcsw_snapshot;    /* 8B: Last nvcsw for yield detection */
	u8  task_class;        /* 1B: CAKE_CLASS_* enum */
	u8  _pad[3];           /* 3B: align to 4B → 64B total */
	u64 cached_cpumask;    /* 8B: Affinity mask (select_cpu) */
}; /* Total: 64B = 1 cache line */


/* ═══ PER-CPU BSS — Arena-free running (Phase 5) ═══
 * Written by cake_running (local CPU only), read by:
 *   - cake_stopping (same CPU, L1 hit)
 *   - Gate 1P/1C-P (remote CPU, MESI-S → L3 hit)
 *
 * 64-byte aligned — one cache line per CPU.
 * SAFETY:
 *   - No false sharing: each CPU owns its own 64B line.
 *   - No atomics needed: single-writer (local running), multi-reader.
 *   - MESI-S for remote reads: same cost as current arena mbox reads.
 *   - stopping bridges BSS→arena mbox for consumers that still read mbox. */
struct cake_cpu_bss {
	u32 run_start;     /* 4B: (u32)scx_bpf_now() when task started */
	u8  is_yielder;    /* 1B: task_class-derived yielder + waker_boost */
	u8  idle_hint;     /* 1B: 0=busy, 1=idle */
	u16 _pad0;         /* 2B: alignment (P4-1: cached_cpu removed — never read) */
	u64 tick_slice;    /* 8B: p->scx.slice ?: quantum_ns */
	u32 last_tgid;     /* 4B: p->tgid (COMPILATION only) */
	u32 last_pid;      /* 4B: Fast path — skip get_task_hot if same task */
	u64 cached_now;    /* 8B: scx_bpf_now() from select_cpu tunnel */
	u8  _pad[32];      /* Pad to 64B cache line */
} __attribute__((aligned(64)));

#define CAKE_MAX_CPUS 64
#define CAKE_MAX_LLCS 8

/* Per-LLC DSQ base — DSQ IDs are LLC_DSQ_BASE + llc_index (0..nr_llcs-1).
 * V3: Single vtime-ordered DSQ per LLC. Priority encoded in vtime:
 * (vtime_tier << 56) | timestamp. T0 always has lowest vtime → dispatches
 * first. Eliminates 3 empty-DSQ probes vs old 4-tier split. */
#define LLC_DSQ_BASE 200

/* ── dsq_vtime STAGED BIT LAYOUT (Rule 54: no magic positions) ──
 * Written by cake_stopping, read by cake_running + cake_select_cpu.
 *   [63]       = VALID (set once context exists)
 *   [62:55]    = HOME_CPU (warm_cpus[1] & 0xFF, prev home)
 *   [53]       = BG_NOISE (non-game, non-wb, non-kernel squeeze)
 *   [52]       = WAKER_BOOST (propagated via waker chain)
 *   [51]       = GAME_MEMBER (tgid match)
 *   [50]       = HOG (BULK tier + non-boosted)
 *   [49]       = WAKER_BOOST_DUP (Gate 1P — was VCSW yielder)
 *   [48]       = NEW_FLOW (first enqueue after init)
 *   [31:0]     = WEIGHT_NS (pelt_runtime_us * 1000) */
#define STAGED_BIT_VALID        63
#define STAGED_SHIFT_HOME       55
#define STAGED_BIT_BG_NOISE     53  /* Background noise squeeze */
#define STAGED_BIT_WAKER_BOOST  52
#define STAGED_BIT_GAME_MEMBER  51
#define STAGED_BIT_HOG          50
#define STAGED_BIT_WB_DUP       49  /* Gate 1P: waker_boost duplicate */
#define STAGED_BIT_NEW_FLOW     48

/* ── Kfunc BenchLab: extensible per-kfunc stopwatch ──
 * Each kfunc gets a slot. Run N iterations, capture min/max/avg + return value.
 * Triggered from TUI via bench_request BSS variable. */
#define BENCH_ITERATIONS 8

enum kfunc_bench_id {
	/* ── Existing entries (0–23) ── */
	BENCH_KTIME_GET_NS       = 0, /* bpf_ktime_get_ns() */
	BENCH_SCX_BPF_NOW        = 1, /* scx_bpf_now() */
	BENCH_GET_SMP_PROC_ID    = 2, /* bpf_get_smp_processor_id() */
	BENCH_TASK_FROM_PID      = 3, /* bpf_task_from_pid() */
	BENCH_TEST_CLEAR_IDLE    = 4, /* scx_bpf_test_and_clear_cpu_idle() */
	BENCH_NR_CPU_IDS         = 5, /* scx_bpf_nr_cpu_ids() */
	BENCH_GET_TASK_CTX       = 6, /* get_task_ctx() → arena deref */
	BENCH_DSQ_NR_QUEUED      = 7, /* scx_bpf_dsq_nr_queued() */
	BENCH_BSS_ARRAY_ACCESS   = 8, /* Raw BSS global_stats[cpu] access */
	BENCH_ARENA_DEREF        = 9, /* Arena per_cpu[cpu].mbox field read */
	BENCH_NOW_PAIR           = 10, /* Back-to-back scx_bpf_now() pair (calibration) */
	BENCH_MBOX_CPU_READ      = 11, /* Read cached CPU from mailbox CL0 (alternative) */
	BENCH_TCTX_FROM_MBOX     = 12, /* Read cached tctx ptr from mailbox CL0 (alternative) */
	BENCH_RINGBUF_CYCLE      = 13, /* bpf_ringbuf_reserve + discard cycle */
	BENCH_TASK_STRUCT_READ   = 14, /* p->scx.slice + p->nvcsw (task_struct fields) */
	BENCH_RODATA_LOOKUP      = 15, /* cpu_llc_id[cpu] + tier_slice_ns[tier] RODATA */
	BENCH_BITFLAG_OPS        = 16, /* Shift+mask+branchless yielder pattern */
	BENCH_RESERVED_17        = 17, /* (was compute_ewma — removed in PELT transition) */
	BENCH_PSYCHIC_HIT_SIM    = 18, /* Psychic cache pointer compare + fused read */
	BENCH_IDLE_REMOTE        = 19, /* scx_bpf_test_and_clear_cpu_idle(sibling) — cross-CPU */
	BENCH_IDLE_SMTMASK       = 20, /* cpumask_test_cpu on smtmask — read-only, no atomic */
	BENCH_DISRUPTOR_READ     = 21, /* Full CL0 Disruptor handoff read (cake_stopping sim) */
	BENCH_TCTX_COLD_SIM      = 22, /* get_task_ctx + arena CL0 read (cake_running sim) */
	BENCH_ARENA_STRIDE       = 23, /* Stride across arena per_cpu array to test TLB/hugepage */

	/* ── New entries (24–42): eBPF helpers + SCX kfuncs ── */
	/* Timing variants */
	BENCH_KTIME_BOOT_NS      = 24, /* bpf_ktime_get_boot_ns() — suspend-aware */
	BENCH_KTIME_COARSE_NS    = 25, /* bpf_ktime_get_coarse_ns() — jiffies-based low-res */
	BENCH_JIFFIES64           = 26, /* bpf_jiffies64() — raw jiffies */
	BENCH_KTIME_TAI_NS       = 27, /* bpf_ktime_get_tai_ns() — TAI clock */

	/* Process info */
	BENCH_CURRENT_PID_TGID   = 28, /* bpf_get_current_pid_tgid() — PID+TGID in one */
	BENCH_CURRENT_TASK_BTF   = 29, /* bpf_get_current_task_btf() — direct task ptr */
	BENCH_CURRENT_COMM       = 30, /* bpf_get_current_comm() — task comm name */

	/* CPU / topology info */
	BENCH_NUMA_NODE_ID       = 31, /* bpf_get_numa_node_id() — NUMA node */
	BENCH_SCX_TASK_RUNNING   = 32, /* scx_bpf_task_running(p) — task running check */
	BENCH_SCX_TASK_CPU       = 33, /* scx_bpf_task_cpu(p) — task's current CPU */
	BENCH_SCX_NR_NODE_IDS    = 34, /* scx_bpf_nr_node_ids() — NUMA node count */
	BENCH_SCX_CPUPERF_CUR    = 35, /* scx_bpf_cpuperf_cur(cpu) — current perf level */

	/* Task storage (what cake replaced with arena) */
	BENCH_TASK_STORAGE_GET   = 36, /* bpf_task_storage_get() — standard per-task map */

	/* Idle probing alternatives */
	BENCH_SCX_PICK_IDLE_CPU  = 37, /* scx_bpf_pick_idle_cpu() — kernel idle scan */
	BENCH_SCX_IDLE_CPUMASK   = 38, /* scx_bpf_get_idle_cpumask() + put cycle */
	BENCH_SCX_KICK_CPU       = 39, /* scx_bpf_kick_cpu() — IPI preemption cost */

	/* Utility */
	BENCH_PRANDOM_U32        = 40, /* bpf_get_prandom_u32() — RNG cost */
	BENCH_SPIN_LOCK          = 41, /* bpf_spin_lock + unlock cycle */
	BENCH_SCX_CPUPERF_CAP    = 42, /* scx_bpf_cpuperf_cap(cpu) — max perf capacity */

	/* ── Cake competitor entries (43–49) ── */
	BENCH_RODATA_NR_CPUS     = 43, /* RODATA const nr_cpus read (vs nr_cpu_ids kfunc) */
	BENCH_RODATA_NR_NODES    = 44, /* RODATA const nr_nodes read (vs nr_node_ids kfunc) */
	BENCH_RODATA_CPUPERF_CAP = 45, /* RODATA cpuperf_cap[cpu] read (vs kfunc) */
	BENCH_ARENA_PID_TGID     = 46, /* Arena tctx.pid+tgid read (vs current_pid_tgid kfunc) */
	BENCH_MBOX_TASK_CPU      = 47, /* Mbox CL0 cached_cpu (vs scx_bpf_task_cpu kfunc) */
	BENCH_CL0_LOCKFREE       = 48, /* CL0 lock-free atomic read (vs bpf_spin_lock cycle) */
	BENCH_BSS_XORSHIFT       = 49, /* BSS xorshift32 PRNG (vs bpf_get_prandom_u32 kfunc) */

	/* ═══ KERNEL FREE DATA PROBES (50–54) ═══ */
	BENCH_PELT_UTIL_AVG      = 50, /* p->se.avg.util_avg — kernel EWMA (0-1024) */
	BENCH_PELT_RUNNABLE_AVG  = 51, /* p->se.avg.runnable_avg — kernel runnable EWMA */
	BENCH_SCHEDSTATS_WAKEUPS = 52, /* p->stats.nr_wakeups — cumulative wakeup count */
	BENCH_TASK_POLICY_FLAGS  = 53, /* p->policy + p->in_iowait — free classification */
	BENCH_PELT_VS_EWMA       = 54, /* PELT read + tier classify (was PELT vs EWMA comparison) */

	/* ═══ END-TO-END WORKFLOW COMPARISONS (55–62) ═══ */
	BENCH_STORAGE_ROUNDTRIP  = 55, /* task_storage: write field → read back (full cycle) */
	BENCH_ARENA_ROUNDTRIP    = 56, /* Arena: write field → read back (full cycle) */
	BENCH_CASCADE_VS_PICK    = 57, /* 6-gate cascade sim: prev→sib→home BSS vs pick_idle */
	BENCH_PICK_IDLE_FULL     = 58, /* pick_idle_cpu full: kfunc + affinity check + result */
	BENCH_CLASSIFY_WEIGHT    = 59, /* bpfland-style: p->scx.weight → vtime calc */
	BENCH_CLASSIFY_LATCRI    = 60, /* lavd-style: wakeup_sync + run_freq → score */
	BENCH_SMT_CAKE_PROBE     = 61, /* cake SMT: test_and_clear(sib) + BSS[sib].idle_hint */
	BENCH_SMT_CPUMASK_PROBE  = 62, /* bpfland SMT: is_smt_contended via cpumask scan */

	/* ═══ FAIRNESS FIXES (63–66) ═══ */
	BENCH_STORAGE_GET_COLD   = 63, /* task_storage_get after L1 eviction (cold task) */
	BENCH_PELT_COLD          = 64, /* PELT util_avg after L1 eviction (cold p->se.avg) */
	BENCH_EWMA_COLD          = 65, /* EWMA compute after L1 eviction (cold cpu_bss) */
	BENCH_KICK_REMOTE        = 66, /* kick_cpu(sibling) — real IPI, not self-noop */

	BENCH_MAX_ENTRIES        = 67,
};

struct kfunc_bench_entry {
	u64 min_ns;         /* Best-case cost */
	u64 max_ns;         /* Worst-case cost */
	u64 total_ns;       /* Sum for avg calc */
	u64 last_value;     /* Last return value from the helper */
	u64 samples[BENCH_ITERATIONS]; /* Raw per-iteration ns for percentile calc */
};

struct kfunc_bench_results {
	struct kfunc_bench_entry entries[BENCH_MAX_ENTRIES];
	u32 cpu;            /* CPU that ran the bench */
	u32 iterations;     /* Iterations per helper */
	u64 bench_timestamp; /* When bench completed (ktime_ns) */
};

/* Gate cascade: G1 (prev_cpu idle), G1b (SMT sibling), G1c (home CPU),
 * G1cp (home preempt-hog), G1WC (waker-chain), G1D (domestic tgid),
 * G1W (waker LLC), G1P (yielder preempts bulk), G3 (kernel idle),
 * and tunnel (DSQ fallback). */

/* Flow state flags (packed_info bits 24-27) */
enum cake_flow_flags {
	CAKE_FLOW_NEW          = 1 << 0, /* Task is newly created */
	CAKE_FLOW_YIELDER      = 1 << 1, /* Task voluntarily yielded since last stop */
	CAKE_FLOW_WAKER_BOOST  = 1 << 2, /* Waker was a yielder — propagate priority (1-cycle) */
	CAKE_FLOW_HOG          = 1 << 3, /* Background hog: BULK + non-yielder + deprioritized */
};

/* Record emitted by SEC("iter/task") cake_task_iter program.
 * One record per managed task. Userspace reads fixed-size records from the
 * iter fd instead of walking the pid_to_tctx hash map.
 * Replaces: pid_to_tctx BPF_MAP_TYPE_HASH (65536 entries, global bucket lock).
 * Benefit: cake_init_task + cake_exit_task become fully lockless (no map ops). */
struct cake_iter_record {
	u32 pid;         /* pid of this task */
	u32 ppid;        /* parent pid (promoted from tctx CL0) */
	u32 packed_info; /* tier + flags — same field read in Rust telemetry loop */
	u16 pelt_util;       /* PELT util_avg (0-1024) from p->se.avg */
	u16 deficit_us;      /* DRR deficit in µs */
	/* telemetry block: everything the TUI currently reads from arena pointers */
	struct {
		u64 run_start_ns;
		u64 run_duration_ns;
		u64 enqueue_start_ns;
		u64 wait_duration_ns;
		u32 select_cpu_duration_ns;
		u32 enqueue_duration_ns;
		u32 dsq_insert_ns;
		u32 gate_1_hits;
		u32 gate_2_hits;
		u32 gate_1w_hits;
		u32 gate_3_hits;
		u32 gate_1p_hits;
		u32 gate_1c_hits;
		u32 gate_1cp_hits;
		u32 gate_1d_hits;
		u32 gate_1wc_hits;
		u32 gate_tun_hits;
		u32 _pad2;
		u64 jitter_accum_ns;
		u32 total_runs;
		u16 core_placement;
		u16 migration_count;
		u16 preempt_count;
		u16 yield_count;
		u16 direct_dispatch_count;
		u16 enqueue_count;
		u16 cpumask_change_count;
		u16 _pad3;
		u32 stopping_duration_ns;
		u32 running_duration_ns;
		u32 max_runtime_us;
		u32 _pad4;
		u64 dispatch_gap_ns;
		u64 max_dispatch_gap_ns;
		u32 wait_hist_lt10us;
		u32 wait_hist_lt100us;
		u32 wait_hist_lt1ms;
		u32 wait_hist_ge1ms;
		u16 slice_util_pct;
		u16 llc_id;
		u16 same_cpu_streak;
		u16 _pad_recomp;
		u32 wakeup_source_pid;
		u64 nivcsw_snapshot;
		u32 nvcsw_delta;
		u32 nivcsw_delta;
		u32 pid_inner;  /* matches telemetry.pid */
		u32 tgid;
		char comm[16];
		u32 gate_cascade_ns;
		u32 idle_probe_ns;
		u32 vtime_compute_ns;
		u32 mbox_staging_ns;
		u32 _pad_ewma;
		u32 classify_ns;
		u32 vtime_staging_ns;
		u32 warm_history_ns;
		u16 quantum_full_count;
		u16 quantum_yield_count;
		u16 quantum_preempt_count;
		u16 _pad_quantum;
		u16 waker_cpu;
		u16 _pad_waker;
		u32 waker_tgid;
		u16 cpu_run_count[CAKE_MAX_CPUS];
	} telemetry;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * CONDITIONAL SIZE MACROS — Release/Debug struct sizing pattern
 *
 * DESIGN PHILOSOPHY: In release (CAKE_RELEASE=1, CAKE_STATS_ENABLED=0),
 * Clang dead-code eliminates every telemetry/BenchLab access. Structs
 * shrink to their scheduling-essential footprint by #ifdef-gating
 * debug-only fields. This saves arena memory, TLB footprint, and
 * cache pollution in production builds.
 *
 * Structs using this pattern:
 *   mega_mailbox_entry:  64B release (1 CL) / 128B debug (2 CL)
 *   cake_task_ctx:       64B release (1 CL) / 512B debug (8 CL)
 *   cake_per_cpu:        matches mailbox size
 * ═══════════════════════════════════════════════════════════════════════════ */
#ifdef CAKE_RELEASE
#define CAKE_MBOX_SIZE  64
#define CAKE_MBOX_ALIGN 64
#define CAKE_TCTX_SIZE  64
#define CAKE_TCTX_ALIGN 64
#else
#define CAKE_MBOX_SIZE  128
#define CAKE_MBOX_ALIGN 128
#define CAKE_TCTX_SIZE  512
#define CAKE_TCTX_ALIGN 512
#endif

/* Per-task flow state — conditional sizing (Release/Debug pattern).
 *   RELEASE: 64B (1 CL) — scheduling hot fields only, telemetry compiled out
 *   DEBUG:  512B (8 CL) — CL0 hot + CL1-7 telemetry for TUI analytics
 *
 * CACHE LINE SEGREGATION (Ghost Struct):
 *   CL0 (bytes 0-63): Every field needed for release-mode scheduling.
 *     In --release, CAKE_STATS_ENABLED=0 → Clang dead-codes all telemetry.
 *     The CPU prefetcher only ever loads CL0 — telemetry bytes stay in RAM.
 *   CL1+ (bytes 64+): Debug-only telemetry for TUI analytics.
 *     Compiled out in release → 448B savings per task in BPF arena.
 *
 * staged_vtime_bits at offset 0: most-read field across all 4 callbacks
 *   (select_cpu, enqueue, running, stopping). JIT emits [reg+0] instead
 *   of [reg+48], saving one ADD instruction per access. */
struct cake_task_ctx {
	/* ═══ CACHE LINE 0 (bytes 0-63): HOT / RELEASE MODE ═══ */

	/* STAGED VTIME BITS — offset 0 for JIT-optimal [reg+0] addressing. */
	u64 staged_vtime_bits; /* 8B: VALID|HOME|WB|GAME|HOG|BG|WB_DUP|NF|weight */

	/* CACHED AFFINITY MASK (Rule 41: Locality Promotion) */
	u64 cached_cpumask; /* 8B: Cached p->cpus_ptr bitmask (max 64 CPUs) */

	/* DRR deficit + packed bitfield. */
	u16 deficit_u16;     /* 2B: DRR deficit */
	u16 _ctx_pad;        /* 2B: alignment padding */
	u32 packed_info;     /* 4B: Bitfield */

	/* Game family detection */
	u32 ppid;             /* 4B: Parent PID (Proton/Wine siblings) */

	/* Anti-starvation + confidence gating */
	u32 last_run_at;      /* 4B: Last run timestamp (ns), wraps 4.2s */
	u32 reclass_counter;  /* 4B: Per-task stop counter for confidence backoff */

	/* Warm CPU history — Gate 1c (home CPU) + Gate 1D (tgid affinity) */
	u16 warm_cpus[3];     /* 6B: [0]=current, [1]=prev (home), [2]=oldest */
	u16 waker_cpu;        /* 2B: CPU where waker last ran (Gate 1W-chain) */

	/* Yield detection — read+written unconditionally every stop */
	u64 nvcsw_snapshot;   /* 8B: Last read of p->nvcsw */

	/* Phase 2: Userspace-stamped task class */
	u8  task_class;        /* 1B: CAKE_CLASS_* enum, written by reclassifier */
	u8  _pad_class[3];    /* 3B: Alignment padding to 64B CL0 */

	/* ─── CL0 total (with alignment): 8+8+(2+2+4)+4+(4+4)+(6+2)+[4 implicit]+8+(1+3) = 60B ─── */
	/* nvcsw_snapshot (u64) at offset 44 → compiler inserts 4B alignment pad to 48.
	 * Explicit pad: 64 - 60 = 4B needed. */
	u8  _pad_cl0[4];      /* 4B: Pad to 64B CL0 boundary (absorbs u64 alignment hole) */

#ifndef CAKE_RELEASE
	/* ═══ CL1+ (bytes 64-511): DEBUG-ONLY TELEMETRY ═══
	 * Compiled out in release → struct shrinks from 512B to 64B.
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
		u32 dsq_insert_ns;       /* Insert/vtime overhead */

		/* Topographic / Cache Data */
		u32 gate_1_hits; /* Number of local cache hit wakeups */
		u32 gate_2_hits; /* SMT sibling hits */
		u32 gate_1w_hits; /* Waker affinity hits (SMT sibling or LLC) */
		u32 gate_3_hits; /* Kernel fallback hits */
		u32 gate_1p_hits; /* Yielder-preempts-bulk hits (Gate 1P) */
		u32 gate_1c_hits; /* Home CPU warm set hits (Gate 1c) */
		u32 gate_1cp_hits; /* Home CPU preempt-hog hits (Gate 1c-P) */
		u32 gate_1d_hits; /* Domestic: same-process cache affinity (Gate 1D) */
		u32 gate_1wc_hits; /* Waker-chain: producer-consumer locality (Gate 1WC) */
		u32 gate_tun_hits; /* Complete miss tunneling */
		u64 jitter_accum_ns; /* Mathematical running variant vs AVG */
		u32 total_runs; /* Total executions over lifetime */
		u16 core_placement; /* Physical CPU task last executed on */

		/* State Change Counters */
		u16 migration_count; /* Inter-cpu bounces inside select_cpu */
		u16 preempt_count;   /* Task kicked/preempted */
		u16 yield_count;     /* Task willingly gave up execution */

		/* Lifecycle Counters */
		u16 direct_dispatch_count; /* SCX_DSQ_LOCAL_ON bypasses (no DSQ) */
		u16 enqueue_count;         /* Total enqueue calls */
		u16 cpumask_change_count;  /* sched_setaffinity changes */

		/* Callback Overhead (last-write-wins, ns) */
		u32 stopping_duration_ns;  /* cake_stopping BPF overhead */
		u32 running_duration_ns;   /* cake_running BPF overhead */

		/* Worst-Case Tracking */
		u32 max_runtime_us;        /* Max runtime in current TUI interval */


		/* Scheduling Period (inter-dispatch gap) */
		u64 dispatch_gap_ns;       /* Time since previous run start */
		u64 max_dispatch_gap_ns;   /* Worst-case gap in current TUI interval */

		/* Wait Latency Histogram (bucket counts, lifetime) */
		u32 wait_hist_lt10us;      /* wait < 10µs */
		u32 wait_hist_lt100us;     /* 10µs <= wait < 100µs */
		u32 wait_hist_lt1ms;       /* 100µs <= wait < 1ms */
		u32 wait_hist_ge1ms;       /* wait >= 1ms */

		/* Blind Spot Metrics (Phase B) */
		u16 slice_util_pct;        /* (actual_run / slice) * 100 */
		u16 llc_id;                /* LLC node this task last ran on */
		u16 same_cpu_streak;       /* Consecutive runs on same CPU */
		u16 _pad_recomp;           /* (was _deprecated_recomp — removed) */
		u32 wakeup_source_pid;     /* PID that woke this task */

		/* Voluntary/involuntary context switch tracking (GPU detection) */
		u64 nivcsw_snapshot;       /* Last read of p->nivcsw (for delta) */
		u32 nvcsw_delta;           /* nvcsw delta since last TUI interval */
		u32 nivcsw_delta;          /* nivcsw delta since last TUI interval */

		u32 pid;
		u32 tgid;  /* Thread group ID (process) for TUI grouping */
		char comm[16];

		/* Per-callback sub-function stopwatch (Phase 8: Verbose Health) */
		u32 gate_cascade_ns;       /* select_cpu: full gate cascade duration */
		u32 idle_probe_ns;         /* select_cpu: winning gate idle probe cost */
		u32 vtime_compute_ns;      /* enqueue: vtime calculation + tier weighting */
		u32 mbox_staging_ns;       /* running: mailbox CL0 write burst */
		u32 _pad_ewma;             /* (was _deprecated_ewma_ns — removed) */
		u32 classify_ns;           /* stopping: tier classify + squeeze fusion */
		u32 vtime_staging_ns;      /* stopping: dsq_vtime bit packing + slice/vtime write */
		u32 warm_history_ns;       /* stopping: warm CPU ring shift (migration-gated) */

		/* Quantum completion tracking (Phase 8) */
		u16 quantum_full_count;    /* Task consumed entire slice */
		u16 quantum_yield_count;   /* Task yielded before slice exhaustion */
		u16 quantum_preempt_count; /* Task was kicked/preempted mid-slice */
		u16 _pad_quantum;          /* Align to 4B boundary */

		/* Wake chain enhancement (Phase 8) */
		u16 waker_cpu;             /* CPU the waker was running on */
		u16 _pad_waker;            /* Align to 4B */
		u32 waker_tgid;            /* TGID of the waker (process group) */

		/* CPU core distribution histogram (Phase 8) */
		u16 cpu_run_count[CAKE_MAX_CPUS]; /* 128 bytes: per-CPU run count */
	} telemetry;
#endif /* !CAKE_RELEASE */
} __attribute__((aligned(CAKE_TCTX_ALIGN)));
_Static_assert(
	sizeof(struct cake_task_ctx) == CAKE_TCTX_SIZE,
	"cake_task_ctx size mismatch (64B release, 512B debug)");

/* Bitfield layout for packed_info (write-set co-located, Rule 24 mask fusion):
 * [Stable:2][Tier:2][Flags:4][KTH:1][BG:1][Rsvd:14][Rsvd:8]
 *  31-30     29-28   27-24    23     22    21-8       7-0
 * TIER+STABLE adjacent → fused 4-bit clear/set in reclassify (2 ops vs 4)
 * KTH = cached PF_KTHREAD (set once in cake_init_task, Rule 41)
 * BG  = background noise squeeze (toggled in cake_stopping) */
#define SHIFT_FLAGS 24 /* 4 bits: flow flags */
#define SHIFT_TIER 28 /* 2 bits: tier 0-3 (coalesced with STABLE) */
#define SHIFT_STABLE 30 /* 2 bits: tier-stability counter (0-3) */
#define BIT_KTHREAD 23 /* 1 bit: cached PF_KTHREAD (Rule 41: cold→init) */
#define BIT_BG_NOISE 22 /* 1 bit: background noise squeeze active */

#define MASK_TIER 0x03 /* 2 bits: 0-3 */
#define MASK_FLAGS 0x0F /* 4 bits */

/* PELT-based HOG detection threshold.
 * util_avg >= 800 ≈ 78% CPU utilization = resource hog.
 * Replaces EWMA-based er.new_avg >= 8000 (1.0.3 design).
 * Kernel maintains PELT for free — zero BPF computation. */
#define CAKE_PELT_HOG_THRESHOLD 800

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: Per-CPU arena state
 *   RELEASE: 64B (1 CL) — all fields DCE'd, struct is dead stub
 *   DEBUG:  128B (2 CL) — CL0 telemetry + CL1 BenchLab handoff
 *
 * In release, Clang dead-code eliminates every mbox read/write.
 * The struct exists only for type correctness.
 *
 * In debug, CL0 holds telemetry + hints. CL1 holds BenchLab
 * snapshot fields for kfunc benchmarking.
 * ═══════════════════════════════════════════════════════════════════════════ */
struct mega_mailbox_entry {
	/* ═══ CACHE LINE 0 (bytes 0-63): TELEMETRY + HINTS ═══
	 * In release: entire struct is DCE'd (zero scheduling reads from mbox).
	 * In debug: stats_on telemetry + shadow hints for BenchLab validation.
	 * Scheduling hot paths read idle_hint/last_tgid from cpu_bss, not mbox. */

	/* --- Telemetry (stats-gated) --- */
	u32 last_stopped_pid;  /* PID of last task that stopped on this CPU */

	/* --- Idle shadow hint --- */
	u32 idle_hint;         /* 0=busy (default), 1=likely idle */

	/* --- Cluster hint --- */
	u32 last_tgid;         /* tgid of last task that ran on this CPU */

	/* --- Padding CL0 --- */
	u8  _pad_cl0[52];     /* 52B pad to end of CL0 */

#ifndef CAKE_RELEASE
	/* ═══ CACHE LINE 1 (bytes 64-127): BENCHLAB HANDOFF (DEBUG ONLY) ═══
	 * These fields are ONLY read by BenchLab instrumentation (run_kfunc_bench).
	 * All scheduling hot paths read equivalent data from cpu_bss or task_hot.
	 * Compiled out in release → struct shrinks to 64B (1 CL). */

	/* --- Tick staging (bytes 64-71) --- */
	u8  is_yielder;        /* BenchLab: yielder flag snapshot */
	u8  tick_tier;         /* BenchLab: tier snapshot */
	u16 cached_cpu;        /* BenchLab: CPU ID snapshot */
	u32 tick_last_run_at;  /* BenchLab: run_start snapshot */

	/* --- Cached fields (bytes 72-95) --- */
	u64 tick_slice;        /* 8B — BenchLab: slice snapshot */
	u64 cached_tctx_ptr;   /* 8B — BenchLab: arena tctx pointer */
	u32 cached_deficit;    /* 4B — BenchLab: deficit snapshot */
	u32 cached_packed;     /* 4B — BenchLab: packed_info snapshot */

	/* --- nvcsw (bytes 96-103) --- */
	u64 cached_nvcsw;      /* 8B — BenchLab: nvcsw_snapshot */

	/* --- Padding CL1 (bytes 104-127) --- */
	u8  _pad_cl1[24];     /* 24B pad to end of CL1 */
#endif /* !CAKE_RELEASE */
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
_Static_assert(
	sizeof(struct mega_mailbox_entry) == CAKE_MBOX_SIZE,
	"mega_mailbox_entry size mismatch (64B release, 128B debug)");

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
	u64 nr_dispatch_misses;     /* dispatch() kfunc found no work (DSQ empty after probe) */
	u64 nr_dispatch_hint_skip;  /* dispatch() skipped kfunc via dsq_pending hint (counter==0) */
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
	u64 nr_stop_confidence_skip; /* Confidence skip — fast path (~4ns) */
	u64 nr_stop_classify;        /* PELT classify path (~14ns, was nr_stop_ewma) */
	u64 nr_stop_ramp;            /* Stability ramp (stable < 3) */
	u64 nr_stop_miss;            /* Cold/self-seed miss path (~30ns) */

	/* ═══ DISPATCH CALLBACK TIMING (Phase 8: Verbose Health) ═══ */
	u64 total_dispatch_ns;       /* Total time in cake_dispatch */
	u64 max_dispatch_ns;         /* Worst single cake_dispatch */

	u64 _pad[1]; /* Pad to 64-byte alignment */
} __attribute__((aligned(64)));

/* Default values (Gaming profile) */
#define CAKE_DEFAULT_QUANTUM_NS (2 * 1000 * 1000) /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS (8 * 1000 * 1000) /* 8ms */

/* ═══ ADAPTIVE QUANTUM — YIELD-GATED (Phase 4.0) ═══
 * Per-task runtime-proportional quantum modulated by voluntary yield signal.
 * Yielders (nvcsw > 0 since last stop) get generous headroom + high ceiling.
 * Non-yielders get tight headroom + low ceiling, forcing faster CPU release.
 *
 * Quantum = clamp(pelt_runtime_us × HEADROOM, MIN, MAX/CEILING)
 * Yielders: game render, audio, input, network → 50ms ceiling (cooperators)
 * Non-yielders: compilation, background tasks → PELT × 1, capped 2ms */
#define AQ_BULK_HEADROOM     1               /* 1× PELT runtime for non-yielders */
#define AQ_MIN_NS            (50 * 1000)     /* 50µs floor — below this overhead > work */
#define AQ_YIELDER_CEILING_NS (50 * 1000000)  /* 50ms ceiling — yielders (covers 20fps+) */
#define AQ_BULK_CEILING_NS        (2 * 1000000)   /* 2ms ceiling — non-yielders (forces release) */
#define AQ_BULK_CEILING_COMPILE_NS (8 * 1000000)   /* 8ms ceiling — COMPILATION state only (reduce ctx-switch overhead) */

/* Scheduler operating state — set by Rust TUI, read by BPF hot path.
 * Priority: GAMING > COMPILATION > IDLE.
 * Written to sched_state BSS u32 by userspace, read-only from BPF. */
#define CAKE_STATE_IDLE        0  /* Fair, unthrottled — desktop/browsing */
#define CAKE_STATE_COMPILATION 1  /* Compile jobs: 8ms bulk ceiling, no squeeze */
#define CAKE_STATE_GAMING      2  /* Game mode: HOG+bg squeeze, Gate 1P active */

/* Gate 1C-P / Gate 1P: adaptive preemption thresholds.
 * STANDARD: 100µs — hog has done meaningful work before yielding to normal tasks.
 *           Below this, preemption context-switch cost (~1.5µs) exceeds benefit.
 * VIP:       50µs — game-family threads (wineserver, WoW workers) get aggressive
 *           preemption to avoid cold-cache migration. WoW data showed wineserver
 *           at 125 MIG/s because the standard threshold blocked reclaiming its home
 *           CPU from hogs that ran <100µs. 50µs ensures the hog got a reasonable
 *           quantum while the VIP avoids the ~10-40ns L3 penalty of migration.
 *           Selected via STAGED_BIT_GAME_MEMBER (already in register, ~0ns). */
#define CAKE_PREEMPT_YIELDER_THRESHOLD_NS (100 * 1000) /* 100µs — normal tasks */
#define CAKE_PREEMPT_VIP_THRESHOLD_NS      (50 * 1000) /*  50µs — game family VIPs */

#endif /* __CAKE_INTF_H */
