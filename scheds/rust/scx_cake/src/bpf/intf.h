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

/* CAKE TIER SYSTEM — legacy 4-tier latency buckets
 *
 * These enum values are retained for telemetry, BenchLab, and older UI paths.
 * The current scheduler does not classify hot-path work into these tiers. */
enum cake_tier {
	CAKE_TIER_CRITICAL = 0, /* Lowest-latency legacy bucket */
	CAKE_TIER_INTERACT = 1, /* Interactive legacy bucket */
	CAKE_TIER_FRAME	   = 2, /* Medium-latency legacy bucket */
	CAKE_TIER_BULK	   = 3, /* Highest-latency legacy bucket */
	CAKE_TIER_MAX	   = 4,
};

/* ═══ TASK CLASS — legacy/debug classification labels ═══
 * The hot path no longer promotes game families. These enums remain for
 * telemetry, iter output, and compatibility with older debug tooling. */
enum cake_class {
	CAKE_CLASS_NORMAL  = 0, /* Default */
	CAKE_CLASS_GAME    = 1, /* Reserved legacy class */
	CAKE_CLASS_HOG     = 2, /* Reserved legacy class */
	CAKE_CLASS_BG      = 3, /* Reserved legacy class */
	CAKE_CLASS_MAX     = 4,
};

enum cake_startup_phase {
	CAKE_STARTUP_PHASE_NONE    = 0,
	CAKE_STARTUP_PHASE_ENQUEUE = 1,
	CAKE_STARTUP_PHASE_SELECT  = 2,
	CAKE_STARTUP_PHASE_RUNNING = 3,
};

#define CAKE_STARTUP_MASK_ENQUEUE (1u << 0)
#define CAKE_STARTUP_MASK_SELECT  (1u << 1)
#define CAKE_STARTUP_MASK_RUNNING (1u << 2)

/* ═══ Additive Fairness Model ═══
 * Hot path reads p->scx.weight directly from task_struct (L1-hot).
 * vtime_mult_cache[] BSS array DELETED. -4KB BSS, -64 cache lines.
 * VTIME_MULT_CACHE_SIZE kept for backward compat only (no consumers). */
#define VTIME_MULT_CACHE_SIZE 2048

/* brain_class_cache REMOVED: 131KB BSS array (16384×8B) was hydrated by Rust
 * every poll cycle but had zero BPF readers. */

/* ═══ Per-Task Context ═══
 * Scheduling state now lives in task_struct plus the arena-backed
 * cake_task_ctx below. Release hot paths avoid arena access where possible;
 * the arena copy exists primarily for iter output and debug telemetry. */


/* ═══ PER-CPU BSS ═══
 * Written by cake_running (local CPU only), read by cake_stopping and a
 * small number of enqueue/dispatch helpers.
 *
 * 128-byte aligned for V-Cache sector isolation.
 * Single-writer (local running), multi-reader (no atomics needed). */
struct cake_cpu_bss {
#ifndef CAKE_RELEASE
	u32 run_start;          /* 4B: (u32)cake_clock when task started.
				 *     Written: cake_running (debug only).
				 *     Read: running_telemetry (debug only).
				 *     Kept in debug: BenchLab bench 55 references it. */
	u8  tick_count;         /* 1B: cake_tick throttle counter */
	u8  llc_id;             /* 1B: per-CPU LLC ID cache.
				 *     Set once at init from cpu_llc_id RODATA.
				 *     Eliminates indexed RODATA load in dispatch/tick. */
	u16 _pad_6;             /* 2B: natural alignment for tick_slice */
#endif
	u64 tick_slice;         /* 8B: p->scx.slice ?: quantum_ns */
	u64 vtime_local;        /* 8B: per-CPU live vtime frontier.
				 *     Tracks the most recently active runnable
				 *     task on this CPU so wakeup rescue can
				 *     clamp against the current workload
				 *     instead of a historical max. */
	u32 last_pid;           /* 4B: Fast path — skip task-change work if same pid */
	u8  idle_hint;          /* 1B: 0=busy, 1=idle */
	u8  cpu_pressure;       /* 1B: rolling lane pressure for same-core spill decisions */
#ifndef CAKE_RELEASE
	u8  busy_wakeup_pending; /* 1B: reserved for future wake handoff policy */
	u8  last_wake_class;    /* 1B: last running task's shadow wake class */
#endif
	u32 owner_avg_runtime_ns; /* 4B: release policy EWMA for current CPU owner */
	u16 owner_run_count;    /* 2B: samples behind owner_avg_runtime_ns */
	u16 _pad_owner_policy;  /* 2B: keep debug-only fields aligned */
#ifndef CAKE_RELEASE
	u8  last_strict_wake_class; /* Strict dry-run class for busy-preempt experiments */
	u8  _pad_strict[7];
	u64 smt_run_start_ns;   /* Wall-clock start for SMT overlap accounting */
	u64 smt_last_stop_ns;   /* Last observed stop for sibling overlap accounting */
	u8  smt_sibling_active_start; /* 1 if sibling lane was active at run start */
	u8  _pad_smt[7];
	u64 cake_clock;         /* 8B: BPF-native monotonic clock (ns).
				 *     Debug-only accumulator. Advanced by consumed
				 *     slice in cake_stopping. Resynced from
				 *     scx_bpf_now() only on task-change (25%). */
#endif
	/* Compiler pads to 4096B via aligned attribute.
	 * Hardware page boundary isolation ensures L2 prefetchers
	 * cannot speculatively load adjacent CPU states. */
} __attribute__((aligned(4096)));
/* 4096B alignment: V-Cache Telescoping (Frontier Phase 1).
 * Hardware page boundary isolation ensures L2 hardware prefetchers cannot
 * speculatively load adjacent CPU states, absolutely eradicating MESI
 * snoop invalidation storms across dual-CCD topologies. */



/* ═══ COMPILE-TIME HARDWARE SCALING ═══
 * build.rs detects host CPU/LLC count from sysfs at compile time,
 * rounds to next power-of-2, and passes -DCAKE_MAX_CPUS=N -DCAKE_MAX_LLCS=N.
 * All arrays, loops, BSS, and RODATA compile to exactly the hardware size.
 *
 * Power-of-2 required: & (CAKE_MAX_CPUS - 1) bitmask at 50+ indexing sites.
 * Range [16, 512] covers 4-core old CPUs (clamped up) to dual EPYC.
 *
 * Fallback values used when -D not provided (generic/CI builds). */
#ifndef CAKE_MAX_CPUS
#define CAKE_MAX_CPUS 64
#endif
/* Compile-time validation (BPF compilation only — skipped during Rust bindgen) */
#ifdef __BPF__
_Static_assert((CAKE_MAX_CPUS & (CAKE_MAX_CPUS - 1)) == 0,
               "CAKE_MAX_CPUS must be power of 2");
_Static_assert(CAKE_MAX_CPUS >= 16 && CAKE_MAX_CPUS <= 512,
               "CAKE_MAX_CPUS out of range [16, 512]");
#endif

#ifndef CAKE_MAX_LLCS
#define CAKE_MAX_LLCS 8
#endif

#ifdef __BPF__
_Static_assert((CAKE_MAX_LLCS & (CAKE_MAX_LLCS - 1)) == 0,
               "CAKE_MAX_LLCS must be power of 2");
#endif

/* CPU mask word count: ceiling division for <64 CPU systems.
 * At 16 CPUs: (16+63)/64 = 1 word.  At 64: 1.  At 512: 8. */
#define CAKE_CPU_MASK_WORDS ((CAKE_MAX_CPUS + 63) / 64)

/* Auto-size CPU ID type: u8 for <256 CPUs (consumer), u16 for ≥256 (EPYC).
 * Strict <256: CPU ID 255 must NOT collide with sentinel 0xFF.
 * Saves 1 byte per RODATA entry on consumer hardware vs always-u16.
 * Uses standard C types for bindgen compatibility. */
#if CAKE_MAX_CPUS < 256
typedef unsigned char  cake_cpu_id_t;
#define CAKE_CPU_SENTINEL 0xFF
#else
typedef unsigned short cake_cpu_id_t;
#define CAKE_CPU_SENTINEL 0xFFFF
#endif

/* Telemetry histogram: scales with hardware for accurate per-CPU run counts.
 * At 16 CPUs: 32B/task (16×u16).  At 64: 128B/task.  Compiled out in release. */
#define CAKE_TELEM_MAX_CPUS CAKE_MAX_CPUS

/* Physical core array sizing: MAX/2 assumes SMT=2 (AMD/Intel consumer).
 * _Static_assert fires if a non-SMT build exceeds this (future EPYC). */
#define CAKE_MAX_CORES (CAKE_MAX_CPUS / 2)
/* Queue policy selected by loader through RODATA. */
#define CAKE_QUEUE_POLICY_LOCAL 0U
#define CAKE_QUEUE_POLICY_LLC_VTIME 1U

/* Shared-DSQ base used by the default per-LLC vtime fallback policy.
 * The local queue policy remains available as an explicit A/B mode. */
#define LLC_DSQ_BASE 200

/* STAGED_BIT_* defines REMOVED: staged_vtime_bits field was dead.
 * Ordering state now lives in p->scx.dsq_vtime; legacy class/tier metadata
 * remains only in packed_info/telemetry paths. */

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

		/* Task storage baseline (kept for BenchLab comparison against arena) */
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
		BENCH_PELT_VS_EWMA       = 54, /* PELT read + legacy tier bucketing */

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
	BENCH_SELECT_CPU_AND     = 67, /* Reserved: select_cpu kfuncs are illegal from stopping BenchLab */

	BENCH_MAX_ENTRIES        = 68,
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

/* Gate cascade (simplified 3-gate design):
 *   Gate 1: prev_cpu idle
 *   Gate 2: perf-ordered idle scan (hybrid systems only)
 *   Gate 3: kernel scx_bpf_select_cpu_dfl (any idle)
 *   Tunnel: all CPUs busy -> return prev_cpu for local enqueue */

/* Flow state flags (packed_info bits 24-27).
 * packed_info is now primarily an iter/debug transport field.
 * Only NEW/YIELDER and KCRITICAL have live readers; the rest are
 * retained for telemetry / BenchLab compatibility. */
enum cake_flow_flags {
	CAKE_FLOW_NEW          = 1 << 0, /* Task is newly created */
	CAKE_FLOW_YIELDER      = 1 << 1, /* Task voluntarily yielded since last stop */
	CAKE_FLOW_WAKER_BOOST  = 1 << 2, /* Reserved legacy flag */
	CAKE_FLOW_HOG          = 1 << 3, /* Reserved legacy flag */
};

enum cake_wake_reason {
	CAKE_WAKE_REASON_NONE   = 0,
	CAKE_WAKE_REASON_DIRECT = 1,
	CAKE_WAKE_REASON_BUSY   = 2,
	CAKE_WAKE_REASON_QUEUED = 3,
	CAKE_WAKE_REASON_MAX    = 4,
};

enum cake_wake_bucket_idx {
	CAKE_WAKE_BUCKET_LT50US  = 0,
	CAKE_WAKE_BUCKET_LT200US = 1,
	CAKE_WAKE_BUCKET_LT1MS   = 2,
	CAKE_WAKE_BUCKET_LT5MS   = 3,
	CAKE_WAKE_BUCKET_GE5MS   = 4,
	CAKE_WAKE_BUCKET_MAX     = 5,
};

enum cake_kick_kind {
	CAKE_KICK_KIND_NONE    = 0,
	CAKE_KICK_KIND_IDLE    = 1,
	CAKE_KICK_KIND_PREEMPT = 2,
	CAKE_KICK_KIND_MAX     = 3,
};

enum cake_wake_class {
	CAKE_WAKE_CLASS_NONE    = 0,
	CAKE_WAKE_CLASS_NORMAL  = 1,
	CAKE_WAKE_CLASS_SHIELD  = 2,
	CAKE_WAKE_CLASS_CONTAIN = 3,
	CAKE_WAKE_CLASS_MAX     = 4,
};

enum cake_wake_class_reason {
	CAKE_WAKE_CLASS_REASON_LOW_UTIL      = 0,
	CAKE_WAKE_CLASS_REASON_SHORT_RUN     = 1,
	CAKE_WAKE_CLASS_REASON_WAKE_DENSE    = 2,
	CAKE_WAKE_CLASS_REASON_LATENCY_PRIO  = 3,
	CAKE_WAKE_CLASS_REASON_RUNTIME_HEAVY = 4,
	CAKE_WAKE_CLASS_REASON_PREEMPT_HEAVY = 5,
	CAKE_WAKE_CLASS_REASON_PRESSURE_HIGH = 6,
	CAKE_WAKE_CLASS_REASON_YIELD_HEAVY   = 7,
	CAKE_WAKE_CLASS_REASON_WAIT_TAIL     = 8,
	CAKE_WAKE_CLASS_REASON_MAX           = 9,
};

enum cake_busy_preempt_shadow {
	CAKE_BUSY_PREEMPT_SHADOW_ALLOW = 0,
	CAKE_BUSY_PREEMPT_SHADOW_SKIP  = 1,
	CAKE_BUSY_PREEMPT_SHADOW_MAX   = 2,
};

enum cake_place_class {
	CAKE_PLACE_HOME_CPU = 0,
	CAKE_PLACE_HOME_CORE = 1,
	CAKE_PLACE_HOME_LLC = 2,
	CAKE_PLACE_REMOTE = 3,
	CAKE_PLACE_CLASS_MAX = 4,
};

enum cake_select_path {
	CAKE_SELECT_PATH_NONE = 0,
	CAKE_SELECT_PATH_HOME_CPU = 1,
	CAKE_SELECT_PATH_HOME_CORE = 2,
	CAKE_SELECT_PATH_PRIMARY = 3,
	CAKE_SELECT_PATH_IDLE = 4,
	CAKE_SELECT_PATH_TUNNEL = 5,
	CAKE_SELECT_PATH_MAX = 6,
};

/* Debug-only select_cpu reason tracking.
 * CAKE_SELECT_PATH keeps the historical high-level buckets used by the dump.
 * These reasons split the coarse "idle" and "primary" paths into the exact
 * winner that led to the CPU choice so debug builds can explain hot-core
 * stickiness precisely. */
enum cake_select_reason {
	CAKE_SELECT_REASON_NONE = 0,
	CAKE_SELECT_REASON_HOME_CPU = 1,
	CAKE_SELECT_REASON_HOME_CORE = 2,
	CAKE_SELECT_REASON_PREV_PRIMARY = 3,
	CAKE_SELECT_REASON_PRIMARY_SCAN = 4,
	CAKE_SELECT_REASON_HYBRID_SCAN = 5,
	CAKE_SELECT_REASON_KERNEL_PREV = 6,
	CAKE_SELECT_REASON_KERNEL_IDLE = 7,
	CAKE_SELECT_REASON_TUNNEL = 8,
	CAKE_SELECT_REASON_PRESSURE_CORE = 9,
	CAKE_SELECT_REASON_MAX = 10,
};

/* Debug coverage uses compact ringbuf events as its BPF/userspace boundary.
 * BPF emits raw facts; userspace builds wake graphs, policy shadows, and
 * long-window histograms so debug coverage does not consume verifier budget
 * with in-BPF analytics tables. */
#ifndef CAKE_RELEASE
#define CAKE_DEBUG_EVENT_STREAM 1
#else
#define CAKE_DEBUG_EVENT_STREAM 0
#endif

#define CAKE_WAKE_EDGE_SAMPLE_NS 1000000000ULL
#define CAKE_WAKE_EDGE_SAMPLE_DENOM 64U

/* Debug-only pressure spill diagnostics.
 * "anchor" groups structural blockers where there is no usable same-core
 * spill candidate. The companion anchor-block enum breaks that aggregate
 * down so dumps can distinguish bad inputs from intentional topology gates. */
enum cake_pressure_probe_site {
	CAKE_PRESSURE_PROBE_SITE_HOME = 0,
	CAKE_PRESSURE_PROBE_SITE_PREV = 1,
	CAKE_PRESSURE_PROBE_SITE_MAX = 2,
};

enum cake_pressure_probe_outcome {
	CAKE_PRESSURE_PROBE_EVALUATED = 0,
	CAKE_PRESSURE_PROBE_BLOCKED_ANCHOR = 1,
	CAKE_PRESSURE_PROBE_BLOCKED_SCORE = 2,
	CAKE_PRESSURE_PROBE_BLOCKED_DELTA = 3,
	CAKE_PRESSURE_PROBE_BLOCKED_SIBLING_BUSY = 4,
	CAKE_PRESSURE_PROBE_SUCCESS = 5,
	CAKE_PRESSURE_PROBE_OUTCOME_MAX = 6,
};

enum cake_pressure_anchor_block_reason {
	CAKE_PRESSURE_ANCHOR_INVALID = 0,
	CAKE_PRESSURE_ANCHOR_SECONDARY = 1,
	CAKE_PRESSURE_ANCHOR_NO_SIBLING = 2,
	CAKE_PRESSURE_ANCHOR_AFFINITY = 3,
	CAKE_PRESSURE_ANCHOR_REASON_MAX = 4,
};

enum cake_cb_idx {
	CAKE_CB_SELECT   = 0,
	CAKE_CB_ENQUEUE  = 1,
	CAKE_CB_DISPATCH = 2,
	CAKE_CB_RUNNING  = 3,
	CAKE_CB_STOPPING = 4,
	CAKE_CB_MAX      = 5,
};

enum cake_cb_bucket_idx {
	CAKE_CB_BUCKET_LT250NS = 0,
	CAKE_CB_BUCKET_LT500NS = 1,
	CAKE_CB_BUCKET_LT1US   = 2,
	CAKE_CB_BUCKET_LT2US   = 3,
	CAKE_CB_BUCKET_LT5US   = 4,
	CAKE_CB_BUCKET_LT10US  = 5,
	CAKE_CB_BUCKET_GE10US  = 6,
	CAKE_CB_BUCKET_MAX     = 7,
};

enum cake_dbg_event_kind {
	CAKE_DBG_EVENT_CALLBACK         = 1,
	CAKE_DBG_EVENT_WAKEWAIT         = 2,
	CAKE_DBG_EVENT_WAKE_TARGET_MISS = 3,
	CAKE_DBG_EVENT_KICK_SLOW        = 4,
	CAKE_DBG_EVENT_WAKE_FOLLOW_MIG  = 5,
	CAKE_DBG_EVENT_DISPATCH_GAP     = 6,
	CAKE_DBG_EVENT_PREEMPT_CHAIN    = 7,
	CAKE_DBG_EVENT_WAKE_EDGE_ENQUEUE = 8,
	CAKE_DBG_EVENT_WAKE_EDGE_RUN     = 9,
	CAKE_DBG_EVENT_WAKE_EDGE_FOLLOW  = 10,
};

#define CAKE_WAKE_EDGE_EVENT_FLAG_HIT_OR_SAME 1U
#define CAKE_WAKE_EDGE_EVENT_FLAG_SAMPLED     2U
#define CAKE_WAKE_EDGE_EVENT_FLAG_IMPORTANT   4U

struct cake_debug_event {
	u64 ts_ns;
	u64 value_ns;
	u32 pid;
	u32 aux;
	u32 tgid;
	u32 peer_pid;
	u32 peer_tgid;
	u16 cpu;
	u16 target_cpu;
	u16 peer_cpu;
	u8 kind;
	u8 slot;
	u8 reason;
	u8 path;
	u8 home_place;
	u8 waker_place;
	u8 flags;
	u8 _pad[3];
	char comm[16];
};

/* Record emitted by SEC("iter/task") cake_task_iter program.
 * One record per managed task. Userspace reads fixed-size records from the
 * iter fd instead of walking the pid_to_tctx hash map.
 * Replaces: pid_to_tctx BPF_MAP_TYPE_HASH (65536 entries, global bucket lock).
 * Benefit: cake_init_task + cake_exit_task become fully lockless (no map ops). */
struct cake_iter_record {
	u32 pid;         /* pid of this task */
	u32 ppid;        /* parent pid (promoted from tctx CL0) */
	u32 packed_info; /* iter/debug packed flags — read in Rust telemetry loop */
	u16 pelt_util;       /* PELT util_avg (0-1024) from p->se.avg */
	u16 allowed_cpus;    /* p->nr_cpus_allowed, capped to u16 */
	u16 task_weight;     /* Raw task weight mirrored for iter/TUI display (100=nice0) */
	u16 home_cpu;        /* Current sticky home CPU, or CAKE_CPU_SENTINEL */
	/* telemetry block: everything the TUI currently reads from arena pointers */
	struct {
		u64 run_start_ns;
		u64 run_duration_ns;
		u64 total_runtime_ns;
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
		u32 _pad2; /* debug iter anatomy: task_flags */
		u64 jitter_accum_ns;
		u32 total_runs;
		u16 core_placement;
		u16 migration_count;
		u16 preempt_count;
		u16 yield_count;
		u16 direct_dispatch_count;
		u16 enqueue_count;
		u16 cpumask_change_count;
		u16 _pad3; /* debug iter anatomy: task_policy */
		u32 stopping_duration_ns;
		u32 running_duration_ns;
		u32 max_runtime_us;
		u32 _pad4; /* debug iter anatomy: prio/static/normal packed as 3 u8s */
		u64 dispatch_gap_ns;
		u64 max_dispatch_gap_ns;
		u32 wait_hist_lt10us;
		u32 wait_hist_lt100us;
		u32 wait_hist_lt1ms;
		u32 wait_hist_ge1ms;
		u16 slice_util_pct;
		u16 llc_id;
		u16 llc_run_mask;
		u16 same_cpu_streak;
		u16 _pad_recomp; /* debug iter anatomy: bit0 has_mm, bit1 kthread */
		u32 wakeup_source_pid;
		u64 nivcsw_snapshot;
		u32 nvcsw_delta;
		u32 nivcsw_delta;
		u32 pid_inner;  /* matches telemetry.pid */
		u32 tgid;
		char comm[16];
			u32 gate_cascade_ns;
			u32 lifecycle_init_ms;
			u32 vtime_compute_ns;
			u32 mbox_staging_ns;
			u32 startup_latency_us;
			u32 startup_enqueue_us;
			u32 lifecycle_live_ms;
			u32 startup_select_us;
		u64 quantum_full_count;
		u64 quantum_yield_count;
		u64 quantum_preempt_count;
		u8 startup_first_phase;
		u8 startup_phase_mask;
		u16 waker_cpu;
		u16 _pad_waker;
		u32 waker_tgid;
		u64 wake_reason_wait_ns[CAKE_WAKE_REASON_MAX - 1];
		u32 wake_reason_count[CAKE_WAKE_REASON_MAX - 1];
		u32 wake_reason_max_us[CAKE_WAKE_REASON_MAX - 1];
		u8 last_select_reason;
		u8 last_select_path;
		u8 last_place_class;
		u8 last_waker_place_class;
		u32 wake_same_tgid_count;
		u32 wake_cross_tgid_count;
		u64 home_place_wait_ns[CAKE_PLACE_CLASS_MAX];
		u32 home_place_wait_count[CAKE_PLACE_CLASS_MAX];
		u32 home_place_wait_max_us[CAKE_PLACE_CLASS_MAX];
		u16 cpu_run_count[CAKE_TELEM_MAX_CPUS];
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
#define CAKE_TCTX_ALIGN 64
#endif

/* Per-task context — conditional sizing (Release/Debug pattern).
 *   RELEASE: 64B (1 CL) — iter-visible fields only, telemetry compiled out
 *   DEBUG:  512B (8 CL) — iter-visible fields plus TUI telemetry
 *
 * CACHE LINE SEGREGATION:
 *   CL0 (bytes 0-63): Fields needed for iter output and debug bookkeeping.
 *     aligned(CAKE_TCTX_ALIGN) handles CL0 padding automatically —
 *     no manual _pad arrays needed.
 *   CL1+ (bytes 64+): Debug-only telemetry for TUI analytics.
 *     Compiled out in release → struct shrinks from 448B to 64B. */
struct cake_task_ctx {
	/* ═══ CACHE LINE 0: RELEASE + ITER FIELDS ═══ */
	u32 packed_info;       /* 4B: Bitfield flags (iter-visible) */
	u32 ppid;              /* 4B: Parent PID (iter-visible) */
	u16 task_weight;       /* 2B: Raw task weight for iter/TUI display (100=nice0) */
	u16 home_cpu;          /* 2B: Sticky preferred CPU (primary SMT lane) */
	u8  home_score;        /* 1B: Hysteresis for updating home_cpu */
	u8  home_core;         /* 1B: Sticky preferred physical core */

#ifdef CAKE_RELEASE
	u8  primary_scan_credit; /* 1B: Guarded primary scans periodically earn one probe */
#else
	/* ── DEBUG-ONLY CL0 FIELDS ── */
	u8  task_class;        /* 1B: CAKE_CLASS_* enum (iter sync, debug stopping) */
	u8  primary_scan_credit; /* 1B: Guarded primary scans periodically earn one probe */
	u64 nvcsw_snapshot;    /* 8B: voluntary ctx switch snapshot (debug stopping) */
#endif
	/* Compiler pads to CAKE_TCTX_ALIGN via aligned attribute. */

#ifndef CAKE_RELEASE
	/* ═══ CL1+ (bytes 64-447): DEBUG-ONLY TELEMETRY ═══
	 * Compiled out in release → struct shrinks from 512B to 64B.
	 * Zero-cost pointer access via BPF Arena. User-space sweeps memory
	 * asynchronously to build 1% Lows and average runtimes. */
	struct {
		/* Timing Metrics */
		u64 run_start_ns;
		u64 run_duration_ns; /* Last observed runtime (stop - run_start) */
		u64 total_runtime_ns; /* Cumulative runtime charged to this task */
		u64 enqueue_start_ns; /* Internal wake-to-run staging timestamp */
		u64 wait_duration_ns; /* Last observed wake-to-run wait */
		u32 select_cpu_duration_ns; /* Last observed select_cpu overhead */
		u32 enqueue_duration_ns; /* Last observed enqueue overhead */
		u32 dsq_insert_ns;       /* Last observed DSQ insert/vtime overhead */

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
		u64 jitter_accum_ns; /* Sum of |observed runtime - expected runtime| */
		u32 total_runs; /* Total executions over task lifetime */
		u16 core_placement; /* Physical CPU task last executed on */

		/* State Change Counters */
		u16 migration_count; /* Inter-cpu bounces inside select_cpu */
		u16 preempt_count;   /* Task kicked/preempted */
		u16 yield_count;     /* Explicit sched_yield callbacks */

		/* Lifecycle Counters */
		u16 direct_dispatch_count; /* SCX_DSQ_LOCAL_ON bypasses (no DSQ) */
		u16 enqueue_count;         /* Total enqueue calls */
		u16 cpumask_change_count;  /* sched_setaffinity changes */

		/* Callback Overhead (last-write-wins, ns) */
		u32 stopping_duration_ns;  /* Last observed cake_stopping BPF overhead */
		u32 running_duration_ns;   /* Last observed cake_running BPF overhead */

		/* Worst-Case Tracking */
		u32 max_runtime_us;        /* Worst observed runtime over task lifetime */


		/* Scheduling Period (inter-dispatch gap) */
		u64 dispatch_gap_ns;       /* Last observed gap since previous run start */
		u64 max_dispatch_gap_ns;   /* Worst observed gap over task lifetime */

		/* Wait Latency Histogram (bucket counts, lifetime) */
		u32 wait_hist_lt10us;      /* wait < 10µs */
		u32 wait_hist_lt100us;     /* 10µs <= wait < 100µs */
		u32 wait_hist_lt1ms;       /* 100µs <= wait < 1ms */
		u32 wait_hist_ge1ms;       /* wait >= 1ms */

		/* Slice Utilization Metrics */
		u16 slice_util_pct;        /* Approximate slice occupancy score where 128 ~= full slice */
		u16 llc_id;                /* LLC node this task last ran on */
		u16 llc_run_mask;          /* Bitmask of LLCs the task has run on */
		u16 same_cpu_streak;       /* Consecutive runs on same CPU */
		u16 _pad_recomp;           /* (was _deprecated_recomp — removed) */
		u32 wakeup_source_pid;     /* PID that woke this task */

		/* Voluntary/involuntary context switch tracking (GPU detection) */
		u64 nivcsw_snapshot;       /* Last read of p->nivcsw (for delta) */
		u32 nvcsw_delta;           /* Accumulated nvcsw delta over task lifetime */
		u32 nivcsw_delta;          /* Accumulated nivcsw delta over task lifetime */

		u32 pid;
		u32 tgid;  /* Thread group ID (process) for TUI grouping */
		char comm[16];

		/* Per-callback sub-function stopwatch (verbose health).
		 * Several slots are retained only so the iter/TUI layout stays stable. */
		u32 gate_cascade_ns;       /* select_cpu: full gate cascade duration */
		u32 lifecycle_init_ms;     /* task init timestamp in monotonic ms */
		u32 vtime_compute_ns;      /* enqueue: vtime calc minus DSQ insert */
		u32 mbox_staging_ns;       /* running: mailbox CL0 write burst */
		u32 startup_latency_us;    /* task init to first observed run, us */
		u32 startup_enqueue_us;    /* task init to first observed enqueue, us */
		u32 lifecycle_live_ms;     /* iter snapshot age for live task, ms */
		u32 startup_select_us;     /* task init to first observed select_cpu, us */

		/* Quantum completion tracking */
		u64 quantum_full_count;    /* Task consumed the full slice */
		u64 quantum_yield_count;   /* Task stopped with slice left and became non-runnable */
		u64 quantum_preempt_count; /* Task was kicked/preempted while still runnable */
		u8 startup_first_phase;    /* enum cake_startup_phase: first observed scheduler phase */
		u8 startup_phase_mask;     /* CAKE_STARTUP_MASK_* phases observed before first run */

		/* Wake chain tracking */
		u16 waker_cpu;             /* CPU the waker was running on */
		u16 _pad_waker;            /* Align to 4B */
		u32 waker_tgid;            /* TGID of the waker (process group) */
		u64 wake_reason_wait_ns[CAKE_WAKE_REASON_MAX - 1]; /* Wait by wake path */
		u32 wake_reason_count[CAKE_WAKE_REASON_MAX - 1];   /* Samples by wake path */
		u32 wake_reason_max_us[CAKE_WAKE_REASON_MAX - 1];  /* Worst wait by wake path */
		u8 pending_wake_reason;    /* Wake path recorded at enqueue, consumed at run */
		u8 pending_select_path;    /* select_cpu path recorded before the run */
		u8 pending_kick_kind;      /* Last wake kick type issued for this wake */
		u8 postwake_watch;         /* Whether the next run should be tracked as a post-wake continuation */
		u16 pending_target_cpu;    /* CPU chosen at enqueue for the current wake */
		u16 postwake_first_cpu;    /* CPU used for the first run after the wake */
		u8 postwake_reason;        /* Wake reason associated with postwake_first_cpu */
		u8 pending_select_reason;  /* select_cpu reason that fed the next run */
		u64 pending_kick_ts_ns;    /* Timestamp when the last wake kick was issued */
		u8 last_select_path;       /* Last select path that actually led to a run */
		u8 last_select_reason;     /* Last select_cpu reason that fed an observed run */
		u8 last_place_class;       /* Last run vs sticky home: cpu/core/llc/remote */
		u8 last_waker_place_class; /* Last run vs waker: cpu/core/llc/remote */
		u32 wake_same_tgid_count;  /* Wake chain stayed inside the same process */
		u32 wake_cross_tgid_count; /* Wake came from a different TGID */
		u64 home_place_wait_ns[CAKE_PLACE_CLASS_MAX]; /* Wait totals by home locality */
		u32 home_place_wait_count[CAKE_PLACE_CLASS_MAX]; /* Wait samples by home locality */
		u32 home_place_wait_max_us[CAKE_PLACE_CLASS_MAX]; /* Worst wait by home locality */
		u32 pending_blocker_pid;  /* CPU owner observed when enqueue hit busy target */
		u16 pending_blocker_cpu;  /* Busy target CPU for pending wake */
		u8 pending_strict_owner_class; /* Strict owner class on busy target */
		u8 pending_target_pressure;    /* Pressure observed on busy target */

		/* CPU core distribution histogram */
		u16 cpu_run_count[CAKE_TELEM_MAX_CPUS]; /* 128 bytes: per-CPU run count */
	} telemetry;
#endif /* !CAKE_RELEASE */
} __attribute__((aligned(CAKE_TCTX_ALIGN)));
_Static_assert(
	sizeof(struct cake_task_ctx) == CAKE_TCTX_SIZE,
	"cake_task_ctx size mismatch (64B release, 512B debug)");

/* packed_info bitfield layout (iter/debug transport field):
 * [Stable:2][Tier:2][Flags:4][KCR:1][BG:1][Rsvd:2][WCS:4][Rsvd:8]
 *  31-30     29-28   27-24    23     22    21-20  19-16  15-8
 * TIER+STABLE+BG are retained legacy fields.
 * KCR = cached critical kernel thread (set once in cake_init_task).
 * WCS = wake-chain locality score, capped to 4 bits.
 * The TUI no longer surfaces the legacy fields as live cake classes. */
#define SHIFT_FLAGS 24 /* 4 bits: flow flags */
#define SHIFT_TIER 28 /* 2 bits: tier 0-3 (coalesced with STABLE) */
#define SHIFT_STABLE 30 /* 2 bits: tier-stability counter (0-3) */
#define SHIFT_WAKE_CHAIN_SCORE 16 /* 4 bits: behavior locality score */
#define BIT_KCRITICAL 23 /* 1 bit: latency-critical kthread (set in init_task) */
#define BIT_BG_NOISE 22 /* 1 bit: reserved legacy flag */

#define MASK_TIER 0x03 /* 2 bits: 0-3 */
#define MASK_FLAGS 0x0F /* 4 bits */
#define MASK_WAKE_CHAIN_SCORE 0x0F /* 4 bits */

/* Legacy HOG detection threshold retained for debug/telemetry compatibility.
 * Current release code does not actively reclassify tasks with it. */

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
		u8  tick_tier;         /* BenchLab: legacy tier snapshot */
	u16 cached_cpu;        /* BenchLab: CPU ID snapshot */
	u32 tick_last_run_at;  /* BenchLab: run_start snapshot */

	/* --- Cached fields (bytes 72-95) --- */
	u64 tick_slice;        /* 8B — BenchLab: slice snapshot */
	u64 cached_tctx_ptr;   /* 8B — BenchLab: arena tctx pointer */
		u32 cached_deficit;    /* 4B — BenchLab: legacy deficit-style snapshot */
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

/* Statistics shared with userspace.
 * Some legacy counters remain in the layout for TUI compatibility
 * even when current release code no longer increments them. */
struct cake_stats {
	u64 nr_prev_cpu_tunnels; /* select_cpu() fell back to returning prev_cpu */
	u64 nr_steer_eligible; /* select_cpu() saw a task eligible for warm steering */
	u64 nr_home_cpu_steers; /* select_cpu() placed a hot task back on its sticky home CPU */
	u64 nr_home_core_steers; /* select_cpu() kept a hot task on its sticky core */
	u64 nr_primary_cpu_steers; /* select_cpu() steered a hot task onto an idle primary SMT lane */
	u64 nr_home_cpu_busy_misses; /* home_cpu was valid but not idle */
	u64 nr_prev_primary_busy_misses; /* prev core primary lane rescue was valid but not idle */
	u64 nr_primary_scan_misses; /* primary-lane scan ran but found no idle candidate */
	u64 nr_primary_scan_guarded; /* primary-lane scan skipped for stable low-util sync wake chains */
	u64 nr_primary_scan_credit_used; /* guard-eligible primary scan allowed by periodic credit */
	u64 nr_primary_scan_hot_guarded; /* primary-lane scan skipped for hot same-TGID micro-workers */
	u64 nr_wake_chain_locality_guarded; /* wake-chain locality held placement on learned/previous CPU */
	u64 nr_wake_chain_locality_credit_used; /* wake-chain locality guard allowed a periodic wide probe */
	u64 nr_busy_handoff_dispatches; /* dispatch() later pulled DSQ work while a busy wakeup was pending */
	u64 nr_busy_keep_suppressed; /* dispatch() skipped keep_running because a busy wakeup was pending */
	u64 nr_wakeup_busy_local_target; /* Busy wakeup fallback where target CPU matched enqueue CPU */
	u64 nr_wakeup_busy_remote_target; /* Busy wakeup fallback where target CPU differed from enqueue CPU */
	u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Reserved legacy per-tier counters */
	u64 nr_starvation_preempts_tier
		[CAKE_TIER_MAX]; /* Reserved legacy per-tier counters */
	u64 total_gate1_latency_ns; /* Total time spent in Gate 1 */
	u64 total_gate2_latency_ns; /* Total time spent in Gate 2 */
	u64 total_enqueue_latency_ns; /* Total time spent in enqueue */
	u64 nr_dropped_allocations; /* Count of failed scx_task_alloc requests */
	u64 nr_local_dispatches;    /* Dispatched from local LLC DSQ */
	u64 nr_stolen_dispatches;   /* Dispatched from remote LLC DSQ (steal) */
	u64 nr_dispatch_misses;     /* dispatch() found no residual shared-queue work */
	u64 nr_dispatch_hint_skip;  /* dispatch() skipped kfunc via dsq_pending hint (counter==0) */
	u64 nr_direct_local_inserts; /* Total SCX_DSQ_LOCAL_ON inserts performed by cake */
	u64 nr_direct_affine_inserts; /* Direct local inserts used to keep restricted-affinity tasks off shared queues */
	u64 nr_direct_kthread_inserts; /* Direct inserts from the kthread bypass path */
	u64 nr_direct_other_inserts; /* Direct inserts that were neither wakeups nor kthread bypass */
	u64 nr_dsq_queued;          /* Shared vtime DSQ enqueue count (for depth calc where used) */
	u64 nr_dsq_consumed;        /* Shared DSQ consume count */
	u64 nr_shared_vtime_inserts; /* Total shared vtime DSQ inserts performed by cake */
	u64 nr_shared_wakeup_inserts; /* Shared vtime inserts from wakeups */
	u64 nr_shared_requeue_inserts; /* Shared vtime inserts from the slice-halving requeue path */
	u64 nr_shared_preserve_inserts; /* Shared vtime inserts preserving slice/deadline state */
	u64 nr_shared_other_inserts; /* Shared vtime inserts that were neither wakeup nor requeue/preserve */

	/* Callback aggregate timing (cumulative ns, system-wide) */
	u64 total_select_cpu_ns;     /* Total time in cake_select_cpu */
	u64 total_stopping_ns;       /* Total time in cake_stopping */
	u64 total_running_ns;        /* Total time in cake_running */
	u64 task_runtime_ns;         /* Total scheduled task runtime completed on this CPU */
	u64 task_run_count;          /* Completed task run segments on this CPU */
	u64 smt_solo_runtime_ns;     /* Runtime completed while sibling lane appeared idle */
	u64 smt_contended_runtime_ns; /* Runtime completed with observed sibling overlap */
	u64 smt_overlap_runtime_ns;  /* Estimated sibling-overlap runtime charged to this CPU */
	u64 smt_solo_run_count;      /* Run segments without observed sibling overlap */
	u64 smt_contended_run_count; /* Run segments with observed sibling overlap */
	u64 smt_sibling_active_start_count; /* Runs whose sibling was active at start */
	u64 smt_sibling_active_stop_count;  /* Runs whose sibling was active at stop */
	u64 smt_wake_wait_ns[2];     /* Wake wait by sibling-active-at-run-start bucket */
	u64 smt_wake_wait_count[2];  /* Wake wait samples by SMT bucket */
	u64 smt_wake_wait_max_ns[2]; /* Worst wake wait by SMT bucket */

	/* Callback max tracking (worst single invocation, ns) */
	u64 max_select_cpu_ns;       /* Worst single cake_select_cpu */
	u64 max_stopping_ns;         /* Worst single cake_stopping */
	u64 max_running_ns;          /* Worst single cake_running */

	/* Stopping path breakdown (invocation counts) */
	u64 nr_stop_deferred_skip;   /* Stops that skipped full task telemetry */
	u64 nr_stop_deferred;        /* Stops that recorded full task telemetry */
	u64 nr_stop_ramp;            /* Reserved legacy counter */
	u64 nr_stop_miss;            /* Reserved legacy counter */

	/* Dispatch callback timing */
	u64 total_dispatch_ns;       /* Total time in cake_dispatch */
	u64 max_dispatch_ns;         /* Worst single cake_dispatch */
	u64 nr_select_cpu_calls;     /* Total cake_select_cpu invocations */
	u64 nr_enqueue_calls;        /* Total cake_enqueue invocations */
	u64 nr_dispatch_calls;       /* Total cake_dispatch invocations */
	u64 nr_running_calls;        /* Total cake_running invocations */
	u64 nr_stopping_calls;       /* Total cake_stopping invocations */
	u64 nr_running_same_task;    /* running(): last_pid matched current task */
	u64 nr_running_task_change;  /* running(): observed a new task on this CPU */
	u64 nr_stopping_runnable;    /* stopping(): task remained runnable */
	u64 nr_stopping_blocked;     /* stopping(): task blocked / slept */
	u64 nr_enqueue_path_kthread; /* enqueue(): high-priority kthread bypass */
	u64 nr_enqueue_path_initial; /* enqueue(): first vtime seed path */
	u64 nr_enqueue_path_preserve; /* enqueue(): preserve slice/vtime state */
	u64 nr_enqueue_path_requeue; /* enqueue(): non-wakeup requeue path */
	u64 nr_enqueue_path_wakeup;  /* enqueue(): normal wakeup path */
	u64 nr_enqueue_path_affine_preserve; /* enqueue(): affinity-restricted preserve */
	u64 nr_enqueue_path_affine_requeue; /* enqueue(): affinity-restricted requeue */
	u64 nr_enqueue_path_affine_dispatch; /* enqueue(): affinity-restricted dispatch */
	u64 nr_llc_vtime_wake_idle_direct; /* llc-vtime: wake found target idle, local insert */
	u64 nr_llc_vtime_wake_busy_shared; /* llc-vtime: wake target busy, shared insert + kick */
	u64 nr_llc_vtime_nonwake_shared; /* llc-vtime: non-wakeup shared insert */
	u64 nr_dispatch_llc_local_hit; /* dispatch(): local LLC DSQ had work */
	u64 nr_dispatch_llc_local_miss; /* dispatch(): local LLC DSQ was empty */
	u64 nr_dispatch_llc_steal_hit; /* dispatch(): remote LLC steal succeeded */
	u64 nr_dispatch_keep_running;  /* dispatch(): replenished prev queued task */

	/* Task lifecycle timing (cumulative us, debug builds) */
	u64 lifecycle_init_enqueue_us; /* Sum of task init to first enqueue */
	u64 lifecycle_init_enqueue_count; /* Samples for init->enqueue */
	u64 lifecycle_init_select_us;  /* Sum of task init to first select_cpu */
	u64 lifecycle_init_select_count; /* Samples for init->select_cpu */
	u64 lifecycle_init_run_us;     /* Sum of task init to first running */
	u64 lifecycle_init_run_count;  /* Samples for init->run */
	u64 lifecycle_init_exit_us;    /* Sum of task init to exit_task */
	u64 lifecycle_init_exit_count; /* Samples for init->exit */

		/* Wakeup enqueue gate counters */
		u64 nr_wakeup_direct_dispatches; /* Wakeups that direct-dispatched to SCX_DSQ_LOCAL_ON */
		u64 nr_wakeup_dsq_fallback_busy; /* Wakeups that missed direct dispatch because target CPU did not look idle */
		u64 nr_wakeup_dsq_fallback_queued; /* Wakeups that missed direct dispatch because the shared DSQ was already non-empty */
	u64 callback_hist[CAKE_CB_MAX][CAKE_CB_BUCKET_MAX]; /* Callback duration histogram buckets */
	u64 callback_slow[CAKE_CB_MAX]; /* Threshold breaches per callback */
	u64 wake_reason_wait_all_ns[CAKE_WAKE_REASON_MAX]; /* Full-pop wake-to-run wait sums by wake path (0 unused) */
	u64 wake_reason_wait_all_count[CAKE_WAKE_REASON_MAX]; /* Full-pop wake-to-run samples by wake path (0 unused) */
	u64 wake_reason_wait_all_max_ns[CAKE_WAKE_REASON_MAX]; /* Full-pop worst wait by wake path (0 unused) */
	u64 wake_reason_wait_ns[CAKE_WAKE_REASON_MAX]; /* Wait sums by wake path (0 unused) */
	u64 wake_reason_wait_count[CAKE_WAKE_REASON_MAX]; /* Wait samples by wake path (0 unused) */
	u64 wake_reason_wait_max_ns[CAKE_WAKE_REASON_MAX]; /* Worst wait by wake path (0 unused) */
	u64 wake_reason_bucket_count[CAKE_WAKE_REASON_MAX][CAKE_WAKE_BUCKET_MAX]; /* Wake-to-run buckets by wake path (0 unused) */
	u64 select_path_count[CAKE_SELECT_PATH_MAX]; /* Path chosen in select_cpu (0 unused) */
	u64 select_path_migration_count[CAKE_SELECT_PATH_MAX]; /* Debug: select_cpu choices that changed CPU by path */
	u64 select_reason_migration_count[CAKE_SELECT_REASON_MAX]; /* Debug: select_cpu choices that changed CPU by reason */
	u64 select_reason_wait_ns[CAKE_SELECT_REASON_MAX]; /* Wake-to-run wait after each select_cpu decision reason */
	u64 select_reason_wait_count[CAKE_SELECT_REASON_MAX]; /* Wait samples after each select_cpu decision reason */
	u64 select_reason_wait_max_ns[CAKE_SELECT_REASON_MAX]; /* Worst wait after each select_cpu decision reason */
	u64 select_reason_bucket_count[CAKE_SELECT_REASON_MAX][CAKE_WAKE_BUCKET_MAX]; /* Wait buckets after each select_cpu decision reason */
	u64 select_reason_select_ns[CAKE_SELECT_REASON_MAX]; /* select_cpu overhead by decision reason */
	u64 select_reason_select_count[CAKE_SELECT_REASON_MAX]; /* select_cpu samples by decision reason */
	u64 select_reason_select_max_ns[CAKE_SELECT_REASON_MAX]; /* Worst select_cpu overhead by decision reason */
	u64 home_place_wait_ns[CAKE_PLACE_CLASS_MAX]; /* Wait sums by task-home locality */
	u64 home_place_wait_count[CAKE_PLACE_CLASS_MAX]; /* Wait samples by task-home locality */
	u64 home_place_wait_max_ns[CAKE_PLACE_CLASS_MAX]; /* Worst wait by task-home locality */
	u64 home_place_run_ns[CAKE_PLACE_CLASS_MAX]; /* First-run sums by task-home locality */
	u64 home_place_run_count[CAKE_PLACE_CLASS_MAX]; /* First-run samples by task-home locality */
	u64 home_place_run_max_ns[CAKE_PLACE_CLASS_MAX]; /* Worst first-run by task-home locality */
	u64 waker_place_wait_ns[CAKE_PLACE_CLASS_MAX]; /* Wait sums by waker locality */
	u64 waker_place_wait_count[CAKE_PLACE_CLASS_MAX]; /* Wait samples by waker locality */
	u64 waker_place_wait_max_ns[CAKE_PLACE_CLASS_MAX]; /* Worst wait by waker locality */
	u64 nr_wake_same_tgid; /* Wakes from the same TGID */
	u64 nr_wake_cross_tgid; /* Wakes from a different TGID */
	u64 nr_idle_hint_remote_reads; /* Cross-CPU idle_hint reads */
	u64 nr_idle_hint_remote_busy; /* Remote idle_hint reads observing busy */
	u64 nr_idle_hint_remote_idle; /* Remote idle_hint reads observing idle */
	u64 nr_busy_pending_remote_sets; /* Cross-CPU busy_wakeup_pending writes for shared-fallback mode */
	u64 nr_enqueue_requeue_fastpath; /* Non-wakeup requeues that bypassed direct-handoff logic */
	u64 nr_enqueue_busy_local_skip_depth; /* Same-CPU busy wakeups that skipped DSQ depth query */
	u64 nr_enqueue_busy_remote_skip_depth; /* Remote busy wakeups that skipped DSQ depth query */
	u64 nr_busy_pending_set_skips; /* busy_wakeup_pending already 1 in shared-fallback mode */
	u64 nr_idle_hint_set_writes; /* idle_hint 0->1 transitions */
	u64 nr_idle_hint_clear_writes; /* idle_hint 1->0 transitions */
	u64 nr_idle_hint_set_skips; /* idle_hint already 1 */
	u64 nr_idle_hint_clear_skips; /* idle_hint already 0 */
	u64 nr_wake_kick_idle; /* Wake-driven kicks that used SCX_KICK_IDLE */
	u64 nr_wake_kick_preempt; /* Wake-driven kicks that used SCX_KICK_PREEMPT */
	u64 wake_class_sample_count[CAKE_WAKE_CLASS_MAX]; /* Shadow wake class samples */
	u64 wake_class_reason_count[CAKE_WAKE_CLASS_REASON_MAX]; /* Shadow class reason hits */
	u64 wake_class_transition_count[CAKE_WAKE_CLASS_MAX][CAKE_WAKE_CLASS_MAX]; /* Per-CPU owner class transitions */
	u64 busy_preempt_shadow_count[CAKE_BUSY_PREEMPT_SHADOW_MAX]; /* Shadow busy-wake decision counts */
	u64 busy_preempt_shadow_wakee_class_count[CAKE_WAKE_CLASS_MAX]; /* Busy shadow by wakee class */
	u64 busy_preempt_shadow_owner_class_count[CAKE_WAKE_CLASS_MAX]; /* Busy shadow by owner class */
	u64 busy_preempt_shadow_local; /* Busy shadow decisions where waker CPU matched target CPU */
	u64 busy_preempt_shadow_remote; /* Busy shadow decisions where target CPU was remote */
	u64 strict_wake_class_sample_count[CAKE_WAKE_CLASS_MAX]; /* Stricter shadow wake class samples */
	u64 strict_wake_class_reason_count[CAKE_WAKE_CLASS_REASON_MAX]; /* Strict class reason hits */
	u64 strict_wake_class_transition_count[CAKE_WAKE_CLASS_MAX][CAKE_WAKE_CLASS_MAX]; /* Strict owner transitions */
	u64 strict_busy_preempt_shadow_count[CAKE_BUSY_PREEMPT_SHADOW_MAX]; /* Strict busy-wake decision counts */
	u64 strict_busy_preempt_shadow_wakee_class_count[CAKE_WAKE_CLASS_MAX]; /* Strict busy shadow by wakee class */
	u64 strict_busy_preempt_shadow_owner_class_count[CAKE_WAKE_CLASS_MAX]; /* Strict busy shadow by owner class */
	u64 strict_busy_preempt_shadow_local; /* Strict busy shadow decisions where waker CPU matched target CPU */
	u64 strict_busy_preempt_shadow_remote; /* Strict busy shadow decisions where target CPU was remote */
	u64 strict_wake_class_wait_ns[CAKE_WAKE_CLASS_MAX]; /* Strict wake-class wait sums */
	u64 strict_wake_class_wait_count[CAKE_WAKE_CLASS_MAX]; /* Strict wake-class wait samples */
	u64 strict_wake_class_wait_max_ns[CAKE_WAKE_CLASS_MAX]; /* Strict wake-class worst wait */
	u64 strict_wake_class_bucket_count[CAKE_WAKE_CLASS_MAX][CAKE_WAKE_BUCKET_MAX]; /* Strict wake wait buckets by class */
	u64 nr_affine_kick_idle; /* Affinity-change kicks that used SCX_KICK_IDLE */
	u64 nr_affine_kick_preempt; /* Affinity-change kicks that used SCX_KICK_PREEMPT */
	u64 nr_quantum_full; /* Stops that consumed the full slice */
	u64 nr_quantum_yield; /* Stops that kept slice left but became non-runnable */
	u64 nr_quantum_preempt; /* Stops that were preempted while still runnable */
	u64 nr_sched_yield_calls; /* Explicit sched_yield callbacks observed by cake_yield() */
		u64 wake_target_hit_count[CAKE_WAKE_REASON_MAX]; /* Post-wake subset: first run landed on the selected CPU */
		u64 wake_target_miss_count[CAKE_WAKE_REASON_MAX]; /* Post-wake subset: first run landed on a different CPU */
		u64 wake_followup_same_cpu_count[CAKE_WAKE_REASON_MAX]; /* Post-wake subset: first continuation stayed on the same CPU */
		u64 wake_followup_migrate_count[CAKE_WAKE_REASON_MAX]; /* Post-wake subset: first continuation migrated away */
	u64 nr_wake_kick_observed[CAKE_KICK_KIND_MAX]; /* Wake kicks followed by an observed run */
	u64 nr_wake_kick_quick[CAKE_KICK_KIND_MAX]; /* Wake kicks that led to a run within 200us */
	u64 total_wake_kick_to_run_ns[CAKE_KICK_KIND_MAX]; /* Kick-to-run total latency by kick kind */
	u64 max_wake_kick_to_run_ns[CAKE_KICK_KIND_MAX]; /* Worst kick-to-run latency by kick kind */
	u64 wake_kick_bucket_count[CAKE_KICK_KIND_MAX][CAKE_WAKE_BUCKET_MAX]; /* Kick-to-run buckets by kick kind */
	} __attribute__((aligned(64)));

/* Current default values */
#define CAKE_DEFAULT_QUANTUM_NS (2 * 1000 * 1000) /* 2ms */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS (3 * 1000 * 1000) /* Reserved legacy constant */

/* Legacy adaptive-quantum constants retained for compatibility with older
 * debug paths and BenchLab comparisons. Current release scheduling does not
 * drive policy from these values. */
#define AQ_BULK_HEADROOM     1               /* 1× PELT runtime for non-yielders */
#define AQ_MIN_NS            (50 * 1000)     /* 50µs legacy floor */
#define AQ_YIELDER_CEILING_NS (50 * 1000000)  /* 50ms legacy yielder ceiling */
#define AQ_BULK_CEILING_NS        (2 * 1000000)   /* 2ms legacy bulk ceiling */
#define AQ_BULK_CEILING_COMPILE_NS (8 * 1000000)   /* 8ms legacy compile ceiling */

/* Legacy preemption thresholds retained for compatibility. */
#define CAKE_PREEMPT_YIELDER_THRESHOLD_NS (100 * 1000) /* 100µs legacy threshold */
#define CAKE_PREEMPT_VIP_THRESHOLD_NS      (50 * 1000) /*  50µs — reserved legacy */

#endif /* __CAKE_INTF_H */
