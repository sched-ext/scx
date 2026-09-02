/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multilevel Feedback Queue scheduling with per-queue EEVDF virtual time.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * This header is shared between BPF, the Rust front-end (via bindgen) and
 * the native unit-test harness. It holds every scheduling constant, the
 * task/queue state layouts and the pure virtual-time and classification
 * math, and it defines its own kernel type aliases so the harness can
 * compile it without the kernel headers.
 */
#ifndef __SCX_MLFQ_INTF_H
#define __SCX_MLFQ_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif

#include <stdbool.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

/*
 * Native-harness fallback for the iterator-based bpf_for loops below.
 * The BPF build gets the real iterator macro from scx/common.bpf.h
 * (included by main.bpf.c before this header). The pure-math harness
 * compiles this header without any BPF machinery, so a plain bounded
 * for-loop preserves the same semantics for the pure functions. The
 * iterator form is what keeps the verifier's exploration of the loop
 * flat. A plain constant-bound loop is not unrolled and the verifier
 * processes each iteration until its states converge, which blows the
 * instruction budget for the steering scan.
 */
#ifndef __VMLINUX_H__
#ifndef bpf_for
/*
 * Harness-only stand-in for the kernel's iterator loop: the native
 * unit-test build has no BPF iterator machinery, and the call sites
 * pass a plain loop variable, which is the iterator contract (the
 * first argument is always a fresh scalar). The BPF build uses the
 * kernel's bpf_for from the toolchain headers instead.
 */
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)
#endif
#endif

/*
 * Instrumentation. Set to 1 to compile the invariant checks
 * into the BPF object; they are compiled out by default. The check
 * predicates themselves live under the same guard and are exercised by the
 * native unit-test harness with MLFQ_CHECK forced on.
 */
#ifndef MLFQ_CHECK
#define MLFQ_CHECK 0
#endif

enum mlfq_consts {
	NSEC_PER_USEC			= 1000ULL,
	NSEC_PER_MSEC			= (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC			= (1000ULL * NSEC_PER_MSEC),

	/* Per-queue request sizes. */
	MLFQ_Q1_SLICE_NS		= (1ULL * NSEC_PER_MSEC),
	MLFQ_Q2_SLICE_NS		= (2ULL * NSEC_PER_MSEC),
	MLFQ_Q3_SLICE_NS		= (4ULL * NSEC_PER_MSEC),

	/*
	 * Assumed tick length for the lag clamp horizon. The tick is used as
	 * the HZ=1000 approximation in the lag bound; limit =
	 * calc_delta_fair(max_slice + TICK, weight), the bound used by
	 * entity_lag() in kernel/sched/fair.c.
	 */
	MLFQ_TICK_NS			= (1ULL * NSEC_PER_MSEC),

	/* EMA interactivity gauge. */
	MLFQ_BUDGET_MAX_NS		= (6ULL * NSEC_PER_MSEC),
	FP_SHIFT			= 8,
	FP_ONE				= (1ULL << FP_SHIFT),
	MLFQ_ALPHA			= 3072ULL,

	/* Classification thresholds. */
	MLFQ_T_L_NS			= (250ULL * NSEC_PER_USEC),
	MLFQ_T_H_NS			= (2ULL * NSEC_PER_MSEC),

	/*
	 * Ceiling of the per-task service-quality EMA, in nsecs. A task
	 * that waits 100 ms in a queue under overload saturates at 16 ms,
	 * the "latency pressure" signal of the per-task gauge.
	 */
	MLFQ_SQ_EMA_MAX_NS		= (16ULL * NSEC_PER_MSEC),

	/*
	 * Ceiling of the system wakeup-latency gauge, in nsecs. The
	 * gauge reads the machine's average wakeup latency, and the
	 * ceiling keeps every downstream threshold and product in a
	 * small, overflow-free range.
	 */
	MLFQ_SYS_LAT_MAX_NS		= (16ULL * NSEC_PER_MSEC),

	/* EMA decay half-life. */
	MLFQ_EMA_HALF_LIFE_NS		= (24ULL * NSEC_PER_MSEC),

	/*
	 * Seconds-scale time constant of the system gauges (wakeup
	 * latency and wakeup rate). The gauges smooth the workload over
	 * seconds while the per-task classification reacts in
	 * milliseconds, so the adaptation they drive cannot chase
	 * sample-level noise.
	 */
	MLFQ_SYS_GAUGE_HALF_LIFE_NS	= (1ULL * NSEC_PER_SEC),

	/*
	 * Ceiling of the wakeup-rate gauge, in wakeups per second. The
	 * rate is carried in FP_SHIFT fixed point, so the ceiling sits
	 * below the u32 fixed-point overflow point and the stored value
	 * (a u64) is exact.
	 */
	MLFQ_SYS_RATE_MAX		= 1000000ULL,

	/*
	 * Short-sleep boost window: covers periodic wakeup cadences such
	 * as the 60 Hz frame interval, so latency-sensitive consumers of
	 * CPU are recognized as interactive even when their runtime
	 * consumption would otherwise classify them as CPU-bound. The
	 * per-task boost rate limit keeps the churn bounded.
	 * The value is set against the slowest common cadence: faster refresh
	 * rates sleep for a shorter interval per frame and fall inside the
	 * window as well.
	 */
	MLFQ_SHORT_SLEEP_NS		= (32ULL * NSEC_PER_MSEC),
	MLFQ_SHORT_SLEEP_RATE_LIMIT_NS	= (2ULL * NSEC_PER_MSEC),
	MLFQ_HYSTERESIS_SLEEP_NS	= (4ULL * NSEC_PER_MSEC),

	/* Aging. */
	MLFQ_AGING_PERIOD_NS		= (1ULL * NSEC_PER_SEC),

	/*
	 * Minimum residency before a same-queue wakeup may preempt the
	 * running task, in nsecs. The interactive same-queue rule (Q1 onto
	 * Q1) preempts on this guard alone; the non-interactive rule
	 * additionally requires the wakeup's fresh deadline to precede the
	 * resident's. Zero, the default, makes the interactive rule
	 * unconditional: a wakeup that just became runnable is served
	 * ahead of the resident at the next scheduling event. Internal
	 * tuning constant, not a user-facing knob.
	 */
	MLFQ_SAMEQ_PREEMPT_MIN_RUN_NS	= 0ULL,

	/*
	 * Slice cap for a preempting wakeup, in nsecs. The preempt path
	 * displaces a running task, so the grant is a bounded burst: the
	 * displaced task (typically the thread that woke this one, whose
	 * early deadline puts it first in the virtual-time order) resumes
	 * at the next scheduling event once the cap expires. The policy
	 * slice still governs the regular path and the continuation after
	 * the run-out re-enqueue. Internal tuning constant, not a
	 * user-facing knob.
	 */
	MLFQ_PREEMPT_SLICE_NS		= (150ULL * NSEC_PER_USEC),

	/*
	 * A sleep longer than this collapses the gauge to (near) zero. The
	 * wakeup then re-adopts the base mapping. Five EMA half-lives =
	 * 120 ms.
	 */
	MLFQ_LONG_SLEEP_NS		= (120ULL * NSEC_PER_MSEC),

	/*
	 * UAPI linux/sched.h policy value; sched_ext only receives
	 * SCHED_NORMAL/BATCH/IDLE/EXT tasks.
	 */
	MLFQ_SCHED_IDLE			= 5,

	/* Dispatch quotas. */
	MLFQ_Q1_QUOTA			= 4ULL,
	MLFQ_Q2_QUOTA			= 8ULL,
	MLFQ_DISPATCH_MAX_BATCH		= 32ULL,

	/*
	 * Cap on the remote CPUs scanned per dispatch slot. The scan
	 * starts at a rotating per-CPU offset so no remote CPU is
	 * permanently excluded. The runtime bound (mlfq_steal_scan) is
	 * this value clamped to the CPU count in init(), so the window
	 * never exceeds the machine size and a small machine does not
	 * re-peek the same remote DSQs. The static bound also bounds the
	 * verifier's exploration of the nested steal loops; it must stay
	 * low enough that mlfq_dispatch() verifies within the kernel's
	 * jump-sequence limit.
	 */
	MLFQ_STEAL_SCAN_MAX		= 64ULL,

	/*
	 * sched_ext cpuperf level (scx_bpf_cpuperf_set(), the schedutil
	 * target hint). The perf argument is a linear relative level in
	 * [0, SCX_CPUPERF_ONE]; SCX_CPUPERF_ONE is 0x400 (1024), the
	 * maximum level. The kernel stores the target per-CPU and it
	 * persists until overwritten, so ops.running() states the level of
	 * the task now on the CPU on every context switch and schedutil
	 * follows. The interactive queue requests the maximum level and
	 * the other queues request the level matching the CPU's recent
	 * activity (mlfq_cpuperf_from_ema()), so a CPU that once ran an
	 * interactive task does not stay at the maximum level for the
	 * background work that follows. With the scheduler in switch-all
	 * mode the target is the only utilization signal schedutil sees.
	 */
	MLFQ_CPUPERF_Q1			= 1024ULL,

	MLFQ_NR_QUEUES			= 3ULL,

	/*
	 * Per-CPU vtime-ordered queue DSQ id space. Every CPU owns
	 * MLFQ_NR_QUEUES DSQs, laid out as MLFQ_DSQ_BASE +
	 * cpu * MLFQ_DSQ_STRIDE + (qid - 1) so the owning CPU and queue
	 * decode arithmetically (see mlfq_dsq_id()). The range ends far
	 * below SCX_DSQ_LOCAL_ON, which reserves the top bits for the
	 * kernel DSQ flags; init() validates this at load time.
	 */
	MLFQ_DSQ_BASE			= 0x1000ULL,
	MLFQ_DSQ_STRIDE			= MLFQ_NR_QUEUES,

	/*
	 * Compile-time CPU bound for the per-CPU capacity array. Matches the
	 * per-CPU state map bound (cpu_state_stor, 1024 entries); init()
	 * rejects machines with more online CPUs.
	 */
	MLFQ_MAX_CPUS			= 1024ULL,

	/*
	 * Compile-time bound for the per-LLC bitmap array. Machines with
	 * more LLC domains than this have LLC-aware placement disabled at
	 * startup (the userspace side refuses to populate the bitmaps).
	 */
	MLFQ_MAX_LLCS			= 32ULL,

	/*
	 * Tier-A same-LLC steal window: the flat scan over the consuming
	 * CPU's own-LLC CPU list, one peek per slot. The compile-time
	 * bound keeps the verifier's exploration flat, identical in shape
	 * to the cross-LLC window it gates.
	 */
	MLFQ_LLC_SCAN_MAX		= 32ULL,

	/*
	 * Per-LLC CPU-list bound: the largest CPU count any LLC domain may
	 * publish into the mlfq_llc_cpus map values. Equal to the Tier-A
	 * scan window, so the window's constant modulo covers the whole
	 * populated list: the front-end populates a domain's list only up
	 * to MLFQ_LLC_SCAN_MAX CPUs, and a domain that exceeds the bound
	 * gets an EMPTY list (nr == 0) instead. Tier A then skips it and
	 * the Tier B rotating window covers the domain, never a silently
	 * shrunk subset of it. The cpus[] array is exactly the window
	 * width, so every published entry is reachable by the scan.
	 */
	MLFQ_MAX_LLC_CPUS		= MLFQ_LLC_SCAN_MAX,

	/*
	 * Steering scan cap: the number of least-loaded-LLC selection
	 * attempts the steering path may make before falling through
	 * to the global fallbacks. The tuning knob lives with the other
	 * steering constants.
	 */
	MLFQ_STEER_LLC_MAX		= 4ULL,

	/*
	 * Number of 64-bit words needed to hold one CPU bit per CPU.
	 */
	MLFQ_BITMAP_WORDS		= (MLFQ_MAX_CPUS + 63) / 64,

	/*
	 * MLFQ regression-tree constants. The tree predicts the next CPU
	 * burst from per-task features and maps the prediction to a queue
	 * band (pred < T_INT -> Q1, pred < T_BOUND -> Q2, else Q3). The
	 * EMA gauge stays on as a tree feature and as the untrained
	 * fallback. Internal tuning constants, not user-facing knobs.
	 */
	MLFQ_TREE_MAX_NODES		= 2048,		/* node budget, power of two */
	MLFQ_TREE_MAX_DEPTH		= 12,		/* walk depth bound */
	MLFQ_TREE_T_INT_NS		= (1ULL * NSEC_PER_MSEC), /* Q1/Q2 split */
	MLFQ_TREE_T_BOUND_NS		= (3ULL * NSEC_PER_MSEC), /* Q2/Q3 split */

	/*
	 * Size of the training-sample ring buffer, in bytes. One
	 * megabyte holds roughly fifteen thousand sample records, a
	 * multiple of the per-minute sample budget, so the daemon drain
	 * cadence never finds the ring full.
	 */
	MLFQ_SAMPLE_RING_BYTES		= (1 * 1024 * 1024),

	/*
	 * The ops watchdog timeout, in milliseconds. The kernel's
	 * maximum detection latency for a stalled scheduler; the
	 * scheduler exits and the kernel reverts to CFS when it fires.
	 */
	MLFQ_OPS_TIMEOUT_MS		= 30000,

	/*
	 * Version tag of the emitted training-sample record layout. The
	 * ring-buffer records are parsed by the daemon with a
	 * byte-for-byte struct mirror compiled from this same header, and
	 * the native harness pins the layout at compile time; the tag is
	 * the runtime check of that contract, so a record produced by an
	 * out-of-tree builder (or a daemon built against a different
	 * intf.h) fails loudly at the parse instead of misreading the
	 * fields.
	 */
	MLFQ_TREE_SAMPLE_VERSION	= 4,

	/*
	 * Number of features the CART splitter may use. The fitter caps
	 * split feature ids to [0, MLFQ_TREE_NR_FEATURES), so a value
	 * here is the contract with mlfq_tree.rs and the walk's feat[]
	 * indexing. The 1.3.11 ABI carries nine split features
	 * (prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
	 * queue_wait, sq_ema, gpu_submit) with sleep_var_ratio remain
	 * carry-along quantised via FP_SHIFT (0..4 steps).
	 */
	MLFQ_TREE_NR_FEATURES		= 9,

	/*
	 * Adaptation control law. The adaptation is a proportional-only
	 * controller on the system wakeup-latency gauge. The band edges
	 * move by a common relative shift, slew-limited per step, within
	 * the hard floor/ceiling ranges below. The target latency equals
	 * the interactive slice, the natural service target of the Q1
	 * boost; k = 0.5 maps a full-range gauge error to half the shift
	 * range, and the slew caps a single step at 10% of the base, so a
	 * full swing needs at least five steps and one bad sample can
	 * never move the bands more than one step. The shift only widens
	 * the bands: a machine at or below the target latency keeps the
	 * base bands, the measured-good configuration, and only a slower
	 * machine widens them. The symmetric negative range was dropped
	 * because narrowing the bands below the base measurably worsened
	 * the wakeup-latency tail under load.
	 */
	MLFQ_ADAPT_MIN_INTERVAL_NS	= (1ULL * NSEC_PER_SEC),
	MLFQ_ADAPT_TARGET_LAT_NS	= (1ULL * NSEC_PER_MSEC),
	MLFQ_ADAPT_K			= (FP_ONE / 2),
	MLFQ_ADAPT_MAX_SHIFT		= (FP_ONE / 2),
	MLFQ_ADAPT_MAX_STEP		= (FP_ONE / 10),

	/*
	 * Hard bounds of the effective band edges. The floor/ceiling
	 * ranges are disjoint per band pair (T_L ceiling 500 us sits below
	 * the T_H floor 1.2 ms, and the T_INT ceiling 1.6 ms below the
	 * T_BOUND floor 1.8 ms), so no admissible shift can collapse a
	 * band to zero width or invert the queue semantics. T_H - T_L
	 * >= 700 us and T_BOUND - T_INT >= 200 us for every reachable
	 * shift. The bounds are enforced on the effective value, never on
	 * the shift input.
	 */
	MLFQ_ADAPT_T_L_FLOOR_NS		= (150ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_L_CEIL_NS		= (500ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_H_FLOOR_NS		= (1200ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_H_CEIL_NS		= (3200ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_INT_FLOOR_NS	= (600ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_INT_CEIL_NS	= (1600ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_BND_FLOOR_NS	= (1800ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_BND_CEIL_NS	= (4800ULL * NSEC_PER_USEC),

	/*
	 * Wakeup-rate storm gate. When the system wakeup-rate gauge
	 * exceeds this high threshold (200k wakeups per second, an order
	 * of magnitude above a normal desktop wakeup cadence), the
	 * positive shift is capped at +0.25 instead of +0.5: under a
	 * wakeup storm the band edges must not chase the latency error as
	 * far as in the normal regime. The threshold is in FP_SHIFT fixed
	 * point to match the gauge.
	 */
	MLFQ_ADAPT_RATE_GATE_HIGH	= (200000ULL << FP_SHIFT),
	MLFQ_ADAPT_RATE_GATE_SHIFT	= (FP_ONE / 4),

	/*
	 * Global training-sample emission limiter: at most one sample per
	 * 500 us across the whole system (the compare-and-swap single-winner
	 * pattern in the stopping path). The per-task spacing is the
	 * separate MLFQ_TREE_PER_TASK_LIMIT_NS gate on the same emission.
	 */
	MLFQ_TREE_SAMPLE_RATE_LIMIT_NS	= (500ULL * NSEC_PER_USEC),

	/*
	 * Per-task training-sample spacing: a task can emit at most one
	 * sample per 10 ms, so no single pid can dominate the training
	 * window. At the global 2k/s rate one task's share of the window is
	 * bounded to ~5%, which stops a chatty task from over-fitting the
	 * tree to its own behavior.
	 */
	MLFQ_TREE_PER_TASK_LIMIT_NS	= (10ULL * NSEC_PER_MSEC),

	/*
	 * Emitted label clamp. The prediction only needs the queue band
	 * (the walk maps the predicted burst to Q1/Q2/Q3), so labels beyond
	 * 64x the Q2/Q3 split bound carry no scheduling information; the
	 * clamp bounds the exact-integer range the f64 SSE in the fitter
	 * sees, so the training math never sums near-u64 values.
	 */
	MLFQ_TREE_LABEL_MAX_NS		= (MLFQ_TREE_T_BOUND_NS * 64),

	MLFQ_TREE_MIN_SAMPLES		= 2048,		/* training set size */

	/*
	 * Drain interval of the realtime-takeover evacuation: at most one
	 * pass per CPU per millisecond. The rate limit bounds the churn a
	 * takeover can stir up, which otherwise has no kernel-side repeat
	 * guard: the stop-class blips that punctuate a takeover, RT tasks
	 * that ping-pong between runnable states, and the pinned-task
	 * reenqueue loop are all absorbed by the window.
	 */
	MLFQ_RTDL_DRAIN_INTERVAL_NS	= (1ULL * NSEC_PER_MSEC),
};

/* task_ctx flags */
enum mlfq_task_flags {
	MLFQ_TF_FIRST_RUN		= 1U << 0,	/* first placement */
	/*
	 * The current enqueue was a wakeup: the enqueue-to-run wait
	 * measured at ops.running() is a wakeup-to-run latency and feeds
	 * the wakeup-latency features and gauges. Set on the wakeup
	 * insert paths only, cleared at the measurement and on every
	 * non-wakeup re-enqueue, so a re-enqueued (takeover-drained) task
	 * is never attributed a wakeup latency it did not have.
	 */
	MLFQ_TF_ENQ_WAKEUP		= 1U << 1,
	/*
	 * The enqueue was a DRM gpu_submit wakeup (amdgpu_cs). Set by
	 * the amdgpu tracepoints, observed by select_cpu to broaden
	 * WAKE_SYNC, cleared after the insert. The flag is advisory
	 * and is not persisted across the measurement.
	 */
	MLFQ_TF_DRM_WAKE			= 1U << 2,
};

/*
 * Upper bound of the rate-fold window, the longest idle gap a fold may
 * smooth over before the instantaneous rate is judged against a full
 * minute. A multi-minute gap (the boot, a long idle stretch before the
 * first step) must not inflate the rate beyond what one busy minute
 * would produce. A macro, not an enum member, because the value exceeds
 * the enum's int range and would widen the bindgen-mirrored type.
 */
#define MLFQ_SYS_RATE_WINDOW_MAX_NS	(60ULL * NSEC_PER_SEC)

/*
 * MLFQ regression tree. The tree predicts the next CPU burst in nsecs
 * from the per-task feature vector. The userspace daemon trains a CART
 * model on emitted samples and publishes it through the double-buffered
 * two-entry map below; the classification path walks the active entry.
 * The node format and the walk are shared with the Rust front-end and
 * the native unit-test harness, so field order and sizes below are part
 * of the scheduler's ABI.
 */

/**
 * struct mlfq_tree_feats - Feature vector of the prediction tree.
 *
 * Theorem: the vector is the per-task state the CART predictor may
 * split on. Invariant: field order and offsets are the shared ABI
 * with emitted samples (mlfq_tree_sample) and the Rust TreeFeats
 * mirror; any reordering breaks bindgen and the ring-buffer parse.
 *
 * Derivation: prev_burst/sleep/ema/io_wait/wake_cnt are the original
 * 32-byte prefix. wake_lat/queue_wait/sq_ema measure the previous
 * episode's enqueue-to-run service, appended without reordering. The
 * 7.1 ABI adds sleep_var_ratio, the fixed-point (FP_SHIFT=8) variation
 * ratio of sleep intervals, to capture frame-cadence regularity; it
 * stays carry-along until the fitter promotes it. sq_ema remains at
 * offset 40, sleep_var_ratio at 48. The 1.3.11 ABI adds gpu_submit,
 * the quantised (FP_SHIFT 0..4) gpu submission count, at offset 56
 * with pad2 for 64-byte alignment. The resulting 64-byte record keeps
 * every u64 at an 8-byte offset and the packed sample at 84 bytes.
 *
 * Why clamp: wake_lat/queue_wait are bounded via _MAX constants and
 * label clamp, so the fitter's f64 sums stay overflow-free; the var
 * ratio is FP_ONE-scaled and clamped to [0, FP_ONE*2] to bound
 * threshold midpoints; gpu_submit is clamped to [0,4] quant steps.
 *
 * Strategy helper: classification selects the queue via the tree
 * walk (Strategy) observing this feature state (Observer) without a
 * vtable; helpers are static inline.
 *
 * 64 bytes, packed fields naturally aligned.
 */
struct mlfq_tree_feats {
	u64 prev_burst_ns;		/* last completed run segment */
	u64 sleep_ns;			/* sleep before the current wakeup */
	u64 ema;			/* EMA interactivity gauge */
	u32 io_wait;			/* 1 if the wakeup is an I/O completion */
	u32 wake_cnt;			/* consecutive short-sleep wakeups */
	u32 wake_lat_us;		/* last wakeup-to-run latency, us */
	u32 queue_wait_us;		/* last enqueue-to-run wait, us */
	u64 sq_ema;			/* service-quality EMA, ns */
	u32 sleep_var_ratio;		/* sleep variation ratio, FP_SHIFT fixed point */
	u32 pad;			/* explicit pad for 64-byte alignment */
	u32 gpu_submit;			/* gpu submissions quantised 0..4, FP_SHIFT steps */
	u32 pad2;			/* explicit pad for 64-byte alignment */
};

/*
 * One node of the serialized tree. threshold is the split point in
 * nsecs. left is the left child index, or the leaf prediction in nsecs
 * when right == 0. right is the right child index, 0 marking a leaf.
 * feature is the split feature id (0..4, indexing the walk's feat[]
 * slots). 24 bytes.
 */
struct mlfq_tree_node {
	u64 threshold;
	u32 left;
	u32 right;
	u8  feature;
	u8  pad[7];
};

/*
 * One buffer of the double-buffered published tree, and the value type
 * of the two-entry mlfq_tree_map: entry 0 and entry 1 form the double
 * buffer. The daemon fills the inactive entry and flips to it with a
 * single meta write (mlfq_tree_ctrl.meta), so a reader that has loaded
 * the meta once walks a consistent tree and never observes a torn
 * publish. The meta commit is the last write of a publish, and the tree
 * contents it points at were fully written before it.
 *
 * The protocol is sound at the 60 s publish cadence: a reader could
 * only observe a torn tree if two publishes completed within one tree
 * walk, and each walk is a few dozen memory reads while a publish moves
 * up to 2048 nodes, so two consecutive publishes cannot complete inside
 * one walk. The consequence of the theoretical race (a reader that
 * loaded the meta between two back-to-back publishes and walks the
 * freshly overwritten buffer) is one mispredicted burst, which the
 * queue-band nets absorb. It is not a memory-safety issue because the
 * walk masks every index to the buffer bound. 49152 bytes.
 */
struct mlfq_tree_store {
	struct mlfq_tree_node nodes[MLFQ_TREE_MAX_NODES];
};

#define MLFQ_TREE_META_TRAINED			(1ULL << 0)
#define MLFQ_TREE_META_ACTIVE			(1ULL << 1)
#define MLFQ_TREE_META_NR_NODES_SHIFT		8
#define MLFQ_TREE_META_NR_NODES_MASK		0xFFFFFF00ULL
#define MLFQ_TREE_META_GENERATION_SHIFT		32
#define MLFQ_TREE_META_GENERATION_MASK		0xFFFFFFFF00000000ULL

/*
 * Published-tree control state, one dedicated cache line (64 bytes, the
 * instance in main.bpf.c is aligned to 64).
 *
 * The tree meta is read by every inference and the sample limiter by
 * every pending-sample emission check, but the pair is written only by
 * the publish (once per 60 s cadence) and the single compare-and-swap
 * winner of each sample window, so the line must not share a cache line
 * with the write-hammered mlfq_stats counters. Keeping the pair alone on
 * a line prevents every counter update from dirtying the line the
 * classification hot path reads.
 *
 * bss defaults zeroed, which is exactly the untrained state (trained bit
 * clear). The meta bit layout is the same as the former combined store:
 *   bit 0   trained (set once a tree has been published)
 *   bit 1   active buffer index (0 or 1)
 *   bits 8..31  number of nodes in the active tree
 *   bits 32..63 generation counter, bumped on every publish
 *   bits 2..7 reserved, zero
 */
struct mlfq_tree_ctrl {
	u64 meta;		/* committed-tree meta, see MLFQ_TREE_META_* */
	u64 sample_last_at;	/* scx_bpf_now() of the last sample emission */
	u64 pad[6];		/* one dedicated cache line */
};

extern volatile struct mlfq_tree_ctrl mlfq_tree_ctrl;

/**
 * struct mlfq_tree_sample - One training sample for the daemon.
 *
 * Theorem: the ring-buffer record is the atomic training unit.
 * Invariant: 84 bytes packed aligned(4), field order is the shared ABI.
 *
 * Derivation: pid/queue (8 bytes) + feats 64 bytes + label 8 bytes +
 * version 4 bytes = 84. The feats vector is the 64-byte form (sq_ema
 * at 40, sleep_var_ratio at 48, gpu_submit at 56). label_ns is clamped to
 * MLFQ_TREE_LABEL_MAX_NS, so the fitter's f64 sums never sum near-u64
 * values.
 *
 * Why clamp: version is MLFQ_TREE_SAMPLE_VERSION (4 for 1.3.11 ABI);
 * mismatch drops the record instead of misreading fields.
 *
 * Observer helper: stopping path observes task state to emit this
 * record; daemon observes the ring buffer (Observer) without shared
 * state.
 *
 * 84 bytes packed aligned(4); every field keeps its natural offset.
 */
struct mlfq_tree_sample {
	u32 pid;
	u32 queue;
	struct mlfq_tree_feats feats;
	u64 label_ns;
	u32 version;			/* MLFQ_TREE_SAMPLE_VERSION */
} __attribute__((packed, aligned(4)));

/* ABI layout pins: compiled on every build, native and BPF. */
_Static_assert(sizeof(struct mlfq_tree_feats) == 64,
	       "mlfq_tree_feats must be 64 bytes (sq_ema at 40, var_ratio at 48, gpu_submit at 56)");
_Static_assert(sizeof(struct mlfq_tree_sample) == 84,
	       "mlfq_tree_sample must be 84 bytes (packed, aligned(4))");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, sq_ema) == 40,
	       "sq_ema must sit at offset 40");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, sleep_var_ratio) == 48,
	       "sleep_var_ratio must sit at offset 48");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, gpu_submit) == 56,
	       "gpu_submit must sit at offset 56");
_Static_assert(__builtin_offsetof(struct mlfq_tree_sample, label_ns) == 72,
	       "label_ns must sit at offset 72 (pid 0, queue 4, feats 8+64)");
_Static_assert(__builtin_offsetof(struct mlfq_tree_sample, version) == 80,
	       "version must sit at offset 80");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, prev_burst_ns) == 0,
	       "prev_burst_ns at 0");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, wake_lat_us) == 32,
	       "wake_lat_us at 32");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, queue_wait_us) == 36,
	       "queue_wait_us at 36");
/* Masking asymmetry: BPF walk feat[16] uses &0xF (0..15) with feat[16]
 * holding nine split features 0..8 (gpu_submit at 8, quant 0..4),
 * sleep_var_ratio carry-along at 9, and 10..15 zeroed; Rust feat[16]
 * mirrors this with match 0..10 and _=>0. The plain < NR_FEATURES
 * check is authoritative (not &0xF<9 which is tautological) and is
 * unconditional, so 9..15 never indexes OOB. NR_FEATURES 9.
 */
_Static_assert(MLFQ_TREE_NR_FEATURES == 9,
	       "NR_FEATURES must be 9 for 1.3.11 ABI (feat[16] 0..8 split, gpu_submit quant 0..4, 9 carry-along)");

/*
 * Sentinel "no LLC owner" value for task_ctx.last_llc. Valid LLC domain
 * ids are 0..MLFQ_MAX_LLCS-1 (0..31), which fit in a u8; 0xFF marks a
 * task that is not counted in the per-LLC runnable gauges: it is not
 * runnable, or it is parked on the kernel-owned global DSQ where no LLC
 * owns it.
 */
#define MLFQ_LLC_UNOWNED 0xFFU

/**
 * struct task_ctx - Per-task state in BPF task storage.
 *
 * Theorem: the task is the unit of EEVDF placement and MLFQ
 * classification. Invariant: vruntime anchored to queue clock via
 * bounded-lag clamp, vlag >=0.
 *
 * Derivation: 96-byte classification/vtime block, 24-byte
 * enqueue-to-run measurement block, plus the 80-byte MLFQ tree sample
 * block (the 64-byte feature vector plus pending_queue and
 * pending_valid padded to 64-bit) plus 24-byte sleep cadence EMA
 * block (mean 8, var 8, ratio 4 + pad 4) plus 4-byte gpu_submit
 * plus 4-byte pad plus 8-byte gpu_submit dedup timestamp.
 * Total 240 bytes aligned for the 1.3.11 ABI
 * (232 before gpu_submit timestamp, 224 before gpu_submit, gpu_submit at 224,
 * last_gpu_submit_at at 232). The 64-byte vector keeps sq_ema at 40,
 * sleep_var_ratio at 48 and gpu_submit at 56 quantised 0..4.
 *
 * Why clamp: placement lag clamped to [0, limit] for bounded-lag;
 * service EMAs clamped to MAX to bound thresholds and f64 sums.
 * gpu_submit dedup window is MLFQ_TREE_PER_TASK_LIMIT_NS (10 ms),
 * the same per-task rate limit as the training-sample gate, so a
 * single logical GPU submission that fires 2-3 tracepoints
 * (amdgpu_cs, amdgpu_cs_ioctl, gpu_sched) is counted once.
 */

/**
 * struct mlfq_q1_occupancy - Per-CPU Q1 occupancy for SMT isolation.
 *
 * Theorem: each CPU's Q1 occupancy is the soft SMT veto the selection
 * observes. Invariant: one byte per CPU, padded to 8 bytes for array
 * map value alignment and to keep per-CPU slots on separate cache
 * lines from mlfq_stats (Observer: select_cpu observes occupancy,
 * Strategy: veto is pluggable via helper).
 *
 * Derivation: occupied==1 when the CPU runs a Q1 task (set in
 * running(), cleared in stopping()), 0 otherwise. The 8-byte value
 * keeps array map values naturally aligned and avoids false sharing
 * with the BSS stats line; the map is BPF_MAP_TYPE_ARRAY, not BSS,
 * so no __sync_* on a shared line is needed and cross-CPU
 * bpf_map_lookup_elem returns the sibling's occupancy. Performance
 * review: no extra cache-line pad needed today — ARRAY already
 * isolates each CPU's slot from the BSS stats line; pad further only
 * if perf measurement shows sibling veto contention (documented, not
 * padded now).
 *
 * Why isolation: keeping occupancy per-CPU avoids the word-bit
 * false sharing of a global q1_mask; sibling lookup is logical via
 * mlfq_cpu_sibling table, not bit arithmetic.
 *
 * 8 bytes.
 */
struct mlfq_q1_occupancy {
	u8 occupied;
	u8 pad[7];
};

struct task_ctx {
	u64 vruntime;			/* last placed virtual runtime */
	s64 vlag;			/* clamped lag at placement, >= 0 */
	u64 deadline;			/* last computed virtual deadline */
	u64 ema;			/* EMA interactivity gauge [0, BUDGET_MAX] */
	u64 last_run_at;		/* scx_bpf_now() at ops.running() */
	u64 last_sleep_at;		/* scx_bpf_now() at stopping(!runnable) */
	u64 queued_at;			/* start of the current Q2/Q3 stay */
	u64 last_ss_boost_at;		/* last short-sleep boost, rate limit */
	u32 weight;			/* cached p->scx.weight [1..10000] */
	u8  queue;			/* current queue, 1..3 */
	u8  reenq_cnt;			/* consecutive slice exhaustions */
	u8  wake_cnt;			/* consecutive short-sleep wakeups */
	u8  flags;			/* MLFQ_TF_* */
	u8  wake_cpu_state;		/* bit0 idle, bit1 valid */
	/*
	 * Runnable-ownership record, maintained by the accounting helpers
	 * (mlfq_runnable_enter/exit). last_llc is the LLC domain owning
	 * the task's current DSQ or running CPU, MLFQ_LLC_UNOWNED when
	 * the task is not runnable or is parked on the kernel-owned
	 * global DSQ; last_qid is the queue (1..3) of the last counted
	 * placement, 0 when unowned. The pair is the single source of
	 * truth for "is this task counted in the per-LLC/per-queue
	 * runnable gauges". The helpers treat last_llc == MLFQ_LLC_UNOWNED
	 * as not counted. The read-modify-write is lock-free. The kernel
	 * serializes enqueue/dequeue/stopping per task, so the counter
	 * RMWs stay exact in the absence of a cross-rq race; a torn read
	 * can only defer one release, self-healed by the next episode
	 * entry.
	 */
	u8  last_llc;			/* owning LLC, MLFQ_LLC_UNOWNED if none */
	u8  last_qid;			/* queue of the last placement, 0 if none */
	u8  pad[2];
	/*
	 * Enqueue-to-run measurement block. enq_at is stamped at every
	 * DSQ insert (except the global park, whose wait is kernel-side)
	 * and the wait since it is measured at the first ops.running()
	 * of the episode: last_q_wait_ns for every episode, last_wake_lat_ns
	 * for wakeup episodes only (MLFQ_TF_ENQ_WAKEUP). sq_ema is the
	 * per-task saturating EMA of the wakeup latency, the service
	 * quality prior the tree can split on. The block is zeroed by
	 * mlfq_reset_task_ctx like every other field.
	 */
	u64 enq_at;			/* stamp of the current enqueue episode */
	u32 last_wake_lat_ns;		/* last wakeup-to-run latency, ns */
	u32 last_q_wait_ns;		/* last enqueue-to-run wait, ns */
	u64 sq_ema;			/* service-quality EMA [0, SQ_EMA_MAX] */
	u64 prev_burst_ns;		/* last completed run segment, tree feature */
	u64 last_sample_at;		/* scx_bpf_now() of the last emitted
					 * training sample, per-task rate limit */
	/*
	 * Sleep cadence EMA block for frame-loop regularity. mean/var are
	 * N=32 EWMA (α=8/256) over sleep intervals, ratio is var/mean² in
	 * FP_SHIFT=8 fixed point saturating 0..1024 (4*FP_ONE). The block
	 * is zeroed by mlfq_reset_task_ctx and updated in stopping(!runnable)
	 * with clamp and long-idle decay (>120ms) to avoid stale cadence
	 * carrying over a long idle.
	 */
	u64 sleep_mean_ema;		/* EMA of sleep intervals, ns */
	u64 sleep_var_ema;		/* EMA of sleep variance, ns² */
	u32 sleep_var_ratio;		/* var/mean² ratio, FP_SHIFT=8, 0..1024 */
	u32 pad2;
	/*
	 * Pending MLFQ tree sample: the feature vector and the queue are
	 * captured at the classification enqueue, and the sample is
	 * completed with the run segment (the label) and emitted at the
	 * segment end in ops.stopping(). pending_queue is the queue at the
	 * capture, so the emitted sample is not mislabeled by later
	 * placement decisions (aging, a subsequent classification).
	 * pending_valid is 1 between capture and emission.
	 */
	struct mlfq_tree_feats pending_feats;
	u32 pending_queue;		/* queue at the capture */
	u64 pending_valid;
	u32 gpu_submit;			/* gpu submissions, quantised 0..4, decay on idle */
	u32 pad3;			/* pad to 8-byte alignment for the timestamp */
	u64 last_gpu_submit_at;		/* scx_bpf_now() of the last gpu_submit bump, per-task dedup window (10 ms) */
};

_Static_assert(sizeof(struct task_ctx) == 240,
	       "task_ctx must be 240 bytes for 1.3.11 ABI (64-byte feats + cadence + gpu_submit + dedup timestamp, 8-byte aligned; 224 before gpu, 232 last_gpu_submit_at)");
_Static_assert(__builtin_offsetof(struct task_ctx, pending_feats) == 144,
	       "pending_feats at 144");
_Static_assert(__builtin_offsetof(struct task_ctx, pending_queue) == 208,
	       "pending_queue at 208");
_Static_assert(__builtin_offsetof(struct task_ctx, pending_valid) == 216,
	       "pending_valid at 216");
_Static_assert(__builtin_offsetof(struct task_ctx, gpu_submit) == 224,
	       "gpu_submit must sit at offset 224");
_Static_assert(__builtin_offsetof(struct task_ctx, last_gpu_submit_at) == 232,
	       "last_gpu_submit_at must sit at offset 232");
_Static_assert(__builtin_offsetof(struct task_ctx, sleep_mean_ema) == 120,
	       "sleep_mean_ema at 120");
_Static_assert(__builtin_offsetof(struct task_ctx, sleep_var_ratio) == 136,
	       "sleep_var_ratio at 136");

/* wake_cpu_state bits */
#define MLFQ_WAKE_CPU_IDLE	0x01U
#define MLFQ_WAKE_CPU_VALID	0x02U

/*
 * Per-queue virtual clock. clock is the service point the queue
 * has reached. It advances monotonically as the queue's tasks run, and
 * placement anchors a task's lag to it. No weighted-average aggregate is
 * maintained because computing it needs consistent reads of two shared
 * sums, which in BPF would require mutual exclusion; the bounded-lag
 * theorem is instead enforced by clamping the task lag to the clock at
 * placement, which is exact enough for the safety properties and keeps
 * the placement lock-free.
 */
struct queue_ctx {
	/*
	 * Virtual clock of the queue. Read without a lock by
	 * every placement; the aligned 64-bit load is atomic on the
	 * supported targets, and a stale read only lowers the clock,
	 * which the placement clamp absorbs.
	 */
	u64 clock;
	u64 max_slice_ns;		/* per-queue request size */
	u64 pad[6];			/* one queue_ctx per cacheline */
};

/*
 * Global idle tracking. mlfq_idle_count is the number of currently idle
 * CPUs, maintained by ops.update_idle() with atomic RMWs (a single u32;
 * the only consumer treats it as a zero/non-zero test). mlfq_idle_tracking
 * is a rodata gate written by the Rust front-end. It is 1 only when the
 * kernel keeps its built-in idle tracking alongside the callback (the
 * KEEP_BUILTIN_IDLE flag), 0 otherwise. Declared here so the modules and
 * the pure-math harness share the same contract.
 */
extern volatile u32 mlfq_idle_count;
extern const volatile u32 mlfq_idle_tracking;

/**
 * struct mlfq_cpu_state - Per-CPU occupancy and scheduling state.
 *
 * Theorem: each CPU's running queue, deadline and EMA are the
 * observable state the dispatch and selection helpers observe.
 * Invariant: one entry per CPU, 64 bytes, one cache line; array key
 * is cpu id.
 *
 * Derivation: running_queue/pid/deadline track the current occupant
 * for same-queue preemption (mlfq_sameq_preempt_owed). cpu_ema is the
 * busy-ns EMA (MLFQ_BUDGET_MAX_NS ceiling, MLFQ_EMA_HALF_LIFE_NS
 * decay) used for cpuperf level (mlfq_cpuperf_from_ema). steal_scan_off
 * rotates the Tier-B steal scan (Observer: dispatch observes this
 * state, Strategy: scan order is a pluggable helper without vtable).
 *
 * Why clamp: cpu_ema clamped to [0, BUDGET_MAX] bounds the cpuperf
 * level to [0, SCX_CPUPERF_ONE] and bounds virtual-time math; deadline
 * 0 marks unknown and never preempts.
 *
 * 64 bytes, one cache line.
 */
struct mlfq_cpu_state {
	s32 running_queue;		/* queue of the running task, 0 none */
	u32 running_pid;
	u32 steal_scan_off;		/* rotating remote-scan start for Q2/Q3 */
	u64 cpu_ema;			/* busy-ns EMA of this CPU's activity */
	u64 cpu_ema_at;			/* scx_bpf_now() of the last update */
	u64 running_deadline;		/* running task's deadline, 0 unknown */
	u64 run_start_at;		/* scx_bpf_now() at ops.running() */
	u32 running_gpu_submit;		/* gpu_submit 0..4 of the running task */
	u32 pad2;
};

/* Per-CPU realtime-occupancy flags. */
#define MLFQ_RTDL_OCCUPIED			(1U << 0)

/**
 * struct mlfq_rtdl_state - Per-CPU realtime occupancy.
 *
 * Theorem: the RT occupancy flag is the gate the scheduler observes
 * before placing work. Invariant: one entry per CPU, flags
 * MLFQ_RTDL_OCCUPIED when the last sched_switch saw RT/DL.
 *
 * Derivation: sched_switch hook (rtdl.bpf.c) observes the switched-in
 * task class (Observer) and sets flags; enqueue and select_cpu observe
 * flags to redirect or skip the CPU (Strategy via helper predicates,
 * static inline, no vtable). last_drain_at rate-limits the evacuation
 * scan to MLFQ_RTDL_DRAIN_INTERVAL_NS, so a takeover blip cannot
 * thrash.
 *
 * Why clamp: flags is a single bit, checked under the 7.1-only
 * watchdog (30 s); drain interval clamps the churn to 1/ms per CPU,
 * bounding the DSQ moves under continuous RT preemption.
 *
 * 16 bytes, BPF_MAP_TYPE_ARRAY value.
 */
struct mlfq_rtdl_state {
	u32 flags;			/* MLFQ_RTDL_* bits */
	u32 pad;
	u64 last_drain_at;		/* scx_bpf_now() of the last drain */
};

/*
 * Op-latency histogram. Each slot (MLFQ_OP_LAT_* below) charges the
 * wall time its callback spends running into one of eight buckets that
 * delimit the elapsed microseconds. The buckets are [0, 2), [2, 5), [5, 10), [10, 20),
 * [20, 50), [50, 100), [100, 250) and [250, inf). The preemption path is
 * healthy when its charges stay in the first few buckets; a regression
 * shows up as a visible shift toward the tail.
 */
enum mlfq_op_lat_slots {
	MLFQ_OP_LAT_STOPPING		= 0,
	MLFQ_OP_LAT_DISPATCH		= 1,
	MLFQ_OP_LAT_ENQUEUE		= 2,
	MLFQ_OP_LAT_CPU_RELEASE		= 3,
	MLFQ_OP_LAT_OPS			= 4,
};

/* Histogram bucket count and the bucket edges, in microseconds. */
enum mlfq_op_lat_consts {
	MLFQ_OP_LAT_BUCKETS		= 8,
	MLFQ_OP_LAT_EDGE_2		= 2,
	MLFQ_OP_LAT_EDGE_5		= 5,
	MLFQ_OP_LAT_EDGE_10		= 10,
	MLFQ_OP_LAT_EDGE_20		= 20,
	MLFQ_OP_LAT_EDGE_50		= 50,
	MLFQ_OP_LAT_EDGE_100		= 100,
	MLFQ_OP_LAT_EDGE_250		= 250,
};

/* One op's latency histogram, a BPF_MAP_TYPE_PERCPU_ARRAY value. */
struct mlfq_op_lat {
	u64 buckets[MLFQ_OP_LAT_BUCKETS];
};

/* System-level BPF counters, reported to userspace through the stats module. */
struct mlfq_stats {
	u64 total_runtime;
	u64 on_cpu;
	u64 q1_placements;
	u64 q2_placements;
	u64 q3_placements;
	u64 promotions;
	u64 demotions;
	u64 aging_boosts;
	u64 short_sleep_boosts;
	u64 preemption_kicks;
	u64 cpuperf_boosts;
	/* Dispatch-path counters: remote-DSQ moves and solo-task keep grants. */
	u64 steals;
	u64 steals_same_llc;		/* steals within one LLC domain */
	u64 steals_cross_llc;		/* steals across LLC domains */
	u64 keep_running;
	/* Enqueue-path diagnostics: the early-return drop counters. */
	u64 enq_no_tctx;
	u64 enq_bad_weight;
	u64 enq_no_deadline;
	u64 enq_fastpath;
	u64 enq_regular;
	u64 enq_pinned_idle;
	u64 enq_pinned_busy;
	u64 enq_pinned_global;
	/* MLFQ tree diagnostics: prediction and sample bookkeeping. */
	u64 tree_inference;		/* prediction walks run */
	u64 tree_fallback;		/* predictions served by the EMA fallback */
	u64 tree_disagree;		/* tree and EMA queue mappings disagreed */
	u64 tree_samples_emitted;	/* completed samples emitted to the daemon */
	u64 tree_samples_dropped;	/* samples dropped (ring buffer full) */
	/* Realtime-takeover diagnostics (rtdl.bpf.c, enqueue.bpf.c). */
	u64 rt_takeovers;		/* 0->1 occupied transitions observed */
	u64 rt_evacuations;		/* DSQ evacuation passes that ran */
	u64 rt_redirects;		/* wakeups redirected off occupied CPUs */
	u64 rt_reenqs;			/* SCX_ENQ_REENQ re-enqueues counted */
	/*
	 * The counter struct is exactly 32 u64s = 256 bytes (four 64-byte
	 * lines): the counters before the pad are write-hammered by the
	 * hot paths, and the published tree meta line (mlfq_tree_ctrl)
	 * must not share a line with them. The isolation itself comes
	 * from the __aligned(64) on the mlfq_tree_ctrl
	 * instance in main.bpf.c, which pins that line to a dedicated
	 * cache line. The size hygiene here lets the aligned instance sit
	 * on the following boundary by the plain declaration order, so
	 * the two never land on the same line by layout accident. The pad
	 * is empty at this exact field count; adding any counter requires
	 * recomputing it to keep the 256-byte size.
	 */
	u64 pad[0];
};

/*
 * System-level wakeup gauges, the inputs of the threshold adaptation.
 * lat_ema is the average wakeup latency of the machine, an EMA over
 * the per-window average wait, so its equilibrium does not depend on
 * the wakeup rate. rate_ema is a wakeup-rate EMA in FP_SHIFT fixed
 * point, folded once per adaptation step. step_at gates the adaptation
 * cadence (the compare-and-swap single-winner step of the adaptation
 * layer). wait_total and wait_count accumulate the episode waits
 * between folds, and the fold derives the average from them. The
 * wakeup arrival counters live in the per-CPU map mlfq_wakeup_stats
 * (see mlfq_wakeup_counters below), not here, so the wakeup path never
 * touches this line. Each CPU owns its own map slot and the u64 totals
 * cannot wrap. The rate fold consumes the per-CPU window slots once
 * per step. The latency fold runs at the cadence even with the
 * adaptation disabled, so the latency gauge stays live, while the rate
 * fold stays gated and the rate EMA stays frozen. 48 bytes.
 */
struct mlfq_sys_gauge {
	u64 lat_ema;		/* average wakeup latency, ns, [0, SYS_LAT_MAX] */
	u64 rate_ema;		/* wakeup rate, wakeups/s in FP_SHIFT fixed point */
	u64 step_at;		/* scx_bpf_now() of the last adaptation step */
	u64 wait_total;		/* wakeup waits accumulated since the last fold */
	u64 wait_count;		/* wakeup episodes since the last fold */
	u32 adapt_steps;	/* lifetime adaptation steps */
	u32 pad;
};

/*
 * Per-CPU wakeup-arrival counters, one slot per CPU in the per-CPU
 * array map mlfq_wakeup_stats. Each CPU owns its own slot, so the
 * wakeup path needs no locked operation on a shared line. total is the
 * lifetime arrival count of the owning CPU, a u64 so it cannot wrap.
 * window counts the arrivals since the last rate fold, consumed and
 * zeroed by the adaptation step with an atomic exchange. The stats
 * read sums every CPU's total with atomic loads, so the counters stay
 * tear-free for the readers. While the adaptation is disabled the fold
 * never runs and the rate EMA stays frozen, but total still grows on
 * every wakeup (the observation-only contract).
 */
struct mlfq_wakeup_counters {
	u64 total;		/* lifetime wakeup arrivals of this CPU */
	u64 window;		/* arrivals since the last rate fold */
};

/*
 * Effective adaptation state, the values the classification predicates
 * consume. Every field is written only by the 1 Hz adaptation step and
 * by mlfq_init() (which copies the rodata bases in, so the bss-zeroed
 * state, which zero thresholds would map every task to Q1, can never be
 * observed). shift_fp is the slew-limited common relative shift of both
 * band pairs, in FP_SHIFT fixed point; the t_*_eff_ns fields are the
 * clamped effective band edges; guard_eff_ns is the same-queue
 * preemption residency guard, fixed at the base constant (the
 * adaptation no longer moves it). 48 bytes.
 */
struct mlfq_adapt_state {
	s64 shift_fp;		/* slew-limited relative shift, FP */
	u64 t_l_eff_ns;		/* effective EMA Q1/Q2 band edge */
	u64 t_h_eff_ns;		/* effective EMA Q2/Q3 band edge */
	u64 t_int_eff_ns;	/* effective tree Q1/Q2 band edge */
	u64 t_bnd_eff_ns;	/* effective tree Q2/Q3 band edge */
	u64 guard_eff_ns;	/* effective same-queue residency guard */
};

extern volatile struct mlfq_sys_gauge mlfq_sys_gauge;
extern volatile struct mlfq_adapt_state mlfq_adapt_state;
extern const volatile bool mlfq_adapt_enabled;

/*
 * GPU submit tracepoint state. mlfq_gpu_submit_total counts every
 * deduped quantised gpu_submit bump (the per-task 0..4 counter's
 * increments, one per MLFQ_TREE_PER_TASK_LIMIT_NS window, so a burst
 * of amdgpu_cs/amdgpu_cs_ioctl/gpu_sched for one job is a single
 * bump) and mlfq_gpu_trace_mask records which tracepoints attached
 * at load: bit0 amdgpu_cs, bit1 amdgpu_cs_ioctl, bit2 gpu_sched. Both
 * are gauges, not interval deltas, and are read by the web metrics.
 * The dedup window mirrors the sample per-task limiter, so the total
 * is not raw trace hits.
 */
#define MLFQ_GPU_TRACE_AMDGPU_CS	(1U << 0)
#define MLFQ_GPU_TRACE_AMDGPU_CS_IOCTL	(1U << 1)
#define MLFQ_GPU_TRACE_GPU_SCHED	(1U << 2)

extern volatile u64 mlfq_gpu_submit_total;
extern volatile u32 mlfq_gpu_trace_mask;

/*
 * Plain u64 bitmap of CPU membership (bit N set = CPU N present). The
 * primary-core set and each LLC domain use one of these, stored in
 * BPF_MAP_TYPE_ARRAY values so the maps are writable from userspace
 * without any kernel cpumask machinery.
 */
struct mlfq_bitmap {
	u64 words[MLFQ_BITMAP_WORDS];
};

/*
 * One LLC domain's CPU list, the value type of the mlfq_llc_cpus array
 * map. Written by the Rust front-end after load; the dispatch Tier-A
 * scan walks the consuming CPU's own-LLC entry as its same-LLC steal
 * window. 132 bytes per value (4 + 32 * 4), far under the ARRAY-map
 * value-size limit; the unpopulated map state means "feature off", and
 * an empty per-domain list (nr == 0, an oversized domain) means "Tier A
 * skips this domain, Tier B's full window covers it".
 */
struct mlfq_llc_cpu_list {
	u32 nr;				/* valid CPUs in cpus[] */
	u32 cpus[MLFQ_MAX_LLC_CPUS];	/* the domain's CPU ids */
};

/*
 * One virtual-time DSQ per queue per CPU. The id is
 * MLFQ_DSQ_BASE + cpu * MLFQ_DSQ_STRIDE + (qid - 1), so the owning
 * CPU and queue decode arithmetically: (id - base) / stride and
 * (id - base) % stride. The range ends far below SCX_DSQ_LOCAL_ON,
 * which reserves the top bits for the kernel DSQ flags.
 */
static __always_inline u64 mlfq_dsq_id(u8 qid, s32 cpu)
{
	return MLFQ_DSQ_BASE + (u64)cpu * MLFQ_DSQ_STRIDE + (u64)(qid - 1);
}

/**
 * mlfq_bitmap_test_cpu - Test a CPU's bit in a bitmap.
 * @bm: The bitmap.
 * @cpu: The CPU id.
 *
 * Out-of-range CPUs never have their bit set.
 *
 * Return: True if @cpu's bit is set.
 */
static __always_inline bool mlfq_bitmap_test_cpu(const struct mlfq_bitmap *bm,
						 u32 cpu)
{
	if (cpu >= MLFQ_MAX_CPUS)
		return false;
	return bm->words[cpu >> 6] & (1ULL << (cpu & 63));
}

/**
 * mlfq_bitmap_set_cpu - Set a CPU's bit in a bitmap.
 * @bm: The bitmap.
 * @cpu: The CPU id.
 *
 * Out-of-range CPUs are ignored.
 */
static __always_inline void mlfq_bitmap_set_cpu(struct mlfq_bitmap *bm, u32 cpu)
{
	if (cpu >= MLFQ_MAX_CPUS)
		return;
	bm->words[cpu >> 6] |= (1ULL << (cpu & 63));
}

/**
 * mlfq_time_before - Wrapping-safe u64 "before" comparison.
 * @a: First comparable as u64.
 * @b: Second comparable as u64.
 *
 * Same convention as fair.c vruntime_cmp()/time_before64(): the kernel
 * DSQ orders by min deadline with the same wrapping semantics.
 *
 * Return: true if @a is before @b.
 */
static __always_inline bool mlfq_time_before(u64 a, u64 b)
{
	return (s64)(b - a) > 0;
}

/**
 * mlfq_ss_boost_allowed - Short-sleep boost rate-limit check.
 * @last_boost_at: scx_bpf_now() of the last short-sleep boost (0 = never).
 * @now: Current time.
 * @rate_limit: Minimum spacing between boosts (MLFQ_SHORT_SLEEP_RATE_LIMIT_NS).
 *
 * At most one short-sleep boost per task per @rate_limit window: the boost
 * fires only once the previous window has fully elapsed, so a wakeup burst
 * cannot chain boosts. The first boost (never boosted before) is always
 * allowed.
 *
 * Return: true if a new boost may be granted at @now.
 */
static __always_inline bool mlfq_ss_boost_allowed(u64 last_boost_at, u64 now,
						  u64 rate_limit)
{
	if (!last_boost_at)
		return true;
	return mlfq_time_before(last_boost_at + rate_limit, now);
}

/**
 * mlfq_boost_eligible - IPC boost eligibility at wakeup.
 * @sleep_ns: Sleep duration at wakeup (scx_bpf_now() delta, 0 = none).
 * @window_ns: Short-sleep window (MLFQ_SHORT_SLEEP_NS).
 * @io_wait: True when the wakeup is an I/O completion
 *	(task_struct::in_iowait).
 *
 * A wakeup is boost-eligible when it is an I/O wakeup regardless of the
 * sleep length, or when the sleep fell within the short-sleep window. The
 * I/O-wait case covers the other classic interactive wakeup source beside
 * the short-sleep window. The rate limit is applied separately by the
 * caller (mlfq_ss_boost_allowed()), so an I/O wakeup burst cannot chain
 * boosts.
 *
 * Return: true if the wakeup is boost-eligible.
 */
static __always_inline bool mlfq_boost_eligible(u64 sleep_ns, u64 window_ns,
						bool io_wait)
{
	if (io_wait)
		return true;
	return sleep_ns && sleep_ns <= window_ns;
}

/**
 * mlfq_ss_boost_pending - Short-sleep boost decision for a wakeup.
 * @tctx: The task context.
 * @sleep_ns: Sleep duration at wakeup.
 * @io_wait: True when the wakeup is an I/O completion.
 * @now: Current time (scx_bpf_now()).
 * @short_sleep: Short-sleep window (MLFQ_SHORT_SLEEP_NS).
 * @rate_limit: Minimum spacing between boosts (MLFQ_SHORT_SLEEP_RATE_LIMIT_NS).
 *
 * Combines the wakeup test (mlfq_boost_eligible()) with the per-task
 * boost rate limit (mlfq_ss_boost_allowed()). The wakeup classification
 * uses it to apply the boost, and the CPU selection uses it to know
 * whether a wakeup will be treated as interactive before the
 * classification runs, so both paths agree on the same condition.
 *
 * Return: true if the wakeup qualifies for the Q1 boost.
 */
static __always_inline bool mlfq_ss_boost_pending(const struct task_ctx *tctx,
						  u64 sleep_ns, bool io_wait,
						  u64 now, u64 short_sleep,
						  u64 rate_limit)
{
	return mlfq_boost_eligible(sleep_ns, short_sleep, io_wait) &&
	       mlfq_ss_boost_allowed(tctx->last_ss_boost_at, now, rate_limit);
}

/**
 * mlfq_cpuperf_from_ema - CPU performance level for a busy-ns gauge.
 * @ema: The per-CPU EMA of the recent run time.
 *
 * Maps the busy-ns gauge to the sched_ext cpuperf scale. A CPU that ran
 * tasks for the whole gauge window requests the maximum level and a
 * lightly loaded CPU requests a proportionally lower one. The gauge
 * ceiling is the per-task budget, so a CPU saturated over the gauge
 * window maps to the maximum.
 *
 * Return: The cpuperf level in [0, SCX_CPUPERF_ONE].
 */
static __always_inline u32 mlfq_cpuperf_from_ema(u64 ema)
{
	u64 perf = ema * MLFQ_CPUPERF_Q1 / MLFQ_BUDGET_MAX_NS;

	return perf > MLFQ_CPUPERF_Q1 ? MLFQ_CPUPERF_Q1 : (u32)perf;
}

/**
 * calc_delta_fair_bpf - Scale a runtime delta to virtual time.
 * @delta: Physical time in nsecs.
 * @weight: Task weight in scx scale (nice-0 = 100, min 1).
 *
 * EEVDF virtual time grows at rate w_i/NICE_0_LOAD while running. With
 * the scx weight scale this is delta * 100 / weight.
 *
 * Return: The virtual time delta.
 */
static __always_inline u64 calc_delta_fair_bpf(u64 delta, u32 weight)
{
	return delta * 100 / weight;
}

/**
 * mlfq_lag_limit - Placement lag bound (fair.c entity_lag()).
 * @q: The queue.
 * @weight: Task weight.
 *
 * limit = calc_delta_fair(max_slice + TICK, weight). A task is placed at
 * most one request plus one tick behind the queue's virtual clock, the
 * bounded-lag horizon of entity_lag() in kernel/sched/fair.c.
 *
 * Return: The lag bound in virtual-time nsecs.
 */
static __always_inline u64 mlfq_lag_limit(const struct queue_ctx *q, u32 weight)
{
	return calc_delta_fair_bpf(q->max_slice_ns + MLFQ_TICK_NS, weight);
}

/**
 * mlfq_queue_advance_clock - Advance a queue's virtual clock.
 * @q: The queue.
 * @vruntime: The virtual runtime just charged for the queue.
 *
 * The clock follows the service given to the queue. It is advanced to
 * @vruntime whenever @vruntime is ahead of it, as a monotone max update.
 * The clock never moves backward. The compare-and-swap stores only when
 * the clock still holds the value the advance read, and the winner of a
 * contended update is the store that lands first, not necessarily the
 * largest one. A losing update can therefore leave the clock behind the
 * true service point by at most the virtual-time spread of the
 * concurrent updates; the placement clamp bounds the error this creates
 * and the next advance heals it. The single-shot compare-and-swap never
 * retries, so the update cost is constant and contention degrades to a
 * stale clock, never to a convoy.
 */
static __always_inline void mlfq_queue_advance_clock(struct queue_ctx *q,
						     u64 vruntime)
{
	u64 cur = q->clock;

	if (mlfq_time_before(cur, vruntime))
		__sync_val_compare_and_swap(&q->clock, cur, vruntime);
}

/**
 * mlfq_place_entity_deadline - Compute a placement deadline, read-only.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 *
 * The placement formula of mlfq_place_entity() without the commit. The
 * deadline a placement against @q's virtual clock would produce, computed
 * from the pre-placement task state. The wakeup-preemption decision uses
 * it to compare a wakeup's fresh deadline against the resident's before
 * deciding to preempt; the preempt path inserts into the local DSQ
 * without placement (the deadline is re-anchored on the next real
 * placement), so the comparison must not consume the placement.
 *
 * Return: The deadline the placement would commit.
 */
static __always_inline u64
mlfq_place_entity_deadline(const struct queue_ctx *q,
			   const struct task_ctx *tctx)
{
	u64 w = tctx->weight;
	u64 limit = mlfq_lag_limit(q, (u32)w);
	u64 clock = q->clock;
	u64 lag, vslice, vruntime_new, deadline;

	/*
	 * The lag is measured in the wrapping order of the virtual-time
	 * clock: a task ahead of the clock sits at it (fair.c
	 * DELAY_ZERO), a task behind is clamped to the clock minus
	 * the bound. The wrapping-aware comparison keeps the u64 epoch
	 * boundary indistinguishable from any other point.
	 */
	lag = mlfq_time_before(clock, tctx->vruntime) ? 0 : clock - tctx->vruntime;
	if (lag > limit)
		lag = limit;

	vruntime_new = clock - lag;

	vslice = calc_delta_fair_bpf(q->max_slice_ns, (u32)w);
	/* fair.c PLACE_DEADLINE_INITIAL: new tasks start with half a slice. */
	if (tctx->flags & MLFQ_TF_FIRST_RUN)
		vslice /= 2;

	deadline = vruntime_new + vslice;
	/*
	 * A deadline that lands exactly on the wrap point computes to zero;
	 * zero is the sentinel for a failed placement, so move the wrapped
	 * deadline to one, which is positionally identical in the wrapping
	 * order the DSQ rbtree uses.
	 */
	if (!deadline)
		deadline = 1;
	return deadline;
}

/**
 * mlfq_place_entity - Place a task on the virtual-time timeline.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 *
 * EEVDF placement against the queue's virtual clock is this.
 *
 *   limit        = calc_delta_fair(max_slice + TICK, weight)
 *   lag          = clamp(clock - vruntime, 0, limit)
 *   vruntime_new = clock - lag       (== clamp(vruntime, clock - limit, clock))
 *   vslice       = calc_delta_fair(slice_q, weight)
 *   if (FIRST_RUN) vslice /= 2
 *   deadline     = vruntime_new + vslice
 *
 * A task that has fallen behind the service point is re-anchored within
 * one lag limit of the clock, the bounded-lag property of fair.c
 * entity_lag(); a task that is ahead of the clock is placed at the
 * clock itself, the fair.c DELAY_ZERO semantics that do not carry
 * leading credit. The stored lag is therefore bounded in [0, limit],
 * and every queued task is eligible, so min-deadline
 * selection over the queue DSQs is EEVDF selection over the queued set.
 *
 * Updates tctx->vruntime, tctx->vlag (>= 0) and tctx->deadline.
 *
 * Return: The placement deadline, also stored in tctx->deadline.
 */
static __always_inline u64 mlfq_place_entity(const struct queue_ctx *q,
					     struct task_ctx *tctx)
{
	u64 w = tctx->weight;
	u64 limit = mlfq_lag_limit(q, (u32)w);
	u64 clock = q->clock;
	u64 lag, vruntime_new, deadline;

	/*
	 * The commit of the mlfq_place_entity_deadline() formula: the
	 * deadline is computed first from the pre-placement state, then
	 * the clamped lag and its vruntime are committed.
	 */
	deadline = mlfq_place_entity_deadline(q, tctx);

	lag = mlfq_time_before(clock, tctx->vruntime) ? 0 : clock - tctx->vruntime;
	if (lag > limit)
		lag = limit;
	vruntime_new = clock - lag;

	tctx->vruntime = vruntime_new;
	tctx->vlag = (s64)lag;
	tctx->deadline = deadline;

	return deadline;
}

/**
 * mlfq_sameq_preempt_owed - Same-queue wakeup preemption test.
 * @qid: Queue of the wakeup (equal to @running_queue at the call site).
 * @running_queue: Queue of the task running on the wakeup's previous CPU.
 * @wakee_deadline: Fresh placement deadline of the wakeup, 0 when no
 *	placement was computed.
 * @running_deadline: Deadline of the resident, or 0 when the resident has
 *	no known deadline (started running without a placement).
 * @run_start_at: scx_bpf_now() at the resident's ops.running(), 0 when
 *	never recorded.
 * @now: Current time.
 * @min_run_ns: Minimum residency before the resident may be displaced.
 *
 * There are two same-queue rules.
 *
 * - Interactive (Q1 onto Q1): the residency guard alone decides.
 *   Interactive wakeups need immediate service. The virtual-time order
 *   still governs the queue DSQ ordering, while the preemption is the
 *   wakeup-latency mechanism. The guard protects the waker's own run
 *   (the wake-all walk executes in the first tens of microseconds of the
 *   waker's run) and prevents preemption thrash.
 * - Non-interactive (Q2/Q3): the guard gates the deadline rule, where a
 *   dispatch pass over the queue would already have picked the wakeup
 *   first (an earlier fresh deadline than the resident's). The resident
 *   must have a known deadline; an unknown wakeup deadline (failed
 *   placement) never preempts.
 *
 * The residency is measured from the resident's ops.running(); an
 * unknown or future run start cannot prove the guard window, so the
 * elapsed time falls back to zero (which is conservative only when the
 * guard is non-zero).
 *
 * Return: true when the resident owes the wakeup its CPU.
 */
static __always_inline bool mlfq_sameq_preempt_owed(u8 qid, u8 running_queue,
						    u64 wakee_deadline,
						    u64 running_deadline,
						    u64 run_start_at, u64 now,
						    u64 min_run_ns)
{
	u64 run_elapsed = 0;

	if (run_start_at && !mlfq_time_before(now, run_start_at))
		run_elapsed = now - run_start_at;

	if (mlfq_time_before(run_elapsed, min_run_ns))
		return false;

	if (qid == 1 && running_queue == 1)
		return true;

	if (!running_deadline || !wakee_deadline)
		return false;

	return mlfq_time_before(wakee_deadline, running_deadline);
}

/**
 * mlfq_ema_climb - Advance the EMA gauge for a run segment.
 * @ema: Current gauge value.
 * @delta: Physical run time in nsecs.
 * @budget_max: Gauge ceiling (MLFQ_BUDGET_MAX_NS).
 * @alpha: Climb aggressiveness (MLFQ_ALPHA).
 *
 * Saturating exponential climb:
 *
 *   step = (budget_max - ema) * delta * alpha / (budget_max * FP_ONE)
 *   ema += min(step, budget_max - ema)
 *
 * with delta clamped to budget_max. The step factorizes the remaining gap,
 * so a CPU-bound task converges to budget_max. The rate is 1/tau_climb
 * with tau_climb = budget_max * FP_ONE / alpha. alpha is fixed.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_ema_climb(u64 ema, u64 delta, u64 budget_max,
					  u64 alpha)
{
	u64 gap, step;

	if (delta > budget_max)
		delta = budget_max;
	gap = budget_max - ema;
	if (gap == 0)
		return ema;

	step = gap * delta * alpha / (budget_max * FP_ONE);
	if (step > gap)
		step = gap;
	return ema + step;
}

/**
 * mlfq_ema_decay - Decay the EMA gauge for a sleep.
 * @ema: Current gauge value.
 * @sleep_ns: Physical sleep time in nsecs.
 * @half_life: Gauge half-life (MLFQ_EMA_HALF_LIFE_NS).
 *
 * Shift decay with a 2nd-order Taylor residual for the sub-period. Whole
 * half-lives shift the gauge right. The fractional period is
 * approximated by 2^-x ~= 1 - x*ln2 + (x*ln2)^2/2 in FP_ONE fixed point
 * (relative error < 10% for x in [0,1)). The gauge is zeroed at or beyond
 * 64 half-lives.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_ema_decay(u64 ema, u64 sleep_ns, u64 half_life)
{
	u64 periods, sub, x_fp, a_fp, factor_fp, decayed;

	if (sleep_ns >= (half_life << 6))	/* >= 64 periods -> zero */
		return 0;

	periods = sleep_ns / half_life;
	sub = sleep_ns % half_life;
	decayed = ema >> periods;

	if (sub == 0 || decayed == 0)
		return decayed;

	x_fp = sub * FP_ONE / half_life;
	a_fp = x_fp * 177 / FP_ONE;		/* 177 ~= FP_ONE * ln(2) */
	factor_fp = FP_ONE - a_fp + (a_fp * a_fp) / (FP_ONE << 1);
	return decayed * factor_fp / FP_ONE;
}

/**
 * mlfq_sys_lat_fold - Fold the accumulated wakeup waits into the gauge.
 * @lat_ema: The gauge, average wakeup latency in nsecs.
 * @wait_total: Sum of the episode waits since the last fold.
 * @wait_count: Number of episodes since the last fold.
 * @elapsed: Wall time since the last fold, in nsecs.
 * @half_life: Gauge half-life (MLFQ_SYS_GAUGE_HALF_LIFE_NS).
 * @max_ns: Gauge ceiling (MLFQ_SYS_LAT_MAX_NS).
 *
 * The gauge is a first-order low-pass filter over the per-window
 * average wakeup wait, the wait_sum and nr_wakeups pattern of fair.c.
 * Episodes accumulate their wait, the fold derives the average, and
 * the gauge moves toward the average by the decayed fraction of the
 * gap. The time constant is the wall-clock half-life, so the
 * equilibrium is the average wait regardless of the episode rate, and
 * a busy desktop and a quiet server with the same per-episode wait
 * settle on the same gauge value. A fold with no episodes leaves the
 * gauge untouched, and the result is capped at the ceiling. A clock
 * wrap that makes the elapsed compute to zero also leaves the gauge
 * untouched, and the caller still resets the totals, the same
 * convention as the rate fold.
 *
 * Overflow: wait_count is bounded by the episodes of one window (the
 * caller resets the totals at every fold) and wait_total by the
 * count times max_ns, both far inside u64.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_sys_lat_fold(u64 lat_ema, u64 wait_total,
					     u64 wait_count, u64 elapsed,
					     u64 half_life, u64 max_ns)
{
	u64 avg, factor, decayed, rise, v;

	if (wait_count == 0)
		return lat_ema;

	avg = wait_total / wait_count;
	if (avg > max_ns)
		avg = max_ns;
	factor = mlfq_ema_decay(FP_ONE, elapsed, half_life);
	decayed = mlfq_ema_decay(lat_ema, elapsed, half_life);
	rise = avg * (FP_ONE - factor) / FP_ONE;
	v = decayed + rise;
	return v > max_ns ? max_ns : v;
}

/**
 * mlfq_sys_rate_step - Fold the wakeup-rate EMA at an adaptation step.
 * @rate_ema: The rate gauge, FP_SHIFT fixed point.
 * @wakeup_cnt: Wakeup arrivals since the last fold.
 * @elapsed: Wall time since the last fold, in nsecs.
 *
 * The instantaneous rate is the arrival count over the elapsed window,
 * clamped to MLFQ_SYS_RATE_MAX, and the EMA folds it at the same 1 s
 * half-life as the latency gauge. The elapsed window is clamped to
 * [MLFQ_ADAPT_MIN_INTERVAL_NS, MLFQ_SYS_RATE_WINDOW_MAX_NS]. The compare-and-swap gate lets
 * the winner through only when at least a full interval has passed
 * since the last step, so a sub-second window is reachable only on the
 * u64 clock wrap path, where the elapsed computes to about zero. The
 * upper clamp covers a multi-minute idle gap (the boot or a long idle
 * stretch before the first step).
 *
 * Overflow: the count argument is a u32, so the rate product is at
 * most 2^32 * 1e9 ~= 4.3e18, inside u64. The fold sums the per-CPU
 * window slots in u64 and truncates to the u32 count, and a one-second
 * arrival total cannot reach 2^32 on any machine, so the truncation
 * cannot clip a measured rate. rate_i is clamped below 1e6, so the
 * fixed-point EMA operands are at most 1e6 << 8 ~= 2.6e8 and the
 * products at most ~6.6e10, far inside u64.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_sys_rate_step(u64 rate_ema, u32 wakeup_cnt,
					      u64 elapsed)
{
	u64 rate_i, rate_i_fp, factor;

	if (elapsed < MLFQ_ADAPT_MIN_INTERVAL_NS)
		elapsed = MLFQ_ADAPT_MIN_INTERVAL_NS;
	if (elapsed > MLFQ_SYS_RATE_WINDOW_MAX_NS)
		elapsed = MLFQ_SYS_RATE_WINDOW_MAX_NS;

	rate_i = (u64)wakeup_cnt * NSEC_PER_SEC / elapsed;
	if (rate_i > MLFQ_SYS_RATE_MAX)
		rate_i = MLFQ_SYS_RATE_MAX;
	rate_i_fp = rate_i << FP_SHIFT;

	/* The EMA fold: rate_ema * factor + rate_i * (1 - factor). */
	factor = mlfq_ema_decay(FP_ONE, elapsed, MLFQ_SYS_GAUGE_HALF_LIFE_NS);
	rate_ema = rate_ema * factor / FP_ONE +
		   rate_i_fp * (FP_ONE - factor) / FP_ONE;
	return rate_ema;
}

/**
 * mlfq_adapt_shift_target - Shift target from the latency and rate gauges.
 * @lat_ema: The wakeup-latency gauge, nsecs.
 * @rate_ema: The wakeup-rate gauge, FP_SHIFT fixed point.
 *
 * The proportional control law of the adaptation is this.
 *
 *   shift = clamp((lat - target) * K / target, 0, +MAX_SHIFT)
 *
 * with K = FP_ONE/2, so a full-range gauge error moves the target by
 * half the shift range. The shift only widens the bands, for the
 * reason given at the control-law constants: a machine at or below
 * the target latency keeps the base bands. The wakeup-rate storm gate
 * caps the positive target at +FP_ONE/4 when the rate gauge exceeds
 * MLFQ_ADAPT_RATE_GATE_HIGH: under a wakeup storm the bands must not
 * chase the latency error as far as in the normal regime.
 *
 * Overflow: the error is at most 15 ms and K is 128, so the product
 * is at most ~1.9e9, inside u64; the division brings the target well
 * below the clamp range before the clamp applies.
 *
 * Return: The slew target, FP_SHIFT fixed point, in
 * [0, +MLFQ_ADAPT_MAX_SHIFT].
 */
static __always_inline s64 mlfq_adapt_shift_target(u64 lat_ema, u64 rate_ema)
{
	s64 err = (s64)lat_ema - (s64)MLFQ_ADAPT_TARGET_LAT_NS;
	u64 mag, scaled;
	s64 target;

	/*
	 * BPF has no signed division, so the magnitude is scaled in u64.
	 * A gauge at or below the target widens nothing; the error is at
	 * most 15 ms and K is 128, so the product is ~1.9e9, inside u64.
	 */
	mag = err < 0 ? 0 : (u64)err;
	scaled = mag * MLFQ_ADAPT_K / MLFQ_ADAPT_TARGET_LAT_NS;
	target = (s64)scaled;

	if (target > (s64)MLFQ_ADAPT_MAX_SHIFT)
		target = (s64)MLFQ_ADAPT_MAX_SHIFT;
	if (rate_ema > MLFQ_ADAPT_RATE_GATE_HIGH &&
	    target > (s64)MLFQ_ADAPT_RATE_GATE_SHIFT)
		target = (s64)MLFQ_ADAPT_RATE_GATE_SHIFT;
	return target;
}

/**
 * mlfq_adapt_slew - Slew-limited shift update.
 * @prev: The current shift, FP_SHIFT fixed point.
 * @target: The gauge-derived shift target.
 *
 * The shift moves by at most MLFQ_ADAPT_MAX_STEP (10% of the base)
 * per step. Together with the gauge's 1 s half-life this is a cascaded
 * first-order limit. A single bad latency sample moves the bands at
 * most one step, and a full regime flip converges over at least five
 * steps. The difference is bounded by twice the shift range, so the
 * arithmetic cannot overflow.
 *
 * Return: The updated shift.
 */
static __always_inline s64 mlfq_adapt_slew(s64 prev, s64 target)
{
	s64 step = target - prev;

	if (step > (s64)MLFQ_ADAPT_MAX_STEP)
		step = (s64)MLFQ_ADAPT_MAX_STEP;
	if (step < -(s64)MLFQ_ADAPT_MAX_STEP)
		step = -(s64)MLFQ_ADAPT_MAX_STEP;
	return prev + step;
}

/**
 * mlfq_adapt_band - Effective band edge from the base and the shift.
 * @base: The base (rodata) band edge, nsecs.
 * @shift_fp: The current shift, FP_SHIFT fixed point.
 * @floor: The band's hard floor, nsecs.
 * @ceil: The band's hard ceiling, nsecs.
 *
 * effective = clamp(base + base * shift / FP_ONE, floor, ceil). The
 * clamps apply to the result, not the input, so a shift at either
 * extreme can never push a band past its hard bound. With shift 0 the
 * effective value is exactly the base, which is what keeps the
 * disabled state (init copies the bases) identical to the fixed
 * thresholds.
 *
 * Overflow: the largest base is below 6 ms and the shift range is
 * +-128, so the product is at most ~7.7e8, inside s64.
 *
 * Return: The effective band edge, clamped to [@floor, @ceil].
 */
static __always_inline u64 mlfq_adapt_band(u64 base, s64 shift_fp,
					   u64 floor, u64 ceil)
{
	s64 v = (s64)base;
	u64 mag, scaled;

	/*
	 * BPF has no signed division, so the delta is scaled in u64
	 * (the shift magnitude) and subtracted or added by sign. The
	 * largest base is below 6 ms and the shift range is +-128, so
	 * the product is at most ~7.7e8, inside s64.
	 */
	mag = shift_fp < 0 ? (u64)(-shift_fp) : (u64)shift_fp;
	scaled = base * mag / FP_ONE;
	if (shift_fp < 0)
		v -= (s64)scaled;
	else
		v += (s64)scaled;

	if (v < (s64)floor)
		v = (s64)floor;
	if (v > (s64)ceil)
		v = (s64)ceil;
	return (u64)v;
}

/**
 * mlfq_queue_from_ema - Base queue mapping from the EMA gauge.
 * @ema: The gauge value.
 * @t_l: Interactive threshold (MLFQ_T_L_NS).
 * @t_h: CPU-bound threshold (MLFQ_T_H_NS).
 *
 * The base mapping is ema <= T_L -> Q1, ema >= T_H -> Q3, else Q2.
 *
 * Return: 1, 2 or 3.
 */
static __always_inline u8 mlfq_queue_from_ema(u64 ema, u64 t_l, u64 t_h)
{
	if (ema <= t_l)
		return 1;
	if (ema >= t_h)
		return 3;
	return 2;
}

/**
 * mlfq_promote_on_wakeup - Wakeup promotion state machine.
 * @tctx: The task.
 * @sleep_ns: Sleep duration at wakeup.
 * @t_l: Interactive threshold.
 * @t_h: CPU-bound threshold.
 * @short_sleep: A sleep at most this long counts toward wake_cnt.
 *
 * The hysteresis promotes Q2->Q1 when ema < T_L/2 and wake_cnt >= 2
 * consecutive short sleeps, and Q3->Q2 when ema < T_H/2 and wake_cnt >= 2.
 * wake_cnt is reset on a long sleep. reenq_cnt is left for the caller to
 * clear on the wakeup path.
 *
 * Return: true if the task was promoted.
 */
static __always_inline bool mlfq_promote_on_wakeup(struct task_ctx *tctx,
						   u64 sleep_ns,
						   u64 t_l, u64 t_h,
						   u64 short_sleep)
{
	bool promoted = false;

	if (sleep_ns <= short_sleep)
		tctx->wake_cnt++;
	else
		tctx->wake_cnt = 0;

	if (tctx->queue == 2 && tctx->ema < t_l / 2 && tctx->wake_cnt >= 2) {
		tctx->queue = 1;
		promoted = true;
	} else if (tctx->queue == 3 && tctx->ema < t_h / 2 &&
		   tctx->wake_cnt >= 2) {
		tctx->queue = 2;
		promoted = true;
	}

	if (promoted)
		tctx->wake_cnt = 0;
	return promoted;
}

/**
 * mlfq_demote_on_reenq - Slice-exhaustion demotion state machine.
 * @tctx: The task.
 * @t_h: CPU-bound threshold (the effective EMA Q2/Q3 edge).
 * @t_bound: Q2/Q3 tree band bound (the effective tree edge).
 * @pred: The tree's predicted next burst (0 while untrained).
 *
 * Called on run-out re-enqueues (ops.enqueue() with flags == 0, the
 * do_enqueue_task(rq, p, 0, -1) slice-exhaustion path). Consecutive
 * slice exhaustions accumulate in reenq_cnt, which gates the band
 * crossings.
 *
 * The CPU-bound test switches on the predictor: with a trained tree the
 * predicted burst itself gates the demotion (a prediction at or above
 * the Q2/Q3 band bound is CPU-bound), and the EMA gauge test is the
 * untrained fallback. The gate is the plain EMA-gauge test while
 * untrained.
 *
 * Demotion requires a sustained run without sleeping. Eight consecutive
 * exhaustions (about 8 ms at the interactive slice) must accumulate
 * while the task is CPU-bound. A task that sleeps between bursts is
 * re-boosted at its wakeup, which resets reenq_cnt, so a bursty
 * consumer of CPU such as a video decoder keeps its queue for the whole
 * burst. An impostor that never sleeps accumulates the counter and is
 * demoted after the same sustained window.
 *
 * Return: true if the task was demoted.
 */
static __always_inline bool mlfq_demote_on_reenq(struct task_ctx *tctx,
						 u64 t_h, u64 t_bound,
						 u64 pred)
{
	bool demoted = false;
	bool cpu_bound;

	tctx->reenq_cnt++;

	cpu_bound = pred ? pred >= t_bound : tctx->ema > t_h;

	if ((tctx->queue == 1 || tctx->queue == 2) &&
	    cpu_bound && tctx->reenq_cnt >= 8) {
		tctx->queue++;
		demoted = true;
	}

	if (demoted)
		tctx->reenq_cnt = 0;
	return demoted;
}

/**
 * mlfq_reset_classification - Fork/exec classification reset.
 * @tctx: The task.
 *
 * New tasks start in Q2 with a zeroed gauge and counters.
 */
static __always_inline void mlfq_reset_classification(struct task_ctx *tctx)
{
	tctx->ema = 0;
	tctx->queue = 2;
	tctx->reenq_cnt = 0;
	tctx->wake_cnt = 0;
	tctx->last_ss_boost_at = 0;
}

#if MLFQ_CHECK
/*
 * Invariant predicates. Compiled only under MLFQ_CHECK; the
 * BPF side reports violations via scx_bpf_error() at the natural points.
 */

static __always_inline bool mlfq_check_ema_bounds(u64 ema, u64 budget_max)
{
	return ema <= budget_max;
}

static __always_inline bool mlfq_check_queue(u8 queue)
{
	return queue >= 1 && queue <= MLFQ_NR_QUEUES;
}

static __always_inline bool mlfq_check_weight(u32 weight)
{
	return weight >= 1;
}

static __always_inline bool mlfq_check_queued_vlag(s64 vlag)
{
	return vlag >= 0;
}

static __always_inline bool mlfq_check_tree_node_index(u32 idx)
{
	return idx < MLFQ_TREE_MAX_NODES;
}

static __always_inline bool mlfq_check_tree_feature(u8 feature)
{
	/*
	 * Theorem: the split feature must be within the populated ABI.
	 * Derivation: 1.3.11 ABI populates nine split features (0..8:
	 * prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
	 * queue_wait, sq_ema, gpu_submit). The fitter caps splits to
	 * [0, MLFQ_TREE_NR_FEATURES), and sleep_var_ratio at id 9 is
	 * carry-along for the next ABI (zeroed until promoted; BPF walk
	 * feat[16] holds it at 9 with 10..15 zeroed, &0xF keeps 0..15
	 * in bounds). The bound check is unconditional, so feature 9..15
	 * never indexes OOB even with MLFQ_CHECK=0, and serialize_validate
	 * is defense in depth.
	 * Why clamp: plain < bound is authoritative, not masked tautology.
	 *
	 * Strategy helper: the walk observes the feature vector
	 * (Strategy pattern without vtable) via this predicate.
	 */
	return feature < MLFQ_TREE_NR_FEATURES;
}

static __always_inline bool mlfq_check_bands(u64 t_l, u64 t_h,
					     u64 t_int, u64 t_bnd)
{
	/*
	 * The effective band edges must keep the queue semantics of the
	 * fixed thresholds: each band sits within its hard floor/ceiling
	 * and the two edges of each pair stay strictly ordered (T_L <
	 * T_H, T_INT < T_BOUND), so no band can collapse to zero width.
	 */
	return t_l < t_h && t_int < t_bnd &&
	       t_l >= MLFQ_ADAPT_T_L_FLOOR_NS && t_l <= MLFQ_ADAPT_T_L_CEIL_NS &&
	       t_h >= MLFQ_ADAPT_T_H_FLOOR_NS && t_h <= MLFQ_ADAPT_T_H_CEIL_NS &&
	       t_int >= MLFQ_ADAPT_T_INT_FLOOR_NS && t_int <= MLFQ_ADAPT_T_INT_CEIL_NS &&
	       t_bnd >= MLFQ_ADAPT_T_BND_FLOOR_NS && t_bnd <= MLFQ_ADAPT_T_BND_CEIL_NS;
}
#endif /* MLFQ_CHECK */

/**
 * mlfq_tree_walk - Walk a tree buffer and predict the next CPU burst.
 * @store: The tree buffer (one entry of mlfq_tree_map).
 * @f: The feature vector.
 *
 * Theorem: the walk is a bounded, masked descent over the 9-feature
 * tree (prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
 * queue_wait, sq_ema, gpu_submit). Invariant: depth <= MLFQ_TREE_MAX_DEPTH.
 *
 * Derivation: every index is masked to the node budget
 * (MLFQ_TREE_MAX_NODES - 1), so a corrupted tree can never address
 * outside the buffer. feat[16] holds nine split features 0..8 plus
 * sleep_var_ratio carry-along at 9 and 10..15 zeroed; Rust mirrors
 * feat[16]. An out-of-range feature (>=9) is rejected unconditionally
 * before dereference, so serialize_validate is defense in depth and
 * MLFQ_CHECK=0 cannot compile out the bound. Walk past tail lands on
 * zeroed node predicting 0. The walk is the Strategy observed via the
 * feature vector (Observer) without a vtable.
 *
 * Why clamp: the 30 s watchdog bounds the dispatch stall, and the
 * 16 ms label clamp bounds the f64 sums; the unconditional feat bound
 * prevents OOB reads even when MLFQ_CHECK=0.
 *
 * Return: The predicted burst in nsecs.
 */
static __always_inline u64
mlfq_tree_walk(const struct mlfq_tree_store *store,
	       const struct mlfq_tree_feats *f)
{
	u64 feat[16] = { f->prev_burst_ns, f->sleep_ns, f->ema,
			f->io_wait, f->wake_cnt, f->wake_lat_us,
			f->queue_wait_us, f->sq_ema, f->gpu_submit,
			f->sleep_var_ratio, 0, 0, 0, 0, 0, 0 };
	u32 idx = 0, nidx;
	const struct mlfq_tree_node *n;
	u8 feature;
	int i;

	for (i = 0; i < MLFQ_TREE_MAX_DEPTH; i++) {
		nidx = idx & (MLFQ_TREE_MAX_NODES - 1);
		n = &store->nodes[nidx];
#if MLFQ_CHECK
		if (!mlfq_check_tree_node_index(nidx))
			return 0;
#endif
		if (n->right == 0)
			return n->left;

		/* BPF walk feat[16] with &0xF (0..15); 9 is sleep_var_ratio
		 * carry-along, 10..15 zeroed. Bound check is unconditional.
		 */
		feature = n->feature & 0xF;
		if (feature >= MLFQ_TREE_NR_FEATURES)
			return 0;
#if MLFQ_CHECK
		if (!mlfq_check_tree_feature(feature))
			return 0;
#endif
		idx = feat[feature] <= n->threshold ? n->left : n->right;
	}

	/*
	 * When the depth is exhausted, the last reachable node is returned as a leaf
	 * only when it really is one. An internal node here means the
	 * tree is deeper than the walk bound; returning its left would
	 * leak a child index as a prediction, so a non-leaf yields 0.
	 */
	nidx = idx & (MLFQ_TREE_MAX_NODES - 1);
	n = &store->nodes[nidx];
#if MLFQ_CHECK
	if (!mlfq_check_tree_node_index(nidx))
		return 0;
#endif
	return n->right == 0 ? n->left : 0;
}

/**
 * mlfq_tree_map_queue - Promotion-only queue mapping of a prediction.
 * @pred: The predicted next burst, 0 while untrained.
 * @cur: The task's current queue (1..3).
 * @t_int: The tree Q1/Q2 band edge (the effective value).
 * @t_bound: The tree Q2/Q3 band edge (the effective value).
 *
 * The wakeup path is promotion-only: a Q1-band prediction raises the
 * queue to 1, a Q2-band prediction raises a Q3 task to 2, and a
 * Q3-band or untrained prediction leaves the queue unchanged. Demotions
 * are the run-out gate's job (mlfq_demote_on_reenq), so a single wakeup
 * prediction can never demote a task and bypass the exhaustion
 * hysteresis, the classic MLFQ asymmetry where the wakeup only
 * promotes and the run-out only demotes.
 *
 * Return: The new queue.
 */
static __always_inline u8 mlfq_tree_map_queue(u64 pred, u8 cur,
					      u64 t_int, u64 t_bound)
{
	/* 0 is the untrained sentinel: it never moves the queue. */
	if (pred && pred < t_int)
		return 1;
	if (pred && pred < t_bound && cur > 2)
		return 2;
	return cur;
}

#ifdef __VMLINUX_H__
/*
 * The published tree as a two-entry array map, defined in main.bpf.c.
 * The type and the extern are declared here so the BPF wrapper can look
 * up the active entry. Both are skipped outside the BPF build, where
 * the native harness has no map machinery.
 */
struct mlfq_tree_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct mlfq_tree_store);
};

extern struct mlfq_tree_map mlfq_tree_map;

/*
 * The per-CPU realtime-occupancy state as a BPF array map, defined in
 * main.bpf.c. The type and the extern are declared here so the BPF
 * modules can look up the state. Both are skipped outside the BPF
 * build, where the native harness has no map machinery.
 */
struct mlfq_rtdl_state_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_rtdl_state);
};

extern struct mlfq_rtdl_state_map rtdl_state_stor;

/*
 * The op-latency histogram as a per-CPU array map, defined in
 * main.bpf.c. The type, the extern and the charge helper are declared
 * here so the modules can charge their callbacks. All of it is skipped
 * outside the BPF build, where the native harness has no map machinery.
 */
struct mlfq_op_lat_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MLFQ_OP_LAT_OPS);
	__type(key, u32);
	__type(value, struct mlfq_op_lat);
};

extern struct mlfq_op_lat_map mlfq_op_lat;

/*
 * The per-CPU wakeup-arrival counters as a one-entry per-CPU array map,
 * defined in main.bpf.c. The type and the extern are declared here so
 * the enqueue module can bump the counters. Each CPU owns its own
 * slot, so the wakeup path needs no locked operation on a shared line,
 * and the fold (mlfq_adapt_step) iterates the slots with
 * bpf_map_lookup_percpu_elem.
 */
struct mlfq_wakeup_stats_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_wakeup_counters);
};

extern struct mlfq_wakeup_stats_map mlfq_wakeup_stats;

/**
 * mlfq_op_lat_bucket - Histogram bucket covering an elapsed time.
 * @delta_us: Elapsed microseconds.
 *
 * The eight buckets delimit [0, 2) [2, 5) [5, 10) [10, 20) [20, 50)
 * [50, 100) [100, 250) [250, inf) microseconds.
 *
 * Return: The bucket index in [0, MLFQ_OP_LAT_BUCKETS).
 */
static __always_inline u32 mlfq_op_lat_bucket(u64 delta_us)
{
	if (delta_us < MLFQ_OP_LAT_EDGE_2)
		return 0;
	if (delta_us < MLFQ_OP_LAT_EDGE_5)
		return 1;
	if (delta_us < MLFQ_OP_LAT_EDGE_10)
		return 2;
	if (delta_us < MLFQ_OP_LAT_EDGE_20)
		return 3;
	if (delta_us < MLFQ_OP_LAT_EDGE_50)
		return 4;
	if (delta_us < MLFQ_OP_LAT_EDGE_100)
		return 5;
	if (delta_us < MLFQ_OP_LAT_EDGE_250)
		return 6;
	return 7;
}

/**
 * mlfq_op_lat_charge - Charge one op into its latency histogram.
 * @op: The MLFQ_OP_LAT_* slot.
 * @start_ns: scx_bpf_now() captured at the op entry.
 *
 * Computes the elapsed time and increments the covering bucket of the
 * per-CPU histogram. A failed map lookup is a no-op. The per-CPU
 * counters never contend, and the Rust front-end sums the CPUs for the
 * stats output.
 */
static __always_inline void mlfq_op_lat_charge(u32 op, u64 start_ns)
{
	struct mlfq_op_lat *lat;
	u64 now, delta_us;
	u32 key = op;

	now = scx_bpf_now();
	if (mlfq_time_before(now, start_ns))
		return;
	lat = bpf_map_lookup_elem(&mlfq_op_lat, &key);
	if (!lat)
		return;
	delta_us = (now - start_ns) / NSEC_PER_USEC;
	lat->buckets[mlfq_op_lat_bucket(delta_us)]++;
}

/**
 * mlfq_tree_predict - Predict the next CPU burst from a feature vector.
 * @f: The feature vector.
 *
 * The BPF entry point. Reads mlfq_tree_ctrl.meta exactly once: the
 * trained bit gates the inference and the active bit selects the buffer
 * entry of mlfq_tree_map, so a reader sees either the tree before a
 * publish or the fully committed tree after it, never a partially
 * written one (the daemon writes the inactive entry first and commits
 * the meta last).
 *
 * Return: The predicted burst in nsecs. 0 while untrained or on a
 * failed map lookup.
 */
static __always_inline u64 mlfq_tree_predict(const struct mlfq_tree_feats *f)
{
	u64 meta = mlfq_tree_ctrl.meta;
	struct mlfq_tree_store *store;
	u32 key;

	if (!(meta & MLFQ_TREE_META_TRAINED))
		return 0;

	key = (meta & MLFQ_TREE_META_ACTIVE) ? 1 : 0;
	store = bpf_map_lookup_elem(&mlfq_tree_map, &key);
	if (!store)
		return 0;

	return mlfq_tree_walk(store, f);
}

#endif /* __VMLINUX_H__ */

/*
 * The per-LLC and per-queue runnable gauges, defined in the main.bpf.c
 * bss block before mlfq_stats. The externs are declared here, outside
 * the BPF-only guard above, so the accounting helpers below can
 * reference them in every build. The BPF build links them against the
 * bss block, and the native harness supplies its own shadow storage.
 */
extern volatile u32 mlfq_llc_runnable[MLFQ_MAX_LLCS];
extern volatile u32 mlfq_queue_runnable[MLFQ_NR_QUEUES + 1];

/**
 * mlfq_llc_add - One atomic step on the per-LLC runnable gauge.
 * @llc: The LLC domain id.
 * @delta: +1 to count, -1 to un-count.
 *
 * The index is validated against the hard array bound; an out-of-range
 * id (the MLFQ_MAX_LLCS sentinel the call sites pass for an unpopulated
 * domain) is a no-op. The gauge is advisory, so a lost update under
 * contention is absorbed by the next RMW.
 */
static __always_inline void mlfq_llc_add(u32 llc, s64 delta)
{
	if (llc >= MLFQ_MAX_LLCS)
		return;
	if (delta > 0)
		__sync_fetch_and_add(&mlfq_llc_runnable[llc], (u32)delta);
	else
		__sync_fetch_and_sub(&mlfq_llc_runnable[llc], (u32)(-delta));
}

/**
 * mlfq_queue_add - One atomic step on the per-queue runnable gauge.
 * @qid: The queue id (1..3; index 0 is unused).
 * @delta: +1 to count, -1 to un-count.
 *
 * The index is validated against the queue range; an out-of-range id is
 * a no-op (defense in depth on top of the classification range checks).
 */
static __always_inline void mlfq_queue_add(u32 qid, s64 delta)
{
	if (qid < 1 || qid > MLFQ_NR_QUEUES)
		return;
	if (delta > 0)
		__sync_fetch_and_add(&mlfq_queue_runnable[qid], (u32)delta);
	else
		__sync_fetch_and_sub(&mlfq_queue_runnable[qid], (u32)(-delta));
}

/**
 * mlfq_runnable_enter - Count a task's LLC/queue ownership at an insert.
 * @tctx: The task being placed.
 * @qid: The queue it is placed into (1..3).
 * @llc: The LLC owning the target CPU (mlfq_llc_of_cpu(). The sentinel
 *	is a no-op).
 *
 * Called once per DSQ insert, after the queue and the owning CPU are
 * final. A task with no recorded ownership starts a runnable episode
 * (wakeup, fork, class-switch-in) and is counted once at the destination
 * LLC and queue. A task already counted is a continuation (run-out,
 * preemption, REENQ, a dispatch move) and the call only moves its LLC
 * and/or queue ownership when either changed, leaving the total count
 * unchanged. The mlfq_llc_of_cpu() sentinel makes the whole call a no-op
 * when LLC awareness is disabled (nr_llcs == 0), so an unpopulated
 * machine never moves any gauge.
 */
static __always_inline void mlfq_runnable_enter(struct task_ctx *tctx,
						u8 qid, u32 llc)
{
	/*
	 * The llc guard is the populated-state gate: the call sites pass
	 * mlfq_llc_of_cpu(), which yields the MLFQ_MAX_LLCS sentinel for
	 * an unknown domain or when nr_llcs == 0. The whole call is a
	 * no-op then, counters and ownership record alike.
	 */
	if (llc >= MLFQ_MAX_LLCS)
		return;

	if (tctx->last_llc == MLFQ_LLC_UNOWNED) {
		mlfq_llc_add(llc, 1);
		mlfq_queue_add(qid, 1);
		tctx->last_llc = (u8)llc;
		tctx->last_qid = qid;
		return;
	}

	/* Continuation: the task is counted, only its ownership moves. */
	if (tctx->last_llc != (u8)llc) {
		mlfq_llc_add(tctx->last_llc, -1);
		mlfq_llc_add(llc, 1);
		tctx->last_llc = (u8)llc;
	}
	if (tctx->last_qid != qid) {
		mlfq_queue_add(tctx->last_qid, -1);
		mlfq_queue_add(qid, 1);
		tctx->last_qid = qid;
	}
}

/**
 * mlfq_runnable_exit - Release a task's LLC/queue ownership.
 * @tctx: The task leaving the runnable set (or leaving LLC ownership).
 *
 * The single release primitive. A task that was counted is removed from
 * the per-LLC and per-queue gauges and its ownership record returns to
 * the unowned state. A task with no recorded ownership (never counted,
 * or already released) is a no-op, which makes the call idempotent
 * against a racing double-release.
 */
static __always_inline void mlfq_runnable_exit(struct task_ctx *tctx)
{
	if (tctx->last_llc == MLFQ_LLC_UNOWNED)
		return;
	mlfq_llc_add(tctx->last_llc, -1);
	mlfq_queue_add(tctx->last_qid, -1);
	tctx->last_llc = MLFQ_LLC_UNOWNED;
	tctx->last_qid = 0;
}

/**
 * mlfq_steer_pick_llc - Least-loaded eligible LLC selection.
 * @runnable: Per-LLC runnable gauge (advisory, stale-tolerant).
 * @idle: Per-LLC idle-CPU gate. A zero entry excludes the domain.
 * @nr_llcs: Number of populated LLC domains; domains at or above it are
 *	excluded (defense in depth on top of the idle gate, which already
 *	keeps the unpopulated-domain gauges at zero).
 * @waker_llc: The waker's own domain, always excluded.
 * @visited: Bitmask of domains already tried by earlier selection passes
 *	of this steering step (bit llc set = excluded).
 *
 * One min-selection pass over the eligible domains (idle-populated,
 * other than @waker_llc, not visited), returning the one with the lowest
 * runnable count; ties are broken by ascending domain id, so the
 * selection is deterministic. The caller repeats the pass up to
 * MLFQ_STEER_LLC_MAX times, marking each returned domain visited, so at
 * most MLFQ_STEER_LLC_MAX distinct domains are ever probed and the
 * bitmap walks (the expensive part) stay bounded.
 *
 * The step is advisory: a stale runnable count costs one suboptimal
 * (still idle) placement in a race window, never a correctness issue.
 * This is the same trust model as the idle-count saturation fast path. The
 * empty state (nr_llcs == 0, or every idle gauge zero) yields the
 * sentinel and the step dies; placement then proceeds unchanged.
 *
 * The scan is compile-time bounded (MLFQ_MAX_LLCS iterations) and uses
 * the iterator form (bpf_for) so the verifier explores the pass once
 * instead of re-walking a plain loop until its states converge; the
 * native harness drives the same code through the fallback macro above.
 *
 * Return: The chosen domain id, or MLFQ_MAX_LLCS when no domain is
 * eligible.
 */
static __always_inline u32
mlfq_steer_pick_llc(const volatile u32 *runnable, const volatile u32 *idle,
		    u32 nr_llcs, u32 waker_llc, u64 visited)
{
	u32 llc, best = MLFQ_MAX_LLCS;

	bpf_for(llc, 0, MLFQ_MAX_LLCS) {
		if (llc >= nr_llcs)
			continue;
		if (llc == waker_llc)
			continue;
		if (visited & (1ULL << llc))
			continue;
		if (!idle[llc])
			continue;
		if (best >= MLFQ_MAX_LLCS ||
		    runnable[llc] < runnable[best] ||
		    (runnable[llc] == runnable[best] && llc < best))
			best = llc;
	}

	return best;
}
#endif /* __SCX_MLFQ_INTF_H */
