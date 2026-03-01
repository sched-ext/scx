/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Deadline calculation variants across sched_ext schedulers.
 *
 * Each dl_*() function computes a virtual deadline for a task using the
 * approach from the corresponding scheduler. All share the same signature:
 *
 *   static u64 dl_<name>(struct task_struct *p,
 *                        struct task_ctx *tctx,
 *                        const struct dl_params *params)
 *
 * Functions are pure: they compute and return a deadline value without
 * modifying any state. Callers are responsible for clamping dsq_vtime
 * before dispatching if needed (see clamp helpers below).
 *
 * The unified task_ctx contains the superset of all per-task fields
 * required across schedulers. Unused fields for a given variant are
 * simply ignored.
 */

/*
 * ==========================================================================
 *  Common types
 * ==========================================================================
 */

struct task_ctx {
	/*
	 * Timing
	 */
	u64 last_run_at;		/* timestamp when task started running */
	u64 last_woke_at;		/* timestamp of last wakeup */
	u64 last_blocked_at;		/* timestamp of last block event */

	/*
	 * Accumulated runtime since last sleep (cosmos, flash, tickless).
	 *
	 * Reset to 0 in ops.runnable(), incremented in ops.stopping().
	 * Used as the latency-sensitivity signal: tasks that sleep often
	 * accumulate less exec_runtime → earlier deadline.
	 */
	u64 exec_runtime;

	/*
	 * Accumulated vruntime while awake (beerland, bpfland).
	 *
	 * Like exec_runtime but measured in weight-inverse-scaled virtual
	 * time. Reset to 0 on wakeup. Penalizes tasks that never sleep
	 * even if their wakeup_freq is stale.
	 */
	u64 awake_vtime;

	/*
	 * Wakeup frequency — EWMA of (100ms / interval_since_last_wake).
	 * Used by cosmos, beerland, bpfland to scale sleep credit: high
	 * frequency sleepers get more credit.
	 */
	u64 wakeup_freq;

	/*
	 * Voluntary context-switch rate — EWMA (flash).
	 * Similar role to wakeup_freq but measured as nvcsw per slice.
	 */
	u64 avg_nvcsw;

	/*
	 * Average and accumulated runtime (rusty, wd40, lavd, layered).
	 * EWMA of per-schedule wall-clock runtime.
	 */
	u64 avg_runtime;
	u64 sum_runtime;

	/*
	 * Interactivity frequencies (rusty, wd40).
	 * - waker_freq: how often this task wakes others (producer signal).
	 * - blocked_freq: how often this task blocks (consumer signal).
	 */
	u64 waker_freq;
	u64 blocked_freq;

	/*
	 * Latency criticality — pre-computed (lavd).
	 * Higher value → more latency-critical → tighter deadline.
	 * Computed from wait_freq, wake_freq, runtime, weight, and
	 * inherited criticality from waker/wakee.
	 */
	u64 lat_cri;
	u64 acc_runtime_wall;		/* accumulated wall-clock runtime */
	u64 svc_time_wwgt;		/* weighted-service-time for fairness */
	u64 wait_freq;			/* consumer frequency */
	u64 wake_freq;			/* producer frequency */
	u64 flags;			/* LAVD_FLAG_* context flags */

	/*
	 * Task-local deadline field (tickless).
	 * Tickless stores its own vruntime cursor per-task rather than
	 * using dsq_vtime for clamping.
	 */
	u64 deadline;
};

/*
 * Global / system-wide parameters passed to every dl function.
 * Callers populate the fields relevant to their chosen variant.
 */
struct dl_params {
	u64 vtime_now;		/* global (or domain/LLC) vruntime cursor */
	u64 slice_ns;		/* base scheduling time-slice */
	u64 slice_lag;		/* max sleep-credit window (cosmos family) */
	u64 run_lag;		/* max exec_runtime charge (flash) */
	u64 cpu_util;		/* current CPU util [0..SCX_CPUPERF_ONE] */
	u64 nr_queued;		/* tasks queued in DSQ (bpfland) */
	u64 slice_max;		/* max slice for starvation calc (bpfland) */
	u64 cur_logical_clk;	/* logical clock (lavd) */
	u64 avg_svc_time;	/* system-wide avg service time (lavd) */
	u64 dom_vruntime;	/* domain min_vruntime (rusty/wd40) */
};

/*
 * ==========================================================================
 *  Shared helpers
 * ==========================================================================
 */

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef NSEC_PER_USEC
#define NSEC_PER_USEC	1000ULL
#endif
#ifndef NSEC_PER_MSEC
#define NSEC_PER_MSEC	(1000ULL * NSEC_PER_USEC)
#endif
#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC	(1000ULL * NSEC_PER_MSEC)
#endif

/*
 * time_before / time_after — wrapping-safe comparisons.
 */
#ifndef time_before
#define time_before(a, b)	((s64)((a) - (b)) < 0)
#endif
#ifndef time_after
#define time_after(a, b)	((s64)((a) - (b)) > 0)
#endif

static __always_inline u64 dl_scale_by_weight(u64 value, u64 weight)
{
	return (value * weight) / 100;
}

static __always_inline u64 dl_scale_by_weight_inverse(u64 value, u64 weight)
{
	return (value * 100) / weight;
}

/*
 * EWMA: new_avg = old * 0.75 + new * 0.25
 * Shared by cosmos, beerland, bpfland, flash, rusty, wd40.
 */
static __always_inline u64 dl_calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Integer log2 via leading-zero count.
 * Used by rusty, wd40, lavd for linearizing exponential distributions.
 */
static __always_inline u64 dl_log2(u64 v)
{
	if (v <= 1)
		return 0;
	return 63 - __builtin_clzll(v);
}

/*
 * Clamp vtime: ensure it is no older than (vtime_now - sleep_credit).
 * Used by all vruntime-family schedulers.
 */
static __always_inline u64 dl_clamp_vtime(u64 vtime, u64 vtime_now,
					   u64 sleep_credit)
{
	u64 vtime_min = vtime_now - sleep_credit;

	if (time_before(vtime, vtime_min))
		vtime = vtime_min;
	return vtime;
}

/*
 * Compute sleep credit from slice_lag, lag_scale, and weight parameters.
 * Used by cosmos, beerland, bpfland, flash.
 */
static __always_inline u64 dl_sleep_credit(u64 slice_lag, u64 lag_scale,
					    u64 weight, u64 base_weight)
{
	return slice_lag * lag_scale * weight / base_weight;
}

/*
 * Deadline = clamped vtime + weight-inverse exec_runtime.
 * Shared core for cosmos and tickless.
 */
static __always_inline u64 dl_exec_runtime_deadline(u64 vtime, u64 vtime_now,
						     u64 sleep_credit,
						     u64 exec_runtime,
						     u64 weight)
{
	vtime = dl_clamp_vtime(vtime, vtime_now, sleep_credit);
	return vtime + dl_scale_by_weight_inverse(exec_runtime, weight);
}

/*
 * Deadline = clamped vtime + capped awake_vtime.
 * Shared core for beerland and bpfland.
 */
static __always_inline u64 dl_awake_vtime_deadline(u64 vtime, u64 vtime_now,
						    u64 sleep_credit,
						    u64 awake_vtime,
						    u64 awake_max)
{
	vtime = dl_clamp_vtime(vtime, vtime_now, sleep_credit);
	if (time_after(awake_vtime, awake_max))
		awake_vtime = awake_max;
	return vtime + awake_vtime;
}

/*
 * ==========================================================================
 *  COSMOS — vruntime + weight-inverse exec_runtime
 *
 *  deadline = clamp(dsq_vtime, vtime_now - vsleep_max)
 *           + scale_inverse(exec_runtime)
 *
 *  Sleep credit scaled by wakeup_freq: frequent sleepers get more credit.
 *  exec_runtime penalizes CPU-bound tasks.
 * ==========================================================================
 */
static u64 dl_cosmos(struct task_struct *p,
		     struct task_ctx *tctx,
		     const struct dl_params *params)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 credit = dl_sleep_credit(params->slice_lag, lag_scale,
				     p->scx.weight, 100);

	return dl_exec_runtime_deadline(p->scx.dsq_vtime, params->vtime_now,
					credit, tctx->exec_runtime,
					p->scx.weight);
}

/*
 * ==========================================================================
 *  BEERLAND — vruntime + capped awake_vtime
 *
 *  Like cosmos but replaces exec_runtime with awake_vtime (already
 *  weight-inverse-scaled). Also caps awake_vtime to slice_lag/weight,
 *  preventing CPU-bound tasks from exploiting stale wakeup frequencies.
 * ==========================================================================
 */
static u64 dl_beerland(struct task_struct *p,
		       struct task_ctx *tctx,
		       const struct dl_params *params)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 credit = dl_sleep_credit(params->slice_lag, lag_scale,
				     p->scx.weight, 100);
	u64 awake_max = dl_scale_by_weight_inverse(params->slice_lag,
						   p->scx.weight);

	return dl_awake_vtime_deadline(p->scx.dsq_vtime, params->vtime_now,
				      credit, tctx->awake_vtime, awake_max);
}

/*
 * ==========================================================================
 *  BPFLAND — beerland + queue-pressure throttling
 *
 *  Extends beerland by dynamically reducing sleep credit (lag_scale)
 *  under queue pressure.  When queued work approaches the starvation
 *  threshold, sleep-credit boosting is disabled entirely (lag_scale = 1).
 *
 *  Starvation threshold: 500ms of queued work at slice_max per task.
 * ==========================================================================
 */
#define BPFLAND_STARVATION_MS	5000ULL

static u64 dl_bpfland(struct task_struct *p,
		      struct task_ctx *tctx,
		      const struct dl_params *params)
{
	const u64 starvation_thresh = BPFLAND_STARVATION_MS *
				      NSEC_PER_MSEC / 10;
	const u64 q_thresh = MAX(starvation_thresh / params->slice_max, 1);

	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 credit, awake_max;

	/*
	 * Queue-pressure dampening:
	 *   emergency: queued work >= starvation window → no boost.
	 *   normal:    lag_scale *= q_thresh / (q_thresh + nr_queued).
	 */
	if (params->nr_queued * params->slice_max >= starvation_thresh)
		lag_scale = 1;
	else
		lag_scale = MAX(lag_scale * q_thresh /
				(q_thresh + params->nr_queued), 1);

	credit = dl_sleep_credit(params->slice_lag, lag_scale,
				 p->scx.weight, 100);
	awake_max = dl_scale_by_weight_inverse(params->slice_lag,
					       p->scx.weight);

	return dl_awake_vtime_deadline(p->scx.dsq_vtime, params->vtime_now,
				      credit, tctx->awake_vtime, awake_max);
}

/*
 * ==========================================================================
 *  FLASH — normalized-weight deadline with nvcsw-based sleep credit
 *
 *  Uses voluntary context-switch rate (avg_nvcsw) instead of wakeup
 *  frequency, log-compressed weight normalization, and optional CPU
 *  utilization scaling of sleep credit.
 *
 *  Weight normalization compresses the [1..10000] range to [1..128]:
 *    normalized = 1 + 127 * log2(weight) / log2(10000)
 *  This prevents extreme priority gaps from causing starvation.
 *
 *  The deadline is set (not added to): dsq_vtime is clamped then
 *  exec_runtime is added using the normalized weight.
 * ==========================================================================
 */
#define FLASH_LOG2_10000	13	/* floor(log2(10000)) */

static __always_inline u64 flash_task_weight(u64 scx_weight)
{
	return 1 + (127 * dl_log2(scx_weight) / FLASH_LOG2_10000);
}

#define FLASH_BASE_WEIGHT	64

static u64 dl_flash(struct task_struct *p,
		    struct task_ctx *tctx,
		    const struct dl_params *params)
{
	u64 weight_n = flash_task_weight(p->scx.weight);
	u64 lag_scale, credit;
	u64 vtime;
	u64 exec = MIN(tctx->exec_runtime, params->run_lag);

	/*
	 * Sleep-credit scale from voluntary context-switch rate.
	 * log2(max(nvcsw, 2)) gives [1..7] for typical rates.
	 */
	lag_scale = dl_log2(MAX(tctx->avg_nvcsw, 2));

	/*
	 * Optional CPU-utilization scaling: increase credit spread when
	 * CPUs are busy, reduce when idle (dynamic fairness).
	 */
	if (params->cpu_util)
		lag_scale = lag_scale * params->cpu_util / 1024;

	credit = dl_sleep_credit(params->slice_lag, lag_scale,
				 weight_n, FLASH_BASE_WEIGHT);
	vtime = dl_clamp_vtime(p->scx.dsq_vtime, params->vtime_now, credit);

	/*
	 * Add execution penalty using normalized weight.
	 */
	return vtime + exec * FLASH_BASE_WEIGHT / weight_n;
}

/*
 * ==========================================================================
 *  LAVD — latency-criticality virtual deadline
 *
 *  Fundamentally different from the vruntime family. Uses a logical
 *  clock (not vruntime) and computes:
 *
 *    deadline = (cur_logical_clk - compete_window) + delta
 *    delta = (adjusted_runtime * greedy_penalty) / lat_cri
 *
 *  lat_cri encodes how latency-sensitive a task is (higher = more
 *  critical = tighter deadline). It is pre-computed from:
 *    - wait_freq × wake_freq (producer/consumer chain detection)
 *    - inverse runtime (short tasks are more critical)
 *    - context-aware boosts (IRQ, kernel, lock holder)
 *    - inherited criticality from waker/wakee
 *
 *  greedy_penalty penalizes tasks that consumed more than their fair
 *  share of CPU relative to the system average (fairness knob).
 * ==========================================================================
 */
#define LAVD_SHIFT			10
#define LAVD_SCALE			(1ULL << LAVD_SHIFT)
#define LAVD_ACC_RUNTIME_MAX		(5ULL * NSEC_PER_MSEC)
#define LAVD_TASK_LAG_MAX		(500ULL * NSEC_PER_MSEC)
#define LAVD_DL_COMPETE_WINDOW		((300ULL * NSEC_PER_MSEC) >> 16)
#define LAVD_LC_GREEDY_SHIFT		1

static u64 dl_lavd(struct task_struct *p,
		   struct task_ctx *tctx,
		   const struct dl_params *params)
{
	u64 adjusted_runtime, greedy_penalty, dl_delta;
	s64 lag;
	u64 lag_max;

	/*
	 * Adjusted runtime: prefer short-running + recently-woken tasks.
	 * Cap acc_runtime to prevent starvation of CPU-bound tasks.
	 */
	adjusted_runtime = LAVD_ACC_RUNTIME_MAX +
			   MIN(tctx->acc_runtime_wall, LAVD_ACC_RUNTIME_MAX);

	/*
	 * Greedy penalty: [LAVD_SCALE .. 2*LAVD_SCALE] (i.e., [100%..200%]).
	 * Positive lag  = underserved → penalty near 100%.
	 * Negative lag  = greedy      → penalty near 200%.
	 */
	lag = (s64)(params->avg_svc_time - tctx->svc_time_wwgt);
	lag_max = dl_scale_by_weight_inverse(LAVD_TASK_LAG_MAX,
					     p->scx.weight);

	if (lag > (s64)lag_max)
		lag = (s64)lag_max;
	else if (lag < -(s64)lag_max)
		lag = -(s64)lag_max;

	greedy_penalty = (((-lag + (s64)lag_max) << LAVD_SHIFT) / lag_max);
	greedy_penalty = LAVD_SCALE + (greedy_penalty >> LAVD_LC_GREEDY_SHIFT);

	/*
	 * Compute deadline delta: runtime * penalty / criticality.
	 * lat_cri is pre-computed; higher → tighter deadline.
	 */
	dl_delta = tctx->lat_cri > 0 ?
		   (adjusted_runtime * greedy_penalty) / tctx->lat_cri : 0;

	return (params->cur_logical_clk - LAVD_DL_COMPETE_WINDOW) +
	       (dl_delta >> LAVD_SHIFT);
}

/*
 * ==========================================================================
 *  RUSTY / WD40 — interactivity-aware request-length deadline
 *
 *  Computes a "CPU request length" from waker/blocked frequencies and
 *  average runtime, then uses it as a vtime offset. Inspired by lavd's
 *  latency-criticality concept but uses the Linux nice-to-weight table
 *  to map an interactivity priority to a scaling factor.
 *
 *  Formula:
 *    freq_factor = blocked_freq * waker_freq² * weight / 100
 *    lat_prio    = log2(freq_factor) - log2(avg_runtime / 2 / weight)
 *    lat_scale   = nice_to_weight[39 - lat_prio]
 *    request_len = avg_runtime * 100 / lat_scale
 *    deadline    = clamped(dsq_vtime) + request_len
 *
 *  wd40 is identical except it uses arena-based domain contexts.
 * ==========================================================================
 */
#define DL_FREQ_FT_MAX		100000ULL
#define DL_RUNTIME_SCALE	2ULL
#define DL_MAX_LATENCY_NS	(50ULL * NSEC_PER_MSEC)
#define DL_MAX_LAT_PRIO		39ULL
#define DL_LB_MAX_WEIGHT	10000ULL

static const int dl_prio_to_weight[DL_MAX_LAT_PRIO + 1] = {
	/* -20 */ 88761, 71755, 56483, 46273, 36291,
	/* -15 */ 29154, 23254, 18705, 14949, 11916,
	/* -10 */  9548,  7620,  6100,  4904,  3906,
	/*  -5 */  3121,  2501,  1991,  1586,  1277,
	/*   0 */  1024,   820,   655,   526,   423,
	/*   5 */   335,   272,   215,   172,   137,
	/*  10 */   110,    87,    70,    56,    45,
	/*  15 */    36,    29,    23,    18,    15,
};

static __always_inline u64 dl_prio_to_lat_weight(u64 prio)
{
	if (prio >= DL_MAX_LAT_PRIO)
		return dl_prio_to_weight[0]; /* max boost */
	return dl_prio_to_weight[DL_MAX_LAT_PRIO - prio - 1];
}

static u64 dl_rusty(struct task_struct *p,
		    struct task_ctx *tctx,
		    const struct dl_params *params)
{
	u64 waker_freq = MIN(tctx->waker_freq, DL_FREQ_FT_MAX);
	u64 blocked_freq = MIN(tctx->blocked_freq, DL_FREQ_FT_MAX);
	u64 freq_factor, lat_prio, lat_scale;
	u64 avg_run_raw, avg_run;
	u64 request_len, vtime;

	/*
	 * Interactivity signal: producer × consumer² × weight.
	 */
	freq_factor = blocked_freq * waker_freq * waker_freq;
	freq_factor = dl_scale_by_weight(freq_factor, p->scx.weight);

	/*
	 * Linearize exponential distribution.
	 */
	lat_prio = dl_log2(freq_factor + 1);
	lat_prio = MIN(lat_prio, DL_MAX_LAT_PRIO);

	/*
	 * Penalize long average runtime (inverse-scaled by weight).
	 */
	avg_run_raw = tctx->avg_runtime / DL_RUNTIME_SCALE;
	avg_run_raw = MIN(avg_run_raw, DL_MAX_LATENCY_NS);
	avg_run_raw = dl_scale_by_weight_inverse(avg_run_raw, p->scx.weight);
	avg_run = dl_log2(avg_run_raw + 1);

	if (avg_run < lat_prio)
		lat_prio -= avg_run;
	else
		lat_prio = 0;

	/*
	 * Map interactivity priority → weight via nice table.
	 */
	lat_scale = dl_prio_to_lat_weight(lat_prio);
	lat_scale = MIN(lat_scale, DL_LB_MAX_WEIGHT);

	/*
	 * Request length: shorter for interactive tasks.
	 */
	request_len = dl_scale_by_weight_inverse(tctx->avg_runtime, lat_scale);

	/*
	 * Clamp vtime: max one slice of sleep credit.
	 */
	vtime = dl_clamp_vtime(p->scx.dsq_vtime, params->dom_vruntime,
			       params->slice_ns);

	return vtime + request_len;
}

/* wd40 uses the same formula as rusty */
static u64 dl_wd40(struct task_struct *p,
		   struct task_ctx *tctx,
		   const struct dl_params *params)
{
	return dl_rusty(p, tctx, params);
}

/*
 * ==========================================================================
 *  TICKLESS — minimal vruntime + exec_runtime
 *
 *  Simplest of the family. Sleep credit is only one slice_ns (no
 *  wakeup-frequency scaling). Tasks run with infinite slices; a BPF
 *  timer checks for preemption periodically.
 *
 *  Uses a task-local deadline field instead of dsq_vtime for the
 *  vruntime cursor.
 * ==========================================================================
 */
static u64 dl_tickless(struct task_struct *p,
		       struct task_ctx *tctx,
		       const struct dl_params *params)
{
	return dl_exec_runtime_deadline(tctx->deadline, params->vtime_now,
					params->slice_ns, tctx->exec_runtime,
					p->scx.weight);
}

/*
 * ==========================================================================
 *  LAYERED — pure CFS vtime (no explicit deadline delta)
 *
 *  Layered does not compute a deadline delta. It dispatches tasks ordered
 *  by their raw dsq_vtime, which advances as runtime * 100 / weight.
 *
 *  The "deadline" is simply the clamped dsq_vtime itself. Sleep credit
 *  is capped to one slice per layer. Each layer on each LLC maintains
 *  its own vtime cursor (params->vtime_now should be the per-layer
 *  per-LLC vtime_now).
 *
 *  When tasks migrate across LLCs, their vtime is rebased:
 *    vtime_delta = dsq_vtime - old_llc_vtime_now
 *    dsq_vtime   = new_llc_vtime_now + vtime_delta
 *  (This rebasing must happen before calling dl_layered.)
 * ==========================================================================
 */
static u64 dl_layered(struct task_struct *p,
		      struct task_ctx *tctx,
		      const struct dl_params *params)
{
	u64 vtime_max = params->vtime_now + 8192 * params->slice_ns;
	u64 vtime = dl_clamp_vtime(p->scx.dsq_vtime, params->vtime_now,
				   params->slice_ns);

	if (time_after(vtime, vtime_max))
		vtime = vtime_max;

	return vtime;
}

/*
 * ==========================================================================
 *  Summary of approaches
 * ==========================================================================
 *
 *  Scheduler   | Base            | Delta / offset          | Sleep credit scale
 *  ------------|-----------------|-------------------------|-------------------
 *  cosmos      | dsq_vtime       | exec_runtime / weight   | wakeup_freq * slice_lag
 *  beerland    | dsq_vtime       | awake_vtime (capped)    | wakeup_freq * slice_lag
 *  bpfland     | dsq_vtime       | awake_vtime (capped)    | wakeup_freq * slice_lag, throttled by queue pressure
 *  flash       | dsq_vtime       | exec_runtime / norm_wt  | log2(nvcsw) * slice_lag, scaled by cpu_util
 *  lavd        | logical_clock   | runtime*penalty/lat_cri | compete window (fixed)
 *  rusty/wd40  | dsq_vtime       | avg_rt * 100 / lat_wt   | one slice (domain vruntime)
 *  tickless    | task deadline   | exec_runtime / weight   | one slice_ns (fixed)
 *  layered     | dsq_vtime       | (none — pure vtime)     | one slice_ns (per-layer per-LLC)
 */
