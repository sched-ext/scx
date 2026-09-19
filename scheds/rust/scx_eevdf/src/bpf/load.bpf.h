/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The signals placement and balance are decided on: how much of a CPU a
 * task uses, how busy a cid has been, and the averaged runnable weight that
 * stands for its load. What a higher scheduling class leaves behind is
 * measured in load.bpf.c.
 */
#pragma once

#include "eevdf.bpf.h"
#include "task.bpf.h"

/*
 * Note that @p started or stopped running at @now.
 */
static void util_set_running(task_ctx_t *tctx, bool running, u64 now)
{
	ravg_accumulate_arena(&tctx->run_avg, running, now);
}

/*
 * Return what @p is using, the larger of what it is using now and what it
 * used over its last activation. This is task_util_est():
 *
 *	return max(task_util(p), _task_util_est(p));
 *
 * A task that runs in bursts, a frame at a time, is idle when it wakes,
 * and the running average alone would call it small at exactly the moment
 * it is about to ask for a whole CPU again.
 */
static u64 task_util(task_ctx_t *tctx, u64 now)
{
	u64 util = ravg_read_arena(&tctx->run_avg, now) >> UTIL_SHIFT;

	return MAX(util, tctx->util_est);
}

/*
 * Fold what @p just used into its estimate, as it stops being runnable.
 *
 * The estimate rises to a new demand at once and comes down slowly, which
 * is what util_est_update() does:
 *
 *	if (ewma <= dequeued) {
 *		ewma = dequeued;
 *		goto done;
 *	}
 *
 * before smoothing the decrease. A task is asked to prove that it needs
 * less, over several activations; it is taken at its word that it needs
 * more.
 */
static void util_est_update(task_ctx_t *tctx, u64 now)
{
	u64 dequeued = ravg_read_arena(&tctx->run_avg, now) >> UTIL_SHIFT;

	if (tctx->util_est <= dequeued)
		tctx->util_est = dequeued;
	else
		tctx->util_est -= (tctx->util_est - dequeued) >> 2;
}

/*
 * Note that @cid started or stopped running a task at @now, and fold the
 * interval that just ended into how busy it has been.
 */
static void cid_util_set_running(s32 cid, bool running, u64 now)
{
	/*
	 * Placement uses this signal too, so keep it even when frequency
	 * control is disabled. update_cpufreq() independently honors
	 * cpufreq_enabled before applying it to the governor.
	 */
	if (!cid_valid(cid))
		return;
	ravg_accumulate_arena(&cid_ctx(cid)->run_avg, running, now);
}

/*
 * Return how busy @cid has been, in the [0 .. SCX_CPUPERF_ONE] range the
 * cpufreq governor is driven in.
 */
static u64 cid_util(s32 cid, u64 now)
{
	return ravg_read_arena(&cid_ctx(cid)->run_avg, now) >> UTIL_SHIFT;
}

/*
 * Record whether @cid has sched_ext work which could consume the CPU. A new
 * demand period starts a fresh sample: an old reduced-capacity estimate must
 * not affect placement until current demand has observed the pressure again.
 */
static void cid_demand_set(s32 cid, bool demand, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!capacity_pressure || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (demand == cctx->pressure_demand)
		return;
	cctx->pressure_demand = demand;
	if (demand) {
		/*
		 * Unlike fair's RT PELT, scx_eevdf has no clock source while no
		 * sched_ext task wants the cid. Retain short gaps so pressure
		 * cannot attract work straight back, but do not let an old event
		 * suppress this cid forever.
		 */
		if (cctx->pressure_idle_at &&
		    now - cctx->pressure_idle_at >= NSEC_PER_SEC) {
			cctx->pressure_avail = 1024;
			cctx->pressure_migrate_next = 0;
			cctx->pressure_migrate_failed = 0;
			WRITE_ONCE(cctx->busy_balance_cap, cid_topo(cid)->cap);
		}
		cctx->pressure_idle_at = 0;
		cctx->pressure_at = now;
		cctx->pressure_lost_at = cctx->pressure_lost;
		cctx->pressure_clock_off_at = cctx->clock_off;
		cctx->pressure_valid = 0;
	} else {
		cctx->pressure_idle_at = now;
		cctx->pressure_blocked_at = 0;
		cctx->pressure_migrate_next = 0;
		cctx->pressure_migrate_failed = 0;
		cctx->pressure_valid = 0;
		WRITE_ONCE(cctx->busy_balance_cap, cid_topo(cid)->cap);
	}
}

/*
 * A runnable task stopped with slice remaining was displaced by a higher
 * scheduling class or core scheduling. Measure the interval until sched_ext
 * next runs on this cid. Unlike service/wall accounting, this does not count
 * ordinary dispatch and context-switch overhead as unavailable capacity.
 */
static void cid_pressure_displaced(s32 cid, u64 tnow)
{
	struct cid_ctx __arena *cctx;

	if (!capacity_pressure || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (cctx->pressure_demand && !cctx->pressure_blocked_at)
		cctx->pressure_blocked_at = tnow;
}

static void cid_pressure_resumed(s32 cid, u64 tnow)
{
	struct cid_ctx __arena *cctx;

	if (!capacity_pressure || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (cctx->pressure_blocked_at) {
		cctx->pressure_lost += tnow - cctx->pressure_blocked_at;
		cctx->pressure_blocked_at = 0;
	}
}

/*
 * The load of a cid, cpu_load(): what cfs_rq->avg.load_avg is, the weight
 * of the runnable tasks averaged over time, and what wake_affine_weight()
 * compares. The weight is the pack's, @vsum_w, the sum over the running
 * task and the queued ones, and it is sampled into the average from the
 * cid's own CPU. ops.tick() maintains it and ops.update_idle() records the
 * empty pack when the tick stops with the CPU. Updating it at every context
 * switch would be finer grained, but unlike fair's PELT that means entering a
 * BPF running-average state machine twice per switch. A join or a leave from
 * another CPU changes @vsum_w atomically but cannot update a running average
 * that is not owned there, so the sample is at most one tick behind. A read
 * from another CPU is the same unlocked read cid_util() makes.
 */
static __always_inline u64 ravg_read_fast(struct ravg_data __arena *rd, u64 now);

static void cid_load_accumulate(s32 cid, u64 now)
{
	struct cid_ctx __arena *cctx;

	if (!cid_valid(cid))
		return;
	cctx = cid_ctx(cid);

	ravg_accumulate_arena(&cctx->load_avg, cctx->pack.vsum_w, now);
	cctx->wake_load = ravg_read_fast(&cctx->load_avg, now) >> RAVG_FRAC_BITS;
}

/* ((@a * @b) >> RAVG_FRAC_BITS) without overflowing the intermediate. */
static __always_inline u64 ravg_scale_fast(u64 a, u32 b)
{
	u64 lo = (a & 0xffffffffULL) * b;
	u64 hi = (a >> 32) * b;

	return (lo >> RAVG_FRAC_BITS) + (hi << (32 - RAVG_FRAC_BITS));
}

/*
 * The common ravg_read() case when the last update and this read are in the
 * same 32 ms period. Avoid copying the arena value and running the general
 * period-crossing state machine. Fall back at a boundary, where the general
 * path is needed to fold and decay periods.
 */
static __always_inline u64 ravg_read_fast(struct ravg_data __arena *rd, u64 now)
{
	u64 val, val_at, old, cur, add;
	u32 elapsed, progress;

	/* Match ravg_from_arena()'s snapshot order for concurrent remote reads. */
	val = READ_ONCE(rd->val);
	val_at = READ_ONCE(rd->val_at);
	old = READ_ONCE(rd->old);
	cur = READ_ONCE(rd->cur);
	if (now < val_at || now / UTIL_HALF_LIFE_NS != val_at / UTIL_HALF_LIFE_NS)
		return ravg_read_arena(rd, now);
	elapsed = now % UTIL_HALF_LIFE_NS;
	if (!elapsed)
		return old;

	progress = ravg_normalize_dur(elapsed, UTIL_HALF_LIFE_NS);
	old = ravg_scale_fast(old, (1U << RAVG_FRAC_BITS) - progress / 2);
	if (val && now > val_at) {
		add = val * ravg_normalize_dur(now - val_at,
					       UTIL_HALF_LIFE_NS);
		ravg_add(&cur, add);
	}
	return old + cur / 2;
}

static u64 cid_load(s32 cid, u64 now)
{
	return ravg_read_fast(&cid_ctx(cid)->load_avg, now) >> RAVG_FRAC_BITS;
}

static u64 cid_wake_load(s32 cid)
{
	return READ_ONCE(cid_ctx(cid)->wake_load);
}

/*
 * Tell the cpufreq governor how busy @cid is.
 *
 * Just how busy it is, with nothing added: what schedutil is handed is a
 * utilization, and it does the shaping itself in
 * sugov_effective_cpu_perf():
 *
 *	actual = map_util_perf(actual);
 *	if (actual < max)
 *		max = actual;
 *	return max(min, max);
 *
 * so the quarter of headroom is already there, the ceiling is already
 * there, and @min already keeps a CPU above whatever floor the bandwidth
 * of what runs on it demands. This is what the fair class passes, see
 * cpu_util_cfs_boost() in sugov_get_util().
 */
static void update_cpufreq(s32 cid, u64 now)
{
	if (!cpufreq_enabled || !cid_valid(cid))
		return;

	/*
	 * cpu_util_cfs() reads the average as of the last update, and
	 * ops.running() has just brought it up to @now: no second clock read.
	 */
	scx_bpf_cidperf_set(cid, cid_util(cid, now));
}

/*
 * The fraction of wall time the task spends runnable, folded in once per
 * sleep from the last wakeup-to-sleep span over the whole cycle since the
 * previous sleep, with the weight of eight cycles. This is what fair.c's
 * runnable PELT measures for task_h_load(), and it is what makes the load
 * comparison of wake_affine_weight() hold up under contention: a task kept
 * waiting behind a CPU-bound one still counts what it asks for, not what
 * it was given. Once per sleep is a store at the wakeup and a division at
 * the block, where a running average on every transition was the machinery
 * WA_WEIGHT was not allowed to add.
 */
static void task_runnable_update(task_ctx_t *tctx, u64 now)
{
	u64 cycle = now - tctx->last_sleep_at;
	u64 runnable = now - tctx->runnable_at;
	u64 frac;

	if (!tctx->last_sleep_at || !tctx->runnable_at || !cycle)
		return;
	frac = runnable >= cycle ? 1024 : runnable * 1024 / cycle;
	tctx->runnable_est = (tctx->runnable_est * 7 + frac) / 8;
}

/*
 * Approximate task_h_load() from the averages scx_eevdf already keeps: the
 * execution utilization maintained for capacity placement and the runnable
 * fraction above. The larger of the two stands for the load; they agree for
 * a task that runs as soon as it wakes, and only the runnable fraction sees
 * a task that is delayed by contention. Measured by execution alone, a
 * pipeline thread starved beside a CPU-bound task weighed ever less, its
 * previous cid looked ever heavier without it, and wake_affine_weight()
 * pulled it onto its waker's cid, where the two shared one CPU with the
 * CPU-bound task there and each got a third; fair.c leaves it where it was.
 */
static u64 task_load(const struct task_struct *p, task_ctx_t *tctx, u64 now)
{
	u64 util = MAX(READ_ONCE(tctx->util_est), READ_ONCE(tctx->runnable_est));

	/* Approximate PELT decay while a sleeping task receives no callbacks. */
	if (!scx_bpf_task_running(p) && time_after(now, tctx->last_sleep_at))
		util >>= MIN((now - tctx->last_sleep_at) / UTIL_HALF_LIFE_NS, 63ULL);

	return task_weight(p, tctx) * MIN(util, 1024) / 1024;
}
