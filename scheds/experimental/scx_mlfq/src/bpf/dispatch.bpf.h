// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and task lifecycle for the mlfq scheduler.
 *
 * A CPU first serves the tasks pinned to it, then its own LLC, then the
 * other LLCs of its node, then remote LLCs and finally the fallback DSQ.
 * When nothing is queued anywhere and the previous task still wants to
 * run, it keeps the CPU with a fresh slice.
 *
 * Runtime is charged when a task stops running, from the time it spent on
 * the CPU. At every tick, a task that already had a minimum slice gives
 * up the CPU when a waiting task is due before it, so an urgent wakeup
 * waits for at most about one tick even when every CPU is busy.
 *
 * A busy CPU asks for its highest performance level when a task starts
 * and refreshes the request every tick, because the cpufreq governor
 * drops requests that arrive within its rate limit.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __MLFQ_DISPATCH_BPF_H
#define __MLFQ_DISPATCH_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "stats.bpf.h"
#include "enqueue.bpf.h"

/* Pull a task from another LLC, either in the node of @llc or outside of it. */
static bool mlfq_steal(u32 llc, bool same_node)
{
	u32 node = mlfq_llc_node[llc];
	u32 i;

	bpf_for(i, 1, mlfq_nr_llcs) {
		u32 other = (llc + i) % mlfq_nr_llcs;

		if (other >= MLFQ_MAX_LLCS)
			break;
		if ((mlfq_llc_node[other] == node) != same_node)
			continue;
		if (scx_bpf_dsq_move_to_local(MLFQ_LLC_DSQ_BASE + other, 0))
			return true;
	}
	return false;
}

/* CPU time @t got in its current run, up to @now. */
static __always_inline u64 mlfq_ran(const struct mlfq_task_ctx *t, u64 now)
{
	return time_after(now, t->last_running_clk) ? now - t->last_running_clk : 0;
}

/* True when the head of @dsq_id can run on @cpu and is due before @deadline. */
static bool mlfq_queued_ahead(u64 dsq_id, u64 deadline, s32 cpu)
{
	struct task_struct *head = __COMPAT_scx_bpf_dsq_peek(dsq_id);

	return head && time_before(head->scx.dsq_vtime, deadline) &&
	       bpf_cpumask_test_cpu(cpu, head->cpus_ptr);
}

/*
 * Let @prev, which is still runnable, keep @cpu with a fresh slice. Its run
 * continues without passing through ops.stopping(), so its deadline is
 * refreshed from the virtual time it reached so far. Unless @always is
 * set, @prev only keeps the CPU while nothing queued for @cpu is due
 * before it, which spares a switch and a likely move to another core.
 */
static bool mlfq_keep_prev(s32 cpu, u32 llc, struct task_struct *prev, bool always)
{
	struct mlfq_task_ctx *t;
	u64 now, ran, acc, vtime, deadline, slice;

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED) ||
	    !bpf_cpumask_test_cpu(cpu, prev->cpus_ptr))
		return false;
	t = mlfq_task_ctx(prev);
	if (!t)
		return false;

	now = scx_bpf_now();
	ran = mlfq_ran(t, now);
	acc = t->acc_runtime_ns + ran;
	vtime = t->vtime + mlfq_charge(prev, ran, mlfq_level(acc));
	deadline = mlfq_deadline(t, vtime, acc);
	if (!always && (mlfq_queued_ahead(MLFQ_CPU_DSQ_BASE + cpu, deadline, cpu) ||
			mlfq_queued_ahead(MLFQ_LLC_DSQ_BASE + llc, deadline, cpu)))
		return false;

	if (mlfq_top_level(acc))
		mlfq_advance_vtime_now(vtime);
	scx_bpf_task_set_dsq_vtime(prev, deadline);
	slice = mlfq_calc_slice(t, cpu);
	scx_bpf_task_set_slice(prev, slice);
	WRITE_ONCE(mlfq_cpu_states[cpu].est_stopping_clk, mlfq_est_stop(t, acc, slice, now));
	return true;
}

void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct mlfq_cpu_state *cs;
	u32 llc;

	if (!mlfq_cpu_valid(cpu))
		return;
	llc = mlfq_llc_of(cpu);

	if (mlfq_keep_prev(cpu, llc, prev, false)) {
		mlfq_stat_inc(MLFQ_STAT_KEEP);
		return;
	}
	if (scx_bpf_dsq_move_to_local(MLFQ_CPU_DSQ_BASE + cpu, 0) ||
	    scx_bpf_dsq_move_to_local(MLFQ_LLC_DSQ_BASE + llc, 0)) {
		mlfq_stat_inc(MLFQ_STAT_DISPATCHED);
		return;
	}
	if (mlfq_steal(llc, true) || mlfq_steal(llc, false)) {
		mlfq_stat_inc(MLFQ_STAT_DISPATCHED);
		mlfq_stat_inc(MLFQ_STAT_STEAL);
		return;
	}
	if (scx_bpf_dsq_move_to_local(MLFQ_FALLBACK_DSQ, 0)) {
		mlfq_stat_inc(MLFQ_STAT_DISPATCHED);
		return;
	}
	if (mlfq_keep_prev(cpu, llc, prev, true)) {
		mlfq_stat_inc(MLFQ_STAT_KEEP);
		return;
	}

	/* The CPU is about to go idle: it is no preemption victim anymore. */
	cs = &mlfq_cpu_states[cpu];
	WRITE_ONCE(cs->lat_cri, 0);
	WRITE_ONCE(cs->est_stopping_clk, 0);
	if (!READ_ONCE(cs->idle_start_clk))
		WRITE_ONCE(cs->idle_start_clk, scx_bpf_now());
}

void BPF_STRUCT_OPS(mlfq_running, struct task_struct *p)
{
	struct mlfq_task_ctx *t = mlfq_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	struct mlfq_cpu_state *cs;
	u64 now;

	if (!t || !mlfq_cpu_valid(cpu))
		return;

	now = scx_bpf_now();
	if (mlfq_top_level(t->acc_runtime_ns))
		mlfq_advance_vtime_now(t->vtime);
	mlfq_clear_pinned(t);
	t->last_running_clk = now;

	cs = &mlfq_cpu_states[cpu];
	WRITE_ONCE(cs->lat_cri, t->lat_cri);
	WRITE_ONCE(cs->est_stopping_clk, mlfq_est_stop(t, t->acc_runtime_ns, p->scx.slice, now));
	WRITE_ONCE(cs->idle_start_clk, 0);
	if (t->lat_cri > READ_ONCE(cs->max_lat_cri))
		WRITE_ONCE(cs->max_lat_cri, t->lat_cri);
	__sync_fetch_and_add(&cs->sum_lat_cri, t->lat_cri);
	__sync_fetch_and_add(&cs->nr_sched, 1);

	if (READ_ONCE(cs->cpuperf_cur) != SCX_CPUPERF_ONE)
		mlfq_cpuperf_commit(cpu, cs, SCX_CPUPERF_ONE, now);
}

void BPF_STRUCT_OPS(mlfq_tick, struct task_struct *p)
{
	struct mlfq_task_ctx *t = mlfq_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	struct mlfq_cpu_state *cs;
	u64 now, deadline, base;

	if (!t || !mlfq_cpu_valid(cpu))
		return;
	cs = &mlfq_cpu_states[cpu];

	now = scx_bpf_now();
	if (now - READ_ONCE(cs->cpuperf_commit_clk) >= MLFQ_CPUPERF_REFRESH_NS)
		mlfq_cpuperf_commit(cpu, cs, SCX_CPUPERF_ONE, now);

	/*
	 * Once the task had a minimum slice, give the CPU to a waiting task
	 * with an earlier deadline. Comparing against the deadline the task
	 * started with lets equally urgent tasks run their slices out.
	 */
	deadline = p->scx.dsq_vtime;
	if (mlfq_ran(t, now) >= MLFQ_SLICE_MIN_NS &&
	    (mlfq_queued_ahead(MLFQ_CPU_DSQ_BASE + cpu, deadline, cpu) ||
	     mlfq_queued_ahead(MLFQ_LLC_DSQ_BASE + mlfq_llc_of(cpu), deadline, cpu))) {
		scx_bpf_task_set_slice(p, 0);
		return;
	}

	/* A pinned task cannot go elsewhere, so cut a long slice short for it. */
	base = READ_ONCE(mlfq_sys_stat.slice_ns);
	if (READ_ONCE(cs->nr_pinned) && p->scx.slice > base)
		scx_bpf_task_set_slice(p, base);
}

void BPF_STRUCT_OPS(mlfq_stopping, struct task_struct *p, bool runnable)
{
	struct mlfq_task_ctx *t = mlfq_task_ctx(p);
	u64 used, before;
	u32 level;

	if (!t)
		return;

	used = t->last_running_clk ? mlfq_ran(t, scx_bpf_now()) : 0;
	before = t->acc_runtime_ns;
	t->acc_runtime_ns += used;
	level = mlfq_level(t->acc_runtime_ns);
	t->vtime += mlfq_charge(p, used, level);

	if (before < mlfq_level_start(level))
		mlfq_stat_inc(MLFQ_STAT_DEMOTED);
	if (runnable)
		mlfq_stat_inc(MLFQ_STAT_PREEMPTED);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct mlfq_task_ctx *t;

	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return -ENOMEM;
	t->vtime = READ_ONCE(mlfq_clock.vtime_now);
	t->lat_cri = 1;
	t->pinned_cpu = -1;
	return 0;
}

/*
 * Largest L3 among the LLCs if the LLCs differ in size, zero if they are
 * all the same or any size is unknown.
 */
static u32 mlfq_big_cache_kb(void)
{
	u32 llc, kb, min_kb = 0, max_kb = 0;

	bpf_for(llc, 0, mlfq_nr_llcs) {
		if (llc >= MLFQ_MAX_LLCS)
			break;
		kb = mlfq_llc_kb[llc];
		if (!kb)
			return 0;
		if (!min_kb || kb < min_kb)
			min_kb = kb;
		if (kb > max_kb)
			max_kb = kb;
	}
	return max_kb > min_kb ? max_kb : 0;
}

static s32 mlfq_init_cpus(void)
{
	u32 cpu, big_kb = mlfq_big_cache_kb();

	mlfq_has_big_cache = big_kb;
	bpf_for(cpu, 0, mlfq_nr_cpus) {
		struct bpf_cpumask *mask;
		s32 ret;

		if (cpu >= MLFQ_MAX_CPUS)
			break;
		ret = scx_bpf_create_dsq(MLFQ_CPU_DSQ_BASE + cpu, -1);
		if (ret) {
			scx_bpf_error("failed to create the DSQ of CPU %u (%d)", cpu, ret);
			return ret;
		}

		if (big_kb && mlfq_llc_kb[mlfq_llc_of(cpu)] == big_kb)
			bpf_cpumask_set_cpu(cpu, &mlfq_big_cache_cpumask);

		mask = MEMBER_VPTR(mlfq_llc_cpumask, [mlfq_llc_of(cpu)]);
		if (mask)
			bpf_cpumask_set_cpu(cpu, mask);
		if (mlfq_nr_groups > mlfq_nr_llcs) {
			mask = MEMBER_VPTR(mlfq_group_cpumask, [mlfq_cpu_group[cpu]]);
			if (mask)
				bpf_cpumask_set_cpu(cpu, mask);
		}
	}
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init)
{
	struct mlfq_timer *ft;
	u32 llc, zero = 0;
	s32 ret;

	if (!mlfq_nr_cpus || mlfq_nr_cpus > MLFQ_MAX_CPUS ||
	    !mlfq_nr_llcs || mlfq_nr_llcs > MLFQ_MAX_LLCS ||
	    mlfq_nr_groups > MLFQ_MAX_GROUPS) {
		scx_bpf_error("invalid topology: %u CPUs, %u LLCs, %u groups",
			      mlfq_nr_cpus, mlfq_nr_llcs, mlfq_nr_groups);
		return -EINVAL;
	}

	WRITE_ONCE(mlfq_sys_stat.slice_ns, MLFQ_SLICE_MAX_NS);

	ret = mlfq_init_cpus();
	if (ret)
		return ret;

	bpf_for(llc, 0, mlfq_nr_llcs) {
		ret = scx_bpf_create_dsq(MLFQ_LLC_DSQ_BASE + llc, -1);
		if (ret) {
			scx_bpf_error("failed to create the DSQ of LLC %u (%d)", llc, ret);
			return ret;
		}
	}

	ret = scx_bpf_create_dsq(MLFQ_FALLBACK_DSQ, -1);
	if (ret) {
		scx_bpf_error("failed to create the fallback DSQ (%d)", ret);
		return ret;
	}

	ft = bpf_map_lookup_elem(&stat_timer, &zero);
	if (!ft) {
		scx_bpf_error("failed to look up the stat timer");
		return -ESRCH;
	}
	bpf_timer_init(&ft->timer, &stat_timer, MLFQ_CLOCK_BOOTTIME);
	bpf_timer_set_callback(&ft->timer, mlfq_stat_timer_fn);
	ret = bpf_timer_start(&ft->timer, MLFQ_STAT_INTERVAL_NS, 0);
	if (ret)
		scx_bpf_error("failed to start the stat timer (%d)", ret);
	return ret;
}

void BPF_STRUCT_OPS(mlfq_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

#endif /* __MLFQ_DISPATCH_BPF_H */
