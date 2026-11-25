// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch and task lifecycle for the flow scheduler.
 *
 * A CPU first serves the fallback DSQ, which only holds the rare tasks
 * without a context, then the tasks pinned to it, then its own LLC, then
 * the other LLCs of its node and finally remote LLCs. A task of its own
 * LLC that is due well before the pinned tasks goes first, so pinned tasks
 * cannot starve the LLC. When nothing is queued anywhere and the previous
 * task still wants to run, it keeps the CPU with a fresh slice. With
 * --performance, the strand of an LLC counts as one more queue of it, see
 * helix.bpf.h.
 *
 * Runtime is charged when a task stops running, from the time it spent on
 * the CPU. With --performance, that time is what the kernel accounted for
 * the run, from the clock of the runqueue of the task. With --helicoprion,
 * it is charged when the task wakes up or is queued again, from the CPU
 * time the kernel accounted for it. At every tick, a task that already had
 * a minimum slice gives up the CPU when a waiting task is due before it,
 * so an urgent wakeup waits for at most about one tick even when every CPU
 * is busy. With --helicoprion, the cgroup callbacks keep the weight of
 * each cgroup for that charge.
 *
 * A busy CPU asks for its highest performance level when a task starts
 * and refreshes the request every tick, because the cpufreq governor
 * drops requests that arrive within its rate limit.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_DISPATCH_BPF_H
#define __FLOW_DISPATCH_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "stats.bpf.h"
#include "enqueue.bpf.h"
#include "helix.bpf.h"

/*
 * Pull a task from another LLC for @cpu of @llc, either in the node of
 * @llc or outside of it.
 */
static bool flow_steal(s32 cpu, u32 llc, bool same_node)
{
	u32 i;

	bpf_for(i, 1, flow_nr_llcs) {
		s32 other = flow_peer_llc(llc, i, same_node);

		if (other >= 0 && flow_take_llc(cpu, llc, other))
			return true;
	}
	return false;
}

/*
 * A task that computed for longer than a boosted slice without sleeping
 * does not move the system virtual time, so it cannot drag the clock away
 * from the tasks that run in short bursts. While cgroups compete it does,
 * so that the cgroup factors can tell such tasks apart.
 */
static __always_inline bool flow_long_burst(u64 acc)
{
	return acc >= FLOW_SLICE_BOOST_MAX_NS;
}

/*
 * True when a task of @dsq_id that can run on @cpu is due before @deadline.
 * The first FLOW_AHEAD_DEPTH tasks are looked at, so that a head that may
 * only run on other CPUs does not hide the tasks behind it. The walk takes
 * the lock of the DSQ at every step, while the head can be read without
 * it, so the walk only starts when the head is due first but cannot run on
 * @cpu.
 */
static bool flow_queued_ahead(u64 dsq_id, u64 deadline, s32 cpu)
{
	struct task_struct *p = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	u32 seen = 0;

	if (!p || !time_before(p->scx.dsq_vtime, deadline))
		return false;
	if (flow_task_fits(p, cpu))
		return true;
	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		if (!time_before(p->scx.dsq_vtime, deadline) || seen++ >= FLOW_AHEAD_DEPTH)
			return false;
		if (flow_task_fits(p, cpu))
			return true;
	}
	return false;
}

/*
 * A task of @llc, in its DSQ or its strand, may run on @cpu and is due
 * before @deadline.
 */
static __always_inline bool flow_llc_ahead(u32 llc, u64 deadline, s32 cpu)
{
	return flow_queued_ahead(FLOW_LLC_DSQ_BASE + llc, deadline, cpu) ||
	       flow_helix_ahead(llc, deadline, cpu);
}

/*
 * Move a task pinned to @cpu or a task of @llc to the local DSQ of @cpu.
 * Pinned tasks cannot run anywhere else, so they go first unless the head
 * of @llc is due more than a maximum slice before them. Without that
 * limit, CPUs that always have a pinned task waiting would starve the rest
 * of the LLC, as when stress-ng pins two tasks to every CPU.
 */
static bool flow_consume_local(s32 cpu, u32 llc)
{
	u64 cpu_dsq = FLOW_CPU_DSQ_BASE + cpu;
	struct task_struct *pinned = __COMPAT_scx_bpf_dsq_peek(cpu_dsq);

	if (pinned && flow_llc_ahead(llc, pinned->scx.dsq_vtime - FLOW_SLICE_MAX_NS, cpu) &&
	    flow_take_llc(cpu, llc, llc))
		return true;
	return scx_bpf_dsq_move_to_local(cpu_dsq, 0) || flow_take_llc(cpu, llc, llc);
}

/*
 * Let @prev, which is still runnable, keep @cpu with a fresh slice. Its run
 * continues without passing through ops.stopping(), so its deadline is
 * refreshed from the virtual time it reached so far. Unless @always is
 * set, @prev only keeps the CPU while nothing queued for @cpu, in its own
 * DSQ or for @llc, is due before it, which spares a switch and a likely
 * move to another core.
 */
static bool flow_keep_prev(s32 cpu, u32 llc, struct task_struct *prev, bool always)
{
	struct flow_task_ctx *t;
	u64 now, ran, acc, vtime, deadline, slice;
	bool cgrp = flow_cgrp_active();

	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED) ||
	    !bpf_cpumask_test_cpu(cpu, prev->cpus_ptr))
		return false;
	t = flow_task_ctx(prev);
	if (!t)
		return false;

	now = flow_now();
	ran = flow_ran(t, now);
	acc = t->acc_runtime_ns + ran;
	vtime = t->vtime + (cgrp ? flow_charge_cgrp(prev, t, ran) : flow_charge(prev, ran, acc));
	deadline = flow_deadline(t, vtime, acc);
	if (!always && (flow_queued_ahead(FLOW_CPU_DSQ_BASE + cpu, deadline, cpu) ||
			flow_llc_ahead(llc, deadline, cpu)))
		return false;

	if (cgrp || !flow_long_burst(acc))
		flow_advance_vtime_now(vtime);
	scx_bpf_task_set_dsq_vtime(prev, deadline);
	slice = flow_calc_slice(t, cpu);
	scx_bpf_task_set_slice(prev, slice);
	WRITE_ONCE(flow_cpu_states[cpu].est_stopping_clk, flow_est_stop(t, acc, slice, now));
	return true;
}

void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	struct flow_cpu_state *cs;
	u32 llc;

	if (!flow_cpu_valid(cpu))
		return;
	llc = flow_llc_of(cpu);

	if (flow_keep_prev(cpu, llc, prev, false)) {
		flow_stat_inc(FLOW_STAT_KEEP);
		return;
	}
	/* Tasks without a context are rare and would starve behind the rest. */
	if ((READ_ONCE(flow_fallback_used) && scx_bpf_dsq_move_to_local(FLOW_FALLBACK_DSQ, 0)) ||
	    flow_consume_local(cpu, llc)) {
		flow_stat_inc(FLOW_STAT_DISPATCHED);
		return;
	}
	if (flow_steal(cpu, llc, true) || flow_steal(cpu, llc, false)) {
		flow_stat_inc(FLOW_STAT_DISPATCHED);
		flow_stat_inc(FLOW_STAT_STEAL);
		return;
	}
	if (flow_keep_prev(cpu, llc, prev, true)) {
		flow_stat_inc(FLOW_STAT_KEEP);
		return;
	}

	/* The CPU is about to go idle: it is no preemption victim anymore. */
	cs = &flow_cpu_states[cpu];
	WRITE_ONCE(cs->lat_cri, 0);
	WRITE_ONCE(cs->est_stopping_clk, 0);
	if (flow_helicoprion && !READ_ONCE(cs->idled))
		WRITE_ONCE(cs->idled, 1);
	if (!READ_ONCE(cs->idle_start_clk))
		WRITE_ONCE(cs->idle_start_clk, flow_now());

	/* Come back for the entries left in the strand of the LLC. */
	if (flow_helix_queued(llc))
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	struct flow_cpu_state *cs;
	u64 now;

	if (!t || !flow_cpu_valid(cpu))
		return;

	now = flow_now();
	if ((!flow_long_burst(t->acc_runtime_ns) || flow_cgrp_active()) &&
	    (!flow_helicoprion ||
	     time_after(t->vtime, READ_ONCE(flow_clock.vtime_now) + FLOW_VTIME_GRAIN_NS)))
		flow_advance_vtime_now(t->vtime);
	flow_clear_pinned(t);
	t->last_running_clk = now;
	/* --performance charges from here, see flow_stopping(). */
	if (flow_performance)
		t->sum_exec_ns = p->se.sum_exec_runtime;

	cs = &flow_cpu_states[cpu];
	WRITE_ONCE(cs->lat_cri, t->lat_cri);
	WRITE_ONCE(cs->est_stopping_clk, flow_est_stop(t, t->acc_runtime_ns, p->scx.slice, now));
	if (flow_performance) {
		u64 idle_start = READ_ONCE(cs->idle_start_clk);

		if (idle_start && time_after(now, idle_start))
			WRITE_ONCE(cs->idle_ns, cs->idle_ns + now - idle_start);
	}
	WRITE_ONCE(cs->idle_start_clk, 0);
	if (flow_helicoprion || flow_performance)
		WRITE_ONCE(cs->burst_start_clk, now - t->acc_runtime_ns);
	if (t->lat_cri > READ_ONCE(cs->max_lat_cri))
		WRITE_ONCE(cs->max_lat_cri, t->lat_cri);
	__sync_fetch_and_add(&cs->sum_lat_cri, t->lat_cri);
	__sync_fetch_and_add(&cs->nr_sched, 1);

	if (READ_ONCE(cs->cpuperf_cur) != SCX_CPUPERF_ONE)
		flow_cpuperf_commit(cpu, cs, SCX_CPUPERF_ONE, now);
}

void BPF_STRUCT_OPS(flow_tick, struct task_struct *p)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	struct flow_cpu_state *cs;
	u64 now, deadline, base;

	if (!t || !flow_cpu_valid(cpu))
		return;
	cs = &flow_cpu_states[cpu];

	now = flow_now();
	if (now - READ_ONCE(cs->cpuperf_commit_clk) >= FLOW_CPUPERF_REFRESH_NS)
		flow_cpuperf_commit(cpu, cs, SCX_CPUPERF_ONE, now);

	/*
	 * A task that is still running a minimum slice after it started is no
	 * waker that is about to sleep. A shorter run can be two tasks that
	 * briefly poll for each other on two CPUs, which says nothing about
	 * how they behave once they share one.
	 */
	if (flow_helicoprion && flow_ran(t, now) >= FLOW_SLICE_MIN_NS)
		t->sync_score = 0;

	/*
	 * Once the task had a minimum slice, give the CPU to a waiting task
	 * with an earlier deadline. Comparing against the deadline the task
	 * started with lets equally urgent tasks run their slices out.
	 */
	deadline = p->scx.dsq_vtime;
	if (flow_ran(t, now) >= FLOW_SLICE_MIN_NS &&
	    (flow_queued_ahead(FLOW_CPU_DSQ_BASE + cpu, deadline, cpu) ||
	     flow_llc_ahead(flow_llc_of(cpu), deadline, cpu))) {
		scx_bpf_task_set_slice(p, 0);
		return;
	}

	/* A pinned task cannot go elsewhere, so cut a long slice short for it. */
	base = READ_ONCE(flow_sys_stat.slice_ns);
	if (READ_ONCE(cs->nr_pinned) && p->scx.slice > base)
		scx_bpf_task_set_slice(p, base);
}

/*
 * With --performance, @p is charged the CPU time that the kernel accounted
 * for its run. The kernel brings that time up to date right before this,
 * from the clock of the runqueue of @p, which was updated for the switch,
 * so the charge is exact and the clock is not read once more.
 */
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	u64 used;

	if (!t)
		return;

	if (flow_performance)
		used = p->se.sum_exec_runtime - t->sum_exec_ns;
	else
		used = t->last_running_clk ? flow_ran(t, flow_now()) : 0;
	flow_charge_run(p, t, used);

	if (runnable)
		flow_stat_inc(FLOW_STAT_PREEMPTED);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct flow_task_ctx *t;

	t = bpf_task_storage_get(&task_ctx_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!t)
		return -ENOMEM;
	t->vtime = READ_ONCE(flow_clock.vtime_now);
	t->sum_exec_ns = p->se.sum_exec_runtime;
	t->cgrp_factor = FLOW_FACTOR_ONE;
	t->lat_cri = 1;
	t->pinned_cpu = -1;
	t->flags = FLOW_FLAG_NEW;
	return 0;
}

/*
 * Keep the cpu.weight of @cgrp for flow_refresh_cgrp(). A cgroup whose
 * storage cannot be allocated is charged with a factor of one, which is
 * no reason to fail the load of the scheduler or the creation of the
 * cgroup.
 */
static __always_inline void flow_set_cgrp_weight(struct cgroup *cgrp, u32 weight)
{
	struct flow_cgrp_ctx *cc;

	cc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (cc)
		WRITE_ONCE(cc->weight, weight);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_cgroup_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	flow_set_cgrp_weight(cgrp, args->weight);
	return 0;
}

void BPF_STRUCT_OPS(flow_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	flow_set_cgrp_weight(cgrp, weight);
}

/*
 * Largest L3 among the LLCs if the LLCs differ in size, zero if they are
 * all the same or any size is unknown.
 */
static u32 flow_big_cache_kb(void)
{
	u32 llc, kb, min_kb = 0, max_kb = 0;

	bpf_for(llc, 0, flow_nr_llcs) {
		if (llc >= FLOW_MAX_LLCS)
			break;
		kb = flow_llc_kb[llc];
		if (!kb)
			return 0;
		if (!min_kb || kb < min_kb)
			min_kb = kb;
		if (kb > max_kb)
			max_kb = kb;
	}
	return max_kb > min_kb ? max_kb : 0;
}

static s32 flow_init_cpus(void)
{
	u32 cpu, big_kb = flow_big_cache_kb();

	flow_has_big_cache = big_kb;
	bpf_for(cpu, 0, flow_nr_cpus) {
		struct bpf_cpumask *mask;
		s32 ret;

		if (cpu >= FLOW_MAX_CPUS)
			break;
		ret = scx_bpf_create_dsq(FLOW_CPU_DSQ_BASE + cpu, -1);
		if (ret) {
			scx_bpf_error("failed to create the DSQ of CPU %u (%d)", cpu, ret);
			return ret;
		}

		if (big_kb && flow_llc_kb[flow_llc_of(cpu)] == big_kb)
			bpf_cpumask_set_cpu(cpu, &flow_big_cache_cpumask);

		mask = MEMBER_VPTR(flow_llc_cpumask, [flow_llc_of(cpu)]);
		if (mask)
			bpf_cpumask_set_cpu(cpu, mask);
		if (flow_nr_groups > flow_nr_llcs) {
			mask = MEMBER_VPTR(flow_group_cpumask, [flow_cpu_group[cpu]]);
			if (mask)
				bpf_cpumask_set_cpu(cpu, mask);
		}
	}
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	struct flow_timer *ft;
	u32 llc, zero = 0;
	s32 ret;

	if (!flow_nr_cpus || flow_nr_cpus > FLOW_MAX_CPUS ||
	    !flow_nr_llcs || flow_nr_llcs > FLOW_MAX_LLCS ||
	    flow_nr_groups > FLOW_MAX_GROUPS) {
		scx_bpf_error("invalid topology: %u CPUs, %u LLCs, %u groups",
			      flow_nr_cpus, flow_nr_llcs, flow_nr_groups);
		return -EINVAL;
	}

	WRITE_ONCE(flow_sys_stat.slice_ns, FLOW_SLICE_MAX_NS);

	ret = flow_init_cpus();
	if (ret)
		return ret;

	bpf_for(llc, 0, flow_nr_llcs) {
		ret = scx_bpf_create_dsq(FLOW_LLC_DSQ_BASE + llc, -1);
		if (ret) {
			scx_bpf_error("failed to create the DSQ of LLC %u (%d)", llc, ret);
			return ret;
		}
	}

	ret = scx_bpf_create_dsq(FLOW_FALLBACK_DSQ, -1);
	if (ret) {
		scx_bpf_error("failed to create the fallback DSQ (%d)", ret);
		return ret;
	}

	ft = bpf_map_lookup_elem(&stat_timer, &zero);
	if (!ft) {
		scx_bpf_error("failed to look up the stat timer");
		return -ESRCH;
	}
	bpf_timer_init(&ft->timer, &stat_timer, FLOW_CLOCK_BOOTTIME);
	bpf_timer_set_callback(&ft->timer, flow_stat_timer_fn);
	ret = bpf_timer_start(&ft->timer, FLOW_STAT_INTERVAL_NS, 0);
	if (ret) {
		scx_bpf_error("failed to start the stat timer (%d)", ret);
		return ret;
	}
	return 0;
}

void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

#endif /* __FLOW_DISPATCH_BPF_H */
