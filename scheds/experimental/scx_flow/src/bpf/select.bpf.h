// SPDX-License-Identifier: GPL-2.0
/*
 * Wakeup placement for the flow scheduler.
 *
 * The kernel's idle CPU picker already walks the topology in the order
 * flow wants: the previous CPU if its core is fully idle, a fully idle
 * core in the same LLC, then in the same node, then anywhere, and only
 * then partially idle cores. Flow adds two steps in front of it.
 *
 * On a CPU whose LLCs differ in size, a latency critical task that last
 * ran outside of the largest LLC first tries a fully idle core in it, so
 * that the tasks that matter most for responsiveness keep their working
 * set in the biggest cache. Then, when the LLCs are split into smaller
 * core groups, a fully idle core in the group of the previous CPU is
 * tried.
 *
 * A wakeup that wins an idle CPU goes straight to its local DSQ, and the
 * kernel then skips ops.enqueue() for that wakeup. With --helicoprion, the
 * partner of a waker with tiny bursts tries to take over the CPU of the
 * waker first, see flow_sync_handoff(), and then the idle hardware thread
 * next to it. With --performance, the kernel may queue a wakeup to the CPU
 * of the wakee, so the waker is noted here rather than in ops.runnable(),
 * see flow_note_waker().
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_SELECT_BPF_H
#define __FLOW_SELECT_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

static __always_inline void flow_tag_wakeup(struct flow_task_ctx *t, u64 wake_flags)
{
	u32 flags = t->flags & ~(FLOW_FLAG_SYNC_WAKEUP | FLOW_FLAG_HARDIRQ_WAKEUP |
				 FLOW_FLAG_SOFTIRQ_WAKEUP);

	if (wake_flags & SCX_WAKE_SYNC)
		flags |= FLOW_FLAG_SYNC_WAKEUP;
	if (bpf_in_hardirq() || bpf_in_nmi())
		flags |= FLOW_FLAG_HARDIRQ_WAKEUP;
	else if (bpf_in_serving_softirq())
		flags |= FLOW_FLAG_SOFTIRQ_WAKEUP;
	t->flags = flags;
}

static bool flow_wants_big_cache(const struct flow_task_ctx *t, s32 prev_cpu)
{
	return flow_has_big_cache &&
	       t->lat_cri >= READ_ONCE(flow_sys_stat.avg_lat_cri) &&
	       !bpf_cpumask_test_cpu(prev_cpu, cast_mask(&flow_big_cache_cpumask));
}

/* Claim an idle CPU for @p, or return a negative value if there is none. */
static s32 flow_pick_idle_cpu(struct task_struct *p, const struct flow_task_ctx *t,
			      s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (flow_wants_big_cache(t, prev_cpu)) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
					     cast_mask(&flow_big_cache_cpumask),
					     SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			return cpu;
	}
	if (flow_nr_groups > flow_nr_llcs && flow_cpu_valid(prev_cpu)) {
		struct bpf_cpumask *group;

		group = MEMBER_VPTR(flow_group_cpumask, [flow_cpu_group[prev_cpu]]);
		if (group) {
			cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
						     cast_mask(group), SCX_PICK_IDLE_CORE);
			if (cpu >= 0)
				return cpu;
		}
	}
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * The other hardware thread of @cpu is busy at @now while a whole core is
 * idle, so a task running on @cpu would be faster on that core. The
 * sibling only counts when it did not go idle during the whole last period
 * or when its CPU is being handed back and forth as well. A task that
 * occupies the sibling for a moment does not count, or every short task
 * that runs next to a hand-off would move it.
 */
static __always_inline bool flow_smt_contended(s32 cpu, u64 now)
{
	const struct cpumask *idle;
	u32 sib = flow_cpu_sibling[cpu];
	struct flow_cpu_state *cs;
	bool contended = false;

	if (sib == cpu || sib >= FLOW_MAX_CPUS)
		return false;
	cs = &flow_cpu_states[sib];
	if (READ_ONCE(cs->idle_start_clk) ||
	    (!READ_ONCE(cs->busy) && now - READ_ONCE(cs->handoff_clk) > FLOW_SLICE_MIN_NS))
		return false;

	idle = scx_bpf_get_idle_cpumask();
	if (!bpf_cpumask_test_cpu(sib, idle)) {
		const struct cpumask *idle_smt = scx_bpf_get_idle_smtmask();

		contended = !bpf_cpumask_empty(idle_smt);
		scx_bpf_put_idle_cpumask(idle_smt);
	}
	scx_bpf_put_idle_cpumask(idle);
	return contended;
}

/*
 * A waker that keeps going to sleep right after it wakes up a related task,
 * as the two sides of a request and its reply do, is about to leave its
 * CPU, so the wakee takes that CPU over. It skips the IPI and the idle
 * exit of another CPU and finds what the waker just wrote still in the
 * cache. Only the partner of the waker qualifies, see flow_select_cpu(),
 * so a waker that wakes up a whole group of tasks does not pile them up on
 * its own CPU. Only tasks with tiny bursts take part. Threads that hand
 * frames or work items to each other run far longer, and moving them onto
 * one CPU makes them wait for each other. While a whole core is idle, a
 * CPU whose other hardware thread is kept busy is not handed over: the
 * wakee goes to the idle core and its waker follows it there at the next
 * hand-off.
 *
 * While some CPU still goes idle, the waker goes to sleep on its own and
 * its slice is trimmed, so that a wrong guess delays the wakee by
 * FLOW_SYNC_SLICE_NS at most. Once no CPU was idle at any time in a period
 * while tasks waited, every sleep and wakeup costs more because the CPUs
 * are shared, and a waker that does not sleep after all would wait for a
 * CPU anyway. The wakee then preempts the waker, which goes back to the
 * local DSQ and finds the reply when it resumes, instead of sleeping and
 * being woken up for it. Both get FLOW_SYNC_SLICE_NS, so neither holds the
 * CPU for long if the guess was wrong.
 *
 * Tasks already in the local DSQ of the CPU or in its own DSQ, or a task of
 * the LLC that is due a maximum slice before the wakee and has already
 * waited for a tick, are not skipped. The wakee then waits in the DSQ of
 * the CPU, where ops.dispatch() weighs it against them as it does for
 * pinned tasks. If it went to the local DSQ while the DSQ of the CPU holds
 * tasks, hand-offs that go back and forth could keep ops.dispatch() from
 * ever running, and those tasks would wait. A task that has just woken up
 * is left to the tick of a busy CPU, as it would be without hand-offs,
 * rather than delaying the hand-off.
 */
static bool flow_sync_handoff(struct task_struct *p, struct flow_task_ctx *t,
			      struct task_struct *waker, struct flow_task_ctx *wt, u64 now)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct task_struct *head = NULL;
	u64 deadline;
	s32 queued;
	u32 llc;

	if (wt->sync_score < FLOW_SYNC_SCORE_MIN ||
	    t->avg_runtime_ns >= FLOW_SYNC_WAKE_NS || wt->avg_runtime_ns >= FLOW_SYNC_WAKE_NS ||
	    t->flags & (FLOW_FLAG_HARDIRQ_WAKEUP | FLOW_FLAG_SOFTIRQ_WAKEUP) ||
	    !flow_cpu_valid(cpu) || !flow_may_run_on(p, cpu))
		return false;

	queued = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL);

	/* The queue length is sampled, so only look at the DSQ when it was in use. */
	llc = flow_llc_of(cpu);
	if (READ_ONCE(flow_llc_nr_queued[llc]))
		head = __COMPAT_scx_bpf_dsq_peek(FLOW_LLC_DSQ_BASE + llc);
	else if (flow_smt_contended(cpu, now))
		return false;

	deadline = flow_handoff_deadline(p, t, now);
	WRITE_ONCE(flow_cpu_states[cpu].handoff_clk, now);

	if (queued || READ_ONCE(flow_cpu_states[cpu].nr_pinned) ||
	    scx_bpf_dsq_nr_queued(FLOW_CPU_DSQ_BASE + cpu) > 0 ||
	    (head && time_before(head->scx.dsq_vtime, deadline - FLOW_SLICE_MAX_NS) &&
	     time_after(bpf_jiffies64(), head->scx.runnable_at + 1) &&
	     bpf_cpumask_test_cpu(cpu, head->cpus_ptr))) {
		scx_bpf_dsq_insert_vtime(p, FLOW_CPU_DSQ_BASE + cpu, FLOW_SYNC_SLICE_NS, deadline,
					 0);
	} else if (head && READ_ONCE(flow_sys_stat.saturated)) {
		wt->flags |= FLOW_FLAG_YIELDED;
		scx_bpf_task_set_dsq_vtime(p, deadline);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, FLOW_SYNC_SLICE_NS, SCX_ENQ_PREEMPT);
		return true;
	} else {
		scx_bpf_task_set_dsq_vtime(p, deadline);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, FLOW_SYNC_SLICE_NS, 0);
	}
	if (waker->scx.slice > FLOW_SYNC_SLICE_NS)
		scx_bpf_task_set_slice(waker, FLOW_SYNC_SLICE_NS);
	return true;
}

/*
 * When @p, the partner of @waker, cannot take over the CPU of the waker, it
 * can still run on the other hardware thread of that core if it is idle.
 * The two share the L1 and L2 caches of the core, so what the waker wrote is
 * close to the wakee, and a tiny wakee slows the core of its waker only for
 * a moment. Returns the CPU claimed for @p, or a negative value if there is
 * none.
 */
static s32 flow_claim_sibling(const struct task_struct *p, const struct flow_task_ctx *t,
			      const struct flow_task_ctx *wt)
{
	s32 cpu = bpf_get_smp_processor_id();
	u32 sib;

	if (!flow_cpu_valid(cpu) || t->avg_runtime_ns >= FLOW_SYNC_WAKE_NS ||
	    wt->avg_runtime_ns >= FLOW_SYNC_WAKE_NS)
		return -EBUSY;

	sib = flow_cpu_sibling[cpu];
	if (sib == cpu || sib >= FLOW_MAX_CPUS || !flow_may_run_on(p, sib) ||
	    !scx_bpf_test_and_clear_cpu_idle(sib))
		return -EBUSY;
	return sib;
}

/*
 * Score whether @t, which is waking up, went to sleep soon after it woke up
 * another task, as the two sides of a request and its reply do. Its burst
 * is all that it ran between its last wakeup and that sleep. A short burst
 * that woke up nobody says nothing either way: the partner of @t may have
 * been preempted by @t itself, see flow_sync_handoff(), so it was not
 * asleep when @t replied.
 */
static __always_inline void flow_learn_sync(struct flow_task_ctx *t)
{
	if (t->acc_runtime_ns >= FLOW_SYNC_WAKE_NS)
		t->sync_score >>= 1;
	else if (t->flags & FLOW_FLAG_WOKE)
		t->sync_score = flow_min(t->sync_score + FLOW_SYNC_SCORE_STEP, FLOW_SYNC_SCORE_MAX);
	t->flags &= ~(FLOW_FLAG_WOKE | FLOW_FLAG_YIELDED);
}

/*
 * With --helicoprion, ops.runnable(), ops.stopping() and ops.quiescent()
 * are not registered. Every callback adds a fixed cost to each switch, and
 * tasks that hand a CPU back and forth switch hundreds of thousands of
 * times a second, so leaving these three out shortens such a round trip by
 * about a tenth. Their work is done here instead, when @waker wakes up @p
 * at @now: the CPU time that @p used since it was last charged is charged,
 * the burst that its sleep ended is folded in and the two tasks are
 * linked. @wt is NULL when @waker has no context, as the idle task does.
 */
static __always_inline void flow_wake_task(struct task_struct *p, struct flow_task_ctx *t,
					   struct task_struct *waker, struct flow_task_ctx *wt,
					   u64 now)
{
	flow_charge_exec(p, t);
	flow_learn_sync(t);
	flow_end_burst(t, now);
	t->acc_runtime_ns = 0;
	if (!wt)
		return;
	flow_note_wakeup(t, wt, now);
	wt->flags |= FLOW_FLAG_WOKE;
	t->last_waker = waker->pid;
}

/*
 * With queued wakeups, the kernel may activate @p on its new CPU from an
 * IPI or from the idle loop, where the running task did not wake it up.
 * ops.select_cpu() still runs on the CPU of the waker, so the waker is
 * noted here, before @p is scored, and ops.runnable() leaves it alone. A
 * waker without a context, such as the idle task, is not noted, but the
 * wakeup still counts as noted, or ops.runnable() would pick an unrelated
 * task.
 */
static __always_inline void flow_note_waker(struct task_struct *p, struct flow_task_ctx *t)
{
	struct task_struct *waker = bpf_get_current_task_btf();
	struct flow_task_ctx *wt = flow_task_ctx(waker);

	t->flags |= FLOW_FLAG_NOTED;
	if (wt && waker != p)
		flow_note_wakeup(t, wt, flow_now());
}

s32 BPF_STRUCT_OPS(flow_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu = -EBUSY;

	if (!t)
		return prev_cpu;

	flow_tag_wakeup(t, wake_flags);
	if (flow_queued_wakeup && (wake_flags & SCX_WAKE_TTWU))
		flow_note_waker(p, t);
	if (flow_helicoprion && (wake_flags & SCX_WAKE_TTWU)) {
		struct task_struct *waker = bpf_get_current_task_btf();
		struct flow_task_ctx *wt = flow_task_ctx(waker);
		u64 now = flow_now();
		bool related;

		/*
		 * Only the task that last woke up the waker, and was last woken
		 * up by it in turn, takes over the CPU of the waker. Threads
		 * released by the same task, or passing work along a chain,
		 * keep running on CPUs of their own. A realtime waker, or one
		 * boosted to a realtime priority, keeps its CPU, so the wakee
		 * would only wait behind it.
		 */
		related = wt && wt->last_waker == p->pid && t->last_waker == waker->pid &&
			  waker->prio >= FLOW_MAX_RT_PRIO;

		flow_wake_task(p, t, waker, wt, now);
		if (related) {
			if (flow_sync_handoff(p, t, waker, wt, now))
				return bpf_get_smp_processor_id();
			cpu = flow_claim_sibling(p, t, wt);
		}
	}

	if (cpu < 0)
		cpu = flow_pick_idle_cpu(p, t, prev_cpu, wake_flags);
	if (cpu < 0)
		return prev_cpu;

	/* The task starts a new activation, so it has not run yet. */
	t->acc_runtime_ns = 0;
	scx_bpf_task_set_dsq_vtime(p, flow_score_task(p, t));
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, flow_calc_slice(t, cpu), 0);
	flow_stat_inc(FLOW_STAT_DIRECT);
	return cpu;
}

#endif /* __FLOW_SELECT_BPF_H */
