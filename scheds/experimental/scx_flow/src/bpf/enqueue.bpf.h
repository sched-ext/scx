// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the flow scheduler.
 *
 * Pinned tasks wait in the DSQ of their CPU and everything else waits in
 * the DSQ of the LLC of its CPU, both ordered by virtual deadline. Every
 * path through ops.enqueue() inserts the task exactly once.
 *
 * After the insert, flow looks for an idle CPU to wake up. If there is
 * none and the task is urgent enough, it asks the running task with the
 * lowest latency criticality in the LLC to give up its CPU. The request
 * shortens the slice of that task instead of sending an IPI, so the CPU
 * switches at its next scheduling point.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_ENQUEUE_BPF_H
#define __FLOW_ENQUEUE_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "select.bpf.h"

struct flow_victim {
	s32	cpu;
	u32	lat_cri;
	u64	est_stop;
};

static __always_inline void flow_mark_pinned(struct flow_task_ctx *t, s32 cpu)
{
	if (t->pinned_cpu >= 0)
		return;
	t->pinned_cpu = cpu;
	__sync_fetch_and_add(&flow_cpu_states[cpu].nr_pinned, 1);
}

static __always_inline void flow_clear_pinned(struct flow_task_ctx *t)
{
	s32 cpu = t->pinned_cpu;

	if (cpu < 0)
		return;
	t->pinned_cpu = -1;
	if (flow_cpu_valid(cpu))
		__sync_fetch_and_sub(&flow_cpu_states[cpu].nr_pinned, 1);
}

/*
 * Wake up an idle CPU that can run @p. A pinned task can only use @cpu.
 * When ops.select_cpu() already looked for an idle CPU and found none,
 * there is no point in searching again.
 */
static bool flow_kick_idle(struct task_struct *p, const struct flow_task_ctx *t, s32 cpu,
			   bool pinned, u64 enq_flags)
{
	s32 idle;

	if (pinned)
		idle = scx_bpf_test_and_clear_cpu_idle(cpu) ? cpu : -EBUSY;
	else if (!__COMPAT_is_enq_cpu_selected(enq_flags))
		idle = flow_pick_idle_cpu(p, t, cpu, 0);
	else
		return false;

	if (idle < 0)
		return false;
	scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
	flow_stat_inc(FLOW_STAT_KICK_IDLE);
	return true;
}

/*
 * A CPU is a victim candidate when its task is less latency critical than
 * the enqueued one and is expected to keep the CPU for longer. A CPU with
 * no stop stamp is idle or was already claimed by another enqueue.
 */
static bool flow_probe_victim(s32 cpu, u32 lat_cri, u64 est_stop, struct flow_victim *v)
{
	struct flow_cpu_state *cs;
	u64 stop;
	u32 victim_lat_cri;

	if (!flow_cpu_valid(cpu))
		return false;
	cs = &flow_cpu_states[cpu];
	stop = READ_ONCE(cs->est_stopping_clk);
	victim_lat_cri = READ_ONCE(cs->lat_cri);
	if (!stop || victim_lat_cri >= lat_cri || !time_after(stop, est_stop))
		return false;

	v->cpu = cpu;
	v->lat_cri = victim_lat_cri;
	v->est_stop = stop;
	return true;
}

/*
 * Claim the victim by clearing its stop stamp, so that concurrent
 * enqueues pick someone else, then shorten the slice of its task. A slice
 * of one nanosecond, rather than zero, keeps the kernel from refilling it
 * with the default slice.
 */
static bool flow_ask_yield(const struct flow_victim *v)
{
	struct task_struct *curr;
	bool asked = false;

	if (!flow_cpu_valid(v->cpu))
		return false;
	if (!__sync_bool_compare_and_swap(&flow_cpu_states[v->cpu].est_stopping_clk,
					  v->est_stop, 0))
		return false;

	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(v->cpu);
	if (curr && curr->pid)
		asked = scx_bpf_task_set_slice(curr, 1);
	bpf_rcu_read_unlock();
	return asked;
}

/*
 * Look for a victim among the CPUs of the LLC that @p can use. @cpu is
 * checked first, then a few random CPUs, and the better of the first two
 * candidates wins. Random probes keep enqueues on different CPUs from
 * all going after the same victim.
 */
static void flow_try_preempt(struct task_struct *p, struct flow_task_ctx *t, s32 cpu, u32 llc)
{
	struct flow_victim cand[2];
	struct bpf_cpumask *llc_mask;
	u64 thr = READ_ONCE(flow_sys_stat.thr_lat_cri);
	u64 est_stop;
	u32 nr = 0, i;

	if (!thr || t->lat_cri < thr)
		return;

	est_stop = flow_est_stop(t, t->acc_runtime_ns, READ_ONCE(flow_sys_stat.slice_ns),
				 scx_bpf_now());
	if (flow_probe_victim(cpu, t->lat_cri, est_stop, &cand[0]))
		nr = 1;

	llc_mask = MEMBER_VPTR(flow_llc_cpumask, [llc]);
	if (llc_mask) {
		bpf_for(i, 0, FLOW_VICTIM_PROBES) {
			s32 probe;

			if (nr >= 2)
				break;
			probe = bpf_cpumask_any_and_distribute(cast_mask(llc_mask), p->cpus_ptr);
			if (probe == cpu || (nr && probe == cand[0].cpu))
				continue;
			if (flow_probe_victim(probe, t->lat_cri, est_stop,
					      nr ? &cand[1] : &cand[0]))
				nr++;
		}
	}

	if (!nr)
		return;
	if (nr == 2 && (cand[1].lat_cri < cand[0].lat_cri ||
			(cand[1].lat_cri == cand[0].lat_cri &&
			 time_after(cand[1].est_stop, cand[0].est_stop))))
		cand[0] = cand[1];
	if (flow_ask_yield(&cand[0]))
		flow_stat_inc(FLOW_STAT_KICK_PREEMPT);
}

void BPF_STRUCT_OPS(flow_runnable, struct task_struct *p, u64 enq_flags)
{
	struct flow_task_ctx *t, *wt;
	struct task_struct *waker;
	u64 now;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;
	t = flow_task_ctx(p);
	if (!t)
		return;
	t->acc_runtime_ns = 0;

	waker = bpf_get_current_task_btf();
	wt = flow_task_ctx(waker);
	if (!wt)
		return;

	now = scx_bpf_now();
	if (wt->last_wake_clk && time_after(now, wt->last_wake_clk))
		wt->wake_freq = flow_calc_avg_freq(wt->wake_freq, now - wt->last_wake_clk);
	wt->last_wake_clk = now;

	t->lat_cri_waker = wt->lat_cri;
	wt->lat_cri_wakee = t->lat_cri;
}

void BPF_STRUCT_OPS(flow_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	s32 cpu = scx_bpf_task_cpu(p);
	u64 deadline, slice, dsq_id;
	bool pinned;
	u32 llc;

	/*
	 * An affinity change re-enqueues the task before it is migrated, so
	 * its current CPU can be outside of the new mask.
	 */
	if (!bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		cpu = bpf_cpumask_first(p->cpus_ptr);

	if (!t || !flow_cpu_valid(cpu)) {
		scx_bpf_dsq_insert(p, FLOW_FALLBACK_DSQ, FLOW_SLICE_MIN_NS, enq_flags);
		flow_stat_inc(FLOW_STAT_FALLBACK);
		return;
	}

	pinned = flow_is_pinned(p);
	llc = flow_llc_of(cpu);
	deadline = flow_score_task(p, t);
	slice = flow_calc_slice(t, cpu);
	if (pinned) {
		flow_mark_pinned(t, cpu);
		dsq_id = FLOW_CPU_DSQ_BASE + cpu;
	} else {
		dsq_id = FLOW_LLC_DSQ_BASE + llc;
	}
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, deadline, enq_flags);

	/*
	 * The last runnable task of a CPU whose slice ran out is picked up
	 * again by that CPU, so waking another one would only migrate it.
	 */
	if (enq_flags & SCX_ENQ_LAST)
		return;
	if (!flow_kick_idle(p, t, cpu, pinned, enq_flags))
		flow_try_preempt(p, t, cpu, llc);
}

void BPF_STRUCT_OPS(flow_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct flow_task_ctx *t = flow_task_ctx(p);
	u64 now;

	if (!t)
		return;

	/* A pinned task can leave its DSQ without running, e.g. on an affinity change. */
	flow_clear_pinned(t);

	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	/* The burst ends here, so it can be folded in as a whole. */
	t->avg_runtime_ns = flow_calc_avg(t->avg_runtime_ns, t->acc_runtime_ns);

	now = scx_bpf_now();
	if (t->last_quiescent_clk && time_after(now, t->last_quiescent_clk))
		t->wait_freq = flow_calc_avg_freq(t->wait_freq, now - t->last_quiescent_clk);
	t->last_quiescent_clk = now;
}

#endif /* __FLOW_ENQUEUE_BPF_H */
