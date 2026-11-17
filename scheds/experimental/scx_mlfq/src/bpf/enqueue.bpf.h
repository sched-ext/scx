// SPDX-License-Identifier: GPL-2.0
/*
 * Queueing for the mlfq scheduler.
 *
 * Pinned tasks wait in the DSQ of their CPU and everything else waits in
 * the DSQ of the LLC of its CPU, both ordered by virtual deadline. Every
 * path through ops.enqueue() inserts the task exactly once.
 *
 * After the insert, mlfq looks for an idle CPU to wake up. If there is
 * none, a task that just woke up on the top level takes the CPU of a task
 * of another process that sank deep, right away. Otherwise, if the task
 * is urgent enough, it asks the running task with the lowest latency
 * criticality in the LLC to give up its CPU. That request shortens the
 * slice of the task instead of sending an IPI, so the CPU switches at its
 * next scheduling point.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __MLFQ_ENQUEUE_BPF_H
#define __MLFQ_ENQUEUE_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"
#include "select.bpf.h"

struct mlfq_victim {
	s32	cpu;
	u32	lat_cri;
	u64	est_stop;
};

static __always_inline void mlfq_mark_pinned(struct mlfq_task_ctx *t, s32 cpu)
{
	if (t->pinned_cpu >= 0)
		return;
	t->pinned_cpu = cpu;
	__sync_fetch_and_add(&mlfq_cpu_states[cpu].nr_pinned, 1);
}

static __always_inline void mlfq_clear_pinned(struct mlfq_task_ctx *t)
{
	s32 cpu = t->pinned_cpu;

	if (cpu < 0)
		return;
	t->pinned_cpu = -1;
	if (mlfq_cpu_valid(cpu))
		__sync_fetch_and_sub(&mlfq_cpu_states[cpu].nr_pinned, 1);
}

/*
 * Wake up an idle CPU that can run @p. A pinned task can only use @cpu.
 * When ops.select_cpu() already looked for an idle CPU and found none,
 * there is no point in searching again.
 */
static bool mlfq_kick_idle(struct task_struct *p, const struct mlfq_task_ctx *t, s32 cpu,
			   bool pinned, u64 enq_flags)
{
	s32 idle;

	if (pinned)
		idle = scx_bpf_test_and_clear_cpu_idle(cpu) ? cpu : -EBUSY;
	else if (!__COMPAT_is_enq_cpu_selected(enq_flags))
		idle = mlfq_pick_idle_cpu(p, t, cpu, 0);
	else
		return false;

	if (idle < 0)
		return false;
	scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
	mlfq_stat_inc(MLFQ_STAT_KICK_IDLE);
	return true;
}

/*
 * A CPU is a victim candidate when its task is less latency critical than
 * the enqueued one and is expected to keep the CPU for longer. A CPU with
 * no stop stamp is idle or was already claimed by another enqueue.
 */
static bool mlfq_probe_victim(s32 cpu, u32 lat_cri, u64 est_stop, struct mlfq_victim *v)
{
	struct mlfq_cpu_state *cs;
	u64 stop;
	u32 victim_lat_cri;

	if (!mlfq_cpu_valid(cpu))
		return false;
	cs = &mlfq_cpu_states[cpu];
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
static bool mlfq_ask_yield(const struct mlfq_victim *v)
{
	struct task_struct *curr;
	bool asked = false;

	if (!mlfq_cpu_valid(v->cpu))
		return false;
	if (!__sync_bool_compare_and_swap(&mlfq_cpu_states[v->cpu].est_stopping_clk,
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
static void mlfq_try_preempt(struct task_struct *p, struct mlfq_task_ctx *t, s32 cpu, u32 llc)
{
	struct mlfq_victim cand[2];
	struct bpf_cpumask *llc_mask;
	u64 thr = READ_ONCE(mlfq_sys_stat.thr_lat_cri);
	u64 est_stop;
	u32 nr = 0, i;

	if (!thr || t->lat_cri < thr)
		return;

	est_stop = mlfq_est_stop(t, t->acc_runtime_ns, READ_ONCE(mlfq_sys_stat.slice_ns),
				 scx_bpf_now());
	if (mlfq_probe_victim(cpu, t->lat_cri, est_stop, &cand[0]))
		nr = 1;

	llc_mask = MEMBER_VPTR(mlfq_llc_cpumask, [llc]);
	if (llc_mask) {
		bpf_for(i, 0, MLFQ_VICTIM_PROBES) {
			s32 probe;

			if (nr >= 2)
				break;
			probe = bpf_cpumask_any_and_distribute(cast_mask(llc_mask), p->cpus_ptr);
			if (probe == cpu || (nr && probe == cand[0].cpu))
				continue;
			if (mlfq_probe_victim(probe, t->lat_cri, est_stop,
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
	if (mlfq_ask_yield(&cand[0]))
		mlfq_stat_inc(MLFQ_STAT_KICK_PREEMPT);
}

/*
 * Claim @cpu when its task has sunk to MLFQ_PREEMPT_LEVEL by @now, has
 * had MLFQ_PREEMPT_MIN_RUN_NS since it started or was kept and is not in
 * the thread group @tgid. Tasks that only lost the top level because a
 * busy queue kept preempting them are left alone, and the minimum run
 * keeps a stream of wakeups from bouncing a task that only just got a CPU.
 * The threads of one process share locks and work, as when the workers of
 * a game spin on a job queue, and taking the CPU of one of them at once
 * tends to delay the very work its siblings wait for, so they are
 * preempted at the tick instead. Clearing the run stamp makes concurrent
 * enqueues pick another CPU, and the stamp comes back once the CPU starts
 * or keeps a task. Returns the cleared stamp, or zero when the CPU was not
 * claimed.
 */
static u64 mlfq_claim_lower(s32 cpu, u64 now, s32 tgid)
{
	struct mlfq_cpu_state *cs;
	struct task_struct *curr;
	u64 start, ran;
	bool other;

	if (!mlfq_cpu_valid(cpu))
		return 0;
	cs = &mlfq_cpu_states[cpu];
	start = READ_ONCE(cs->run_start_clk);
	if (!start || !time_after(now, start))
		return 0;
	ran = now - start;
	if (ran < MLFQ_PREEMPT_MIN_RUN_NS ||
	    (u64)READ_ONCE(cs->run_acc_ms) * MLFQ_NSEC_PER_MSEC + ran <
	    mlfq_level_start(MLFQ_PREEMPT_LEVEL))
		return 0;
	bpf_rcu_read_lock();
	curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	other = curr && curr->tgid != tgid;
	bpf_rcu_read_unlock();
	if (!other)
		return 0;
	return __sync_bool_compare_and_swap(&cs->run_start_clk, start, 0) ? start : 0;
}

/*
 * Tasks queued in @dsq_id that are due before @deadline, counted up to
 * MLFQ_PREEMPT_MAX_AHEAD.
 */
static u32 mlfq_nr_ahead(u64 dsq_id, u64 deadline)
{
	struct task_struct *q;
	u32 nr = 0;

	bpf_for_each(scx_dsq, q, dsq_id, 0) {
		if (nr >= MLFQ_PREEMPT_MAX_AHEAD || !time_before(q->scx.dsq_vtime, deadline))
			break;
		nr++;
	}
	return nr;
}

/*
 * A task that wakes up on the top level outranks the tasks that sank
 * deep, so when it finds no idle CPU it takes the CPU of such a task of
 * another process in its LLC right away instead of waiting for that CPU's
 * next tick. Tasks on nearby levels and deep tasks of the same process
 * still yield at the tick. Kicked CPUs serve the DSQ in deadline order, so
 * this only pays off while few queued tasks are due before @deadline, as
 * when a task wakes up several workers at once. Walking the DSQ takes its
 * lock, so it only happens once a victim was found. The insert of @p only
 * lands once ops.enqueue() returns, so @p itself is not in the DSQ yet.
 * @cpu is tried first, then a few random CPUs. A pinned task can only use
 * @cpu.
 */
static bool mlfq_preempt_lower(struct task_struct *p, const struct mlfq_task_ctx *t, s32 cpu,
			       u64 dsq_id, u64 deadline, u32 llc, bool pinned, u64 enq_flags)
{
	struct bpf_cpumask *llc_mask;
	s32 victim = -1;
	u64 now, stamp;
	u32 i;

	if (!(enq_flags & SCX_ENQ_WAKEUP) || !mlfq_top_level(t->acc_runtime_ns))
		return false;

	now = scx_bpf_now();
	stamp = mlfq_claim_lower(cpu, now, p->tgid);
	if (stamp) {
		victim = cpu;
	} else if (!pinned) {
		llc_mask = MEMBER_VPTR(mlfq_llc_cpumask, [llc]);
		if (!llc_mask)
			return false;
		bpf_for(i, 0, MLFQ_VICTIM_PROBES) {
			s32 probe = bpf_cpumask_any_and_distribute(cast_mask(llc_mask),
								   p->cpus_ptr);

			if (probe == cpu)
				continue;
			stamp = mlfq_claim_lower(probe, now, p->tgid);
			if (stamp) {
				victim = probe;
				break;
			}
		}
	}
	if (!mlfq_cpu_valid(victim))
		return false;
	/* Hand the claim back unless the CPU moved on to another task meanwhile. */
	if (mlfq_nr_ahead(dsq_id, deadline) >= MLFQ_PREEMPT_MAX_AHEAD) {
		__sync_bool_compare_and_swap(&mlfq_cpu_states[victim].run_start_clk, 0, stamp);
		return false;
	}

	scx_bpf_kick_cpu(victim, SCX_KICK_PREEMPT);
	mlfq_stat_inc(MLFQ_STAT_KICK_LOWER);
	return true;
}

void BPF_STRUCT_OPS(mlfq_runnable, struct task_struct *p, u64 enq_flags)
{
	struct mlfq_task_ctx *t, *wt;
	struct task_struct *waker;
	u64 now;

	if (!(enq_flags & SCX_ENQ_WAKEUP))
		return;
	t = mlfq_task_ctx(p);
	if (!t)
		return;

	/* Waking up starts a new burst on the top level. */
	if (!mlfq_top_level(t->acc_runtime_ns))
		mlfq_stat_inc(MLFQ_STAT_PROMOTED);
	t->acc_runtime_ns = 0;

	waker = bpf_get_current_task_btf();
	wt = mlfq_task_ctx(waker);
	if (!wt)
		return;

	now = scx_bpf_now();
	if (wt->last_wake_clk && time_after(now, wt->last_wake_clk))
		wt->wake_freq = mlfq_calc_avg_freq(wt->wake_freq, now - wt->last_wake_clk);
	wt->last_wake_clk = now;

	t->lat_cri_waker = wt->lat_cri;
	wt->lat_cri_wakee = t->lat_cri;
}

void BPF_STRUCT_OPS(mlfq_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct mlfq_task_ctx *t = mlfq_task_ctx(p);
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

	if (!t || !mlfq_cpu_valid(cpu)) {
		scx_bpf_dsq_insert(p, MLFQ_FALLBACK_DSQ, MLFQ_SLICE_MIN_NS, enq_flags);
		mlfq_stat_inc(MLFQ_STAT_FALLBACK);
		return;
	}

	pinned = mlfq_is_pinned(p);
	llc = mlfq_llc_of(cpu);
	deadline = mlfq_score_task(p, t);
	slice = mlfq_calc_slice(t, cpu);
	if (pinned) {
		mlfq_mark_pinned(t, cpu);
		dsq_id = MLFQ_CPU_DSQ_BASE + cpu;
	} else {
		dsq_id = MLFQ_LLC_DSQ_BASE + llc;
	}
	scx_bpf_dsq_insert_vtime(p, dsq_id, slice, deadline, enq_flags);

	/*
	 * The last runnable task of a CPU whose slice ran out is picked up
	 * again by that CPU, so waking another one would only migrate it.
	 */
	if (enq_flags & SCX_ENQ_LAST)
		return;
	if (!mlfq_kick_idle(p, t, cpu, pinned, enq_flags) &&
	    !mlfq_preempt_lower(p, t, cpu, dsq_id, deadline, llc, pinned, enq_flags))
		mlfq_try_preempt(p, t, cpu, llc);
}

void BPF_STRUCT_OPS(mlfq_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct mlfq_task_ctx *t = mlfq_task_ctx(p);
	u64 now;

	if (!t)
		return;

	/* A pinned task can leave its DSQ without running, e.g. on an affinity change. */
	mlfq_clear_pinned(t);

	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	/* The burst ends here, so it can be folded in as a whole. */
	t->avg_runtime_ns = mlfq_calc_avg(t->avg_runtime_ns, t->acc_runtime_ns);

	now = scx_bpf_now();
	if (t->last_quiescent_clk && time_after(now, t->last_quiescent_clk))
		t->wait_freq = mlfq_calc_avg_freq(t->wait_freq, now - t->last_quiescent_clk);
	t->last_quiescent_clk = now;
}

#endif /* __MLFQ_ENQUEUE_BPF_H */
