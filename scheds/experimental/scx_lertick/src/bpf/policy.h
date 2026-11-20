/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Hungyu Lin <dennylin0707@gmail.com>
 *
 * scx_lertick scheduling policy: per-LLC queues, continuation of the running
 * task, cache-affine pick, sync wakeups and cgroup weights. Queues and CPU
 * selection follow scx_simple; cgroup weights follow scx_flatcg (Tejun Heo).
 *
 * The including file defines, before including this header:
 *   struct task_ctx with u64 runtime_start_ns, bool running, u32 rq_weight,
 *     bool cg_counted and u32 eff_weight;
 *   NSEC_PER_MSEC, LERTICK_MAX_CPUS (a power of two) and LERTICK_MAX_DOMAINS;
 *   LERTICK_MOVE_TO_LOCAL(dsq), its kernel's scx_bpf_dsq_move_to_local();
 *   LERTICK_TASK_CGROUP(p), its kernel's scx_bpf_task_cgroup().
 * It may define LERTICK_PREV_DEADLINE(p, tctx), the amount by which queued
 * tasks' vtimes include a deadline offset, to compare a running task on the
 * same terms (0 when not defined).
 */
#ifndef __LERTICK_POLICY_H
#define __LERTICK_POLICY_H

#ifndef LERTICK_PREV_DEADLINE
#define LERTICK_PREV_DEADLINE(p, tctx) 0
#endif

static u64 vtime_now;

/*
 * The clock is updated from every CPU at once. A plain read-modify-write can
 * lose an advance or, worse, write back an older value and move the clock
 * backward; tasks already ahead of it then wait behind every newly woken task
 * for seconds. Advance with an atomic add, and raise it only forward with a
 * compare-and-swap.
 */
static __always_inline void clock_advance(u64 delta)
{
	__sync_fetch_and_add(&vtime_now, delta);
}

static __always_inline void clock_raise(u64 vtime)
{
	u64 cur;
	int i;

	bpf_for(i, 0, 4)
	{
		cur = *(volatile u64 *)&vtime_now;
		if (!time_before(cur, vtime))
			return;
		if (__sync_val_compare_and_swap(&vtime_now, cur, vtime) == cur)
			return;
	}
}
/* Sum of runnable tasks' weights: the virtual clock advances by service / weight. */
static u64 runnable_weight;
/*
 * Sleeper credit: a woken task is placed at most this far behind the clock,
 * about one fixed slice, as EEVDF bounds lag to about one slice.
 */
#define LAG_NS (2ULL * NSEC_PER_MSEC)
/*
 * A queued task may sit at most AHEAD_NS (scaled by its own weight) ahead of
 * the clock, as EEVDF bounds lag in both directions, and never further than
 * the clock covers in WAIT_MAX_NS. The clock advances by service over the
 * runnable weight, about nr_cpus x 100 / runnable_weight per nanosecond, so
 * with dozens of runnable tasks a nice-19 task (weight 1, up to 2 s ahead by
 * the first bound) would wait over 10 s and trip the watchdog. The second
 * bound keeps that wait near WAIT_MAX_NS; under such load a light task gets a
 * little more than its weight's share instead of none.
 *
 * Every queued task also sits at most BEHIND_NS behind the clock, whatever
 * brought it to the queue. Only wakeups were bounded before: tasks pinned to
 * one crowded CPU each run a small fraction of it while the other CPUs move
 * the one clock ahead, so they fell seconds behind it; one of them then held
 * that CPU for a second and every task woken there (placed at the clock)
 * waited past the watchdog. In a balanced system queued tasks stay within a
 * few slices of the clock and the bound never applies.
 */
#define AHEAD_NS (20ULL * NSEC_PER_MSEC)
#define BEHIND_NS (20ULL * NSEC_PER_MSEC)
#define WAIT_MAX_NS (500ULL * NSEC_PER_MSEC)

static __always_inline u64 clamp_ahead(struct task_struct *p, u64 vtime)
{
	u32 w	   = p->scx.weight ? p->scx.weight : 1;
	u64 rw	   = runnable_weight;
	u64 ahead  = AHEAD_NS * 100 / w;
	u64 by_now = WAIT_MAX_NS / NSEC_PER_MSEC * scx_bpf_nr_cpu_ids() * 100 /
		     (rw < 100 ? 100 : rw) * NSEC_PER_MSEC;
	u64 cap;

	if (by_now < ahead)
		ahead = by_now;
	cap = vtime_now + ahead;
	if (time_before(cap, vtime))
		return cap;
	if (time_before(vtime, vtime_now - BEHIND_NS))
		return vtime_now - BEHIND_NS;
	return vtime;
}
/*
 * When taking the next task, prefer one that last ran on this CPU among the
 * first AFFINE_DEPTH queued tasks within AFFINE_WINDOW_NS of the head in
 * vtime. A preempted task then usually resumes on its own CPU instead of
 * the next CPU whose slice ends, which matters most to tasks that leave
 * others waiting on per-CPU state such as a lock; vtime order moves by at
 * most the window. A 2 ms window migrated 2.5 times as often as EEVDF under
 * schbench -m 4 -t 2; 8 ms migrates less than EEVDF.
 */
#define AFFINE_WINDOW_NS (8ULL * NSEC_PER_MSEC)
#define AFFINE_DEPTH 16
/* A sync wakeup may queue on the waker's CPU if within this much vtime of the queue head. */
#define SYNC_WINDOW_NS (2ULL * NSEC_PER_MSEC)
/* Queued tasks examined, and the longest unbroken run, when prev may keep its CPU. */
#define HEAD_SCAN 16
#define KEEP_MAX_NS (20ULL * NSEC_PER_MSEC)

/*
 * One vtime-ordered queue per last-level cache domain; DSQ id d serves domain
 * d. The loader fills cpu_domain from the cache topology; with one domain (the
 * default, or an unknown topology) this is a single shared queue. All queues
 * share one virtual clock, so vtimes compare across domains. A CPU takes work
 * from its own domain first and steals from the others when that is empty.
 */
const volatile u32	   nr_domains = 1;
const volatile u8	   cpu_domain[LERTICK_MAX_CPUS];

static __always_inline u32 domain_count(void)
{
	u32 n = nr_domains;

	if (n < 1)
		n = 1;
	return n < LERTICK_MAX_DOMAINS ? n : LERTICK_MAX_DOMAINS;
}

static __always_inline u32 domain_of(s32 cpu)
{
	u32 idx = cpu, d;

	if (idx >= LERTICK_MAX_CPUS)
		return 0;
	/* Keep the mask: clang may bound one copy of idx and index with another. */
	barrier_var(idx);
	d = cpu_domain[idx & (LERTICK_MAX_CPUS - 1)];
	return d < domain_count() ? d : 0;
}

/* Tasks queued in all domains. */
static __always_inline u64 nr_queued_all(void)
{
	u64 sum = 0;
	u32 d;

	bpf_for(d, 0, domain_count()) sum += scx_bpf_dsq_nr_queued(d);
	return sum;
}

/*
 * A sync waker is about to sleep, so its CPU is the next free one and its
 * cache holds what the wakee will read. Queue the wakee there, unless its
 * vtime is more than SYNC_WINDOW_NS after the queue head's: it would then run
 * before tasks that precede it in vtime order.
 */
static __always_inline bool sync_local(struct task_struct *p, s32 *cpu)
{
	struct bpf_iter_scx_dsq it;
	struct task_struct     *head;
	s32 this   = bpf_get_smp_processor_id();
	u64  vtime = p->scx.dsq_vtime;
	bool ok	   = true;

	if (!bpf_cpumask_test_cpu(this, p->cpus_ptr))
		return false;
	if (time_before(vtime, vtime_now - LAG_NS))
		vtime = vtime_now - LAG_NS;
	vtime = clamp_ahead(p, vtime);
	if (bpf_iter_scx_dsq_new(&it, domain_of(this), 0) == 0) {
		head = bpf_iter_scx_dsq_next(&it);
		ok   = !head ||
		     !time_before(head->scx.dsq_vtime + SYNC_WINDOW_NS, vtime);
	}
	bpf_iter_scx_dsq_destroy(&it);
	if (!ok)
		return false;
	p->scx.dsq_vtime = vtime;
	*cpu		 = this;
	return true;
}

/*
 * cgroup CPU weights (cpu.weight, systemd CPUWeight=). The hierarchy is
 * flattened as in the sched_ext scx_flatcg example (Tejun Heo, GPL-2.0): a
 * cgroup's hierarchical share (hweight) is the product, at each level, of
 * its weight over the weights of its active siblings. Lertick keeps one
 * virtual clock for all queues, so the share becomes a per-task effective weight:
 * the task's part of its cgroup's runnable weight times the cgroup's share
 * of all runnable weight. With every cgroup at the default weight, and
 * runnable tasks in one cgroup, this equals the task weight.
 */
#define HWEIGHT_ONE (1ULL << 16)

struct cgrp_ctx {
	u32 nr_active; /* this cgroup or a descendant has runnable tasks */
	u32 nr_runnable; /* runnable tasks directly in this cgroup */
	u32 weight;
	u32 hweight; /* share of the whole machine, HWEIGHT_ONE = all */
	u64 child_weight_sum; /* weights of active children */
	u64 hweight_gen;
	u64 task_weight_sum; /* weights of runnable tasks directly in this cgroup */
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cgrp_ctx);
} cgrp_ctx_stor SEC(".maps");

private(LERTICK_CGRP) struct bpf_spin_lock cgrp_lock;
static u64 hweight_gen = 1;

/* Return the context of @cgrp, or NULL. */
static __always_inline struct cgrp_ctx *cgrp_ctx(struct cgroup *cgrp)
{
	return bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0, 0);
}

/* Return the context of @cgrp's ancestor at @level, or NULL. */
static struct cgrp_ctx *cgrp_ancestor_ctx(struct cgroup *cgrp, int level)
{
	struct cgrp_ctx *cgc;

	cgrp = bpf_cgroup_ancestor(cgrp, level);
	if (!cgrp)
		return NULL;
	cgc = cgrp_ctx(cgrp);
	bpf_cgroup_release(cgrp);
	return cgc;
}

/*
 * Recompute @cgrp's hierarchical weight from the root down, unless it is
 * still current: hweight_gen changes whenever a weight or the set of active
 * cgroups does.
 */
static void cgrp_refresh_hweight(struct cgroup *cgrp, struct cgrp_ctx *cgc)
{
	int level;

	if (!cgc->nr_active || cgc->hweight_gen == hweight_gen)
		return;
	bpf_for(level, 0, cgrp->level + 1)
	{
		struct cgrp_ctx *c, *pc;
		bool		 active;

		c = cgrp_ancestor_ctx(cgrp, level);
		if (!c)
			break;
		if (!level) {
			c->hweight     = HWEIGHT_ONE;
			c->hweight_gen = hweight_gen;
			continue;
		}
		pc = cgrp_ancestor_ctx(cgrp, level - 1);
		if (!pc)
			break;
		bpf_spin_lock(&cgrp_lock);
		active = c->nr_active;
		if (active && pc->child_weight_sum) {
			c->hweight_gen = pc->hweight_gen;
			c->hweight     = (u64)pc->hweight * c->weight /
				     pc->child_weight_sum;
			if (!c->hweight)
				c->hweight = 1;
		}
		bpf_spin_unlock(&cgrp_lock);
		if (!active)
			break;
	}
}

/* A cgroup gains or loses its first or last runnable task: update active sums upward. */
static void cgrp_update_active(struct cgroup *cgrp, struct cgrp_ctx *cgc,
			       bool runnable)
{
	bool updated = false;
	int  idx;

	if (runnable) {
		if (__sync_fetch_and_add(&cgc->nr_runnable, 1))
			return;
	} else {
		if (__sync_sub_and_fetch(&cgc->nr_runnable, 1))
			return;
		cgrp_refresh_hweight(cgrp, cgc);
	}
	bpf_for(idx, 0, cgrp->level)
	{
		int		 level = cgrp->level - idx;
		struct cgrp_ctx *c, *pc = NULL;
		bool		 propagate = false;

		c			   = cgrp_ancestor_ctx(cgrp, level);
		if (!c)
			break;
		if (level) {
			pc = cgrp_ancestor_ctx(cgrp, level - 1);
			if (!pc)
				break;
		}
		bpf_spin_lock(&cgrp_lock);
		if (runnable) {
			if (!c->nr_active++) {
				updated = true;
				if (pc) {
					propagate = true;
					pc->child_weight_sum += c->weight;
				}
			}
		} else if (c->nr_active) {
			if (!--c->nr_active) {
				updated = true;
				if (pc) {
					propagate = true;
					pc->child_weight_sum -= c->weight;
				}
			}
		}
		bpf_spin_unlock(&cgrp_lock);
		if (!propagate)
			break;
	}
	if (updated)
		__sync_fetch_and_add(&hweight_gen, 1);
	if (runnable)
		cgrp_refresh_hweight(cgrp, cgc);
}

/* Add @tctx's weight to @cgrp's runnable sums, or remove it. */
static void cgrp_account(struct cgroup *cgrp, struct task_ctx *tctx,
			 bool runnable)
{
	struct cgrp_ctx *cgc = cgrp_ctx(cgrp);

	if (!cgc)
		return;
	if (runnable)
		__sync_fetch_and_add(&cgc->task_weight_sum, tctx->rq_weight);
	else
		__sync_fetch_and_sub(&cgc->task_weight_sum, tctx->rq_weight);
	cgrp_update_active(cgrp, cgc, runnable);
	tctx->cg_counted = runnable;
}

/* Count @p in its cgroup while it is runnable. */
static void cgrp_task_runnable(struct task_struct *p, struct task_ctx *tctx,
			       bool runnable)
{
	struct cgroup *cgrp;

	if (runnable == tctx->cg_counted)
		return;
	cgrp = LERTICK_TASK_CGROUP(p);
	if (!cgrp)
		return;
	cgrp_account(cgrp, tctx, runnable);
	bpf_cgroup_release(cgrp);
}

/*
 * Weight to charge service against: the task's share of its cgroup's share.
 *
 * Only the root cgroup holds both tasks and child cgroups (cgroup v2 allows
 * no internal tasks elsewhere). Its tasks, mostly kernel threads, compete by
 * their own weights, as in CFS; the child cgroups split the rest of the
 * runnable weight by their hierarchical shares. Without that split a
 * runnable root task was counted twice: a nice -20 kworker (weight 8668)
 * made every task in a child cgroup be charged about a tenth of its run,
 * and tasks ahead of the clock waited ten times longer, past the watchdog.
 */
static u32 cgrp_effective_weight(struct task_struct *p, struct task_ctx *tctx,
				 u32 weight)
{
	struct cgrp_ctx *cgc, *root;
	struct cgroup	*cgrp;
	u64		 eff, tws, rw = runnable_weight, root_tws = 0;

	if (!tctx || !tctx->cg_counted)
		return weight;
	cgrp = LERTICK_TASK_CGROUP(p);
	if (!cgrp)
		return weight;
	if (!cgrp->level) {
		bpf_cgroup_release(cgrp);
		return weight;
	}
	cgc = cgrp_ctx(cgrp);
	if (!cgc) {
		bpf_cgroup_release(cgrp);
		return weight;
	}
	root = cgrp_ancestor_ctx(cgrp, 0);
	if (root)
		root_tws = root->task_weight_sum;
	cgrp_refresh_hweight(cgrp, cgc);
	tws = cgc->task_weight_sum;
	eff = (u64)weight * cgc->hweight / HWEIGHT_ONE;
	bpf_cgroup_release(cgrp);
	rw = rw > root_tws ? rw - root_tws : 0;
	if (!tws || !rw)
		return weight;
	eff = eff * rw / tws;
	if (eff < 1)
		eff = 1;
	if (eff > 1000000)
		eff = 1000000;
	return eff;
}

/*
 * Whether the head of another domain's queue can run on @cpu and precedes
 * @vtime.
 */
static __always_inline bool other_head_before(u32 home, s32 cpu, u64 vtime)
{
	struct task_struct *q;
	u32		    n = domain_count(), i;

	bpf_for(i, 1, n)
	{
		u32 d = home + i;

		if (d >= n)
			d -= n;
		bpf_for_each(scx_dsq, q, d, 0) {
			if (bpf_cpumask_test_cpu(cpu, q->cpus_ptr) &&
			    time_before(q->scx.dsq_vtime, vtime))
				return true;
			break;
		}
	}
	return false;
}

/*
 * Whether prev should keep its CPU instead of taking the next queued task. A
 * task whose slice ends otherwise always yields, so two tasks sharing a CPU
 * alternate and get equal time whatever their weights. prev stays while its
 * vtime (its current run included, plus any deadline offset the queue uses)
 * is not after that of the first queued task that can run here. It yields
 * after KEEP_MAX_NS without a break, and when no such task is within the
 * first HEAD_SCAN queued: a task that can run only here must not wait behind
 * prev indefinitely. The own domain is scanned; when it holds nothing for
 * this CPU, the head of each other domain is compared too, since this CPU
 * would steal from it.
 */
static __always_inline bool keep_prev(struct task_struct *prev,
				      struct task_ctx *tctx, s32 cpu)
{
	struct task_struct *q;
	u64		    vtime = prev->scx.dsq_vtime, ran = 0;
	u32 weight = tctx && tctx->eff_weight ? tctx->eff_weight :
		     prev->scx.weight	      ? prev->scx.weight :
						1;
	u32 home   = domain_of(cpu);
	int n	   = 0;

	if (tctx && tctx->running &&
	    prev->se.sum_exec_runtime > tctx->runtime_start_ns)
		ran = prev->se.sum_exec_runtime - tctx->runtime_start_ns;
	if (ran >= KEEP_MAX_NS)
		return false;
	vtime += ran * 100 / weight + LERTICK_PREV_DEADLINE(prev, tctx);
	bpf_for_each(scx_dsq, q, home, 0) {
		if (n++ >= HEAD_SCAN)
			return false;
		if (bpf_cpumask_test_cpu(cpu, q->cpus_ptr))
			return !time_before(q->scx.dsq_vtime, vtime);
	}
	return !other_head_before(home, cpu, vtime);
}

/* Take a task from the next domain that has one for this CPU. */
static __always_inline bool steal(u32 home)
{
	u32 n = domain_count(), i;

	bpf_for(i, 1, n)
	{
		u32 d = home + i;

		if (d >= n)
			d -= n;
		if (LERTICK_MOVE_TO_LOCAL(d))
			return true;
	}
	return false;
}

/*
 * A sync wakee waits in a queue of the waker's CPU, which takes from it
 * before its domain queue, as it did from its local DSQ. Unlike the local
 * DSQ, other CPUs can take it:
 * one that has nothing else to run takes from the CPU queue holding the most
 * tasks, as an idle CPU pulls from a busy one in the kernel's load balancing.
 * A waker that keeps running while it wakes many tasks, as a sender does
 * when it writes to many receivers, would otherwise leave them stacked
 * behind it while other CPUs idle.
 */
#define CPU_DSQ(cpu) (0x10000ULL + (u64)(cpu))

static __always_inline s32 create_cpu_dsqs(void)
{
	u32 c;
	s32 ret;

	bpf_for(c, 0, scx_bpf_nr_cpu_ids())
	{
		ret = scx_bpf_create_dsq(CPU_DSQ(c), -1);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Queue sync wakee @p on @cpu, the waker's CPU. If tasks already wait there,
 * wake an idle CPU to take one.
 */
static __always_inline void queue_on_cpu(struct task_struct *p, s32 cpu,
					 u64 slice)
{
	scx_bpf_dsq_insert_vtime(p, CPU_DSQ(cpu), slice, p->scx.dsq_vtime, 0);
	if (scx_bpf_dsq_nr_queued(CPU_DSQ(cpu)) > 1) {
		s32 idle = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

		if (idle >= 0)
			scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
	}
}

/*
 * Take a task from the CPU queue holding the most, preferring CPUs of the
 * same domain: another domain's queue only when none here holds a task.
 */
static __always_inline bool steal_from_cpu(s32 cpu)
{
	u32 n = scx_bpf_nr_cpu_ids(), home = domain_of(cpu), i;
	s32 best = -1, far = -1;
	u64 most = 0, most_far = 0;

	bpf_for(i, 0, n)
	{
		u64 q;

		if (i >= LERTICK_MAX_CPUS)
			break;
		if ((s32)i == cpu)
			continue;
		q = scx_bpf_dsq_nr_queued(CPU_DSQ(i));
		if (domain_of(i) == home) {
			if (q > most) {
				most = q;
				best = i;
			}
		} else if (q > most_far) {
			most_far = q;
			far	 = i;
		}
	}
	if (best < 0)
		best = far;
	return best >= 0 && LERTICK_MOVE_TO_LOCAL(CPU_DSQ(best));
}

/*
 * Take the next task for this CPU: a sync wakee queued on it first. Then,
 * among the first few tasks of the domain queue whose vtime is within a
 * small window of the head, prefer one that last ran here and may still
 * have a warm cache; vtime order moves by at most the window. With the own
 * domain empty, steal from the next domain that has work, and then from
 * another CPU's queue.
 */
static __always_inline bool take_next(s32 cpu)
{
	struct task_struct *q;
	u32		    home = domain_of(cpu);
	u64		    head = 0;
	int		    n	 = 0;

	if (LERTICK_MOVE_TO_LOCAL(CPU_DSQ(cpu)))
		return true;
	bpf_for_each(scx_dsq, q, home, 0) {
		if (!n)
			head = q->scx.dsq_vtime;
		if (n >= AFFINE_DEPTH ||
		    time_before(head + AFFINE_WINDOW_NS, q->scx.dsq_vtime))
			break;
		if (scx_bpf_task_cpu(q) == cpu &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, q, SCX_DSQ_LOCAL, 0))
			return true;
		n++;
	}
	return LERTICK_MOVE_TO_LOCAL(home) || steal(home) ||
	       steal_from_cpu(cpu);
}

#endif /* __LERTICK_POLICY_H */
