// SPDX-License-Identifier: GPL-2.0
/*
 * Double helix queues for the flow scheduler, used by --performance.
 *
 * The LLCs of each NUMA node are paired up in the order of their ids, and
 * the two LLCs of a pair share one double helix queue from the arena
 * library of scx. Each LLC owns one strand of it. A task that is not
 * pinned and may run in both LLCs of its pair waits in the strand of the
 * LLC of its CPU, ordered by virtual deadline as in a DSQ. The CPUs of an
 * LLC weigh the head of their own strand against the heads of their DSQs.
 * Only once they have nothing of their own left do they take from the
 * strand and the DSQ of another LLC, first in their node and then in the
 * other nodes, so that tasks keep running next to their cache while work
 * queued in any pair still reaches every CPU that may run it.
 *
 * A strand takes no more tasks once it holds FLOW_HELIX_IMBALANCE more
 * than the other strand of its queue. That bound is loose on purpose: an
 * LLC busy with a game can queue ten more of its threads than its partner
 * before any of them go to its DSQ, so most of its waiting threads share
 * one deadline order, and its partner still only steals from it once it
 * runs dry. A task that a strand does not take, because the strand is
 * that far ahead or the queue is full, waits in the DSQ of its LLC as it
 * would without --performance.
 *
 * An LLC without a partner in its node, such as the last one of an odd
 * count, only uses its DSQ, and so does a machine with a single LLC. All
 * CPUs of an LLC share its cache, so a second strand there would add a
 * lock to every enqueue and dispatch and keep no task closer to its data.
 * If the arena cannot hold every queue when the scheduler loads, all LLCs
 * use their DSQs.
 *
 * The kernel does not see the tasks in a strand, so flow makes sure that
 * each of them reaches a CPU:
 *
 * - A strand holds pids. A waiting task that the kernel dequeues, as on
 *   an affinity or scheduling class change, leaves a stale entry behind,
 *   and is queued again if it remains with flow. Dispatching a stale entry
 *   does no harm: the kernel drops the insert unless the task waits for
 *   flow right then, in which case it runs early and its newer entry goes
 *   stale instead.
 * - A task taken off a strand is inserted into a DSQ and moved from there
 *   to the local DSQ, so that the kernel checks its affinity as it moves
 *   it. A task that may not run on the CPU that took it goes to the DSQ of
 *   an LLC in its mask instead, and a CPU of its mask there is kicked.
 * - An exiting task can lose its pid before it runs for the last time, so
 *   it never waits in a strand.
 * - A CPU does not go idle while its own strand holds entries. It takes up
 *   to FLOW_HELIX_POPS of them per dispatch and kicks itself for the rest.
 * - The tick and the choice to keep the previous task running look at the
 *   head of the strand of the LLC as they do at the heads of its DSQs.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_HELIX_BPF_H
#define __FLOW_HELIX_BPF_H

#include "maps.bpf.h"
#include "fair.bpf.h"

/*
 * Between two moves to a local DSQ, which flush the inserts of
 * ops.dispatch(), at most two takes of FLOW_HELIX_POPS entries add to
 * them, see flow_take_llc(). They have to fit in the dispatch buffer.
 */
_Static_assert(2 * FLOW_HELIX_POPS < SCX_DSP_DFL_MAX_BATCH,
	       "strand takes overflow the dispatch buffer");

/* The largest strand has to fit in one block of the static allocator. */
_Static_assert(FLOW_HELIX_SLOTS * FLOW_MAX_CPUS / 2 * sizeof(struct scx_minheap_elem) +
	       sizeof(scx_minheap_t) <= FLOW_HELIX_PAGES * 4096,
	       "a strand does not fit in the arena block");

/*
 * The queue that each LLC shares with its partner, NULL if it has none.
 * The table lives in the arena, so that every program that reads it is
 * tied to the arena, as the verifier requires of programs that follow
 * arena pointers.
 */
scx_dhq_t *__arena_global flow_helix[FLOW_MAX_LLCS];

static __always_inline scx_dhq_t *flow_helix_of(u32 llc)
{
	if (!flow_performance || llc >= FLOW_MAX_LLCS)
		return NULL;
	return flow_helix[llc];
}

/* The strand of its queue that @llc owns. */
static __always_inline u64 flow_strand_of(u32 llc)
{
	return llc < FLOW_MAX_LLCS && flow_llc_mate[llc] > llc ? SCX_DHQ_STRAND_A :
								SCX_DHQ_STRAND_B;
}

/* Entries in the strand of @llc, stale ones too, or zero without one. */
static __always_inline u64 flow_helix_queued(u32 llc)
{
	scx_dhq_t *dhq = flow_helix_of(llc);
	s32 nr;

	if (!dhq)
		return 0;
	nr = scx_dhq_nr_queued_strand(dhq, flow_strand_of(llc));
	return nr > 0 ? nr : 0;
}

/*
 * Queue @p, due at @deadline with @slice, in the strand of @llc. The
 * deadline and the slice are also set on @p, where they are read back
 * when a CPU takes it off the strand. Returns false if @p has to wait in
 * the DSQ of @llc instead.
 */
static bool flow_helix_queue(struct task_struct *p, u32 llc, u64 deadline, u64 slice)
{
	scx_dhq_t *dhq = flow_helix_of(llc);
	struct bpf_cpumask *mate;

	if (!dhq || (p->flags & PF_EXITING))
		return false;
	if (p->nr_cpus_allowed < flow_nr_cpus) {
		mate = MEMBER_VPTR(flow_llc_cpumask, [flow_llc_mate[llc]]);
		if (!mate || !bpf_cpumask_intersects(cast_mask(mate), p->cpus_ptr))
			return false;
	}
	scx_bpf_task_set_slice(p, slice);
	scx_bpf_task_set_dsq_vtime(p, deadline);
	if (scx_dhq_insert_vtime(dhq, (u64)p->pid, deadline, flow_strand_of(llc)))
		return false;
	flow_stat_inc(FLOW_STAT_HELIX);
	return true;
}

/*
 * If the head of the strand of @llc may run on @cpu, return true and its
 * deadline in @vtime. A stale head is judged by what its task waits for
 * now.
 */
static bool flow_helix_head(u32 llc, s32 cpu, u64 *vtime)
{
	scx_dhq_t *dhq = flow_helix_of(llc);
	u64 strand = flow_strand_of(llc), pid;
	struct task_struct *p;
	bool fits;

	if (!dhq || scx_dhq_nr_queued_strand(dhq, strand) <= 0)
		return false;
	pid = scx_dhq_peek_strand(dhq, strand);
	if (!pid)
		return false;
	p = bpf_task_from_pid((s32)pid);
	if (!p)
		return false;
	fits = flow_task_fits(p, cpu);
	*vtime = p->scx.dsq_vtime;
	bpf_task_release(p);
	return fits;
}

/* The head of the strand of @llc may run on @cpu and is due before @deadline. */
static __always_inline bool flow_helix_ahead(u32 llc, u64 deadline, s32 cpu)
{
	u64 vtime;

	return flow_helix_head(llc, cpu, &vtime) && time_before(vtime, deadline);
}

/*
 * Insert @p, just taken off a strand by @cpu of @llc, into a DSQ that it
 * can be run from. Returns true if that is the DSQ of @llc. Otherwise @p
 * goes to the DSQ of the LLC of a CPU in its mask, which is kicked in case
 * it is idle.
 */
static bool flow_helix_place(struct task_struct *p, s32 cpu, u32 llc)
{
	u64 slice = p->scx.slice ?: FLOW_SLICE_MIN_NS;
	s32 home;

	if (flow_may_run_on(p, cpu)) {
		scx_bpf_dsq_insert_vtime(p, FLOW_LLC_DSQ_BASE + llc, slice, p->scx.dsq_vtime, 0);
		return true;
	}
	home = scx_bpf_task_cpu(p);
	if (!bpf_cpumask_test_cpu(home, p->cpus_ptr))
		home = bpf_cpumask_first(p->cpus_ptr);
	if (!flow_cpu_valid(home)) {
		WRITE_ONCE(flow_fallback_used, true);
		scx_bpf_dsq_insert(p, FLOW_FALLBACK_DSQ, FLOW_SLICE_MIN_NS, 0);
		flow_stat_inc(FLOW_STAT_FALLBACK);
		return false;
	}
	scx_bpf_dsq_insert_vtime(p, FLOW_LLC_DSQ_BASE + flow_llc_of(home), slice,
				 p->scx.dsq_vtime, 0);
	scx_bpf_kick_cpu(home, SCX_KICK_IDLE);
	return false;
}

/*
 * Take up to FLOW_HELIX_POPS entries off the strand of @src for @cpu of
 * @llc, until a task is moved to the local DSQ of @cpu. Entries whose task
 * is gone are dropped.
 */
static bool flow_helix_take(s32 cpu, u32 llc, u32 src)
{
	scx_dhq_t *dhq = flow_helix_of(src);
	u64 strand = flow_strand_of(src), pid;
	struct task_struct *p;
	bool here;
	u32 i;

	if (!dhq)
		return false;
	bpf_for(i, 0, FLOW_HELIX_POPS) {
		if (scx_dhq_nr_queued_strand(dhq, strand) <= 0)
			return false;
		pid = scx_dhq_pop_strand(dhq, strand);
		if (!pid)
			return false;
		p = bpf_task_from_pid((s32)pid);
		if (!p)
			continue;
		here = flow_helix_place(p, cpu, llc);
		bpf_task_release(p);
		if (here && scx_bpf_dsq_move_to_local(FLOW_LLC_DSQ_BASE + llc, 0))
			return true;
	}
	return false;
}

/*
 * Move the most urgent task of @src that may run on @cpu of @llc to the
 * local DSQ of @cpu: the head of the strand of @src if it is due before
 * the head of the DSQ of @src, which goes first otherwise.
 */
static bool flow_take_llc(s32 cpu, u32 llc, u32 src)
{
	u64 dsq_id = FLOW_LLC_DSQ_BASE + src, vtime;
	struct task_struct *head;

	if (!flow_helix_of(src))
		return scx_bpf_dsq_move_to_local(dsq_id, 0);
	head = __COMPAT_scx_bpf_dsq_peek(dsq_id);
	if (flow_helix_head(src, cpu, &vtime) &&
	    (!head || time_before(vtime, head->scx.dsq_vtime)) &&
	    flow_helix_take(cpu, llc, src))
		return true;
	return scx_bpf_dsq_move_to_local(dsq_id, 0) || flow_helix_take(cpu, llc, src);
}

/*
 * Create the queues before the scheduler is attached. Each queue gets
 * FLOW_HELIX_SLOTS entries for every online CPU of its two LLCs. If the
 * arena cannot hold all of them, no LLC uses one.
 */
SEC("syscall")
int flow_helix_init(void *ctx)
{
	u32 nr[FLOW_MAX_LLCS] = {};
	u32 i, llc, mate;
	scx_dhq_t *dhq;
	s32 ret;

	bpf_for(i, 0, flow_nr_usable) {
		u32 cpu;

		if (i >= FLOW_MAX_CPUS)
			break;
		cpu = flow_cpu_ids[i];
		if (flow_cpu_valid(cpu))
			nr[flow_llc_of(cpu)]++;
	}

	ret = scx_static_init(FLOW_HELIX_PAGES);
	if (ret)
		return ret;

	bpf_for(llc, 0, flow_nr_llcs) {
		if (llc >= FLOW_MAX_LLCS)
			break;
		mate = flow_llc_mate[llc];
		if (mate <= llc || mate >= flow_nr_llcs || mate >= FLOW_MAX_LLCS ||
		    flow_llc_mate[mate] != llc)
			continue;
		dhq = (scx_dhq_t *)scx_dhq_create_balanced(false,
							   FLOW_HELIX_SLOTS * (nr[llc] + nr[mate]),
							   SCX_DHQ_MODE_PRIORITY,
							   FLOW_HELIX_IMBALANCE);
		if (!dhq) {
			bpf_for(i, 0, FLOW_MAX_LLCS)
				flow_helix[i] = NULL;
			return -ENOMEM;
		}
		flow_helix[llc] = dhq;
		flow_helix[mate] = dhq;
	}
	return 0;
}

#endif /* __FLOW_HELIX_BPF_H */
