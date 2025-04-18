/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#define P2DQ_CREATE_STRUCT_OPS 0
#include "scx_p2dq/main.bpf.c"

#include "intf.h"

#include <stdbool.h>

#define __COMPAT_chaos_scx_bpf_dsq_move_set_slice(it__iter, slice)				\
	(bpf_ksym_exists(scx_bpf_dsq_move_set_slice) ?						\
	  scx_bpf_dsq_move_set_slice((it__iter), (slice)) :					\
	  scx_bpf_dispatch_from_dsq_set_slice___compat((it__iter), (slice)))

#define __COMPAT_chaos_scx_bpf_dsq_move(it__iter, p, dsq_id, enq_flags)				\
	(bpf_ksym_exists(scx_bpf_dsq_move) ?							\
	  scx_bpf_dsq_move((it__iter), (p), (dsq_id), (enq_flags)) :				\
	  scx_bpf_dispatch_from_dsq___compat((it__iter), (p), (dsq_id), (enq_flags)))

#define __COMPAT_chaos_scx_bpf_dsq_move_set_vtime(it__iter, vtime)				\
	(bpf_ksym_exists(scx_bpf_dsq_move_set_vtime) ?						\
	  scx_bpf_dsq_move_set_vtime((it__iter), (vtime)) :					\
	  scx_bpf_dispatch_from_dsq_set_vtime___compat((it__iter), (vtime)))

#define __COMPAT_chaos_scx_bpf_dsq_move_vtime(it__iter, p, dsq_id, enq_flags)			\
	(bpf_ksym_exists(scx_bpf_dsq_move_vtime) ?						\
	  scx_bpf_dsq_move_vtime((it__iter), (p), (dsq_id), (enq_flags)) :			\
	  scx_bpf_dispatch_vtime_from_dsq___compat((it__iter), (p), (dsq_id), (enq_flags)))

const volatile int ppid_targeting_ppid = 1;
const volatile bool ppid_targeting_inclusive = false; /* include ppid_targeting_ppid in chaos */

const volatile u64 chaos_timer_check_queues_min_ns = 500000;
const volatile u64 chaos_timer_check_queues_max_ns = 2000000;
const volatile u64 chaos_timer_check_queues_slack_ns = 2500000;

const volatile u32 random_delays_freq_frac32 = 1; /* for veristat */
const volatile u64 random_delays_min_ns = 1; /* for veristat */
const volatile u64 random_delays_max_ns = 2; /* for veristat */

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define MAX_ITERS_IN_DISPATCH 8

enum chaos_timer_callbacks {
	CHAOS_TIMER_CHECK_QUEUES,
	CHAOS_MAX_TIMERS,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CHAOS_MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} chaos_timers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct chaos_task_ctx);
} chaos_task_ctxs SEC(".maps");

struct chaos_task_ctx *lookup_create_chaos_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&chaos_task_ctxs, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline enum chaos_trait_kind choose_chaos(struct chaos_task_ctx *taskc)
{
	if (taskc->match & CHAOS_MATCH_EXCLUDED)
		return CHAOS_TRAIT_NONE;

	if (bpf_get_prandom_u32() < random_delays_freq_frac32)
		return CHAOS_TRAIT_RANDOM_DELAYS;

	return CHAOS_TRAIT_NONE;
}

static __always_inline u64 get_cpu_delay_dsq(int cpu_idx)
{
	if (cpu_idx >= 0)
		return CHAOS_DSQ_BASE | cpu_idx;

	// use current processor so enqueue runs here next time too
	// TODO: this assumes CPU IDs are linear, and probably needs to be mapped
	// into linear IDs with topology information passed from userspace
	cpu_idx = bpf_get_smp_processor_id();
	return CHAOS_DSQ_BASE | cpu_idx;
}

static __always_inline s32 calculate_chaos_match(struct task_struct *p)
{
	struct chaos_task_ctx *taskc;
	struct task_struct *p2;
	enum chaos_match flags = 0;
	int found_parent = 0;
	int ret = 0;
	int pid;

	if (!(taskc = lookup_create_chaos_task_ctx(p))) {
		scx_bpf_error("couldn't create task context");
		return -EINVAL;
	}

	// set one bit so we can check this step has been completed.
	taskc->match |= CHAOS_MATCH_COMPLETE;

	// no ppid targeting is covered by everything having CHAOS_MATCH_COMPLETE only
	if (ppid_targeting_ppid == -1)
		return 0;

	// no need for the path-to-root walk, this is the task
	if (ppid_targeting_ppid == p->pid) {
		taskc->match |= ppid_targeting_inclusive ?
			CHAOS_MATCH_HAS_PARENT : CHAOS_MATCH_EXCLUDED;
		return 0;
	}

	// we are matching on parent. if this task doesn't have one, exclude.
	if (!p->real_parent || !(pid = p->real_parent->pid)) {
		taskc->match |= CHAOS_MATCH_EXCLUDED;
		return 0;
	}

	// walk the real_parent path-to-root to check for the HAS_PARENT match
	bpf_repeat(CHAOS_NUM_PPIDS_CHECK) {
		p2 = bpf_task_from_pid(pid);
		if (!p2)
			break;

		if (!(taskc = lookup_create_chaos_task_ctx(p2))) {
			bpf_task_release(p2);
			scx_bpf_error("couldn't create task context");
			ret = -EINVAL;
			goto out;
		}

		// parent is matched and is in the parent path
		if (taskc->match & CHAOS_MATCH_HAS_PARENT) {
			flags |= CHAOS_MATCH_HAS_PARENT;
			found_parent = pid;
			bpf_task_release(p2);
			break;
		}

		// found the parent
		if (p2->pid == ppid_targeting_ppid) {
			flags |= CHAOS_MATCH_HAS_PARENT;
			found_parent = pid;
			bpf_task_release(p2);
			break;
		}

		// parent is matched and is not in the parent path
		if (taskc->match) {
			found_parent = pid;
			bpf_task_release(p2);
			break;
		}

		if (!p2->real_parent || !(pid = p2->real_parent->pid)) {
			bpf_task_release(p2);
			break;
		}

		bpf_task_release(p2);
	}

	if (!(flags & CHAOS_MATCH_HAS_PARENT))
		flags |= CHAOS_MATCH_EXCLUDED;

	if (!(taskc = lookup_create_chaos_task_ctx(p))) {
		scx_bpf_error("couldn't create task context");
		return -EINVAL;
	}
	taskc->match |= flags;

	if (!p->real_parent || !(pid = p->real_parent->pid))
		return 0;

	bpf_repeat(CHAOS_NUM_PPIDS_CHECK) {
		p2 = bpf_task_from_pid(pid);
		if (!p2)
			break;

		if (!(taskc = lookup_create_chaos_task_ctx(p2))) {
			bpf_task_release(p2);
			scx_bpf_error("couldn't create task context");
			ret = -EINVAL;
			goto out;
		}

		if (pid == found_parent) {
			bpf_task_release(p2);
			break;
		}

		taskc->match |= flags;

		if (!p2->real_parent || !(pid = p2->real_parent->pid)) {
			bpf_task_release(p2);
			break;
		}

		bpf_task_release(p2);
	}

out:
	return ret;
}

__weak s32 enqueue_random_delay(struct task_struct *p __arg_trusted, u64 enq_flags,
				struct chaos_task_ctx *taskc __arg_nonnull)
{
	u64 rand64 = ((u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();

	u64 vtime = bpf_ktime_get_ns() + random_delays_min_ns;
	if (random_delays_min_ns != random_delays_max_ns) {
		vtime += rand64 % (random_delays_max_ns - random_delays_min_ns);
	}

	scx_bpf_dsq_insert_vtime(p, get_cpu_delay_dsq(-1), 0, vtime, enq_flags);

	return true;
}

__weak s32 enqueue_chaotic(struct task_struct *p __arg_trusted, u64 enq_flags,
			   struct chaos_task_ctx *taskc __arg_nonnull)
{
	bool out;

	switch (taskc->next_trait) {
	case CHAOS_TRAIT_RANDOM_DELAYS:
		out = enqueue_random_delay(p, enq_flags, taskc);
		break;

	case CHAOS_TRAIT_NONE:
	case CHAOS_TRAIT_MAX:
		out = false;
		break;
	}

	taskc->next_trait = CHAOS_TRAIT_NONE;
	return out;
}

/*
 * Walk a CPU's delay dsq and kick it if the task should already have been
 * scheduled. Use a slack time to avoid preempting for small differences. Return
 * the next time a task in this DSQ might need kicking. The next time is
 * obviously very racy and may return 0 if the DSQ will all be handled by the
 * next dispatch, so should be clamped before being relied on.
 */
__weak u64 check_dsq_times(int cpu_idx)
{
	struct task_struct *p;
	u64 next_trigger_time = 0;
	u64 now = bpf_ktime_get_ns();
	int i = 0;
	bool has_kicked = false;

	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, p, get_cpu_delay_dsq(cpu_idx), 0) {
		p = bpf_task_from_pid(p->pid);
		if (!p)
			break;

		if (i++ >= MAX_ITERS_IN_DISPATCH) {
			next_trigger_time = p->scx.dsq_vtime;
			bpf_task_release(p);
			break;
		}

		if (has_kicked) {
			bpf_task_release(p);
			continue;
		}

		if (p->scx.dsq_vtime < now + chaos_timer_check_queues_slack_ns) {
			has_kicked = true;
			scx_bpf_kick_cpu(cpu_idx, SCX_KICK_PREEMPT);
		} else if (p->scx.dsq_vtime < now) {
			has_kicked = true;
			scx_bpf_kick_cpu(cpu_idx, SCX_KICK_IDLE);
		}

		bpf_task_release(p);
	}
	bpf_rcu_read_unlock();

	return next_trigger_time;
}

static int chaos_timer_check_queues_callback(void *map, int key, struct timer_wrapper *timerw)
{
	u64 started_at = bpf_ktime_get_ns();
	u64 next_trigger_time = 0;
	u64 this_next_trigger_time;
	int cpu_idx;

	bpf_for(cpu_idx, 0, nr_cpus) {
		this_next_trigger_time = check_dsq_times(cpu_idx);
		next_trigger_time = MAX(next_trigger_time, this_next_trigger_time);
	}

	if (next_trigger_time == 0) {
		bpf_timer_start(&timerw->timer, chaos_timer_check_queues_max_ns, 0);
		return 0;
	}

	next_trigger_time = MAX(next_trigger_time, started_at + chaos_timer_check_queues_min_ns);
	next_trigger_time = MIN(next_trigger_time, started_at + chaos_timer_check_queues_max_ns);

	bpf_timer_start(&timerw->timer, next_trigger_time, BPF_F_TIMER_ABS);
	return 0;
}


s32 BPF_STRUCT_OPS_SLEEPABLE(chaos_init)
{
	struct timer_wrapper *timerw;
	struct llc_ctx *llcx;
	struct cpu_ctx *cpuc;
	int timer_id, ret, i;

	bpf_for(i, 0, nr_cpus) {
		if (!(cpuc = lookup_cpu_ctx(i)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
			return -EINVAL;

		ret = scx_bpf_create_dsq(CHAOS_DSQ_BASE | i, llcx->node_id);
		if (ret < 0)
			return ret;
	}

	timer_id = CHAOS_TIMER_CHECK_QUEUES;
	timerw = bpf_map_lookup_elem(&chaos_timers, &timer_id);
	if (!timerw)
		return -1;

	timerw->key = timer_id;

	ret = bpf_timer_init(&timerw->timer, &chaos_timers, CLOCK_BOOTTIME);
	if (ret)
		return -1;

	ret = bpf_timer_set_callback(&timerw->timer, &chaos_timer_check_queues_callback);
	if (ret)
		return -1;

	ret = bpf_timer_start(&timerw->timer, chaos_timer_check_queues_max_ns, 0);
	if (ret)
		return -1;

	return p2dq_init_impl();
}

static __always_inline void complete_p2dq_enqueue_move(struct enqueue_promise *pro,
						       struct bpf_iter_scx_dsq *it__iter,
						       struct task_struct *p)
{
	switch (pro->kind) {
	case P2DQ_ENQUEUE_PROMISE_COMPLETE:
		goto out;
	case P2DQ_ENQUEUE_PROMISE_FIFO:
		__COMPAT_chaos_scx_bpf_dsq_move_set_slice(it__iter, *MEMBER_VPTR(pro->fifo, .slice_ns));
		__COMPAT_chaos_scx_bpf_dsq_move(it__iter, p, pro->fifo.dsq_id, pro->fifo.enq_flags);
		goto out;
	case P2DQ_ENQUEUE_PROMISE_VTIME:
		__COMPAT_chaos_scx_bpf_dsq_move_set_slice(it__iter, pro->vtime.slice_ns);
		__COMPAT_chaos_scx_bpf_dsq_move_set_vtime(it__iter, pro->vtime.vtime);
		__COMPAT_chaos_scx_bpf_dsq_move_vtime(it__iter, p, pro->vtime.dsq_id, pro->vtime.enq_flags);
		goto out;
	}

out:
	pro->kind = P2DQ_ENQUEUE_PROMISE_COMPLETE;
}

void BPF_STRUCT_OPS(chaos_dispatch, s32 cpu, struct task_struct *prev)
{
	struct enqueue_promise promise;
	struct chaos_task_ctx *taskc;
	struct task_struct *p;
	u64 now = bpf_ktime_get_ns();

	int i = 0;
	bpf_for_each(scx_dsq, p, get_cpu_delay_dsq(-1), 0) {
		if (i++ >= MAX_ITERS_IN_DISPATCH)
			break; // the verifier can't handle this loop, so limit it

		p = bpf_task_from_pid(p->pid);
		if (!p)
			continue;

		if (!(taskc = lookup_create_chaos_task_ctx(p))) {
			scx_bpf_error("couldn't find task context");
			bpf_task_release(p);
			break;
		}

		if (p->scx.dsq_vtime > now) {
			bpf_task_release(p);
			break; // this is the DSQ's key so we're done
		}

		// restore vtime to p2dq's timeline
		p->scx.dsq_vtime = taskc->p2dq_vtime;

		async_p2dq_enqueue(&promise, p, taskc->enq_flags);
		complete_p2dq_enqueue_move(&promise, BPF_FOR_EACH_ITER, p);
		bpf_task_release(p);
	}

	return p2dq_dispatch_impl(cpu, prev);
}

void BPF_STRUCT_OPS(chaos_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct enqueue_promise promise;
	struct chaos_task_ctx *taskc;

	if (!(taskc = lookup_create_chaos_task_ctx(p))) {
		scx_bpf_error("failed to lookup task context in enqueue");
		return;
	}

	// capture vtime before the potentially discarded enqueue
	taskc->p2dq_vtime = p->scx.dsq_vtime;

	async_p2dq_enqueue(&promise, p, enq_flags);
	if (promise.kind == P2DQ_ENQUEUE_PROMISE_COMPLETE)
		return;

	if (taskc->next_trait == CHAOS_TRAIT_NONE)
		return complete_p2dq_enqueue(&promise, p);

	if (enqueue_chaotic(p, enq_flags, taskc))
		return;

	complete_p2dq_enqueue(&promise, p);
}

void BPF_STRUCT_OPS(chaos_runnable, struct task_struct *p, u64 enq_flags)
{
	struct chaos_task_ctx *wakee_ctx;
	if (!(wakee_ctx = lookup_create_chaos_task_ctx(p)))
		goto p2dq;

	enum chaos_trait_kind t = choose_chaos(wakee_ctx);
	if (t == CHAOS_TRAIT_NONE)
		goto p2dq;

	wakee_ctx->next_trait = t;
p2dq:
	return p2dq_runnable_impl(p, enq_flags);
}

s32 BPF_STRUCT_OPS(chaos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct chaos_task_ctx *wakee_ctx;
	if (!(wakee_ctx = lookup_create_chaos_task_ctx(p)))
		goto p2dq;

	// don't allow p2dq to select_cpu if we plan chaos to ensure we hit enqueue
	if (wakee_ctx->next_trait != CHAOS_TRAIT_NONE)
		return prev_cpu;

p2dq:
	return p2dq_select_cpu_impl(p, prev_cpu, wake_flags);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chaos_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	s32 ret = p2dq_init_task_impl(p, args);
	if (ret)
		return ret;

	ret = calculate_chaos_match(p);
	if (ret)
		return ret;

	return 0;
}

SCX_OPS_DEFINE(chaos,
	       .dispatch		= (void *)chaos_dispatch,
	       .enqueue			= (void *)chaos_enqueue,
	       .init			= (void *)chaos_init,
	       .init_task		= (void *)chaos_init_task,
	       .runnable		= (void *)chaos_runnable,
	       .select_cpu		= (void *)chaos_select_cpu,

	       .exit_task		= (void *)p2dq_exit_task,
	       .exit			= (void *)p2dq_exit,
	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_cpumask		= (void *)p2dq_set_cpumask,

	       .timeout_ms		= 30000,
	       .name			= "chaos");
