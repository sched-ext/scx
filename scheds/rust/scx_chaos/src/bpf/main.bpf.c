/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#define P2DQ_CREATE_STRUCT_OPS 0
#include "../../../scx_p2dq/src/bpf/main.bpf.c"

#include "intf.h"

#include <stdbool.h>

const volatile u32 random_delays_freq_frac32 = 1; /* for veristat */
const volatile u32 random_delays_min_ns = 1; /* for veristat */
const volatile u32 random_delays_max_ns = 2; /* for veristat */

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

static __always_inline enum chaos_trait_kind choose_chaos()
{
	if (bpf_get_prandom_u32() < random_delays_freq_frac32)
		return CHAOS_TRAIT_RANDOM_DELAYS;

	return CHAOS_TRAIT_NONE;
}

static __always_inline u32 get_current_cpu_delay_dsq()
{
	// use current processor so enqueue runs here next time too
	// TODO: this assumes CPU IDs are linear, and probably needs to be mapped
	// into linear IDs with topology information passed from userspace
	u32 cpu = bpf_get_smp_processor_id();

	return CHAOS_DSQ_BASE | cpu;
}

__weak s32 enqueue_random_delay(struct task_struct *p __arg_trusted, u64 enq_flags,
				struct chaos_task_ctx *taskc __arg_nonnull)
{
	u64 rand64 = ((u64)bpf_get_prandom_u32() << 32) | bpf_get_prandom_u32();

	u64 vtime = bpf_ktime_get_ns() + random_delays_min_ns;
	if (random_delays_min_ns != random_delays_max_ns) {
		vtime += rand64 % (random_delays_max_ns - random_delays_min_ns);
	}

	scx_bpf_dsq_insert_vtime(p, get_current_cpu_delay_dsq(), 0, vtime, enq_flags);

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

s32 BPF_STRUCT_OPS_SLEEPABLE(chaos_init)
{
	struct llc_ctx *llcx;
	struct cpu_ctx *cpuc;
	int i, ret;

	bpf_for(i, 0, nr_cpus) {
		if (!(cpuc = lookup_cpu_ctx(i)) ||
		    !(llcx = lookup_llc_ctx(cpuc->llc_id)))
			return -EINVAL;

		ret = scx_bpf_create_dsq(CHAOS_DSQ_BASE | i, llcx->node_id);
		if (ret < 0)
			return ret;
	}

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
		__COMPAT_scx_bpf_dsq_move_set_slice(it__iter, *MEMBER_VPTR(pro->fifo, .slice_ns));
		__COMPAT_scx_bpf_dsq_move(it__iter, p, pro->fifo.dsq_id, pro->fifo.enq_flags);
		goto out;
	case P2DQ_ENQUEUE_PROMISE_VTIME:
		__COMPAT_scx_bpf_dsq_move_set_slice(it__iter, pro->vtime.slice_ns);
		__COMPAT_scx_bpf_dsq_move_set_vtime(it__iter, pro->vtime.vtime);
		__COMPAT_scx_bpf_dsq_move_vtime(it__iter, p, pro->vtime.dsq_id, pro->vtime.enq_flags);
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
	bpf_for_each(scx_dsq, p, get_current_cpu_delay_dsq(), 0) {
		if (++i >= 8)
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

	async_p2dq_enqueue(&promise, p, enq_flags);
	if (promise.kind == P2DQ_ENQUEUE_PROMISE_COMPLETE)
		return;

	if (taskc->next_trait != CHAOS_TRAIT_NONE &&
	    enqueue_chaotic(p, enq_flags, taskc))
		return;

	complete_p2dq_enqueue(&promise, p);
}

void BPF_STRUCT_OPS(chaos_runnable, struct task_struct *p, u64 enq_flags)
{
	enum chaos_trait_kind t = choose_chaos();
	if (t == CHAOS_TRAIT_NONE)
		goto p2dq;

	struct chaos_task_ctx *wakee_ctx;
	if (!(wakee_ctx = lookup_create_chaos_task_ctx(p)))
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

SCX_OPS_DEFINE(chaos,
	       .select_cpu		= (void *)chaos_select_cpu,
	       .enqueue			= (void *)chaos_enqueue,
	       .runnable		= (void *)chaos_runnable,
	       .init			= (void *)chaos_init,
	       .dispatch		= (void *)chaos_dispatch,

	       .running			= (void *)p2dq_running,
	       .stopping		= (void *)p2dq_stopping,
	       .set_cpumask		= (void *)p2dq_set_cpumask,
	       .init_task		= (void *)p2dq_init_task,
	       .exit			= (void *)p2dq_exit,

	       .timeout_ms		= 30000,
	       .name			= "chaos");
