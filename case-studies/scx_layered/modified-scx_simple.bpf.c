/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include "scx_common.bpf.h"

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile bool switch_partial;

static u64 vtime_now;
struct user_exit_info uei;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

struct task_ctx {
	bool enq_local;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *idle_smtmask = scx_bpf_get_idle_smtmask();
	const struct cpumask *idle_cpumask = scx_bpf_get_idle_cpumask();
	struct task_struct *current = (void *)bpf_get_current_task();
	struct task_ctx *tctx;
	s32 cpu;

	tctx = bpf_task_storage_get(&task_ctxs, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("task_ctx lookup failed");
		cpu = -ESRCH;
		goto out;
	}

	/*
	 * If WAKE_SYNC and the machine isn't fully saturated, wake up @p to the
	 * local DSQ of the waker.
	 */
	if ((wake_flags & SCX_WAKE_SYNC) && p->nr_cpus_allowed > 1 &&
	    !bpf_cpumask_empty(idle_cpumask) &&
	    !(BPF_CORE_READ(current, flags) & PF_EXITING)) {
		cpu = bpf_get_smp_processor_id();
		if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
			tctx->enq_local = true;
			goto out;
		}
	}

	if (p->nr_cpus_allowed == 1) {
		cpu = prev_cpu;
		goto out;
	}

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	/*if (bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		tctx->enq_local = true;
		cpu = prev_cpu;
		goto out;
	}

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, SCX_PICK_IDLE_CORE);
	if (cpu >= 0) {
		tctx->enq_local = true;
		goto out;
		}*/

	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		tctx->enq_local = true;
		cpu = prev_cpu;
		goto out;
	}

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0) {
		tctx->enq_local = true;
		goto out;
	}

	cpu = prev_cpu;
out:
	scx_bpf_put_idle_cpumask(idle_cpumask);
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctxs, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("task_ctx lookup failed");
		return;
	}

	/*
	 * If scx_select_cpu_dfl() is setting %SCX_ENQ_LOCAL, it indicates that
	 * running @p on its CPU directly shouldn't affect fairness. Just queue
	 * it on the local FIFO.
	 */
	if (tctx->enq_local) {
		tctx->enq_local = false;
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}

	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

s32 BPF_STRUCT_OPS(simple_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	if (bpf_task_storage_get(&task_ctxs, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p,
		    struct scx_enable_args *args)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS(simple_init)
{
	if (!switch_partial)
		scx_bpf_switch_all();
	return 0;
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops simple_ops = {
	.select_cpu		= (void *)simple_select_cpu,
	.enqueue		= (void *)simple_enqueue,
	.running		= (void *)simple_running,
	.stopping		= (void *)simple_stopping,
	.prep_enable		= (void *)simple_prep_enable,
	.enable			= (void *)simple_enable,
	.init			= (void *)simple_init,
	.exit			= (void *)simple_exit,
	.name			= "simple",
};
