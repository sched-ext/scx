/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

#include "helpers.h"
#include "intf.h"

#ifdef SCX_MAIN_SCHED
#error "SCX_MAIN_SCHED declared outside of main.bpf.c"
#endif

const volatile u8 debug;
#define dbg_log(fmt, ...)		\
		if (debug > 0)		\
			bpf_printk(fmt, __VA_ARGS__);

#define SCX_MAIN_SCHED
#include "pcpu.h"
#include "qos.h"
#include "domains.h"
#include "tasks.h"
#undef SCX_MAIN_SCHED

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

void BPF_STRUCT_OPS(framesched_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	taskc->runtime.curr_runtime = 0;
}

void BPF_STRUCT_OPS(framesched_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	u64 now = bpf_ktime_get_ns();

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	taskc->runtime.running_at = now;
}

void BPF_STRUCT_OPS(framesched_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	u64 now = bpf_ktime_get_ns(), runtime;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	runtime = now - taskc->runtime.running_at;
	taskc->runtime.curr_runtime += runtime;
	taskc->runtime.vruntime += scale_inverse_fair(runtime, p->scx.weight);

	if (!runnable)
		taskc->runtime.average_runtime =
			calc_avg(taskc->runtime.average_runtime,
				 taskc->runtime.curr_runtime);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(framesched_init_task,
			     struct task_struct *p,
			     struct scx_init_task_args *args)
{
	int err;
	struct task_ctx *taskc;

	err = tasks_init_task(p, args);
	if (err)
		return err;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return -ENOENT;

	tasks_publish_notif(p, taskc);
	err = domains_task_pick_dom(p, taskc);
	if (err && !taskc->orphaned) {
		scx_bpf_error("Failed to pick domain for %s[%d]", p->comm, p->pid);
		return err;
	} else {
		return 0;
	}
}

void BPF_STRUCT_OPS(framesched_cgroup_move,
		    struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *taskc = tasks_lookup_ctx(p);

	if (!taskc)
		return;

	tasks_publish_notif(p, taskc);
}

void BPF_STRUCT_OPS(framesched_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc = tasks_lookup_ctx(p);

	if (!taskc)
		return;

	tasks_publish_notif(p, taskc);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(framesched_init)
{
	s32 cpu;
	int err;

	bpf_for(cpu, 0, nr_cpu_ids) {
		err = pcpu_init_ctx(cpu);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(framesched_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

static void enqueue_task_qos(struct task_struct *p,
			     struct task_ctx *taskc,
			     struct dom_ctx *udomc,
			     u64 enq_flags)
{
	u64 deadline, vtime, delta;
	struct entity_runtime *runtime;

	runtime = &taskc->runtime;
	vtime = runtime->vruntime;
	delta = scale_up_fair(runtime->average_runtime, p->scx.weight);
	switch (taskc->runtime.qos) {
		case FS_DL_QOS_LOW:
			deadline = vtime +
				scale_inverse_fair(runtime->average_runtime,
						   p->scx.weight);
			break;

		case FS_DL_QOS_NORMAL:
			deadline = vtime;
			break;

		case FS_DL_QOS_MAX:
			delta *= delta;
		case FS_DL_QOS_HIGH:
			if (unlikely(delta > vtime))
				deadline = 0;
			else
				deadline = vtime - delta;
			break;
		default:
			scx_bpf_error("Invalid QoS: %d", taskc->runtime.qos);
			deadline = 0;
	}

	scx_bpf_dsq_insert_vtime(p, taskc->dom_id, SCX_SLICE_DFL, deadline,
			         enq_flags);
}

void BPF_STRUCT_OPS(framesched_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;
	struct dom_ctx *domc;
	int cpu = bpf_get_smp_processor_id();
	const struct cpumask *task_mask;

	taskc = tasks_lookup_ctx(p);
	if (!taskc)
		return;

	if (unlikely(taskc->orphaned))
		scx_bpf_error("%s[%d] enqueuing orphan task", p->comm, p->pid);

	domc = domains_lookup_ctx(taskc->dom_id);
	if (unlikely(!domc)) {
		bpf_printk("%s[%d]: %d (%u)", p->comm, p->pid, taskc->orphaned, taskc->dom_id);
		return;
	}

	if (scx_bpf_test_and_clear_cpu_idle(cpu)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	} else if (p->nr_cpus_allowed == 1)
		goto enqueue;

	bpf_rcu_read_lock();
	cpu = -1;
	task_mask = cast_mask(taskc->cpumask);
	if (likely(task_mask))
		cpu = scx_bpf_pick_idle_cpu(task_mask, 0);
	bpf_rcu_read_unlock();
	if (cpu >= 0)
		goto direct;

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		goto direct;

enqueue:
	enqueue_task_qos(p, taskc, domc, enq_flags);
	return;

direct:
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(framesched_dispatch, s32 cpu, struct task_struct *prev)
{
	struct pcpu_ctx *pcpuc = pcpu_lookup_ctx(cpu);
	u64 dom_id, idx;

	if (!pcpuc)
		return;

	if (scx_bpf_dsq_move_to_local(pcpuc->dom_id))
		return;

	bpf_for(idx, 0, nr_dom_ids) {
		dom_id = pcpuc->rr_idx++ % nr_dom_ids;
		if (dom_id == pcpuc->dom_id)
			continue;

		if (scx_bpf_dsq_move_to_local(pcpuc->dom_id))
			return;
	}
}

SCX_OPS_DEFINE(framesched,
		.cgroup_move		= (void *)framesched_cgroup_move,
		.dispatch		= (void *)framesched_dispatch,
		.enqueue		= (void *)framesched_enqueue,
		.exit			= (void *)framesched_exit,
		.init			= (void *)framesched_init,
		.init_task		= (void *)framesched_init_task,
		.runnable		= (void *)framesched_runnable,
		.running		= (void *)framesched_running,
		.set_weight		= (void *)framesched_set_weight,
		.stopping		= (void *)framesched_stopping,
		.timeout_ms		= 10000,
		.name			= "framesched");
