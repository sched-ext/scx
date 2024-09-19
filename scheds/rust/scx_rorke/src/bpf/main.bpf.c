/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Rorke: A special purpose scheduler for hypervisors
 * TODO: Add a proper description
 *
 * Copyright(C) 2024 Vahab Jabrayilov<vjabrayilov@cs.columbia.edu>
 * Influenced by the scx_central scheduler
 */

#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * const volatiles are set again during initialization
 * here we assign values just to pass the verifier
 */
const volatile u32 central_cpu = 0;
const volatile u32 nr_cpus = 1;
const volatile u32 nr_vms = 1;
const volatile u64 timer_interval_ns = 100000;

const volatile u64 vms[MAX_VMS];
const volatile u64 cpu_to_vm[MAX_CPUS];

const volatile u32 debug = 0;

bool timer_pinned = true;
u64 nr_total, nr_locals, nr_queued, nr_lost_pids;
u64 nr_timers, nr_dispatches, nr_mismatches, nr_retries;
u64 nr_overflows;

/* Exit information */

struct central_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct central_timer);
} central_timer SEC(".maps");

s32 BPF_STRUCT_OPS(rorke_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/*
   * Steer wakeups to the central CPU to avoid disturbing other CPUs.
   * NOTE: This is a simple implementation. A more sophisticated approach
   * would check to directly steer to the previously assigned CPU if idle.
   */
	trace("rorke_select_cpu: VM: %d, vCPU: %d, prev_cpu: %d", p->tgid,
	      p->pid, prev_cpu);
	return central_cpu;
}

void BPF_STRUCT_OPS(rorke_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid = p->pid;
	s32 tgid = p->tgid;

	__sync_fetch_and_add(&nr_total, 1);

	/*
   * Push per-cpu kthreads at the head of local dsq's and preempt the
   * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
   * behind other threads which is necessary for forward progress
   * guarantee as we depend on the BPF timer which may run from ksoftirqd.
   */
	if ((p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		__sync_fetch_and_add(&nr_locals, 1);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
				 enq_flags | SCX_ENQ_PREEMPT);
		trace("rorke_enqueue: enqueued local kthread %d", pid);
		return;
	}

	scx_bpf_dispatch(p, tgid, SCX_SLICE_INF, enq_flags);
	trace("rorke_enqueue: enqueued VM: %d vCPU: %d", tgid, pid);

	__sync_fetch_and_add(&nr_queued, 1);
}

void BPF_STRUCT_OPS(rorke_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 vm_id = cpu < nr_cpus ? cpu_to_vm[cpu] : 0;
	if (vm_id == 0) {
		return;
	}
	if (scx_bpf_consume(vm_id)) {
		trace("rorke_dispatch: VM - %d", vm_id);
        __sync_fetch_and_sub(&nr_queued, 1);
		return;
	}
	dbg("rorke_dispatch: empty... didn't consumed from VM - %d", vm_id);
}

void BPF_STRUCT_OPS(rorke_runnable, struct task_struct *p, u64 enq_flags)
{
	trace("rorke_runnable: VM: %d, vCPU: %d", p->tgid, p->pid);
}

void BPF_STRUCT_OPS(rorke_running, struct task_struct *p)
{
	trace("rorke_running: VM: %d, vCPU: %d", p->tgid, p->pid);
}

void BPF_STRUCT_OPS(rorke_stopping, struct task_struct *p, bool runnable)
{
	trace("rorke_stopping: VM: %d, vCPU: %d, runnable: %d", p->tgid, p->pid,
	      runnable);
}

void BPF_STRUCT_OPS(rorke_quiescent, struct task_struct *p, u64 deq_flags)
{
	trace("rorke_quiescent: VM: %d, vCPU: %d", p->tgid, p->pid);
}

s32 BPF_STRUCT_OPS(rorke_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	return 0;
}

void BPF_STRUCT_OPS(rorke_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
}

/*
 * At every timer_interval_ns, preempts all CPUs other than central.
 */
static int central_timerfn(void *map, int *key, struct bpf_timer *timer)
{
	// u64 now = bpf_ktime_get_ns();
	u64 nr_to_kick = nr_queued;
	s32 curr_cpu;

	curr_cpu = bpf_get_smp_processor_id();
	if (timer_pinned && (curr_cpu != central_cpu)) {
		scx_bpf_error(
			"Central Timer ran on CPU %d, not central CPU %d\n",
			curr_cpu, central_cpu);
		return 0;
	}

	bpf_for(curr_cpu, 0, nr_cpus)
	{
		if (curr_cpu == central_cpu) {
			// trace("central_timerfn: curr_cpu[%d] == central_cpu[%d] skipping...",
			// curr_cpu, central_cpu);
			continue;
		}

		if (scx_bpf_dsq_nr_queued(FALLBACK_DSQ_ID) ||
		    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | curr_cpu))
			trace("central_timerfn: local non-empty, will kick CPU %d",
                  curr_cpu);
		else if (nr_to_kick)
			nr_to_kick--;
		else
			continue;

		scx_bpf_kick_cpu(curr_cpu, SCX_KICK_PREEMPT);
		trace("central_timerfn: kicked CPU %d", curr_cpu);
	}

	bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rorke_init)
{
	/* Create DSQ for fallback */
	int ret;
	ret = scx_bpf_create_dsq(FALLBACK_DSQ_ID, -1);
	if (ret) {
		scx_bpf_error("Failed to create DSQ for fallback");
		return ret;
	}
	info("Created DSQ for fallback");

	/* Create DSQ per VM */
	u32 i;
	bpf_for(i, 0, nr_vms)
	{
		ret = scx_bpf_create_dsq(vms[i], -1);
		if (ret) {
			scx_bpf_error("Failed to create DSQ for VM %lld",
				      vms[i]);
			return ret;
		}
		info("Created DSQ for VM %d", vms[i]);
	}

	/* Setup timer */
	struct bpf_timer *timer;
	u32 key = 0;
	timer = bpf_map_lookup_elem(&central_timer, &key);
	if (!timer) {
		info("Failed to lookup timer");
		return -ESRCH;
	}

	if (bpf_get_smp_processor_id() != central_cpu) {
		scx_bpf_error("Fatal: init on non-central CPU");
		return EINVAL;
	}

	bpf_timer_init(timer, &central_timer, CLOCK_MONOTONIC);
	bpf_timer_set_callback(timer, central_timerfn);
	info("Initialized timer\n");

	ret = bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
	/*
   * BPF_F_TIMER_CPU_PIN is not supported in all kernels (>= 6.7). If we're
   * running on an older kernel, it'll return -EINVAL
   * Retry w/o BPF_F_TIMER_CPU_PIN
   */
	if (ret == -EINVAL) {
		timer_pinned = false;
		ret = bpf_timer_start(timer, timer_interval_ns, 0);
	}
	if (ret)
		scx_bpf_error("bpf_timer_start failed (%d)", ret);
	info("Started timer -- rorke_init successfully finished");

	return ret;
}

void BPF_STRUCT_OPS(rorke_exit, struct scx_exit_info *ei)
{
	info("Exiting rorke");
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rorke,
	       /*
     * We are offloading all scheduling decisions to the central CPU
     * and thus being the last task on a given CPU doesn't mean
     * anything special. Enqueue the last tasks like any other tasks.
     */

	       // .flags = SCX_OPS_ENQ_LAST,
	       .select_cpu = (void *)rorke_select_cpu,
	       .enqueue = (void *)rorke_enqueue,
	       .dispatch = (void *)rorke_dispatch,
	       .runnable = (void *)rorke_runnable,
	       .running = (void *)rorke_running,
	       .stopping = (void *)rorke_stopping,
	       .quiescent = (void *)rorke_quiescent,
	       .init_task = (void *)rorke_init_task,
	       .exit_task = (void *)rorke_exit_task, .init = (void *)rorke_init,
	       .exit = (void *)rorke_exit, .name = "rorke");
