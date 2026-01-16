/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, 2024 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "power.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


/*
 * Flag to represent whether the scheduler is being monitored or not.
 */
volatile bool is_monitored;

/*
 * Introspection commands
 */
struct introspec intrspc;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 /* 16 KB */);
} introspec_msg SEC(".maps");

static __always_inline
int submit_task_ctx(struct task_struct *p, task_ctx __arg_arena *taskc, u32 cpu_id)
{
	struct cpu_ctx *cpuc;
	struct cpdom_ctx *cpdomc;
	struct msg_task_ctx *m;
	int i;

	cpuc = get_cpu_ctx_id(cpu_id);
	if (!cpuc)
		return -EINVAL;

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
	if (!cpdomc)
		return -EINVAL;

	m = bpf_ringbuf_reserve(&introspec_msg, sizeof(*m), 0);
	if (!m)
		return -ENOMEM;

	m->hdr.kind = LAVD_MSG_TASKC;
	m->taskc_x.pid = taskc->pid;
	__builtin_memcpy_inline(m->taskc_x.comm, p->comm, TASK_COMM_LEN);
	m->taskc_x.stat[0] = is_lat_cri(taskc) ? 'L' : 'R';
	m->taskc_x.stat[1] = is_perf_cri(taskc) ? 'H' : 'I';
	m->taskc_x.stat[2] = cpuc->big_core ? 'B' : 'T';
	m->taskc_x.stat[3] = test_task_flag(taskc, LAVD_FLAG_IS_GREEDY)? 'G' : 'E';
	m->taskc_x.stat[4] = '\0';
	m->taskc_x.cpu_id = taskc->cpu_id;
	m->taskc_x.prev_cpu_id = taskc->prev_cpu_id;
	m->taskc_x.suggested_cpu_id = taskc->suggested_cpu_id;
	m->taskc_x.waker_pid = taskc->waker_pid;
	for (i = 0; i < sizeof(m->taskc_x.waker_comm) && can_loop; i++)
		((char *)m->taskc_x.waker_comm)[i] = ((char __arena *)taskc->waker_comm)[i];
	m->taskc_x.slice = taskc->slice;
	m->taskc_x.lat_cri = taskc->lat_cri;
	m->taskc_x.avg_lat_cri = sys_stat.avg_lat_cri;
	m->taskc_x.static_prio = get_nice_prio(p);
	m->taskc_x.rerunnable_interval = time_delta(taskc->last_quiescent_clk, taskc->last_runnable_clk);
	m->taskc_x.resched_interval = taskc->resched_interval;
	m->taskc_x.run_freq = taskc->run_freq;
	m->taskc_x.avg_runtime = taskc->avg_runtime;
	m->taskc_x.wait_freq = taskc->wait_freq;
	m->taskc_x.wake_freq = taskc->wake_freq;
	m->taskc_x.perf_cri = taskc->perf_cri;
	m->taskc_x.thr_perf_cri = sys_stat.thr_perf_cri;
	m->taskc_x.cpuperf_cur = cpuc->cpuperf_cur;
	m->taskc_x.cpu_util = s2p(cpuc->avg_util);
	m->taskc_x.cpu_sutil = s2p(cpuc->avg_sc_util);
	m->taskc_x.nr_active = sys_stat.nr_active;
	m->taskc_x.dsq_id = cpdomc->id;
	m->taskc_x.dsq_consume_lat = cpdomc->dsq_consume_lat;
	m->taskc_x.last_slice_used = taskc->last_slice_used;

	bpf_ringbuf_submit(m, 0);

	return 0;
}

static void proc_introspec_sched_n(struct task_struct *p,
				   task_ctx __arg_arena *taskc)
{
	u64 cur_nr, prev_nr;
	u32 cpu_id;
	int i;

	/* do not introspect itself */
	if (bpf_strncmp(p->comm, 8, "scx_lavd") == 0)
		return;

	/* introspec_arg is the number of schedules remaining */
	cpu_id = bpf_get_smp_processor_id();
	cur_nr = intrspc.arg;

	/*
	 * Note that the bounded retry (@LAVD_MAX_RETRY) does *not *guarantee*
	 * to decrement introspec_arg. However, it is unlikely to happen. Even
	 * if it happens, it is nothing but a matter of delaying a message
	 * delivery. That's because other threads will try and succeed the CAS
	 * operation eventually. So this is good enough. ;-)
	 */
	for (i = 0; cur_nr > 0 && i < LAVD_MAX_RETRY; i++) {
		prev_nr = __sync_val_compare_and_swap(
				&intrspc.arg, cur_nr, cur_nr - 1);
		/* CAS success: submit a message and done */
		if (prev_nr == cur_nr) {
			submit_task_ctx(p, taskc, cpu_id);
			break;
		}
		/* CAS failure: retry */
		cur_nr = prev_nr;
	}
}

__hidden
void try_proc_introspec_cmd(struct task_struct *p, task_ctx __arg_arena *taskc)
{
	if (!is_monitored)
		return;

	switch(intrspc.cmd) {
	case LAVD_CMD_SCHED_N:
		proc_introspec_sched_n(p, taskc);
		break;
	case LAVD_CMD_NOP:
		/* do nothing */
		break;
	default:
		scx_bpf_error("Unknown introspec command: %d", intrspc.cmd);
		break;
	}
}


