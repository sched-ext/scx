// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#define LSP_INC
#include "../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// dummy for generating types
struct bpf_event _event = {0};

bool enable_bpf_events = true;
u32 sample_rate = 128;


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10 * 1024 * 1024 /* 10Mib */);
} events SEC(".maps");

static __always_inline u32 get_random_sample(u32 n)
{
	u32 val = bpf_get_prandom_u32();

	return (val % n) + 1;
}

static bool should_sample(void)
{
	if (sample_rate == 0 || (sample_rate > 1 && get_random_sample(sample_rate) > 1))
		return false;
	return true;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct task_ctx);
	__uint(max_entries, 1000000);
	__uint(map_flags, 0);
} task_data SEC(".maps");


static __always_inline u64 t_to_tptr(struct task_struct *p)
{
	u64 tptr;
	int err;

	err = bpf_probe_read_kernel(&tptr, sizeof(tptr), &p);
	if (err)
		return 0;

	return tptr;
}

static struct task_ctx *try_lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;
	u64 tptr;

	if (!p)
		return NULL;

	tptr = t_to_tptr(p);
	if (tptr == 0)
		return NULL;

	tctx = bpf_map_lookup_elem(&task_data, &tptr);
	if (!tctx) {
		struct task_ctx new_tctx;
		new_tctx.dsq_id = SCX_DSQ_INVALID;
		new_tctx.dsq_vtime = 0;
		new_tctx.slice_ns = 0;
		new_tctx.last_run_ns = 0;

		if (!bpf_map_update_elem(&task_data, &tptr, &new_tctx, BPF_ANY))
			return NULL;

		tctx = bpf_map_lookup_elem(&task_data, &tptr);
	}
	return tctx;
}

static int update_task_ctx(struct task_struct *p, u64 dsq, u64 vtime, u64 slice_ns)
{
	if (!enable_bpf_events)
		return 0;

	struct task_ctx *tctx;

	if (!(tctx = try_lookup_task_ctx(p)))
		return -ENOENT;

	tctx->dsq_insert_time = bpf_ktime_get_ns();
	tctx->dsq_id = dsq;
	tctx->dsq_vtime = vtime;
	tctx->slice_ns = slice_ns;

	return 0;
}

SEC("kprobe/bpf_scx_reg")
int BPF_KPROBE(scx_sched_reg)
{
	struct bpf_event *event;

	if (!enable_bpf_events)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return -ENOENT;

	event->type = SCHED_REG;
	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("kprobe/bpf_scx_unreg")
int BPF_KPROBE(scx_sched_unreg)
{
	struct bpf_event *event;

	if (!enable_bpf_events)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return -ENOENT;

	event->type = SCHED_UNREG;
	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("kprobe/scx_bpf_cpuperf_set")
int BPF_KPROBE(on_sched_cpu_perf, s32 cpu, u32 perf)
{
	struct bpf_event *event;

	if (!enable_bpf_events)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return -ENOENT;

	event->type = CPU_PERF_SET;
	event->cpu = cpu;
	event->event.perf.perf = perf;
	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("kprobe/scx_bpf_dsq_insert_vtime")
int BPF_KPROBE(scx_insert_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return update_task_ctx(p, dsq, vtime, slice_ns);
}

SEC("kprobe/scx_bpf_dispatch_vtime")
int BPF_KPROBE(scx_dispatch_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return update_task_ctx(p, dsq, vtime, slice_ns);
}

static int on_insert(struct task_struct *p, u64 dsq)
{
	if (!enable_bpf_events)
		return 0;

	struct task_ctx *tctx;

	if (!(tctx = try_lookup_task_ctx(p)))
		return -ENOENT;

	tctx->dsq_insert_time = bpf_ktime_get_ns();
	tctx->dsq_id = dsq;
	tctx->dsq_vtime = 0;

	return 0;
}


SEC("kprobe/scx_bpf_dsq_insert")
int BPF_KPROBE(scx_insert, struct task_struct *p, u64 dsq)
{
	return on_insert(p, dsq);
}

SEC("kprobe/scx_bpf_dispatch")
int BPF_KPROBE(scx_dispatch, struct task_struct *p, u64 dsq)
{
	return on_insert(p, dsq);
}

static int on_dsq_move(struct task_struct *p, u64 dsq)
{
	if (!enable_bpf_events)
		return 0;

	struct task_ctx *tctx;

	if (!(tctx = try_lookup_task_ctx(p)))
		return -ENOENT;

	tctx->dsq_id = dsq;
	tctx->dsq_vtime = 0;

	return 0;
}

SEC("kprobe/scx_bpf_dsq_move")
int BPF_KPROBE(scx_dsq_move, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move(p, dsq_id);
}

SEC("kprobe/scx_bpf_dispatch_from_dsq")
int BPF_KPROBE(scx_dispatch_from_dsq, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move(p, dsq_id);
}

static int on_dsq_move_vtime(struct task_struct *p, u64 dsq)
{
	if (!enable_bpf_events)
		return 0;

	struct task_ctx *tctx;

	if (!(tctx = try_lookup_task_ctx(p)))
		return -ENOENT;

	tctx->dsq_id = dsq;
	bpf_core_read(&tctx->dsq_vtime, sizeof(u64), &p->scx.dsq_vtime);

	return 0;
}

SEC("kprobe/scx_bpf_dsq_move_vtime")
int BPF_KPROBE(scx_dsq_move_vtime, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move_vtime(p, dsq_id);
}

SEC("kprobe/scx_bpf_dispatch_vtime_from_dsq")
int BPF_KPROBE(scx_dispatch_vtime_from_dsq, struct bpf_iter_scx_dsq *it__iter,
	       struct task_struct *p, u64 dsq_id, u64 enq_flags)
{
	return on_dsq_move_vtime(p, dsq_id);
}

static int on_move_set_slice(struct task_struct *p, u64 slice)
{
	if (!enable_bpf_events || !p)
		return 0;

	struct task_ctx *tctx;

	if (!(tctx = try_lookup_task_ctx(p)))
		return -ENOENT;

	tctx->slice_ns = slice;

	return 0;
}

SEC("kprobe/scx_bpf_dsq_move_set_slice")
int BPF_KPROBE(scx_dsq_move_set_slice, struct bpf_iter_scx_dsq *it__iter, u64 slice)
{
	// TODO: figure out how to return task from iterator without consuming.
	return on_move_set_slice(NULL, slice);
}

SEC("kprobe/scx_bpf_dispatch_from_dsq_set_slice")
int BPF_KPROBE(scx_dispatch_from_dsq_set_slice, struct bpf_iter_scx_dsq *it__iter,
	       u64 slice)
{
	// TODO: figure out how to return task from iterator without consuming.
	return on_move_set_slice(NULL, slice);
}

static int on_move_set_vtime(struct task_struct *p, u64 vtime)
{
	if (!enable_bpf_events || !p)
		return 0;

	struct task_ctx *tctx;

	if (!(tctx = try_lookup_task_ctx(p)))
		return -ENOENT;

	tctx->dsq_vtime = vtime;

	return 0;
}

SEC("kprobe/scx_bpf_dsq_move_set_vtime")
int BPF_KPROBE(scx_dsq_move_set_vtime, struct bpf_iter_scx_dsq *it__iter, u64 vtime)
{
	// TODO: figure out how to return task from iterator without consuming.
	return on_move_set_vtime(NULL, vtime);
}

SEC("kprobe/scx_bpf_dispatch_from_dsq_set_vtime")
int BPF_KPROBE(scx_dispatch_from_dsq_set_vtime, struct bpf_iter_scx_dsq *it__iter, u64 vtime)
{
	// TODO: figure out how to return task from iterator without consuming.
	return on_move_set_vtime(NULL, vtime);
}

static __always_inline int __on_sched_wakeup(struct task_struct *p)
{
	struct task_ctx *tctx;
	struct bpf_event *event;

	if (!p || !should_sample())
		return 0;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return 0;

	tctx->wakeup_ts = bpf_ktime_get_ns();
	event->type = SCHED_WAKEUP;
	event->ts = tctx->wakeup_ts;
	event->cpu = bpf_get_smp_processor_id();
	event->event.wakeup.pid = p->pid;
	event->event.wakeup.prio = (int)p->prio;
	__builtin_memcpy_inline(&event->event.wakeup.comm, &p->comm, MAX_COMM);
	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_sched_wakeup, struct task_struct *p)
{
	return __on_sched_wakeup(p);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_sched_wakeup_new, struct task_struct *p)
{
	return __on_sched_wakeup(p);
}

SEC("tp_btf/sched_waking")
int BPF_PROG(on_sched_waking, struct task_struct *p)
{
	struct bpf_event *event;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return 0;

	event->type = SCHED_WAKING;
	event->ts = bpf_ktime_get_ns();
	event->cpu = bpf_get_smp_processor_id();
	event->event.wakeup.pid = p->pid;
	event->event.wakeup.prio = (int)p->prio;
	__builtin_memcpy(&event->event.wakeup.comm, &p->comm, MAX_COMM);

	bpf_ringbuf_submit(event, 0);
	return 0;
}


static __always_inline int on_sched_switch_non_scx(bool preempt, struct task_struct *prev,
						   struct task_struct *next, u64 prev_state)
{
	struct bpf_event *event;

	if (!prev || !next)
		return -ENOENT;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return -ENOENT;

	u64 now = bpf_ktime_get_ns();
	event->type = SCHED_SWITCH;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = now;
	event->event.sched_switch.preempt = preempt;
	event->event.sched_switch.next_pid = next->pid;
	event->event.sched_switch.next_tgid = next->tgid;
	event->event.sched_switch.next_prio = (int)next->prio;
	event->event.sched_switch.next_dsq_id = SCX_DSQ_INVALID;
	event->event.sched_switch.prev_pid = prev->pid;
	event->event.sched_switch.prev_tgid = prev->tgid;
	event->event.sched_switch.prev_prio = (int)prev->prio;
	event->event.sched_switch.prev_dsq_id = SCX_DSQ_INVALID;
	event->event.sched_switch.prev_state = prev_state;
	__builtin_memcpy_inline(&event->event.sched_switch.next_comm, &next->comm, MAX_COMM);
	__builtin_memcpy_inline(&event->event.sched_switch.prev_comm, &prev->comm, MAX_COMM);

	bpf_ringbuf_submit(event, 0);

	return 0;
}


SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, bool preempt, struct task_struct *prev,
	     struct task_struct *next, u64 prev_state)
{
	struct task_ctx *next_tctx, *prev_tctx;
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	next_tctx = try_lookup_task_ctx(next);
	if (!next_tctx || next_tctx->dsq_id == SCX_DSQ_INVALID || next_tctx->dsq_insert_time == 0) {
		if (sample_rate == 1)
			return on_sched_switch_non_scx(preempt, prev, next, prev_state);
		return -ENOENT;
	}

	prev_tctx = try_lookup_task_ctx(prev);
	if (!prev_tctx || prev_tctx->dsq_id == SCX_DSQ_INVALID) {
		if (sample_rate == 1)
			return on_sched_switch_non_scx(preempt, prev, next, prev_state);
		return -ENOENT;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return -ENOENT;

	u64 now = bpf_ktime_get_ns();
	event->type = SCHED_SWITCH;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = now;

	/*
	 * Tracking vtime **and** the dsq a task was inserted to is kind of
	 * tricky. We could read dsq_vtime directly of the sched_ext_entity on
	 * the task_struct, but the dsq field will not be available on
	 * sched_switch as the task is not on any dsq. The current hacky
	 * solution is to record the dsq that the task was inserted to and
	 * store it in a map for the task. There still needs to be handling for
	 * when tasks are moved from iterators.
	 */
	event->event.sched_switch.preempt = preempt;
	event->event.sched_switch.next_pid = next->pid;
	event->event.sched_switch.next_tgid = next->tgid;
	event->event.sched_switch.next_prio = (int)next->prio;
	event->event.sched_switch.next_dsq_id = next_tctx->dsq_id;
	event->event.sched_switch.next_dsq_lat_us = (now - next_tctx->dsq_insert_time) / 1000;
	event->event.sched_switch.next_dsq_nr = scx_bpf_dsq_nr_queued(next_tctx->dsq_id);
	event->event.sched_switch.prev_pid = prev->pid;
	event->event.sched_switch.prev_tgid = prev->tgid;
	event->event.sched_switch.prev_prio = (int)prev->prio;
	event->event.sched_switch.prev_state = prev_state;
	event->event.sched_switch.prev_used_slice_ns = prev_tctx->last_run_ns - now;
	event->event.sched_switch.prev_dsq_id = prev_tctx->dsq_id;
	__builtin_memcpy(&event->event.sched_switch.next_comm, &next->comm, MAX_COMM);
	event->event.sched_switch.prev_slice_ns = prev_tctx->slice_ns;
	__builtin_memcpy(&event->event.sched_switch.prev_comm, &prev->comm, MAX_COMM);

	/*
	 * XXX: if a task gets moved to another dsq and the vtime is updated
	 * then vtime should be read off the sched_ext_entity. To properly
	 * handle vtime any time a task is inserted to a dsq or the vtime is
	 * updated the tctx needs to be updated.
	 */
	// bpf_core_read(&event->dsq_vtime, sizeof(u64), &p->scx.dsq_vtime);
	event->event.sched_switch.next_dsq_vtime = next_tctx->dsq_vtime;
	bpf_ringbuf_submit(event, 0);

	next_tctx->last_run_ns = bpf_ktime_get_ns();
	next_tctx->dsq_vtime = 0;
	next_tctx->dsq_insert_time = 0;
	next_tctx->wakeup_ts = 0;
	prev_tctx->dsq_id = SCX_DSQ_INVALID;
	prev_tctx->dsq_vtime = 0;
	prev_tctx->wakeup_ts = 0;
	prev_tctx->dsq_insert_time = 0;

	return 0;
}
