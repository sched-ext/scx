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
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline u32 get_random_sample(u32 n)
{
    u32 val = bpf_get_prandom_u32();

    return (val % n) + 1;
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, struct task_ctx);
	__uint(max_entries, 1000000);
	__uint(map_flags, 0);
} task_data SEC(".maps");


static u64 t_to_tptr(struct task_struct *p)
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
	u64 tptr;
	tptr = t_to_tptr(p);

	return bpf_map_lookup_elem(&task_data, &tptr);
}

SEC("kprobe/bpf_scx_reg")
int BPF_KPROBE(scx_sched_reg)
{
	struct bpf_event *event;

	if (!enable_bpf_events)
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return 1;

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
		return 1;

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
		return 1;

	event->type = CPU_PERF_SET;
	event->cpu = cpu;
	event->perf = perf;
	bpf_ringbuf_submit(event, 0);

	return 0;
}

static int on_insert_vtime(struct task_struct *p, u64 dsq, u64 vtime)
{
	if (!enable_bpf_events)
		return 0;

	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		struct task_ctx new_tctx;
		tctx = &new_tctx;
	}

	u64 tptr;
	tptr = t_to_tptr(p);

	tctx->dsq_insert_time = bpf_ktime_get_ns();
	tctx->dsq_id = dsq;
	tctx->dsq_vtime = vtime;
	bpf_map_update_elem(&task_data, &tptr, tctx, BPF_ANY);

	return 0;
}

SEC("kprobe/scx_bpf_dsq_insert_vtime")
int BPF_KPROBE(scx_insert_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return on_insert_vtime(p, dsq, vtime);
}

SEC("kprobe/scx_bpf_dispatch_vtime")
int BPF_KPROBE(scx_dispatch_vtime, struct task_struct *p, u64 dsq, u64 slice_ns, u64 vtime)
{
	return on_insert_vtime(p, dsq, vtime);
}

static int on_insert(struct task_struct *p, u64 dsq)
{
	if (!enable_bpf_events)
		return 0;

	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx) {
		struct task_ctx new_tctx;
		tctx = &new_tctx;
	}

	u64 tptr;
	tptr = t_to_tptr(p);

	tctx->dsq_insert_time = bpf_ktime_get_ns();
	tctx->dsq_id = dsq;
	tctx->dsq_vtime = 0;
	bpf_map_update_elem(&task_data, &tptr, tctx, BPF_ANY);

	return 0;
}


SEC("kprobe/scx_bpf_dispatch")
int BPF_KPROBE(scx_dispatch, struct task_struct *p, u64 dsq)
{
	return on_insert(p, dsq);
}

SEC("kprobe/scx_bpf_dsq_insert")
int BPF_KPROBE(scx_insert, struct task_struct *p, u64 dsq)
{
	return on_insert(p, dsq);
}

static __always_inline int __on_sched_wakeup(struct task_struct *p)
{
	struct bpf_event *event;

	if (!p || !p->scx.dsq)
		return 0;

	u32 val = get_random_sample(sample_rate);
	if (val > 1) {
		return 0;
	}

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return 1;

	event->type = SCHED_WAKEUP;
	event->cpu = bpf_get_smp_processor_id();
	bpf_core_read(&event->dsq_id, sizeof(u64), &p->scx.dsq->id);
	bpf_core_read(&event->dsq_nr, sizeof(u32), &p->scx.dsq->nr);
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

SEC("raw_tracepoint/sched_switch")
int on_sched_switch(struct pt_regs *ctx)
{
	struct task_struct *p;
	struct task_ctx *tctx;
	struct bpf_event *event;

	if (!enable_bpf_events)
		return 0;

	p = (struct task_struct*)bpf_get_current_task();
	if (!p)
		return 0;

	u32 val = get_random_sample(sample_rate);
	if (val > 1) {
		return 0;
	}

	tctx = try_lookup_task_ctx(p);
	if (!tctx || tctx->dsq_id == SCX_DSQ_INVALID || tctx->dsq_insert_time == 0)
		return 0;

	u64 now = bpf_ktime_get_ns();

	event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0);
	if (!event)
		return 1;

	event->type = SCHED_SWITCH;
	event->cpu = bpf_get_smp_processor_id();
	/*
	 * Tracking vtime **and** the dsq a task was inserted to is kind of
	 * tricky. We could read dsq_vtime directly of the sched_ext_entity on
	 * the task_struct, but the dsq field will not be available on
	 * sched_switch as the task is not on any dsq. The current hacky
	 * solution is to record the dsq that the task was inserted to and
	 * store it in a map for the task. There still needs to be handling for
	 * when tasks are moved from iterators.
	 */
	event->dsq_id = tctx->dsq_id;
	event->dsq_lat_us = (now - tctx->dsq_insert_time) / 1000;

	/*
	 * XXX: if a task gets moved to another dsq and the vtime is updated
	 * then vtime should be read off the sched_ext_entity. To properly
	 * handle vtime any time a task is inserted to a dsq or the vtime is
	 * updated the tctx needs to be updated.
	 */
	// bpf_core_read(&event->dsq_vtime, sizeof(u64), &p->scx.dsq_vtime);
	event->dsq_vtime = tctx->dsq_vtime;
	bpf_ringbuf_submit(event, 0);

	tctx->dsq_vtime = 0;
	tctx->dsq_id = 0;
	tctx->dsq_insert_time = 0;

	return 0;
}
