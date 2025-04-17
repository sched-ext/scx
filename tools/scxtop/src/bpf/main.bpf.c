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

#define CLOCK_BOOTTIME 7

char _license[] SEC("license") = "GPL";

const volatile u64 long_tail_tracing_min_latency_ns = 0;

u64 trace_duration_ns = 1000000000;
u64 trace_warmup_ns = 500000000;
u64 last_trace_end_time = 0;

// dummy for generating types
struct bpf_event _event = {0};

bool enable_bpf_events = true;

enum mode mode = MODE_NORMAL;
u32 sample_rate = 128;
u32 last_sample_rate;

const int zero_int = 0;

struct timer_wrapper{
	struct bpf_timer	timer;
	int			key;
};

enum scxtop_timer_callbacks {
	TIMER_STOP_TRACE,
	MAX_TIMERS,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_TIMERS);
	__type(key, int);
	__type(value, struct timer_wrapper);
} timers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 10 * 1024 * 1024 /* 10Mib */);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, NR_SCXTOP_STATS);
} stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static __always_inline struct bpf_event* try_reserve_event()
{
	struct bpf_event *event = NULL;

	if (!(event = bpf_ringbuf_reserve(&events, sizeof(struct bpf_event), 0)))
		stat_inc(STAT_DROPPED_EVENTS);

	return event;

}

static __always_inline u32 get_random_sample(u32 n)
{
	u32 val = bpf_get_prandom_u32();

	return (val % n) + 1;
}

static bool should_sample(void)
{
	if (sample_rate == 1)
		return true;
	if (sample_rate == 0 || (get_random_sample(sample_rate) > 1))
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1000000);
} long_tail_entries SEC(".maps");

struct __softirq_event {
	u32		pid;
	u64		start_ts;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, struct __softirq_event);
	__uint(max_entries, 1);
} softirq_events SEC(".maps");


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

	if (!(event = try_reserve_event()))
		return -ENOMEM;

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

	if (!(event = try_reserve_event()))
		return -ENOMEM;

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

	if (!(event = try_reserve_event()))
		return -ENOMEM;

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

	tctx->dsq_insert_time = bpf_ktime_get_ns();
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

	tctx->dsq_insert_time = bpf_ktime_get_ns();
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

static void record_real_comm(char *comm, struct task_struct *task)
{
	if (task->flags & PF_WQ_WORKER) {
		/*
		 * Worker queue thread names are 32 characters long but let's
		 * stick with the measly 16 characters of the comm field to
		 * keep things simple.
		 */
		struct kthread *k = bpf_core_cast(task->worker_private,
						  struct kthread);
		struct worker *worker = bpf_core_cast(k->data, struct worker);
		bpf_probe_read_kernel_str(comm, MAX_COMM, worker->desc);
	} else {
		__builtin_memcpy_inline(comm, &task->comm, MAX_COMM);
	}
}

static __always_inline int __on_sched_wakeup(struct task_struct *p)
{
	struct task_ctx *tctx;
	struct bpf_event *event;

	if (!p || !should_sample())
		return 0;

	u64 now = bpf_ktime_get_ns();
	tctx = try_lookup_task_ctx(p);

	if (!(event = try_reserve_event()))
		return 0;

	event->type = SCHED_WAKEUP;

	if (tctx)
		tctx->wakeup_ts = now;

	event->ts = now;
	event->cpu = bpf_get_smp_processor_id();
	event->event.wakeup.pid = p->pid;
	event->event.wakeup.tgid = p->tgid;
	event->event.wakeup.prio = (int)p->prio;
	record_real_comm(event->event.wakeup.comm, p);

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

        if (!enable_bpf_events || !should_sample())
                return 0;

        if (!(event = try_reserve_event()))
                return -ENOMEM;

	event->type = SCHED_WAKING;
	event->ts = bpf_ktime_get_ns();
	event->cpu = bpf_get_smp_processor_id();
	event->event.wakeup.pid = p->pid;
	event->event.wakeup.tgid = p->tgid;
	event->event.wakeup.prio = (int)p->prio;
	record_real_comm(event->event.wakeup.comm, p);

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
	prev_tctx = try_lookup_task_ctx(prev);

	if (!(event = try_reserve_event()))
		return -ENOMEM;

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
	if (next) {
		event->event.sched_switch.next_pid = next->pid;
		event->event.sched_switch.next_tgid = next->tgid;
		event->event.sched_switch.next_prio = (int)next->prio;
		if (next_tctx && next_tctx->dsq_insert_time > 0) {
			event->event.sched_switch.next_dsq_lat_us = (now - next_tctx->dsq_insert_time) / 1000;
			event->event.sched_switch.next_dsq_id = next_tctx->dsq_id;
			event->event.sched_switch.next_dsq_nr = scx_bpf_dsq_nr_queued(next_tctx->dsq_id);
			/*
			 * XXX: if a task gets moved to another dsq and the vtime is updated
			 * then vtime should be read off the sched_ext_entity. To properly
			 * handle vtime any time a task is inserted to a dsq or the vtime is
			 * updated the tctx needs to be updated.
			 */
			// bpf_core_read(&event->dsq_vtime, sizeof(u64), &p->scx.dsq_vtime);
			event->event.sched_switch.next_dsq_vtime = next_tctx->dsq_vtime;
		} else {
			event->event.sched_switch.next_dsq_id = SCX_DSQ_INVALID;
			event->event.sched_switch.next_dsq_lat_us = 0;
			event->event.sched_switch.next_dsq_nr = 0;
			event->event.sched_switch.next_dsq_vtime = 0;
		}
		record_real_comm(event->event.sched_switch.next_comm, next);
	} else {
		event->event.sched_switch.next_pid = 0;
		event->event.sched_switch.next_tgid = 0;
	}

	if (prev) {
		event->event.sched_switch.prev_pid = prev->pid;
		event->event.sched_switch.prev_tgid = prev->tgid;
		event->event.sched_switch.prev_prio = (int)prev->prio;
		event->event.sched_switch.prev_state = prev_state;
		if (prev_tctx && prev_tctx->last_run_ns > 0) {
			event->event.sched_switch.prev_used_slice_ns = prev_tctx->last_run_ns - now;
			event->event.sched_switch.prev_dsq_id = prev_tctx->dsq_id;
			event->event.sched_switch.prev_slice_ns = prev_tctx->slice_ns;
		} else {
			event->event.sched_switch.prev_dsq_id = SCX_DSQ_INVALID;
		}
		record_real_comm(event->event.sched_switch.prev_comm, prev);
	} else {
		event->event.sched_switch.prev_pid = 0;
		event->event.sched_switch.prev_tgid = 0;
	}

	bpf_ringbuf_submit(event, 0);

	if (next_tctx) {
		next_tctx->last_run_ns = bpf_ktime_get_ns();
		next_tctx->dsq_vtime = 0;
		next_tctx->dsq_insert_time = 0;
		next_tctx->wakeup_ts = 0;
	}
	if (prev_tctx) {
		prev_tctx->dsq_id = SCX_DSQ_INVALID;
		prev_tctx->dsq_vtime = 0;
		prev_tctx->wakeup_ts = 0;
		prev_tctx->dsq_insert_time = 0;
	}

	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(on_softirq_entry, unsigned int nr)
{
	struct task_struct *p;

	if (!enable_bpf_events || !should_sample())
		return 0;

	p = (struct task_struct *)bpf_get_current_task();

	struct __softirq_event event;
	event.start_ts = bpf_ktime_get_ns();
	if (p)
		event.pid = BPF_CORE_READ(p, pid);
	else
		event.pid = 0;

	bpf_map_update_elem(&softirq_events, &zero_int, &event, BPF_ANY);

	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(on_softirq_exit, unsigned int nr)
{
	struct bpf_event *event;
	struct __softirq_event *softirq_event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	u64 exit_ts = bpf_ktime_get_ns();

	softirq_event = bpf_map_lookup_elem(&softirq_events, &zero_int);
	if (!softirq_event)
		return 0;

	bpf_map_delete_elem(&softirq_events, &zero_int);

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = SOFTIRQ;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = exit_ts;
	event->event.softirq.pid = softirq_event->pid;
	event->event.softirq.entry_ts = softirq_event->start_ts;
	event->event.softirq.exit_ts = exit_ts;
	event->event.softirq.softirq_nr = nr;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

static int stop_trace_timer_callback(void *map, int key, struct timer_wrapper *timerw)
{
	struct bpf_event *event;
	u64 end = mode == MODE_TRACING ? bpf_ktime_get_ns() : last_trace_end_time;

	sample_rate = last_sample_rate;

	if ((event = try_reserve_event())) {
		mode = MODE_NORMAL;

		event->ts = end;
		event->type = TRACE_STOPPED;

		bpf_ringbuf_submit(event, 0);
		return 0;
	}

	// Failed to get event. We've already slowed down the sample rate which
	// will reduce the amount of events userspace needs to handle. Log when
	// the trace actually ended and retry in 5ms.
	mode = MODE_TRACE_STOPPING;
	last_trace_end_time = end;

	bpf_timer_start(&timerw->timer, 5000000, 0);
	return 0;
}

static __always_inline int start_trace_real(bool schedule_stop, bool start_immediately)
{
	static const enum scxtop_timer_callbacks stop_trace_key = TIMER_STOP_TRACE;

	u64 duration_ns = trace_duration_ns;
	if (!start_immediately)
		duration_ns += trace_warmup_ns;

	// do not restart a started trace. this may be relaxed in future.
	enum mode last_mode = __sync_val_compare_and_swap(&mode, MODE_NORMAL, MODE_TRACING);
	if (last_mode == MODE_TRACING)
		return 0;

	struct timer_wrapper *timerw;
	struct bpf_event *event;

	// replicate the actions of userspace starting a trace so it starts
	// immediately, but such that events will come after our ringbuffer
	// entry informing userspace we've started a trace.
	// we don't enable softirqs from the bpf side and I don't think it's
	// possible with the current setup. we'd likely have to attach the uprobes
	// always and activate them with a global, which could be expensive. for
	// now let them start late.
	last_sample_rate = sample_rate;
	sample_rate = 1;

	// inform userspace that following events are in trace mode
	if (!(event = try_reserve_event()))
		goto error_no_event;

	if (schedule_stop) {
		timerw = bpf_map_lookup_elem(&timers, &stop_trace_key);
		if (!timerw)
			goto error_no_timer;
		if (bpf_timer_start(&timerw->timer, duration_ns, 0) < 0)
			goto error_no_timer;
	}

	event->ts = bpf_ktime_get_ns();
	event->type = TRACE_STARTED;
	event->event.trace.start_immediately = start_immediately;
	event->event.trace.stop_scheduled = schedule_stop;

	bpf_ringbuf_submit(event, 0);
	return 0;

error_no_timer:
	bpf_ringbuf_discard(event, 0);
error_no_event:
	__sync_val_compare_and_swap(&sample_rate, 1, last_sample_rate);
	__sync_val_compare_and_swap(&mode, MODE_TRACING, MODE_NORMAL);
	return -1;
}

/*
 * Begin a trace and schedule stopping it. This is called via BPF_PROG_RUN from userspace.
 */
SEC("syscall")
int BPF_PROG(start_trace)
{
	start_trace_real(true /* schedule_stop */, false /* start_immediately */);
	return 0;
}

SEC("uprobe")
int BPF_UPROBE(long_tail_tracker_entry)
{
	u64 pidtgid = bpf_get_current_pid_tgid();
	u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&long_tail_entries, &pidtgid, &ts, BPF_ANY);
	return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(long_tail_tracker_exit)
{
	u64 *entry_time;
	u64 now = bpf_ktime_get_ns();

	u64 pidtgid = bpf_get_current_pid_tgid();
	if (!(entry_time = bpf_map_lookup_elem(&long_tail_entries, &pidtgid)))
		return -ENOENT;

	if (now - *entry_time < long_tail_tracing_min_latency_ns)
		return 0;

	// we can't start the trace fully from the bpf side directly here because
	// we need to schedule the timer that terminates the trace, and:
	//     tracing progs cannot use bpf_timer yet
	// instead start the trace but include in the message to userspace the
	// fact we haven't scheduled the stop, and have userspace call back into
	// a "syscall" type program which can schedule the stop. userspace can
	// compute the absolute stop time to make this less racy.
	return start_trace_real(false /* schedule_stop */, true /* start_immediately */);
}

SEC("syscall")
int schedule_stop_trace(struct schedule_stop_trace_args *args)
{
	static const enum scxtop_timer_callbacks stop_trace_key = TIMER_STOP_TRACE;

	struct timer_wrapper *timerw = bpf_map_lookup_elem(&timers, &stop_trace_key);
	if (!timerw)
		return -ENOENT;
	if (bpf_timer_start(&timerw->timer, args->stop_timestamp, BPF_F_TIMER_ABS) < 0)
		return -ENOENT;

	return 0;
}

SEC("tp_btf/ipi_send_cpu")
int BPF_PROG(on_ipi_send_cpu, u32 cpu, void *callsite, void *callback)
{
	struct bpf_event *event;
	struct task_struct *p;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = IPI;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.ipi.target_cpu = cpu;

	p = (struct task_struct *)bpf_get_current_task();
	if (p)
		event->event.ipi.pid = BPF_CORE_READ(p, pid);
	else
		event->event.ipi.pid = 0;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_sched_exit, struct task_struct *task)
{
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = EXIT;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.exit.pid = BPF_CORE_READ(task, pid);
	event->event.exit.tgid = BPF_CORE_READ(task, tgid);
	event->event.exit.prio = BPF_CORE_READ(task, prio);
	record_real_comm(event->event.exit.comm, task);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_sched_fork, struct task_struct *parent, struct task_struct *child)
{
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = FORK;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.fork.parent_pid = BPF_CORE_READ(parent, pid);
	event->event.fork.child_pid = BPF_CORE_READ(child, pid);
	record_real_comm(event->event.fork.parent_comm, parent);
	record_real_comm(event->event.fork.child_comm, child);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_sched_exec, struct task_struct *p, u32 old_pid, struct linux_binprm *prm)
{
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = EXEC;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.exec.old_pid = old_pid;
	event->event.exec.pid = BPF_CORE_READ(p, pid);

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("?tp_btf/gpu_mem_total")
int BPF_PROG(on_gpu_memory_total, u32 gpu, u32 pid, u64 size)
{
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = GPU_MEM;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.gm.gpu = gpu;
	event->event.gm.pid = pid;
	event->event.gm.size = size;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/cpuhp_enter")
int BPF_PROG(on_cpuhp_enter, u32 cpu, int target, int state)
{
	struct bpf_event *event;
	struct task_struct *p;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = CPU_HP_ENTER;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.chp.cpu = cpu;
	event->event.chp.target = target;
	event->event.chp.state = state;
	p = (struct task_struct *)bpf_get_current_task();
	if (p)
		event->event.chp.pid = BPF_CORE_READ(p, pid);
	else
		event->event.chp.pid = 0;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/cpuhp_exit")
int BPF_PROG(on_cpuhp_exit, u32 cpu, int state, int idx, int ret)
{
	struct bpf_event *event;
	struct task_struct *p;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = CPU_HP_EXIT;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.cxp.cpu = cpu;
	event->event.cxp.state = state;
	event->event.cxp.state = idx;
	event->event.cxp.state = ret;
	p = (struct task_struct *)bpf_get_current_task();
	if (p)
		event->event.cxp.pid = BPF_CORE_READ(p, pid);
	else
		event->event.cxp.pid = 0;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("?tp_btf/hw_pressure_update")
int BPF_PROG(on_hw_pressure_update, u32 cpu, u64 hw_pressure)
{
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = HW_PRESSURE;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.hwp.hw_pressure = hw_pressure;
	event->event.hwp.cpu = cpu;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("tp_btf/pstate_sample")
int BPF_PROG(on_pstate_sample, u32 core_busy, u32 scaled_busy, u32 from, u32 to, u64 mperf, u64 aperf, u64 tsc, u32 freq, u32 io_boost)
{
	struct bpf_event *event;

	if (!enable_bpf_events || !should_sample())
		return 0;

	if (!(event = try_reserve_event()))
		return -ENOMEM;

	event->type = PSTATE_SAMPLE;
	event->cpu = bpf_get_smp_processor_id();
	event->ts = bpf_ktime_get_ns();
	event->event.pstate.busy = scaled_busy;

	bpf_ringbuf_submit(event, 0);

	return 0;
}

SEC("syscall")
int BPF_PROG(scxtop_init)
{
	struct timer_wrapper *timerw;
	int timer_id, err;

	bpf_for(timer_id, 0, MAX_TIMERS) {
		timerw = bpf_map_lookup_elem(&timers, &timer_id);
		if (!timerw)
			return 0;

		timerw->key = timer_id;

		err = bpf_timer_init(&timerw->timer, &timers, CLOCK_BOOTTIME);
		if (err)
			return 0;

		err = bpf_timer_set_callback(&timerw->timer, &stop_trace_timer_callback);
		if (err)
			return 0;
	}

	return 0;
}
