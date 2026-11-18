/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Hungyu Lin <dennylin0707@gmail.com>
 *
 * scx_lertick: weighted virtual-time scheduling with learned time slices.
 *
 * Tasks wait in one DSQ per LLC, ordered by a virtual deadline: the weighted
 * virtual time plus half the slice the task is given. An idle CPU steals
 * from another LLC's DSQ. The virtual clock advances with the CPU
 * time actually delivered over the total runnable weight, so tasks that keep
 * waking cannot hold back tasks that have already run. A woken task is placed
 * at most LAG_NS behind the clock.
 *
 * In online mode each task trains a small linear model inside BPF on its own
 * completed CPU bursts (wake to sleep). At the next wakeup the prediction sets
 * the task's time slice, bounded by slice_min and slice_max. A new process
 * starts from the model earlier tasks with the same name trained, and a
 * thread whose bursts depend on who wakes it is told apart by its waker.
 * Fixed mode uses slice_fixed for every task. Fairness always charges the CPU
 * time actually used, never the prediction.
 *
 * The queue policy (per-LLC queues, continuation, cgroup weights) is in
 * policy.h. Queues and CPU selection follow scx_simple; cgroup weights follow
 * scx_flatcg (Tejun Heo).
 */
#include <scx/common.bpf.h>
#include "intf.h"
#include "model.h"

char _license[] SEC("license") = "GPL";

/*
 * Maximum time a task can wait in the scheduler's queue before triggering
 * a stall. With hundreds of runnable tasks per CPU a fair round alone can
 * take most of a second.
 */
#define STARVATION_MS 5000ULL

/* Model inputs and targets are scaled against this burst length. */
#define REFERENCE_NS (10ULL * NSEC_PER_MSEC)
#define QUEUE_REFERENCE 16U

/* Wakers remembered per task. */
#define NR_WAKERS 4

/*
 * Share of a task's slice, in percent, added to its vtime to order the DSQ.
 * A task predicted to run briefly gets a short slice and so an earlier
 * deadline, and runs before longer ones that are about as far behind in
 * vtime, without preempting anyone. Without the offset, the schbench -m 4
 * -t 2 wakeup p99 on 4 CPUs moved between 3 and 5 ms; with 100 or 200
 * percent, perf messaging with processes on 8 CPUs was about 5% slower.
 */
#define DEADLINE_PCT 50

/*
 * Update count a task keeps when it takes over its program's model, so that
 * it still learns with a large step (see train_model()).
 */
#define PROG_INHERIT_UPDATES 2ULL

/*
 * Scheduling mode and slice bounds, set by user space before load.
 */
const volatile u32 mode	       = LERTICK_MODE_ONLINE;
const volatile u64 slice_fixed = 2ULL * NSEC_PER_MSEC;
const volatile u64 slice_min   = 500ULL * NSEC_PER_USEC;
const volatile u64 slice_max   = 3ULL * NSEC_PER_MSEC;
/*
 * Bursts a task's model must have learned from before its prediction sets
 * its slice. A task that takes over its program's model counts as having
 * learned PROG_INHERIT_UPDATES of them.
 */
const volatile u32 min_train_samples = 2;

/*
 * Statistics, read by user space. Each CPU counts in its own slot, so the
 * counters add no cache line that all CPUs write.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, LERTICK_NR_STATS);
} stats SEC(".maps");

static __always_inline void stat_inc(u32 idx)
{
	u64 *cnt = bpf_map_lookup_elem(&stats, &idx);

	if (cnt)
		(*cnt)++;
}

/*
 * Define struct user_exit_info, shared between BPF and user space to
 * communicate the exit status.
 */
UEI_DEFINE(uei);

/*
 * Per-task context: the model, the current wake-to-sleep episode and the
 * weights the task is counted with.
 */
struct task_ctx {
	struct lertick_model model;
	__s32		     features[LERTICK_FEATURES];
	u64		     runtime_start_ns;
	u64		     episode_runtime_ns;
	u64		     last_sleep_ns;
	u64		     last_burst_ns;
	u64		     ewma_burst_ns;
	u64		     prediction_ns;
	u64		     completed_bursts;
	bool		     episode_active;
	bool		     episode_valid;
	bool		     has_slept;
	bool		     running;
	bool		     started_in_select;
	u32 rq_weight; /* weight counted in runnable_weight, 0 when not counted */
	bool cg_counted; /* rq_weight is also counted in its cgroup's sums */
	u32 eff_weight; /* weight of the last charge; dispatch() cannot look up cgroups */
	char comm[16]; /* program whose model this task last took over */
	u32  waker; /* pid that woke the current episode */
	u32  waker_pid[NR_WAKERS]; /* the last wakers of this task ... */
	u64  waker_burst[NR_WAKERS]; /* ... and the last burst each one started */
	u32  waker_next;
	u64  waker_err, avg_err; /* recent error of the two burst guesses */
	u64  dl_off; /* deadline offset in dsq_vtime while queued */
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return the context of task @p, or NULL.
 */
static struct task_ctx *task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
}

/*
 * A model per task name (comm), trained with every completed burst of the
 * tasks with that name. Short-lived processes, such as a compiler's, then
 * predict from their first burst with what earlier processes of the program
 * learned. A task that renames itself only changes which model it starts
 * from: the prediction sets the slice, never the vtime charge. Updates take
 * no lock, so concurrent ones can be lost; that only slows the learning.
 */
struct prog_key {
	char comm[16];
};

struct prog_val {
	struct lertick_model model;
	u64		     ewma_burst_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct prog_key);
	__type(value, struct prog_val);
} prog_stor SEC(".maps");

/* keep_prev() compares the running task with the deadline of a fixed slice. */
#define LERTICK_PREV_DEADLINE(p, tctx)                     \
	(slice_fixed * DEADLINE_PCT /                      \
	 ((tctx) && (tctx)->eff_weight ? (tctx)->eff_weight : 100))
#define LERTICK_MOVE_TO_LOCAL(dsq) scx_bpf_dsq_move_to_local(dsq, 0)
#define LERTICK_TASK_CGROUP(p) scx_bpf_task_cgroup(p)
#include "policy.h"

/*
 * A new model predicts its burst guess (feature 1) as it is, so it is no
 * worse than that guess before it has learned anything.
 */
static void start_model(struct lertick_model *model)
{
	lertick_model_init(model);
	model->weight_q16[0] = 0;
	model->weight_q16[1] = LERTICK_Q;
}

/*
 * One least-mean-squares step. The step starts large and shrinks (1/8 for
 * the first 8 updates, 1/16 up to 32, then 1/64), so a model adapts within a
 * few bursts and is stable afterwards.
 */
static void train_model(struct lertick_model *model,
			const __s32 features[LERTICK_FEATURES], __s32 target_q16)
{
	__s64 error = (__s64)lertick_clip_q16(target_q16) -
		      lertick_model_raw_q16(model, features);
	__s64 alpha = model->updates < 8  ? LERTICK_Q / 8 :
		      model->updates < 32 ? LERTICK_Q / 16 :
					    LERTICK_ALPHA_Q16;
	int   i;

	if (error > LERTICK_Q)
		error = LERTICK_Q;
	if (error < -LERTICK_Q)
		error = -LERTICK_Q;
	bpf_for(i, 0, LERTICK_FEATURES)
	{
		__s64 update;

		if (i >= LERTICK_FEATURES)
			break;
		update = lertick_trunc_shift(
			alpha * error * lertick_clip_q16(features[i]), 32);
		model->weight_q16[i] = lertick_clip_weight(
			(__s64)lertick_clip_weight(model->weight_q16[i]) +
			update);
	}
	if (model->updates != ~(__u64)0)
		model->updates++;
}

static bool same_comm(const char *a, const char *b)
{
	u64 x[2], y[2];

	__builtin_memcpy(x, a, sizeof(x));
	__builtin_memcpy(y, b, sizeof(y));
	return x[0] == y[0] && x[1] == y[1];
}

/*
 * When @p's name differs from the one its model was taken for (first wakeup,
 * exec, rename), take over the model of its new name. Its update count is
 * capped, since threads of one program can behave differently and each must
 * still adapt to its own bursts.
 */
static void prog_sync(struct task_struct *p, struct task_ctx *tctx)
{
	struct prog_key	 key = {};
	struct prog_val *v;

	if (mode != LERTICK_MODE_ONLINE || same_comm(tctx->comm, p->comm))
		return;
	__builtin_memcpy(tctx->comm, p->comm, sizeof(tctx->comm));
	__builtin_memcpy(key.comm, p->comm, sizeof(key.comm));
	v = bpf_map_lookup_elem(&prog_stor, &key);
	if (!v)
		return;
	tctx->model	    = v->model;
	tctx->ewma_burst_ns = v->ewma_burst_ns;
	if (tctx->model.updates > PROG_INHERIT_UPDATES)
		tctx->model.updates = PROG_INHERIT_UPDATES;
}

/* Train @p's program model with the burst that just completed. */
static void prog_learn(struct task_struct *p, struct task_ctx *tctx,
		       __s32 target, u64 burst)
{
	struct prog_key	 key = {};
	struct prog_val *v;

	__builtin_memcpy(key.comm, p->comm, sizeof(key.comm));
	v = bpf_map_lookup_elem(&prog_stor, &key);
	if (!v) {
		struct prog_val init = {};

		start_model(&init.model);
		bpf_map_update_elem(&prog_stor, &key, &init, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&prog_stor, &key);
		if (!v)
			return;
	}
	train_model(&v->model, tctx->features, target);
	v->ewma_burst_ns = v->ewma_burst_ns ?
				   v->ewma_burst_ns * 3 / 4 + burst / 4 :
				   burst;
}

/* Slot of the current episode's waker among the task's last wakers, or -1. */
static __always_inline int waker_slot(struct task_ctx *tctx)
{
	int i, slot = -1;

	bpf_for(i, 0, NR_WAKERS)
	{
		if (tctx->waker_pid[i % NR_WAKERS] == tctx->waker)
			slot = i % NR_WAKERS;
	}
	return slot;
}

/*
 * The burst guess fed to the model: the last burst this waker started, while
 * that has recently been closer than the burst average, else the average.
 * A thread that alternates between two kinds of work, each started by a
 * different waker, then gets the right length for each; a task whose bursts
 * vary at random keeps the steadier average.
 */
static u64 burst_guess(struct task_ctx *tctx)
{
	int slot = waker_slot(tctx);

	if (slot >= 0 && tctx->waker_err < tctx->avg_err)
		return tctx->waker_burst[slot % NR_WAKERS];
	return tctx->ewma_burst_ns;
}

/*
 * Score both burst guesses against the burst that just completed, and
 * remember it as this waker's last.
 */
static void learn_waker(struct task_ctx *tctx, u64 burst)
{
	int slot = waker_slot(tctx);
	u64 g	 = slot >= 0 ? tctx->waker_burst[slot % NR_WAKERS] :
			       MIN(tctx->last_burst_ns, REFERENCE_NS);
	u64 a	 = tctx->ewma_burst_ns;

	tctx->waker_err = tctx->waker_err * 7 / 8 +
			  (g > burst ? g - burst : burst - g) / 8;
	tctx->avg_err	= tctx->avg_err * 7 / 8 +
			  (a > burst ? a - burst : burst - a) / 8;
	if (slot < 0) {
		slot = tctx->waker_next % NR_WAKERS;
		tctx->waker_next++;
		tctx->waker_pid[slot % NR_WAKERS] = tctx->waker;
	}
	tctx->waker_burst[slot % NR_WAKERS] = burst;
}

/*
 * A wakeup starts an episode. Only an episode that starts with a verified
 * wakeup and ends in sleep is a training example: a task that keeps running
 * across slices is not mistaken for one that completed a burst.
 */
static void begin_episode(struct task_ctx *tctx, u64 enq_flags)
{
	u64   now      = bpf_ktime_get_ns();
	u64   sleep_ns = tctx->last_sleep_ns ? now - tctx->last_sleep_ns : 0;
	u64   queued   = nr_queued_all();
	__s32 pred;

	tctx->episode_active = true;
	tctx->episode_valid  = tctx->has_slept && (enq_flags & SCX_ENQ_WAKEUP);
	tctx->episode_runtime_ns = 0;
	tctx->prediction_ns	 = 0;
	/* On a wakeup the running task is the waker. */
	tctx->waker		 = (u32)bpf_get_current_pid_tgid();

	tctx->features[0]	 = LERTICK_Q;
	tctx->features[1] =
		lertick_scale_ns_q16(burst_guess(tctx), REFERENCE_NS);
	tctx->features[2] =
		lertick_scale_ns_q16(tctx->ewma_burst_ns, REFERENCE_NS);
	tctx->features[3] = lertick_scale_ns_q16(sleep_ns, REFERENCE_NS);
	tctx->features[4] = queued >= QUEUE_REFERENCE ?
				    LERTICK_Q :
				    queued * LERTICK_Q / QUEUE_REFERENCE;

	if (mode != LERTICK_MODE_ONLINE || !tctx->episode_valid)
		return;
	pred = lertick_model_predict_q16(&tctx->model, tctx->features);
	tctx->prediction_ns = (u64)pred * REFERENCE_NS / LERTICK_Q;
}

/*
 * Remaining slice: the predicted burst less what already ran, within bounds.
 * A burst predicted past slice_max is cut whatever its slice, so it gets
 * slice_fixed: a longer slice would only make waiting tasks wait longer.
 */
static u64 task_slice(struct task_ctx *tctx, u64 consumed_ns)
{
	u64 slice = slice_fixed;

	if (tctx && mode == LERTICK_MODE_ONLINE && tctx->episode_valid &&
	    tctx->model.updates >= min_train_samples &&
	    tctx->prediction_ns <= slice_max &&
	    tctx->prediction_ns > consumed_ns) {
		slice = tctx->prediction_ns - consumed_ns;
		stat_inc(LERTICK_STAT_ADAPTIVE_SLICES);
	}

	return CLAMP(slice, slice_min, slice_max);
}

/*
 * Pick a CPU for a waking task. An idle CPU, or the waker's CPU on a sync
 * wakeup that sync_local() accepts, gets the task on its local DSQ right
 * away; otherwise ops.enqueue() queues it.
 */
s32 BPF_STRUCT_OPS(lertick_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx = task_ctx(p);
	bool		 idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);

	/* select_cpu() precedes runnable() on a wakeup and can insert directly. */
	if (tctx && !tctx->episode_active) {
		prog_sync(p, tctx);
		begin_episode(tctx, SCX_ENQ_WAKEUP);
		tctx->started_in_select = true;
	}
	if (idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   task_slice(tctx, tctx ? tctx->episode_runtime_ns : 0),
				   0);
		stat_inc(LERTICK_STAT_LOCAL_DISPATCHES);
	} else if ((wake_flags & SCX_WAKE_SYNC) && sync_local(p, &cpu)) {
		queue_on_cpu(p, cpu,
			     task_slice(tctx, tctx ? tctx->episode_runtime_ns : 0));
		stat_inc(LERTICK_STAT_LOCAL_DISPATCHES);
	}

	return cpu;
}

/*
 * Queue @p on its LLC's DSQ in deadline order, with its vtime held within the
 * lag bounds. The deadline offset is kept in dsq_vtime only while @p is
 * queued: running() takes it out, so the charge and the clock use the vtime.
 */
void BPF_STRUCT_OPS(lertick_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx  = task_ctx(p);
	u64		 vtime = p->scx.dsq_vtime;
	u64 slice = task_slice(tctx, tctx ? tctx->episode_runtime_ns : 0);

	/* A task dequeued without running still carries its offset. */
	if (tctx && tctx->dl_off) {
		vtime -= tctx->dl_off;
		tctx->dl_off = 0;
	}

	/*
	 * Only a wakeup earns sleeper credit (LAG_NS); a task requeued after its
	 * slice keeps its vtime within the wider bounds of clamp_ahead(), or
	 * tasks with larger weights would be pulled back to the clock and lose
	 * their share.
	 */
	if ((enq_flags & SCX_ENQ_WAKEUP) &&
	    time_before(vtime, vtime_now - LAG_NS))
		vtime = vtime_now - LAG_NS;
	vtime = clamp_ahead(p, vtime);

	if (tctx) {
		u32 w = tctx->eff_weight ? tctx->eff_weight :
			p->scx.weight	 ? p->scx.weight :
					   1;

		tctx->dl_off = slice * DEADLINE_PCT / w;
		vtime += tctx->dl_off;
	}
	scx_bpf_dsq_insert_vtime(p, domain_of(scx_bpf_task_cpu(p)), slice,
				 vtime, enq_flags);
	stat_inc(LERTICK_STAT_SHARED_DISPATCHES);
}

/*
 * @cpu needs a task. @prev continues if keep_prev() allows it; otherwise the
 * next queued task runs, and @prev continues only when nothing is queued.
 */
void BPF_STRUCT_OPS(lertick_dispatch, s32 cpu, struct task_struct *prev)
{
	bool continuing = prev && (prev->scx.flags & SCX_TASK_QUEUED);
	struct task_ctx *tctx;
	u64		 consumed;

	if (!((continuing && keep_prev(prev, task_ctx(prev), cpu)) ||
	      (!take_next(cpu) && continuing)))
		return;

	/*
	 * prev continues. The kernel may update sum_exec_runtime before
	 * dispatch() and keep prev without stopping() or running(), so read
	 * the pending segment for the slice decision without charging it:
	 * stopping() charges it.
	 */
	tctx	 = task_ctx(prev);
	consumed = tctx ? tctx->episode_runtime_ns : 0;
	if (tctx && tctx->running &&
	    prev->se.sum_exec_runtime > tctx->runtime_start_ns)
		consumed += prev->se.sum_exec_runtime - tctx->runtime_start_ns;

	scx_bpf_dsq_insert(prev, SCX_DSQ_LOCAL, task_slice(tctx, consumed), 0);
	stat_inc(LERTICK_STAT_CONTINUATIONS);
}

/*
 * @p becomes runnable: count its weight toward the clock and its cgroup, and
 * start an episode unless ops.select_cpu() already did.
 */
void BPF_STRUCT_OPS(lertick_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;

	if (!tctx->rq_weight) {
		tctx->rq_weight = p->scx.weight ? p->scx.weight : 1;
		__sync_fetch_and_add(&runnable_weight, tctx->rq_weight);
		cgrp_task_runnable(p, tctx, true);
	}

	/* Migration can produce runnable notifications without a new wakeup. */
	if (!tctx->episode_active) {
		prog_sync(p, tctx);
		begin_episode(tctx, enq_flags);
	} else if (tctx->started_in_select) {
		/* Confirm the wakeup before admitting this episode as a label. */
		if (!(enq_flags & SCX_ENQ_WAKEUP))
			tctx->episode_valid = false;
		tctx->started_in_select = false;
	}
}

/*
 * @p starts running: take its deadline offset out of its vtime, raise the
 * clock to that vtime if the clock is behind, and note where this run starts.
 */
void BPF_STRUCT_OPS(lertick_running, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (tctx && tctx->dl_off) {
		p->scx.dsq_vtime -= tctx->dl_off;
		tctx->dl_off = 0;
	}
	clock_raise(p->scx.dsq_vtime);

	if (!tctx)
		return;
	tctx->runtime_start_ns = p->se.sum_exec_runtime;
	tctx->running	       = true;
}

/*
 * @p stops running: charge the CPU time it used to its vtime, scaled by its
 * effective weight, and advance the clock.
 */
void BPF_STRUCT_OPS(lertick_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx	= task_ctx(p);
	u32		 weight = p->scx.weight ? p->scx.weight : 1;
	u64		 delta, rw;

	if (!tctx || !tctx->running)
		return;
	tctx->running = false;
	if (p->se.sum_exec_runtime < tctx->runtime_start_ns) {
		tctx->episode_valid = false;
		return;
	}
	delta		 = p->se.sum_exec_runtime - tctx->runtime_start_ns;

	tctx->eff_weight = cgrp_effective_weight(p, tctx, weight);
	p->scx.dsq_vtime += delta * 100 / tctx->eff_weight;

	/*
	 * Advance the clock by the service delivered over the runnable weight,
	 * as the average vtime of runnable tasks moves. Otherwise a stream of
	 * short sleepers, each placed just behind the clock, keeps it still and
	 * starves tasks that have already run.
	 */
	rw = runnable_weight;
	clock_advance(delta * 100 / (rw < 100 ? 100 : rw));
	tctx->episode_runtime_ns += delta;
}

/*
 * @p is no longer runnable. When it goes to sleep, the burst that just ended
 * becomes a training example for its model.
 */
void BPF_STRUCT_OPS(lertick_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx = task_ctx(p);
	u64		 burst;

	if (!tctx)
		return;

	if (tctx->rq_weight) {
		cgrp_task_runnable(p, tctx, false);
		__sync_fetch_and_sub(&runnable_weight, tctx->rq_weight);
		tctx->rq_weight = 0;
	}

	/* Non-sleep quiescence keeps the episode across migration and preemption. */
	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	/*
	 * A running task gets stopping(p, false) before this callback, so the
	 * last service segment is already in episode_runtime_ns exactly once.
	 */
	burst = tctx->episode_runtime_ns;
	if (tctx->episode_active && tctx->episode_valid && burst &&
	    !(p->flags & PF_EXITING)) {
		__s32 target = lertick_scale_ns_q16(burst, REFERENCE_NS);

		if (mode == LERTICK_MODE_ONLINE) {
			train_model(&tctx->model, tctx->features, target);
			stat_inc(LERTICK_STAT_TRAINING_UPDATES);
			prog_learn(p, tctx, target, MIN(burst, REFERENCE_NS));
			learn_waker(tctx, MIN(burst, REFERENCE_NS));
		}
		tctx->completed_bursts++;
		tctx->last_burst_ns = burst;
		burst		    = MIN(burst, REFERENCE_NS);
		tctx->ewma_burst_ns =
			tctx->ewma_burst_ns ?
				tctx->ewma_burst_ns * 3 / 4 + burst / 4 :
				burst;
	}

	tctx->last_sleep_ns  = bpf_ktime_get_ns();
	tctx->has_slept	     = true;
	tctx->episode_active = false;
	tctx->episode_valid  = false;
}

/*
 * Allocate and initialize the context of a new task.
 */
s32 BPF_STRUCT_OPS(lertick_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;
	start_model(&tctx->model);

	return 0;
}

/*
 * @p joins the scheduler: start it at the clock.
 */
void BPF_STRUCT_OPS(lertick_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

/*
 * @p leaves the scheduler: drop its unfinished episode.
 */
void BPF_STRUCT_OPS(lertick_disable, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;
	tctx->episode_active = false;
	tctx->episode_valid  = false;
	tctx->has_slept	     = false;
	/* enable() restarts the vtime at the clock, without any offset. */
	tctx->dl_off	     = 0;
}

/*
 * Allocate the context of a new cgroup and record its weight.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(lertick_cgroup_init, struct cgroup *cgrp,
			     struct scx_cgroup_init_args *args)
{
	struct cgrp_ctx *cgc;

	cgc = bpf_cgrp_storage_get(&cgrp_ctx_stor, cgrp, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cgc)
		return -ENOMEM;
	cgc->weight  = args->weight;
	cgc->hweight = HWEIGHT_ONE;

	return 0;
}

/*
 * cpu.weight of @cgrp changed: update its parent's sum and invalidate the
 * cached hierarchical weights.
 */
void BPF_STRUCT_OPS(lertick_cgroup_set_weight, struct cgroup *cgrp, u32 weight)
{
	struct cgrp_ctx *cgc = cgrp_ctx(cgrp), *pc = NULL;

	if (!cgc)
		return;
	if (cgrp->level) {
		pc = cgrp_ancestor_ctx(cgrp, cgrp->level - 1);
		if (!pc)
			return;
	}

	bpf_spin_lock(&cgrp_lock);
	if (pc && cgc->nr_active)
		pc->child_weight_sum += (s64)weight - cgc->weight;
	cgc->weight = weight;
	bpf_spin_unlock(&cgrp_lock);

	__sync_fetch_and_add(&hweight_gen, 1);
}

/* A runnable task changing cgroups takes its weight with it. */
void BPF_STRUCT_OPS(lertick_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx || !tctx->cg_counted)
		return;
	cgrp_account(from, tctx, false);
	cgrp_account(to, tctx, true);
}

/*
 * Create one vtime-ordered DSQ per LLC.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(lertick_init)
{
	u32 d;
	s32 ret;

	bpf_for(d, 0, domain_count())
	{
		ret = scx_bpf_create_dsq(d, -1);
		if (ret)
			return ret;
	}

	return create_cpu_dsqs();
}

/*
 * Debug dump, printed by the kernel when the scheduler exits with an error
 * (for example a runnable-task stall): the clock and queue lengths, and for
 * each task its vtime relative to the clock and its burst prediction.
 */
void BPF_STRUCT_OPS(lertick_dump, struct scx_dump_ctx *dctx)
{
	scx_bpf_dump(
		"lertick clock=%llu runnable_weight=%llu queued=%llu domains=%u",
		vtime_now, runnable_weight, nr_queued_all(), domain_count());
}

void BPF_STRUCT_OPS(lertick_dump_task, struct scx_dump_ctx *dctx,
		    struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;
	scx_bpf_dump(
		"lertick vs_clock=%lld eff_weight=%u predicted=%llu ran=%llu ewma=%llu updates=%llu valid=%d",
		(s64)(p->scx.dsq_vtime - vtime_now), tctx->eff_weight,
		tctx->prediction_ns, tctx->episode_runtime_ns,
		tctx->ewma_burst_ns, tctx->model.updates, tctx->episode_valid);
}

/*
 * Record the exit reason for user space.
 */
void BPF_STRUCT_OPS(lertick_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(lertick_ops, .select_cpu = (void *)lertick_select_cpu,
	       .enqueue		  = (void *)lertick_enqueue,
	       .dispatch	  = (void *)lertick_dispatch,
	       .runnable	  = (void *)lertick_runnable,
	       .running		  = (void *)lertick_running,
	       .stopping	  = (void *)lertick_stopping,
	       .quiescent	  = (void *)lertick_quiescent,
	       .cgroup_init	  = (void *)lertick_cgroup_init,
	       .cgroup_set_weight = (void *)lertick_cgroup_set_weight,
	       .cgroup_move	  = (void *)lertick_cgroup_move,
	       .init_task	  = (void *)lertick_init_task,
	       .enable		  = (void *)lertick_enable,
	       .disable = (void *)lertick_disable, .init = (void *)lertick_init,
	       .exit = (void *)lertick_exit, .dump = (void *)lertick_dump,
	       .dump_task  = (void *)lertick_dump_task,
	       .timeout_ms = STARVATION_MS, .name = "lertick");
