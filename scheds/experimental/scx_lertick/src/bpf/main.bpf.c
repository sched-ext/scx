/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Hungyu Lin <dennylin0707@gmail.com>
 *
 * scx_lertick: weighted virtual-time scheduling with learned time slices.
 *
 * Tasks wait in one DSQ per LLC, ordered by a virtual deadline: the weighted
 * virtual time plus half the slice the task is given, scaled by its weight
 * like the virtual time. An idle CPU steals
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
 * Each CPU also has a DSQ of its own. Whether a woken task preempts the task
 * running on its CPU, and whether a woken or preempted task waits on its
 * CPU's DSQ or its LLC's, is learned for each program (see choose()).
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
 * A model per program, trained with every completed burst of the program's
 * tasks. Short-lived processes, such as a compiler's, then predict from
 * their first burst with what earlier processes of the program learned.
 *
 * A program is the executable's device and inode together with the task's
 * name (comm). The name alone joined unrelated programs that share it. The
 * executable alone would join every script of one interpreter, and threads
 * that name themselves by their role. Kernel threads have no executable and
 * are told apart by name. A task that renames itself only changes which
 * model it starts from: the prediction sets the slice, never the vtime
 * charge. Updates take no lock, so concurrent ones can be lost, and an LRU
 * map reuses an evicted entry at once, so a sample can now and then land in
 * another program's model. Either only slows the learning.
 */
struct prog_key {
	u64  ino;
	u32  dev;
	u32  pad;
	char comm[16];
};

/* A learned choice made: its cell and the CPU whose table holds it. */
struct choice_ref {
	u64 prog;
	u32 decision;
	u32 cpu;
};

/*
 * Per-task context: the model, the current wake-to-sleep episode and the
 * weights the task is counted with.
 */
struct task_ctx {
	struct lertick_model model;
	__s32		     features[LERTICK_FEATURES];
	u64 runtime_start_ns; /* sum_exec_runtime the run is charged up to */
	u64 run_start_ns; /* sum_exec_runtime when it last started running */
	u64		     episode_runtime_ns;
	u64 episode_work_ns; /* the same, scaled by CPU capacity */
	u32 run_cap; /* capacity of the CPU it last ran on */
	s32 rotate_to; /* big CPU + 1 that dispatch() hands it to */
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
	u32  held; /* HELD or RELEASING while asleep but counted, see hold() */
	u32  held_cpu;
	u32  waits_on; /* LLC queue + 1 whose waiter holds this task's deadline */
	u64  waits_dl;
	/* as a waiter (see struct waiter): the choice, and the wait it then had */
	struct choice_ref tw_key;
	bool tw_yield, tw_pend, tw_on;
	u64  tw_ts, tw_wait, tw_rts;
	/*
	 * as a task that gave way at a tick: the waiter's choice, its own wait.
	 * A tick in the run that follows may give way again and set tg_key, so
	 * the run is charged to the choice taken when it started, tg_run_key.
	 */
	struct choice_ref tg_key, tg_run_key;
	bool tg_pend, tg_on;
	u64  tg_ts, tg_wait, tg_rts;
	u32  held_weight; /* what a held task is counted with ... */
	u64  held_cg; /* ... and in, 0 for no cgroup */
	u64  cg_id; /* cgroup rq_weight is counted in */
	u32 eff_weight; /* weight of the last charge; dispatch() cannot look up cgroups */
	bool eff_stale; /* weight or cgroup changed while not counted in it */
	struct prog_key prog_key; /* program the task last synced with ... */
	u64		prog_mm; /* ... at this mm, so that an exec is seen */
	u64		prog; /* that program's id, 0 for none */
	u32  waker; /* pid that woke the current episode */
	u32  waker_pid[NR_WAKERS]; /* the last wakers of this task ... */
	u64  waker_burst[NR_WAKERS]; /* ... and the last burst each one started */
	u32  waker_next;
	u64  waker_err, avg_err; /* recent error of the two burst guesses */
	u64  dl_off; /* deadline offset in dsq_vtime while queued */
	bool wake_sync; /* the last wakeup was a sync one */
	bool yielded; /* called sched_yield() since its last dispatch */
	u64  wait_ts; /* queued since, 0 from when it runs until it is queued */
	u64  queued_ts; /* queued instead of preempting */
	u64  preempted_ts;
	struct choice_ref queued_key, preempted_key;
	u64  qrun_wait, qrun_ts; /* wait after not preempting, run start */
	struct choice_ref qrun_key;
	u64  prun_ts; /* run start of a task that preempted */
	struct choice_ref prun_key;
	bool qrun_on, prun_on, prun_pend, vrun_on;
	u64  vrun_wait, vrun_ts; /* wait after being preempted, run start */
	struct choice_ref vrun_key;
	u64  place_ts; /* when the queue choice queued it */
	struct choice_ref place_key;
	bool place_cpu; /* on its CPU's queue, not the LLC's */
	u64  cpuq_ts, cpuq_wait; /* run start and wait, after a CPU queue */
	struct choice_ref cpuq_key;
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

struct prog_val {
	struct lertick_model model;
	u64		     ewma_burst_ns;
	u64 id; /* never reused: the key of the program's learned choices */
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
/* take_next() follows the CPU queue rules below (see own_first()). */
static __always_inline bool own_first(s32 cpu);
static __always_inline void took_shared(u32 home, u64 t0);
#define LERTICK_OWN_FIRST(cpu) own_first(cpu)
#define LERTICK_NOW() bpf_ktime_get_ns()
#define LERTICK_TOOK_SHARED(home, t0) took_shared(home, t0)
static __always_inline void took_from(u32 d);
static __always_inline bool guard_overdue(s32 cpu);
#define LERTICK_TOOK_FROM(d) took_from(d)
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

static __always_inline bool same_comm(const char *a, const char *b)
{
	u64 x[2], y[2];

	__builtin_memcpy(x, a, sizeof(x));
	__builtin_memcpy(y, b, sizeof(y));
	return x[0] == y[0] && x[1] == y[1];
}

static u64 prog_ids;

/*
 * The entry of @key, made with a new model if it has none. Its id is new
 * as well, so choices learned for an evicted entry are not taken over.
 */
static struct prog_val *prog_get(struct prog_key *key)
{
	struct prog_val *v = bpf_map_lookup_elem(&prog_stor, key);

	if (!v) {
		struct prog_val init = {};

		start_model(&init.model);
		init.id = __sync_add_and_fetch(&prog_ids, 1);
		bpf_map_update_elem(&prog_stor, key, &init, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&prog_stor, key);
	}
	return v;
}

/*
 * When @p's program differs from the one it last synced with (first
 * wakeup, exec, rename), look up the new one. This runs as a burst starts:
 * a task that execs and keeps running decides with the old program's
 * learned choices until it first sleeps. In online mode a task takes
 * over the program's model, or starts a new one if the program has learned
 * nothing yet. Its update count is
 * capped, since threads of one program can behave differently and each must
 * still adapt to its own bursts.
 */
static void prog_sync(struct task_struct *p, struct task_ctx *tctx)
{
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	struct prog_key	  key = {};
	struct prog_val	 *v;

	if (tctx->prog && tctx->prog_mm == (u64)mm &&
	    same_comm(tctx->prog_key.comm, p->comm))
		return;
	__builtin_memcpy(key.comm, p->comm, sizeof(key.comm));
	/* a kernel thread may borrow an mm, never an executable */
	if (mm && !(p->flags & PF_KTHREAD)) {
		key.ino = BPF_CORE_READ(mm, exe_file, f_inode, i_ino);
		key.dev = BPF_CORE_READ(mm, exe_file, f_inode, i_sb, s_dev);
	}
	tctx->prog_key = key;
	tctx->prog_mm  = (u64)mm;
	v	       = prog_get(&key);
	tctx->prog     = v ? v->id : 0;
	if (!v || mode != LERTICK_MODE_ONLINE)
		return;
	/* a new program that learned nothing yet: not the old program's model */
	if (!v->model.updates) {
		start_model(&tctx->model);
		return;
	}
	tctx->model	    = v->model;
	tctx->ewma_burst_ns = v->ewma_burst_ns;
	if (tctx->model.updates > PROG_INHERIT_UPDATES)
		tctx->model.updates = PROG_INHERIT_UPDATES;
}

/*
 * Train @p's program model with the burst that just completed. All tasks of
 * a program write its model, so after its first PROG_LEARN_FIRST bursts a
 * task trains it with one burst in PROG_LEARN_EVERY.
 */
#define PROG_LEARN_FIRST 16
#define PROG_LEARN_EVERY 8

static void prog_learn(struct task_struct *p, struct task_ctx *tctx,
		       __s32 target, u64 burst)
{
	struct prog_val *v;

	if (tctx->completed_bursts >= PROG_LEARN_FIRST &&
	    tctx->completed_bursts % PROG_LEARN_EVERY)
		return;
	/* a burst across an exec or a rename belongs to neither program */
	if (tctx->prog_mm != (u64)BPF_CORE_READ(p, mm) ||
	    !same_comm(tctx->prog_key.comm, p->comm))
		return;
	v = prog_get(&tctx->prog_key);
	if (!v)
		return;
	tctx->prog = v->id;
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
	tctx->episode_work_ns	 = 0;
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
 * CPU capacities, from the loader, the largest 1024. cpus_asym is set when
 * some CPU is more than 5% below the largest in the kernel's capacities, or
 * when scx_utils finds little cores, as on a machine with big and little
 * cores. Without it, nothing below changes the scheduling: every
 * capacity is 1024.
 *
 * With it, bursts are learned as work, their run time scaled by the
 * capacity of the CPU they ran on, so a burst learned on a little CPU
 * predicts the right time on a big one; a woken task whose bursts run long
 * takes an idle CPU of the largest capacity; and a task that keeps running
 * on a little CPU is handed to an idle big one (asym_rotate).
 */
const volatile u16  cpu_cap[LERTICK_MAX_CPUS];
const volatile bool cpus_asym;
const volatile bool asym_rotate = true;

#define BIG_CAP 973 /* within 5% of the largest */
/* Tasks handed to a big CPU wait here, taken by that CPU only. */
#define ROT_DSQ(cpu) (0x20000ULL + (u64)(cpu))

static __always_inline u32 cap_of(s32 cpu)
{
	u16 c = cpu_cap[cpu & (LERTICK_MAX_CPUS - 1)];

	return cpus_asym && c ? c : 1024;
}

/*
 * SMT siblings, from the loader: cpu_sibling[cpu] is the other hardware
 * thread of the CPU's core plus one, 0 for none. smt_on is set when some
 * core has two threads. A task that keeps running on a core whose other
 * thread is busy too moves to a whole idle core (smt_balance), as the
 * kernel's load balancing spreads busy threads over cores.
 */
const volatile u16  cpu_sibling[LERTICK_MAX_CPUS];
const volatile bool smt_on;
const volatile bool smt_balance = true;

static __always_inline s32 sibling_of(s32 cpu)
{
	return smt_on ? (s32)cpu_sibling[cpu & (LERTICK_MAX_CPUS - 1)] - 1 : -1;
}

/* Is the other thread of @cpu's core busy? */
static __always_inline bool sibling_busy(s32 cpu)
{
	const struct cpumask *idle;
	s32		      sib = sibling_of(cpu);
	bool		      busy;

	if (sib < 0)
		return false;
	idle = scx_bpf_get_idle_cpumask();
	busy = !bpf_cpumask_test_cpu(sib, idle);
	scx_bpf_put_idle_cpumask(idle);
	return busy;
}

/* Is @cpu idle in @idle, and its sibling, if any, too? */
static __always_inline bool core_idle_in(s32 cpu, const struct cpumask *idle)
{
	s32 sib = sibling_of(cpu);

	return bpf_cpumask_test_cpu(cpu, idle) &&
	       (sib < 0 || bpf_cpumask_test_cpu(sib, idle));
}

/*
 * Claim an idle CPU for @p: of the largest capacity if @big, of a whole idle
 * core if @whole, @prev first. Returns -1 if there is none.
 */
static __always_inline s32 pick_idle(struct task_struct *p, s32 prev, bool big,
				     bool whole)
{
	const struct cpumask *idle = scx_bpf_get_idle_cpumask();
	u32 n = scx_bpf_nr_cpu_ids(), i;
	s32 cpu = -1;

	if (prev >= 0 && (!big || cap_of(prev) >= BIG_CAP) &&
	    bpf_cpumask_test_cpu(prev, p->cpus_ptr) &&
	    (!whole || core_idle_in(prev, idle)) &&
	    scx_bpf_test_and_clear_cpu_idle(prev)) {
		cpu = prev;
		goto out;
	}
	bpf_for(i, 0, n)
	{
		if (i >= LERTICK_MAX_CPUS)
			break;
		if ((big && cap_of(i) < BIG_CAP) ||
		    !bpf_cpumask_test_cpu(i, p->cpus_ptr) ||
		    (whole && !core_idle_in(i, idle)))
			continue;
		if (scx_bpf_test_and_clear_cpu_idle(i)) {
			cpu = i;
			break;
		}
	}
out:
	scx_bpf_put_idle_cpumask(idle);
	return cpu;
}

/* An idle CPU of the largest capacity, of a whole idle core if possible. */
static __always_inline s32 pick_big_idle(struct task_struct *p, s32 prev)
{
	s32 cpu = smt_on ? pick_idle(p, prev, true, true) : -1;

	return cpu >= 0 ? cpu : pick_idle(p, prev, true, false);
}

/*
 * Is a task that has run @run of its current burst worth moving to a better
 * CPU? With a trusted prediction, the burst is expected to last the larger of
 * the prediction and the average burst (as time on the CPU it runs on): it
 * is worth moving while at least slice_min of that is left, the time below
 * which the kernel also treats a task's cache as still hot, or once it has
 * run twice as long, so that the prediction has plainly missed. A task about
 * to finish its burst then stays rather than finishing on a cold cache.
 * Without a trusted prediction, it is worth moving once it has run past the
 * fixed slice.
 */
const volatile bool pred_move = true;

static __always_inline bool worth_moving(struct task_ctx *tctx, u64 run)
{
	u32 cap = tctx->run_cap ? tctx->run_cap : 1024;
	u64 expect;

	if (!pred_move || mode != LERTICK_MODE_ONLINE || !tctx->episode_valid ||
	    tctx->model.updates < min_train_samples)
		return run >= slice_fixed;
	expect = MAX(tctx->prediction_ns, tctx->ewma_burst_ns) * 1024 / cap;
	return run >= 2 * expect || run + slice_min <= expect;
}

/* Do tasks handed over in dispatch() wait in ROT_DSQ()? */
static __always_inline bool handover_on(void)
{
	return (cpus_asym && asym_rotate) || (smt_on && smt_balance);
}

/*
 * Remaining slice: the predicted burst less what already ran, within bounds.
 * A burst predicted past slice_max is cut whatever its slice, so it gets
 * slice_fixed: a longer slice would only make waiting tasks wait longer.
 *
 * No longer than what a task of weight 100 gets in WAIT_MAX_NS at the
 * current load, and no shorter than slice_min, so that the queue goes round
 * in about the time the deadline bound allows. With 1100 tasks bound to one
 * CPU, a round took about 7 s, and the last tasks queued waited past the
 * watchdog. Below about 160 runnable tasks per busy CPU the cap is above
 * slice_max and changes nothing.
 */
static u64 task_slice(struct task_ctx *tctx, u64 consumed_ns)
{
	u64 slice = slice_fixed, pred = tctx ? tctx->prediction_ns : 0;

	/* Work to time on the CPU the task last ran on (see cpus_asym). */
	if (cpus_asym && tctx) {
		u32 cap	    = tctx->run_cap ? tctx->run_cap : 1024;
		u64 pending = consumed_ns > tctx->episode_runtime_ns ?
				      consumed_ns - tctx->episode_runtime_ns :
				      0;

		pred	    = pred * 1024 / cap;
		consumed_ns = tctx->episode_work_ns * 1024 / cap + pending;
	}
	if (tctx && mode == LERTICK_MODE_ONLINE && tctx->episode_valid &&
	    tctx->model.updates >= min_train_samples && pred <= slice_max &&
	    pred > consumed_ns) {
		slice = pred - consumed_ns;
		stat_inc(LERTICK_STAT_ADAPTIVE_SLICES);
	}

	slice = MIN(slice, wait_max_vtime());
	return CLAMP(slice, slice_min, slice_max);
}

/*
 * Learned choices, one cell per program and decision, each with the average
 * cost of its two options and the average deviation of that cost. The
 * decisions are whether a woken task preempts the task running on its CPU,
 * where a woken task that does not preempt, or a preempted task, waits (on
 * its CPU's queue or on its LLC's queue), and whether a tick gives way to
 * a waiter. Each CPU keeps its own table, so that CPUs do not write each
 * other's cache lines when they decide. A cost is recorded in the table of
 * the CPU that made the choice, which a task that moved since writes from
 * another CPU.
 */
#define CHOICE_CELLS 4096
#define CHOICE_SHIFT 3
#define CHOICE_MIN 4
#define CHOICE_COST_MAX (50ULL * NSEC_PER_MSEC)
#define CHOICE_RUN_MAX 0xffffffffULL
#define CHOICE_N_MAX 0xffff

/*
 * Costs are capped at CHOICE_COST_MAX and runs at CHOICE_RUN_MAX, so a cell
 * fits in 36 bytes, stored in 40, and the table takes 160 KiB per possible
 * CPU.
 */
struct choice {
	u64 tag; /* program id and decision the cell holds, 0 for none */
	u32 cost[2], dev[2];
	u32 run; /* run of a woken task after it preempted, average */
	u16 n[2];
	u16 nrun;
};

/*
 * A cell is picked by a hash of the program's id and the decision, and holds
 * them, so that a program never reads another's costs. One whose cell went
 * to another program starts over. A hash table found by the exact key took
 * longer to look up than this array and cost stress-ng futex 2%.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CHOICE_CELLS);
	__type(key, u32);
	__type(value, struct choice);
} choices SEC(".maps");

/* Average time a take from an LLC's queue costs on this CPU. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} take_cost SEC(".maps");

#define CHOICE_PREEMPT 0
#define CHOICE_WOKEN 1
#define CHOICE_PREEMPTED 2
#define CHOICE_TICK 3

/* The cell of @tctx's program for @decision, on this CPU. */
static __always_inline struct choice_ref choice_key(struct task_ctx *tctx,
						    u32 decision)
{
	struct choice_ref r = {
		.prog	  = tctx->prog,
		.decision = decision,
		.cpu	  = bpf_get_smp_processor_id(),
	};

	return r;
}

/*
 * The cell @r names, or NULL if it holds another program's choice. With
 * @create, such a cell is emptied and taken over. A CPU recording a cost
 * in another CPU's table takes no lock: if that CPU hands the cell to
 * another program meanwhile, the cost can land there, which a few later
 * costs outweigh.
 */
static __always_inline struct choice *choice_at(const struct choice_ref *r,
						bool create)
{
	u64	       tag = (r->prog << 2 | r->decision) + 1;
	u32	       k   = (tag * 0x9e3779b97f4a7c15ULL) >> 52;
	struct choice *c;

	_Static_assert(CHOICE_CELLS == 1 << 12, "the hash keeps 12 bits");
	c = r->cpu == bpf_get_smp_processor_id() ?
		    bpf_map_lookup_elem(&choices, &k) :
		    bpf_map_lookup_percpu_elem(&choices, &k, r->cpu);
	if (!c || c->tag == tag)
		return c;
	if (!create)
		return NULL;
	__builtin_memset(c, 0, sizeof(*c));
	c->tag = tag;
	return c;
}

/*
 * Record @cost for option @opt of cell @key. A cost is capped at
 * CHOICE_COST_MAX, so that one long stall does not outweigh many runs.
 */
static __always_inline void choice_cost(const struct choice_ref *key,
					u32 opt, u64 cost)
{
	struct choice *c = choice_at(key, true);
	u64	       dev;

	if (!c)
		return;
	opt &= 1;
	cost = MIN(cost, CHOICE_COST_MAX);
	dev  = !c->n[opt]	      ? 0 :
	       cost > c->cost[opt] ? cost - c->cost[opt] :
				       c->cost[opt] - cost;
	c->dev[opt] = c->dev[opt] - (c->dev[opt] >> CHOICE_SHIFT) +
		      (dev >> CHOICE_SHIFT);
	if (c->n[opt])
		c->cost[opt] = c->cost[opt] - (c->cost[opt] >> CHOICE_SHIFT) +
			       (cost >> CHOICE_SHIFT);
	else
		c->cost[opt] = cost;
	if (c->n[opt] < CHOICE_N_MAX)
		c->n[opt]++;
}

/*
 * Pick option 1 of cell @key? Each option's cost is drawn from its average
 * plus or minus its deviation, and the lower draw wins, so an option whose
 * cost is close or uncertain is still tried now and then. Each option is
 * tried CHOICE_MIN times first.
 */
static __always_inline bool choose(const struct choice_ref *key)
{
	struct choice *c = choice_at(key, false);
	s64	       r0, r1;

	if (!c)
		return true;
	if (c->n[0] < CHOICE_MIN || c->n[1] < CHOICE_MIN)
		return c->n[1] <= c->n[0];
	r0 = (s64)(bpf_get_prandom_u32() % 2001) - 1000;
	r1 = (s64)(bpf_get_prandom_u32() % 2001) - 1000;
	return (s64)c->cost[1] + r1 * (s64)c->dev[1] / 1000 <
	       (s64)c->cost[0] + r0 * (s64)c->dev[0] / 1000;
}

/*
 * The head deadline of each LLC's queue, lowered on insertion and cleared on
 * a take, each on its own cache line, so that a CPU can compare it with its
 * own queue without taking the LLC queue's lock.
 */
struct llc_head {
	u64 v;
	u64 pad[7];
};
struct llc_head llc_heads[LERTICK_MAX_DOMAINS];

static __always_inline struct llc_head *llc_head_of(u32 d)
{
	return &llc_heads[d & (LERTICK_MAX_DOMAINS - 1)];
}

/* The vtime of the head of @dsq, if it has one. */
static __always_inline bool dsq_head_vtime(u64 dsq, u64 *vt)
{
	struct task_struct *q;

	bpf_for_each(scx_dsq, q, dsq, 0) {
		*vt = q->scx.dsq_vtime;
		return true;
	}
	return false;
}

/*
 * A CPU tries its own queue before its LLC queue while its own head deadline
 * is at most CPUQ_WINDOW_NS after the LLC queue's head deadline, read from a
 * cached copy. Otherwise it tries the LLC queue first and its own queue
 * after it.
 */
#define CPUQ_WINDOW_NS (2ULL * NSEC_PER_MSEC)

/* LERTICK_OWN_FIRST() for take_next(), see CPUQ_WINDOW_NS. */
static __always_inline bool own_first(s32 cpu)
{
	u32  home = domain_of(cpu);
	u64  own = 0, sh;

	if (!dsq_head_vtime(CPU_DSQ(cpu), &own))
		return false;
	if (!scx_bpf_dsq_nr_queued(home))
		return true;
	sh = llc_head_of(home)->v;
	if (!sh && dsq_head_vtime(home, &sh))
		llc_head_of(home)->v = sh;
	return !sh || !time_before(sh + CPUQ_WINDOW_NS, own);
}

/* A take from LLC queue @home started at @t0: time it, and drop the head. */
/* A steal took the head of LLC @d: its cached head is stale. */
static __always_inline void took_from(u32 d)
{
	if (llc_head_of(d)->v)
		llc_head_of(d)->v = 0;
}

static __always_inline void took_shared(u32 home, u64 t0)
{
	u64 d = bpf_ktime_get_ns() - t0, *tc;
	u32 z = 0;

	tc = bpf_map_lookup_elem(&take_cost, &z);
	if (tc)
		*tc = *tc ? *tc - *tc / 8 + d / 8 : d;
	if (llc_head_of(home)->v)
		llc_head_of(home)->v = 0;
}

/*
 * Does the head of @cpu's own queue come before @prev, as keep_prev() asks
 * of the LLC queue?
 */
static __always_inline bool cpu_head_before(struct task_struct *prev, s32 cpu)
{
	struct task_ctx *pt = task_ctx(prev);
	u64		 pv = prev->scx.dsq_vtime, ran = 0, h = 0;
	u32		 pw = pt && pt->eff_weight ? pt->eff_weight :
			      prev->scx.weight	    ? prev->scx.weight :
							1;

	if (pt && pt->running &&
	    prev->se.sum_exec_runtime > pt->runtime_start_ns)
		ran = prev->se.sum_exec_runtime - pt->runtime_start_ns;
	pv += ran * 100 / pw + LERTICK_PREV_DEADLINE(prev, pt);
	return dsq_head_vtime(CPU_DSQ(cpu), &h) && time_before(h, pv);
}

/*
 * A woken task that does not preempt waits on the LLC queue until the running
 * task's slice ends, up to slice_max. A tick lets the running task go once it
 * has run past the deadline of such a waiter, kept per LLC queue in waiters:
 * the earliest one queued since it was last cleared, by that waiter running or
 * a CPU giving way to it, 0 for none, with its choice key.
 * Whether a tick may give way to a program's waiters is learned as wakeup
 * preemption is (see the enqueue side). Tasks queued again after a preemption
 * are not waiters: giving way to them would undo the preemption.
 * A tick does not check that the waiter may run on its CPU, which would take
 * a task lookup: a CPU it may not run on can give way to no effect, and it
 * then waits for a CPU it may run on, as it would without the deadline.
 */
struct waiter {
	struct bpf_spin_lock lock; /* the fields change together under it */
	u64		     dl;
	struct choice_ref    key;
	u32 pid; /* the waiter: tasks woken at one vtime share a deadline */
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LERTICK_MAX_DOMAINS);
	__type(key, u32);
	__type(value, struct waiter);
} waiters SEC(".maps");

static __always_inline struct waiter *waiter_of(u32 d)
{
	d &= LERTICK_MAX_DOMAINS - 1;
	return bpf_map_lookup_elem(&waiters, &d);
}

/*
 * Does woken task @p, at @vtime, preempt the task running on its CPU? It may
 * when its vtime is before the running task's vtime plus the run not yet
 * charged and a fixed slice, both scaled by the running task's weight, much
 * as EEVDF checks a wakeup. Then it does as learned for its program. Not
 * preempting costs the wait of @p over the run that follows it. Preempting
 * costs the wait of the preempted task over the shorter of its own next run
 * and the average run of @p after a preemption. Neither a wakee that runs a
 * few microseconds and sleeps again nor a victim that runs briefly between
 * waits, as a dispatcher does, is then worth a preemption.
 */

static __always_inline bool wake_preempt(struct task_struct *p,
					 struct task_ctx *tctx, u64 vtime,
					 u64 slice, u64 enq_flags)
{
	s32		    c	= scx_bpf_task_cpu(p);
	struct task_struct *cur = __COMPAT_scx_bpf_cpu_curr(c);
	struct task_ctx	   *ct	= cur && cur != p ? task_ctx(cur) : NULL;
	u64		    ran = 0, dl;
	struct choice_ref   key;
	u32		    cw;

	if (!ct || !ct->running)
		return false;
	cw = ct->eff_weight ? ct->eff_weight : 100;
	if (cur->se.sum_exec_runtime > ct->runtime_start_ns)
		ran = cur->se.sum_exec_runtime - ct->runtime_start_ns;
	dl = cur->scx.dsq_vtime + (ran + slice_fixed) * 100 / cw;
	if (!time_before(vtime, dl) || guard_overdue(c))
		return false;

	key = choice_key(tctx, CHOICE_PREEMPT);
	if (!choose(&key)) {
		tctx->queued_ts	 = bpf_ktime_get_ns();
		tctx->queued_key = key;
		return false;
	}
	ct->preempted_ts  = bpf_ktime_get_ns();
	ct->preempted_key = key;
	tctx->prun_key	  = key;
	tctx->prun_pend	  = true;
	p->scx.dsq_vtime  = vtime;
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | c, slice,
			   enq_flags | SCX_ENQ_PREEMPT);
	stat_inc(LERTICK_STAT_PREEMPTS);
	return true;
}

/* When each CPU last called ops.dispatch(), so last took from its queues. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} last_dispatch SEC(".maps");

/*
 * Has this CPU gone KEEP_MAX_NS without a dispatch while tasks are queued
 * for it, on its own DSQ or its LLC DSQ?
 */
static __always_inline bool queues_skipped(s32 cpu)
{
	u32  z = 0;
	u64 *t = bpf_map_lookup_elem(&last_dispatch, &z);

	return t && bpf_ktime_get_ns() - *t >= KEEP_MAX_NS &&
	       (scx_bpf_dsq_nr_queued(CPU_DSQ(cpu)) ||
		scx_bpf_dsq_nr_queued(domain_of(cpu)));
}

/*
 * Pick a CPU for a waking task. An idle CPU gets the task on its local DSQ
 * right away, and the waker's CPU on a sync wakeup that sync_local() accepts
 * gets it on its CPU queue. Otherwise ops.enqueue() queues it.
 */
s32 BPF_STRUCT_OPS(lertick_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx = task_ctx(p);
	u64		 vtime = p->scx.dsq_vtime;
	bool		 idle  = false;
	s32		 cpu   = -1;

	/*
	 * A wakeup may insert here, so bound its sleeper credit as enqueue()
	 * does. Inserted with the vtime it went to sleep with, a task that
	 * slept long kept that credit and later preempted where a task woken
	 * through enqueue() would not.
	 */
	if (!tctx || !tctx->dl_off) {
		if (time_before(vtime, vtime_now - LAG_NS))
			vtime = vtime_now - LAG_NS;
		vtime = clamp_ahead(p, vtime);
		if (vtime != p->scx.dsq_vtime)
			scx_bpf_task_set_dsq_vtime(p, vtime);
	}

	/* A task whose bursts run long takes an idle big CPU if one is free. */
	if (cpus_asym && tctx && tctx->ewma_burst_ns >= slice_fixed) {
		cpu  = pick_big_idle(p, prev_cpu);
		idle = cpu >= 0;
	}
	if (cpu < 0)
		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &idle);

	/* select_cpu() precedes runnable() on a wakeup and can insert directly. */
	if (tctx && !tctx->episode_active) {
		prog_sync(p, tctx);
		begin_episode(tctx, SCX_ENQ_WAKEUP);
		tctx->started_in_select = true;
	}
	if (tctx)
		tctx->wake_sync = wake_flags & SCX_WAKE_SYNC;
	/*
	 * On a sync wakeup the kernel reports the waker's CPU as idle when its
	 * local DSQ is empty and some other CPU is idle. Inserted there
	 * directly, two tasks that hand off to each other kept that CPU's
	 * local DSQ busy, so it never dispatched, and a kworker bound to it
	 * waited on its own DSQ until the watchdog fired. So, as keep_prev()
	 * lets no task keep a CPU past KEEP_MAX_NS, the wakee is queued once
	 * the CPU has gone that long without a dispatch. Queuing it whenever
	 * a task queued for that CPU had an earlier deadline cut the pair's
	 * handoffs to a seventh of EEVDF's: on CPUs crowded by pinned tasks,
	 * those tasks are behind the shared clock and always earlier.
	 */
	if (idle && cpu == bpf_get_smp_processor_id() &&
	    (queues_skipped(cpu) || guard_overdue(cpu)))
		idle = false;
	if (idle) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,
				   task_slice(tctx, tctx ? tctx->episode_runtime_ns : 0),
				   0);
		stat_inc(LERTICK_STAT_LOCAL_DISPATCHES);
	} else if ((wake_flags & SCX_WAKE_SYNC) && sync_local(p, &cpu)) {
		if (tctx && !tctx->wait_ts)
			tctx->wait_ts = bpf_ktime_get_ns();
		queue_on_cpu(p, cpu,
			     task_slice(tctx, tctx ? tctx->episode_runtime_ns : 0));
		stat_inc(LERTICK_STAT_LOCAL_DISPATCHES);
	} else if (tctx) {
		/*
		 * No CPU is idle: queue it on the waker's CPU, where enqueue()
		 * may let it preempt the waker, as the kernel's wake_affine
		 * does.
		 */
		s32		 this = bpf_get_smp_processor_id();
		struct task_ctx *wt   = task_ctx(bpf_get_current_task_btf());

		if (wt && wt->running &&
		    bpf_cpumask_test_cpu(this, p->cpus_ptr))
			cpu = this;
	}

	return cpu;
}

/*
 * Queue @p in deadline order, with its vtime held within the lag bounds: on
 * its CPU's queue or its LLC's queue, unless it preempts the running task.
 * The deadline offset is kept in dsq_vtime only while @p is queued:
 * running() takes it out, so the charge and the clock use the vtime.
 */
/*
 * How long a task bound to @cpu may wait there at the current load: what
 * the shared clock allows, or WAIT_MAX_NS shared among the tasks queued on
 * that CPU's own DSQ if less. The shared bound counts every busy CPU, but
 * only @cpu serves these tasks: with 1100 of them on one CPU while the
 * other CPUs ran a busy loop each for 5 s, tasks queued then were placed
 * and sliced for eight CPUs, and waited past the watchdog after the
 * others went idle.
 */
static __always_inline u64 bound_room(s32 cpu)
{
	s32 n	 = scx_bpf_dsq_nr_queued(CPU_DSQ(cpu));
	u64 room = wait_max_vtime(), own = WAIT_MAX_NS / ((n > 0 ? n : 0) + 1);

	return own < room ? own : room;
}

void BPF_STRUCT_OPS(lertick_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx  = task_ctx(p);
	u64		 vtime = p->scx.dsq_vtime;
	u64 slice = task_slice(tctx, tctx ? tctx->episode_runtime_ns : 0);
	s32  cpu   = scx_bpf_task_cpu(p);
	bool ahead;

	/* A task dispatch() handed to a big CPU waits for that CPU only. */
	if (tctx && tctx->rotate_to) {
		s32 dst = tctx->rotate_to - 1;

		tctx->rotate_to = 0;
		if (!(enq_flags & SCX_ENQ_WAKEUP) &&
		    bpf_cpumask_test_cpu(dst, p->cpus_ptr)) {
			if (!tctx->wait_ts)
				tctx->wait_ts = bpf_ktime_get_ns();
			scx_bpf_dsq_insert_vtime(p, ROT_DSQ(dst), slice_fixed,
						 p->scx.dsq_vtime, enq_flags);
			scx_bpf_kick_cpu(dst, 0);
			return;
		}
		/*
		 * Not handed over after all. dst was claimed as idle: kick it
		 * so that it goes idle again and can be picked.
		 */
		scx_bpf_kick_cpu(dst, 0);
	}

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
		bool sync = tctx->wake_sync;

		tctx->wake_sync = false;
		/* a sync wakeup seen in select_cpu() does not preempt */
		if ((enq_flags & SCX_ENQ_WAKEUP) && !sync &&
		    wake_preempt(p, tctx, vtime, slice, enq_flags))
			return;
	}

	/*
	 * A task whose vtime is past the clock has had more than its share and
	 * waits on the LLC queue. Any other task waits on its CPU's queue or
	 * on the LLC queue, as learned for its program, separately for woken
	 * and preempted tasks. The CPU queue avoids the LLC queue's lock,
	 * which more CPUs contend for. So the LLC queue is charged the time a
	 * take from it costs, and the CPU queue the wait it adds to the LLC
	 * queue's head.
	 */
	ahead = time_before(vtime_now, vtime);
	/*
	 * A task a wakeup just preempted goes to its CPU's local DSQ when no
	 * queued task is waiting for this CPU, so it runs again when the wakee
	 * stops without a dispatch. Not a task the kernel passes as its CPU's
	 * last (SCX_ENQ_LAST): some kernels left the CPU idle with such a task
	 * back on its local DSQ.
	 */
	if (tctx && tctx->preempted_ts &&
	    !(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_LAST)) &&
	    !ahead && !scx_bpf_dsq_nr_queued(domain_of(cpu)) &&
	    !scx_bpf_dsq_nr_queued(CPU_DSQ(cpu)) &&
	    !(handover_on() && scx_bpf_dsq_nr_queued(ROT_DSQ(cpu)))) {
		p->scx.dsq_vtime = vtime;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, enq_flags);
		stat_inc(LERTICK_STAT_LOCAL_DISPATCHES);
		return;
	}
	if (tctx) {
		u32 w	= tctx->eff_weight ? tctx->eff_weight :
			  p->scx.weight	   ? p->scx.weight :
					     1;
		u64 cap = vtime_now + wait_max_vtime();

		tctx->dl_off = slice * DEADLINE_PCT / w;
		/*
		 * The deadline, not only the vtime, stays within what the clock
		 * covers in WAIT_MAX_NS: the offset of a nice 19 task (weight
		 * 1) is a hundred times a nice 0 task's, and under a hundred
		 * runnable tasks on one CPU it waited past the watchdog.
		 */
		if (time_before(cap, vtime + tctx->dl_off))
			tctx->dl_off = time_before(vtime, cap) ? cap - vtime : 0;
		vtime += tctx->dl_off;
	}
	/*
	 * A task that may run on one CPU only waits on that CPU's queue, which
	 * other CPUs look into only a few tasks deep (see steal_one()). On the
	 * LLC queue, every CPU looking for work walked past it with that
	 * queue's lock held: with 1100 such tasks on one CPU, one take looked
	 * at up to 944 of them.
	 */
	if (p->nr_cpus_allowed == 1 && bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
		u64 head;

		if (tctx && !tctx->wait_ts)
			tctx->wait_ts = bpf_ktime_get_ns();
		u64 room = bound_room(cpu);

		/*
		 * Within the bound of that queue's head, not of the shared
		 * clock: tasks bound to a crowded CPU fall behind the clock,
		 * which the other CPUs move, and one placed by the clock
		 * waited until they caught up. With 1100 tasks on one CPU they
		 * sat 20 ms of vtime behind it, the clock moved under 1 ms a
		 * second, and a task started there waited over 7 s.
		 */
		if (dsq_head_vtime(CPU_DSQ(cpu), &head) &&
		    time_before(head + room, vtime)) {
			if (tctx)
				tctx->dl_off = 0;
			vtime = head + room;
		}
		slice = MIN(slice, MAX(room, slice_min));
		scx_bpf_dsq_insert_vtime(p, CPU_DSQ(cpu), slice, vtime,
					 enq_flags);
		stat_inc(LERTICK_STAT_CPU_QUEUED);
		return;
	}
	if (tctx && !ahead) {
		struct choice_ref key = choice_key(
			tctx, (enq_flags & SCX_ENQ_WAKEUP) ? CHOICE_WOKEN :
							     CHOICE_PREEMPTED);

		tctx->place_cpu = choose(&key);
		tctx->place_ts	= bpf_ktime_get_ns();
		tctx->place_key = key;
		if (!tctx->wait_ts)
			tctx->wait_ts = tctx->place_ts;
		if (tctx->place_cpu) {
			scx_bpf_dsq_insert_vtime(p, CPU_DSQ(cpu), slice, vtime,
						 enq_flags);
			/*
			 * No kick: its CPU is the one it ran on or the one
			 * select_cpu() picked, and a kick on every such insert
			 * cut futex throughput by more than half.
			 */
			stat_inc(LERTICK_STAT_CPU_QUEUED);
			return;
		}
	}
	/*
	 * Whether a tick may give way to this waiter is learned for its program
	 * as wakeup preemption is: not giving way costs its wait over the run
	 * that follows, giving way costs the wait of the task that gave way
	 * over its own next run.
	 */
	if (tctx && (enq_flags & SCX_ENQ_WAKEUP)) {
		u32 d  = domain_of(cpu) & (LERTICK_MAX_DOMAINS - 1);
		struct choice_ref ky = choice_key(tctx, CHOICE_TICK);

		tctx->tw_key   = ky;
		tctx->tw_ts    = bpf_ktime_get_ns();
		tctx->tw_pend  = true;
		tctx->tw_yield = choose(&ky);
		if (tctx->tw_yield) {
			struct waiter *wt = waiter_of(d);

			if (wt && (!wt->dl || time_before(vtime, wt->dl))) {
				bpf_spin_lock(&wt->lock);
				if (!wt->dl || time_before(vtime, wt->dl)) {
					wt->dl	= vtime;
					wt->key = ky;
					wt->pid = p->pid;
				}
				bpf_spin_unlock(&wt->lock);
			}
			tctx->waits_on = d + 1;
			tctx->waits_dl = vtime;
		}
	}
	/* for the starvation guard: a task ahead of the clock read no time above */
	if (tctx && ahead && !tctx->wait_ts)
		tctx->wait_ts = bpf_ktime_get_ns();
	scx_bpf_dsq_insert_vtime(p, domain_of(cpu), slice, vtime, enq_flags);
	if (llc_head_of(domain_of(cpu))->v &&
	    time_before(vtime, llc_head_of(domain_of(cpu))->v))
		llc_head_of(domain_of(cpu))->v = vtime;
	stat_inc(LERTICK_STAT_SHARED_DISPATCHES);
}

/*
 * @cpu needs a task. @prev continues if keep_prev() allows it; otherwise the
 * next queued task runs, and @prev continues only when nothing is queued.
 */
static __always_inline void hold_flush(void);
static __always_inline void guard_scan(u64 now);
void BPF_STRUCT_OPS(lertick_dispatch, s32 cpu, struct task_struct *prev)
{
	bool continuing = prev && (prev->scx.flags & SCX_TASK_QUEUED);
	struct task_ctx *tctx;
	u64		 consumed, slice;
	u32		 z = 0;
	/*
	 * With core scheduling a CPU can dispatch for its sibling: note the
	 * time for @cpu, whose queues were looked at.
	 */
	u64 *last = bpf_map_lookup_percpu_elem(&last_dispatch, &z, cpu);
	u64  now  = bpf_ktime_get_ns();

	if (last)
		*last = now;
	guard_scan(now);

	if (handover_on()) {
		u64 run = 0;
		s32 dst = -1;

		/* A task handed to this CPU first. */
		if (LERTICK_MOVE_TO_LOCAL(ROT_DSQ(cpu)))
			return;
		/*
		 * A task that has run past the fixed slice in its current burst
		 * on a little CPU goes to an idle big CPU, as the kernel moves a
		 * misfit task. It is not kept here: the kernel queues it again
		 * (SCX_OPS_ENQ_LAST, which the loader sets on such machines)
		 * and enqueue() hands it over.
		 */
		tctx = continuing ? task_ctx(prev) : NULL;
		/*
		 * The kernel queues an exiting task on its CPU without
		 * enqueue(), which would leave the claimed CPU idle but
		 * unclaimable: do not hand it over.
		 */
		if (tctx && (prev->flags & PF_EXITING))
			tctx = NULL;
		if (tctx) {
			/*
			 * The burst so far as time on this CPU, as the
			 * prediction worth_moving() compares it with: its work
			 * over this CPU's capacity, not its time on CPUs of
			 * other capacities added up.
			 */
			run = tctx->episode_work_ns * 1024 / cap_of(cpu);
			if (tctx->running &&
			    prev->se.sum_exec_runtime > tctx->runtime_start_ns)
				run += prev->se.sum_exec_runtime -
				       tctx->runtime_start_ns;
		}
		if (tctx && worth_moving(tctx, run) && cpus_asym && asym_rotate &&
		    cap_of(cpu) < BIG_CAP)
			dst = pick_big_idle(prev, -1);
		/*
		 * Likewise, a task that keeps running while the other thread of
		 * its core is busy goes to a whole idle core of the same or a
		 * larger capacity.
		 */
		if (dst < 0 && tctx && worth_moving(tctx, run) && smt_on &&
		    smt_balance && sibling_busy(cpu)) {
			dst = pick_idle(prev, -1, cap_of(cpu) >= BIG_CAP, true);
			if (dst >= 0 && cap_of(dst) < cap_of(cpu)) {
				/* Never to a slower CPU: give the claim back. */
				scx_bpf_kick_cpu(dst, 0);
				dst = -1;
			}
		}
		if (dst >= 0 && tctx) {
			stat_inc(LERTICK_STAT_HANDOVERS);
			tctx->rotate_to = dst + 1;
			take_next(cpu);
			return;
		}
	}

	tctx = continuing ? task_ctx(prev) : NULL;
	if (!(continuing && !(tctx && tctx->yielded) &&
	      keep_prev(prev, tctx, cpu) && !cpu_head_before(prev, cpu))) {
		if (tctx)
			tctx->yielded = false;
		if (take_next(cpu))
			return;
		if (!continuing) {
			/* this CPU goes idle: its held task stays asleep */
			hold_flush();
			return;
		}
	}

	/*
	 * prev continues. The kernel may update sum_exec_runtime before
	 * dispatch() and keep prev without stopping() or running(), so read
	 * the pending segment for the slice decision without charging it:
	 * stopping() charges it.
	 */
	tctx	 = task_ctx(prev);
	consumed = tctx ? tctx->episode_runtime_ns : 0;
	/*
	 * A tick may have given way, but prev runs on without stopping() or
	 * running(): no wait follows, so no give-way cost is pending.
	 */
	if (tctx)
		tctx->tg_pend = false;
	if (tctx && tctx->running &&
	    prev->se.sum_exec_runtime > tctx->runtime_start_ns)
		consumed += prev->se.sum_exec_runtime - tctx->runtime_start_ns;

	/*
	 * Set the slice rather than insert prev. Newer kernels write a slice
	 * only when the insert takes place, and prev, which is running, is not
	 * inserted: its slice stayed zero and the kernel refilled it with
	 * SCX_SLICE_DFL.
	 */
	slice = task_slice(tctx, consumed);
	if (prev->nr_cpus_allowed == 1)
		slice = MIN(slice, MAX(bound_room(cpu), slice_min));
	scx_bpf_task_set_slice(prev, slice);
	stat_inc(LERTICK_STAT_CONTINUATIONS);
}

/*
 * @p becomes runnable: count its weight toward the clock and its cgroup, and
 * start an episode unless ops.select_cpu() already did.
 */
/*
 * A task going to sleep stays counted in runnable_weight and its cgroup, held
 * in its CPU's slot. If it wakes while held, nothing shared is written: a task
 * that sleeps and wakes many times a millisecond (futex, pipes) otherwise
 * writes counters every CPU shares on each change. Another task sleeping on
 * the CPU, the CPU's next tick or going idle, a cgroup move or the task
 * leaving sched_ext takes the held one out. So at most one sleeping task per
 * CPU is counted, for at most a tick while sched_ext runs on that CPU. A CPU
 * a higher class holds (a real-time task) keeps it until sched_ext runs there
 * again: ops.cpu_release() is deprecated, and the weight of one sleeper is
 * all it keeps.
 *
 * While held, the counts belong to the hold, recorded in held_weight and
 * held_cg, and the task itself counts as not counted. held goes from HELD to
 * 0 when the task wakes and takes its counts back, or to RELEASING while a
 * CPU takes them out, then to 0. A CPU taking them out touches only the
 * shared counters, so a task that wakes meanwhile just counts itself again.
 */
#define HELD 1
#define RELEASING 2

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, s32);
} hold_slot SEC(".maps");

/* Take the counts of a hold out; @tc->held is RELEASING. */
static void unhold(struct task_ctx *tc)
{
	struct cgroup *cg;

	if (tc->held_cg) {
		cg = bpf_cgroup_from_id(tc->held_cg);
		if (cg) {
			cgrp_count(cg, tc->held_weight, false);
			bpf_cgroup_release(cg);
		}
	}
	__sync_fetch_and_sub(&runnable_weight, tc->held_weight);
	__sync_lock_test_and_set(&tc->held, 0);
}

static void release_held(s32 pid)
{
	struct task_struct *t;
	struct task_ctx	   *tc;

	if (pid <= 0)
		return;
	t = bpf_task_from_pid(pid);
	if (!t)
		return;
	tc = task_ctx(t);
	/*
	 * The task may be waking on another CPU. Whichever changes held first
	 * decides: the task keeps its counts, this CPU takes them out.
	 */
	if (tc && __sync_val_compare_and_swap(&tc->held, HELD, RELEASING) ==
			  HELD)
		unhold(tc);
	bpf_task_release(t);
}

static __always_inline void hold(struct task_struct *p, struct task_ctx *tctx)
{
	u32  z = 0;
	s32 *slot = bpf_map_lookup_elem(&hold_slot, &z), old;

	/* held is not 0 only while a CPU still takes out an earlier hold */
	if (!slot || tctx->held) {
		cgrp_task_runnable(p, tctx, false);
		__sync_fetch_and_sub(&runnable_weight, tctx->rq_weight);
		tctx->rq_weight = 0;
		return;
	}
	tctx->held_weight = tctx->rq_weight;
	tctx->held_cg	  = tctx->cg_counted ? tctx->cg_id : 0;
	tctx->held_cpu	  = bpf_get_smp_processor_id();
	tctx->rq_weight	  = 0;
	tctx->cg_counted  = false;
	__sync_lock_test_and_set(&tctx->held, HELD);
	old = __sync_lock_test_and_set(slot, p->pid);
	if (old != p->pid)
		release_held(old);
}

static __always_inline void hold_flush(void)
{
	u32  z = 0;
	s32 *slot = bpf_map_lookup_elem(&hold_slot, &z);

	if (slot && *slot)
		release_held(__sync_lock_test_and_set(slot, 0));
}

/*
 * @p woke while held, counted in the cgroup held_cg: count it as its own
 * again, moving the count if @p changed cgroups while it slept.
 */
static void unhold_cgroup(struct task_struct *p, struct task_ctx *tctx)
{
	struct cgroup *cgrp = LERTICK_TASK_CGROUP(p), *old;
	u64	       id   = cgrp ? BPF_CORE_READ(cgrp, kn, id) : 0;

	if (id != tctx->held_cg) {
		old = bpf_cgroup_from_id(tctx->held_cg);
		if (old) {
			cgrp_count(old, tctx->rq_weight, false);
			bpf_cgroup_release(old);
		}
		if (!cgrp)
			return;
		cgrp_count(cgrp, tctx->rq_weight, true);
	}
	tctx->cg_id	 = id;
	tctx->cg_counted = true;
	bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(lertick_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;

	/*
	 * A task woken while held takes its counts back, and its slot is
	 * emptied so that no CPU looks it up. If a CPU took it out first, the
	 * task is counted again below.
	 */
	if (tctx->held &&
	    __sync_val_compare_and_swap(&tctx->held, HELD, 0) == HELD) {
		u32  z	  = 0;
		s32 *slot = bpf_map_lookup_percpu_elem(&hold_slot, &z,
						       tctx->held_cpu);

		if (slot)
			__sync_val_compare_and_swap(slot, p->pid, 0);
		if (tctx->held_weight != (p->scx.weight ? p->scx.weight : 1)) {
			/* its nice changed while asleep: count it anew below */
			unhold(tctx);
		} else {
			tctx->rq_weight = tctx->held_weight;
			if (tctx->held_cg)
				unhold_cgroup(p, tctx);
		}
	}
	if (!tctx->rq_weight) {
		tctx->rq_weight = p->scx.weight ? p->scx.weight : 1;
		__sync_fetch_and_add(&runnable_weight, tctx->rq_weight);
		cgrp_task_runnable(p, tctx, true);
	}
	if (tctx->eff_stale) {
		tctx->eff_weight = cgrp_effective_weight(
			p, tctx, p->scx.weight ? p->scx.weight : 1);
		tctx->eff_stale = false;
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
 * @p starts running after waiting: record the costs of the choices that made
 * it wait. A cost that depends on the run that follows is recorded when it
 * stops.
 */
static __always_inline void learn_on_run(struct task_struct *p,
					 struct task_ctx *tctx)
{
	u64 now = bpf_ktime_get_ns(), *tc;
	u32 z	= 0;

	if (tctx->queued_ts && now > tctx->queued_ts) {
		tctx->qrun_wait = now - tctx->queued_ts;
		tctx->qrun_key	= tctx->queued_key;
		tctx->qrun_ts	= now;
		tctx->qrun_on	= true;
	}
	if (tctx->preempted_ts && now > tctx->preempted_ts) {
		tctx->vrun_wait = now - tctx->preempted_ts;
		tctx->vrun_key	= tctx->preempted_key;
		tctx->vrun_ts	= now;
		tctx->vrun_on	= true;
	}
	tctx->queued_ts	   = 0;
	tctx->preempted_ts = 0;

	if (tctx->place_ts && now > tctx->place_ts) {
		if (!tctx->place_cpu) {
			tc = bpf_map_lookup_elem(&take_cost, &z);
			choice_cost(&tctx->place_key, 0,
				    now - tctx->place_ts + (tc ? *tc : 0));
		} else if (scx_bpf_dsq_nr_queued(
				   domain_of(scx_bpf_task_cpu(p)))) {
			tctx->cpuq_ts	= now;
			tctx->cpuq_wait = now - tctx->place_ts;
			tctx->cpuq_key	= tctx->place_key;
		} else {
			choice_cost(&tctx->place_key, 1, now - tctx->place_ts);
		}
	}
	tctx->place_ts = 0;

	if (tctx->prun_pend) {
		tctx->prun_ts	= now;
		tctx->prun_on	= true;
		tctx->prun_pend = false;
	}
}

/* @p stops: record the costs that depend on the run that just ended. */
static __always_inline void learn_on_stop(struct task_ctx *tctx)
{
	u64 now = bpf_ktime_get_ns();

	if (tctx->tw_on && !tctx->tw_yield && now > tctx->tw_rts)
		choice_cost(&tctx->tw_key, 0,
			    tctx->tw_wait * 1000 /
				    MAX(now - tctx->tw_rts, NSEC_PER_USEC));
	if (tctx->tg_on && now > tctx->tg_rts)
		choice_cost(&tctx->tg_run_key, 1,
			    tctx->tg_wait * 1000 /
				    MAX(now - tctx->tg_rts, NSEC_PER_USEC));
	tctx->tw_on  = false;
	tctx->tg_on = false;

	if (tctx->qrun_on && now > tctx->qrun_ts)
		choice_cost(&tctx->qrun_key, 0,
			    tctx->qrun_wait * 1000 /
				    MAX(now - tctx->qrun_ts, NSEC_PER_USEC));
	if (tctx->prun_on && now > tctx->prun_ts) {
		struct choice *c = choice_at(&tctx->prun_key, false);
		u64	       r = MIN(now - tctx->prun_ts, CHOICE_RUN_MAX);

		if (c) {
			c->run = c->nrun ? c->run - c->run / 8 + r / 8 : r;
			if (c->nrun < CHOICE_N_MAX)
				c->nrun++;
		}
	}
	/* the LLC queue's head waited for this run too */
	if (tctx->cpuq_ts && now > tctx->cpuq_ts)
		choice_cost(&tctx->cpuq_key, 1,
			    tctx->cpuq_wait + now - tctx->cpuq_ts);
	/* a preempted task: its wait over the shorter of the two runs */
	if (tctx->vrun_on && now > tctx->vrun_ts) {
		struct choice *c   = choice_at(&tctx->vrun_key, false);
		u64	       own = now - tctx->vrun_ts;
		u64	       r   = c && c->nrun ? MIN(own, (u64)c->run) : own;

		choice_cost(&tctx->vrun_key, 1, tctx->vrun_wait * 1000 /
					  MAX(r, NSEC_PER_USEC));
	}
	tctx->vrun_on = false;
	tctx->qrun_on = false;
	tctx->prun_on = false;
	tctx->cpuq_ts = 0;
}

/*
 * @p starts running: take its deadline offset out of its vtime, raise the
 * clock to that vtime if the clock is behind, and note where this run starts.
 */
void BPF_STRUCT_OPS(lertick_running, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);

	if (tctx) {
		tctx->yielded = false;
		tctx->wait_ts = 0;
	}
	if (tctx && tctx->waits_on) {
		struct waiter *wt = waiter_of(tctx->waits_on - 1);

		if (wt && wt->dl == tctx->waits_dl && wt->pid == p->pid) {
			bpf_spin_lock(&wt->lock);
			if (wt->dl == tctx->waits_dl && wt->pid == p->pid)
				wt->dl = 0;
			bpf_spin_unlock(&wt->lock);
		}
		tctx->waits_on = 0;
	}
	if (tctx && (tctx->tw_pend || tctx->tg_pend)) {
		u64 now = bpf_ktime_get_ns();

		if (tctx->tw_pend && now > tctx->tw_ts) {
			tctx->tw_wait = now - tctx->tw_ts;
			tctx->tw_rts  = now;
			tctx->tw_on   = true;
		}
		if (tctx->tg_pend && now > tctx->tg_ts) {
			tctx->tg_wait	 = now - tctx->tg_ts;
			tctx->tg_rts	 = now;
			tctx->tg_run_key = tctx->tg_key;
			tctx->tg_on	 = true;
		}
		tctx->tw_pend  = false;
		tctx->tg_pend = false;
	}
	if (tctx && tctx->dl_off) {
		p->scx.dsq_vtime -= tctx->dl_off;
		tctx->dl_off = 0;
	}
	clock_raise(p->scx.dsq_vtime);

	if (!tctx)
		return;
	learn_on_run(p, tctx);
	tctx->runtime_start_ns = p->se.sum_exec_runtime;
	tctx->run_start_ns     = p->se.sum_exec_runtime;
	tctx->running	       = true;
	tctx->run_cap	       = cap_of(scx_bpf_task_cpu(p));
}

/*
 * @p stops running: charge the CPU time it used to its vtime, scaled by its
 * effective weight, and advance the clock.
 */
/*
 * Charge @p's run since runtime_start_ns at its current effective weight,
 * and move runtime_start_ns up. ops.tick() charges a running task too, as
 * EEVDF updates the current task on each tick: charged only when it
 * stopped, a run that went on across slices took the weight in force at
 * its end for all of it, after a cpu.weight change or a change in the
 * runnable weight.
 */
static __always_inline void charge_run(struct task_struct *p,
				       struct task_ctx *tctx)
{
	u32 weight = p->scx.weight ? p->scx.weight : 1;
	u64 now	   = p->se.sum_exec_runtime, delta, rw;

	if (now <= tctx->runtime_start_ns)
		return;
	delta		       = now - tctx->runtime_start_ns;
	tctx->runtime_start_ns = now;
	tctx->eff_weight       = cgrp_effective_weight(p, tctx, weight);
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
	tctx->episode_work_ns += delta * cap_of(scx_bpf_task_cpu(p)) / 1024;
}

void BPF_STRUCT_OPS(lertick_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx = task_ctx(p);

	if (tctx)
		learn_on_stop(tctx);
	if (!tctx || !tctx->running)
		return;
	tctx->running = false;
	if (p->se.sum_exec_runtime < tctx->runtime_start_ns) {
		tctx->episode_valid = false;
		return;
	}
	charge_run(p, tctx);
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
		if ((deq_flags & SCX_DEQ_SLEEP) && !(p->flags & PF_EXITING)) {
			hold(p, tctx);
		} else {
			cgrp_task_runnable(p, tctx, false);
			__sync_fetch_and_sub(&runnable_weight, tctx->rq_weight);
			tctx->rq_weight = 0;
		}
	}

	/* Non-sleep quiescence keeps the episode across migration and preemption. */
	if (!(deq_flags & SCX_DEQ_SLEEP))
		return;

	/*
	 * A running task gets stopping(p, false) before this callback, so the
	 * last service segment is already in episode_runtime_ns exactly once.
	 * Bursts are learned as work (see cpus_asym), which is their run time
	 * when the CPUs are alike.
	 */
	burst = tctx->episode_work_ns;
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
 * Allocate and initialize the context of a new task. Sleepable, so that the
 * context is allocated with GFP_KERNEL: an atomic allocation can fail, which
 * keeps the scheduler from starting during attach and fails a fork after.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(lertick_init_task, struct task_struct *p,
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
	/*
	 * A held sleeper leaving sched_ext (a policy change while it sleeps)
	 * gets no quiescent() to take it out.
	 */
	if (tctx->held && __sync_val_compare_and_swap(&tctx->held, HELD,
						      RELEASING) == HELD)
		unhold(tctx);
	tctx->episode_active = false;
	tctx->episode_valid  = false;
	tctx->has_slept	     = false;
	/* enable() restarts the vtime at the clock, without any offset. */
	tctx->dl_off	     = 0;
	/* a wait outside sched_ext does not count toward the guard */
	tctx->wait_ts	     = 0;
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
/*
 * @p's weight changed (nice): a runnable task counted with the old weight
 * moves the sums to the new one, which they would otherwise keep until it
 * sleeps. A held task is counted anew when it wakes, see runnable().
 */
void BPF_STRUCT_OPS(lertick_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *tctx = task_ctx(p);
	s64		 d;

	if (!weight)
		weight = 1;
	if (!tctx)
		return;
	/*
	 * The next deadline offset reads it before the next charge would. A
	 * task not counted in its cgroup, as while the kernel dequeues it to
	 * change its nice, gets only its own weight here: runnable() works it
	 * out again once the task is counted.
	 */
	tctx->eff_weight = cgrp_effective_weight(p, tctx, weight);
	tctx->eff_stale	 = !tctx->cg_counted;
	if (!tctx->rq_weight || tctx->rq_weight == weight)
		return;
	d = (s64)weight - tctx->rq_weight;
	__sync_fetch_and_add(&runnable_weight, d);
	if (tctx->cg_counted) {
		struct cgroup *cg = bpf_cgroup_from_id(tctx->cg_id);

		if (cg) {
			struct cgrp_ctx *cgc = cgrp_ctx(cg);

			if (cgc)
				__sync_fetch_and_add(&cgc->task_weight_sum, d);
			bpf_cgroup_release(cg);
		}
	}
	tctx->rq_weight = weight;
}

/*
 * @cgrp goes away, or the scheduler does. In the first case it has no tasks
 * left, so it should count as inactive in its parent. If it does not, counts a race left behind (a held task's
 * counts taken out by its CPU after a move, the old cgroup gone first)
 * would keep its weight in the parent's child_weight_sum for good: take it
 * out now.
 */
void BPF_STRUCT_OPS(lertick_cgroup_exit, struct cgroup *cgrp)
{
	struct cgrp_ctx *cgc = cgrp_ctx(cgrp);

	if (!cgc || !cgc->nr_runnable)
		return;
	cgc->nr_runnable = 1;
	cgc->task_weight_sum = 0;
	cgrp_update_active(cgrp, cgc, false);
}

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

/*
 * A runnable task changing cgroups takes its weight with it. Its effective
 * weight is still @from's: runnable() works it out again once the task is
 * counted in @to, as the kernel dequeues a queued task for the move.
 */
void BPF_STRUCT_OPS(lertick_cgroup_move, struct task_struct *p,
		    struct cgroup *from, struct cgroup *to)
{
	struct task_ctx *tctx = task_ctx(p);

	if (!tctx)
		return;
	tctx->eff_stale = true;
	/*
	 * A held task's counts are in @from. Take them out now, while @from
	 * exists: once it is removed, its id no longer finds it, and its
	 * parent's sums could not be lowered.
	 */
	if (tctx->held &&
	    __sync_val_compare_and_swap(&tctx->held, HELD, RELEASING) == HELD)
		unhold(tctx);
	if (!tctx->cg_counted)
		return;
	cgrp_account(from, tctx, false);
	cgrp_account(to, tctx, true);
	tctx->cg_id = BPF_CORE_READ(to, kn, id);
}

/*
 * Create one vtime-ordered DSQ per LLC.
 */
/*
 * A starvation guard that does not depend on the clock. The bounds on vtime
 * and deadline hold a queued task to about WAIT_MAX_NS at the load seen when
 * it was queued, but the clock slows when CPUs go idle: a task pinned to a
 * crowded CPU, queued while all CPUs were busy, then waited up to the number
 * of CPUs times longer. So once every GUARD_PERIOD_NS, the CPU whose
 * ops.dispatch() comes first moves any task that has waited on an LLC, CPU
 * or rotation DSQ for longer than GUARD_WAIT_NS, a fifth of the watchdog's
 * timeout, to the local DSQ of a CPU it may run on, at most GUARD_MOVES_MAX
 * tasks a round, at the head of that DSQ. A task queued again before it ran
 * keeps its first queuing time. The rotation DSQs, each holding a task for
 * one CPU, are checked too: a real-time task on that CPU keeps the kick from
 * taking effect.
 *
 * A BPF timer would run the check while every CPU ran its task, but which
 * program sets it up decides what its callback may call: verifiers before
 * v6.18.2 took a callback set up in the sleepable ops.init() for sleepable
 * and refused the DSQ iterator, and from v7.1 one set up in ops.tick() may
 * not move a task. A busy CPU dispatches at least when a slice ends, and
 * with nothing queued nothing waits, so ops.dispatch() is enough.
 */
#define GUARD_PERIOD_NS (100ULL * NSEC_PER_MSEC)
#define GUARD_WAIT_NS (STARVATION_MS * NSEC_PER_MSEC / 5)
#define GUARD_MOVES_MAX 64
#define GUARD_VISITS_MAX 1024

u64 nr_guard_moves, nr_guard_scans;
static u64 guard_last;
static u32 guard_next; /* the DSQ the next round starts at */
static bool guard_due; /* the check is overdue, as ops.tick() last saw */

/*
 * What the round on this CPU has done. In a per-CPU map rather than on the
 * stack: the verifier tracks stack counters exactly, and with one more each
 * time round the DSQ iterator no two passes matched, past its limit on
 * jumps. Per CPU, a round on another CPU does not reset them.
 */
struct guard_round {
	u32 moves, visits;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct guard_round);
} guard_rounds SEC(".maps");

/*
 * The check is overdue and tasks wait for @cpu: the paths that insert on a
 * local DSQ directly then queue instead, so that a CPU fed only through its
 * local DSQ still dispatches, and the check runs.
 */
static __always_inline bool guard_overdue(s32 cpu)
{
	/* guard_due, not the time: the clock read on each wakeup cost futex */
	return guard_due &&
	       (scx_bpf_dsq_nr_queued(CPU_DSQ(cpu)) ||
		scx_bpf_dsq_nr_queued(domain_of(cpu)) ||
		(handover_on() && scx_bpf_dsq_nr_queued(ROT_DSQ(cpu))));
}

/*
 * May @q go to @cpu when no CPU it may run on is idle? @cpu must run a
 * task, and not a real-time or deadline one, which outranks @q and which a
 * kick does not move. An offline CPU runs only its idle task, so it never
 * qualifies, and no cpumask needs taking: one held across this loop kept
 * the verifier from pruning, past its limit on jumps.
 */
static __always_inline bool guard_cpu_ok(struct task_struct *q, s32 cpu)
{
	struct task_struct *curr;

	if (cpu < 0 || cpu >= LERTICK_MAX_CPUS ||
	    !bpf_cpumask_test_cpu(cpu, q->cpus_ptr))
		return false;
	curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	return curr && !(curr->flags & PF_IDLE) &&
	       curr->prio >= 100; /* MAX_RT_PRIO */
}

/*
 * A CPU for @q: an idle one it may run on, claimed, or else its own if
 * guard_cpu_ok() allows. -1 for neither: looking through every CPU here, in
 * a loop inside the DSQ iterator, took the verifier past its limit on jumps.
 */
static __always_inline s32 guard_target(struct task_struct *q, bool *idle)
{
	s32 cpu = scx_bpf_pick_idle_cpu(q->cpus_ptr, 0);

	*idle = cpu >= 0;
	if (*idle)
		return cpu;
	cpu = scx_bpf_task_cpu(q);
	return guard_cpu_ok(q, cpu) ? cpu : -1;
}

/*
 * Move the tasks of @dsq queued since before @old, from the tail: a task
 * that has waited long has a later deadline than the tasks queued since,
 * which went ahead of it. False once the round has moved GUARD_MOVES_MAX
 * tasks or looked at GUARD_VISITS_MAX, as it runs in ops.dispatch() with
 * interrupts off.
 */
static __always_inline bool guard_dsq(u64 dsq, u64 old, struct guard_round *r)
{
	struct task_struct *q;

	bpf_for_each(scx_dsq, q, dsq, SCX_DSQ_ITER_REV) {
		struct task_ctx *tctx = task_ctx(q);
		bool		 idle;
		s32		 cpu;

		if (r->moves >= GUARD_MOVES_MAX || ++r->visits > GUARD_VISITS_MAX)
			return false;
		if (!tctx || !tctx->wait_ts || !time_before(tctx->wait_ts, old))
			continue;
		cpu = guard_target(q, &idle);
		if (cpu < 0) {
			/*
			 * Its CPU is held by a real-time task. Off a CPU or
			 * rotation DSQ, which only that CPU takes from, it
			 * goes to the head of its LLC DSQ, which every CPU of
			 * the LLC takes from. dl_off is left as it is: the
			 * move fails if another CPU has taken the task, whose
			 * running() then takes dl_off out of its vtime. After
			 * a move, the task runs that much ahead of v, and its
			 * next enqueue bounds its vtime again.
			 */
			u32 d = domain_of(scx_bpf_task_cpu(q));
			u64 v = vtime_now - 2 * BEHIND_NS;

			/* a task bound to that CPU could not run elsewhere */
			if (dsq < CPU_DSQ(0) || q->nr_cpus_allowed == 1)
				continue;
			scx_bpf_dsq_move_set_vtime(BPF_FOR_EACH_ITER, v);
			if (scx_bpf_dsq_move_vtime(BPF_FOR_EACH_ITER, q, d, 0)) {
				if (!llc_head_of(d)->v ||
				    time_before(v, llc_head_of(d)->v))
					llc_head_of(d)->v = v;
				__sync_fetch_and_add(&nr_guard_moves, 1);
				r->moves++;
			}
			continue;
		}
		/*
		 * An idle CPU's local DSQ at its head, so that a wakeup
		 * preempting there does not pass it. A busy CPU's at its tail:
		 * that DSQ runs in order, and with 1100 tasks bound to one CPU,
		 * every task waited over a second, each round put its moves
		 * ahead of the last, and tasks moved earlier waited past the
		 * watchdog.
		 */
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, q,
				     SCX_DSQ_LOCAL_ON | cpu,
				     idle ? SCX_ENQ_HEAD : 0)) {
			scx_bpf_kick_cpu(cpu, idle ? SCX_KICK_IDLE :
						     SCX_KICK_PREEMPT);
			__sync_fetch_and_add(&nr_guard_moves, 1);
			r->moves++;
		} else if (idle) {
			/* give the claimed idle CPU back */
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		}
	}
	return r->moves < GUARD_MOVES_MAX && r->visits < GUARD_VISITS_MAX;
}

/*
 * Once every GUARD_PERIOD_NS, from the first ops.dispatch() past it. The
 * LLC, CPU and rotation DSQs are taken as one list. A round that runs out of
 * moves or visits leaves the next to start at the DSQ after the one it
 * stopped in, which that round then reaches last. Started again at the same
 * DSQ, a DSQ that kept as many old or as many queued tasks as a round takes
 * would keep the guard from the others.
 */
static __always_inline void guard_scan(u64 now)
{
	u64		   last = guard_last, old;
	u32		   ncpu = scx_bpf_nr_cpu_ids(), nd = domain_count();
	u32		   total, start, k, i, z = 0;
	struct guard_round *r = bpf_map_lookup_elem(&guard_rounds, &z);

	if (ncpu > LERTICK_MAX_CPUS)
		ncpu = LERTICK_MAX_CPUS;
	/* signed: another CPU may have stored a later time meanwhile */
	if ((s64)(now - last) < (s64)GUARD_PERIOD_NS || now <= GUARD_WAIT_NS ||
	    __sync_val_compare_and_swap(&guard_last, last, now) != last)
		return;
	if (!r)
		return;
	__sync_fetch_and_add(&nr_guard_scans, 1);
	guard_due = false;
	r->moves  = 0;
	r->visits = 0;
	old	  = now - GUARD_WAIT_NS;
	total = nd + ncpu + (handover_on() ? ncpu : 0);
	start = guard_next < total ? guard_next : 0;
	bpf_for(k, 0, total)
	{
		u64 dsq;

		i = start + k;
		if (i >= total)
			i -= total;
		dsq = i < nd		? i :
		      i < nd + ncpu ? CPU_DSQ(i - nd) :
				      ROT_DSQ(i - nd - ncpu);
		if (!guard_dsq(dsq, old, r)) {
			guard_next = i + 1 < total ? i + 1 : 0;
			return;
		}
	}
	guard_next = start;
}

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

	ret = create_cpu_dsqs();
	if (ret)
		return ret;
	if (!handover_on())
		return 0;
	bpf_for(d, 0, scx_bpf_nr_cpu_ids())
	{
		ret = scx_bpf_create_dsq(ROT_DSQ(d), -1);
		if (ret)
			return ret;
	}
	return 0;
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

/*
 * A held task is taken out by a tick at the latest, see hold(). The running
 * task gives way to a waiter on its LLC queue, see struct waiter.
 */
void BPF_STRUCT_OPS(lertick_tick, struct task_struct *p)
{
	struct task_ctx *tctx = task_ctx(p);
	struct waiter	*wt   = waiter_of(domain_of(scx_bpf_task_cpu(p)));
	struct choice_ref key  = {};
	bool		  gave = false;
	u64		  now_v, v, now_ns;
	u32		  w;

	hold_flush();
	now_ns = bpf_ktime_get_ns();
	busy_cpus_refresh(now_ns);
	if ((s64)(now_ns - guard_last) >= (s64)(2 * GUARD_PERIOD_NS))
		guard_due = true;
	/*
	 * The kernel charges the slice before ops.tick(): a task whose slice
	 * ran out stops anyway, and giving way would teach the waiter's
	 * program that a slice's end was its choice.
	 */
	if (tctx && tctx->running)
		charge_run(p, tctx);
	if (!p->scx.slice || !wt || !wt->dl || !tctx || !tctx->running ||
	    p->se.sum_exec_runtime < tctx->runtime_start_ns)
		return;
	w     = tctx->eff_weight ? tctx->eff_weight : 100;
	now_v = p->scx.dsq_vtime +
		(p->se.sum_exec_runtime - tctx->runtime_start_ns) * 100 / w;
	/*
	 * One CPU gives way per waiter: the first to clear its deadline, which
	 * takes the waiter's key with it.
	 */
	v = wt->dl;
	if (!v || !time_before(v, now_v))
		return;
	bpf_spin_lock(&wt->lock);
	if (wt->dl == v) {
		wt->dl = 0;
		key    = wt->key;
		gave   = true;
	}
	bpf_spin_unlock(&wt->lock);
	if (gave) {
		tctx->tg_key  = key;
		tctx->tg_ts   = bpf_ktime_get_ns();
		tctx->tg_pend = true;
		scx_bpf_task_set_slice(p, 0);
	}
}

/*
 * sched_yield(): @from gives up the rest of its slice, and dispatch() does
 * not keep it while another task can run here, as keep_prev() would when
 * its deadline is still the earliest. A directed yield is not supported.
 */
bool BPF_STRUCT_OPS(lertick_yield, struct task_struct *from,
		    struct task_struct *to)
{
	struct task_ctx *tctx;

	if (to)
		return false;
	tctx = task_ctx(from);
	if (tctx)
		tctx->yielded = true;
	scx_bpf_task_set_slice(from, 0);
	return false;
}

SCX_OPS_DEFINE(lertick_ops, .select_cpu = (void *)lertick_select_cpu,
	       .enqueue		  = (void *)lertick_enqueue,
	       .dispatch	  = (void *)lertick_dispatch,
	       .yield		  = (void *)lertick_yield,
	       .runnable	  = (void *)lertick_runnable,
	       .running		  = (void *)lertick_running,
	       .stopping	  = (void *)lertick_stopping,
	       .tick		  = (void *)lertick_tick,
	       .quiescent	  = (void *)lertick_quiescent,
	       .cgroup_init	  = (void *)lertick_cgroup_init,
	       .cgroup_set_weight = (void *)lertick_cgroup_set_weight,
	       .cgroup_exit	  = (void *)lertick_cgroup_exit,
	       .set_weight	  = (void *)lertick_set_weight,
	       .cgroup_move	  = (void *)lertick_cgroup_move,
	       .init_task	  = (void *)lertick_init_task,
	       .enable		  = (void *)lertick_enable,
	       .disable = (void *)lertick_disable, .init = (void *)lertick_init,
	       .exit = (void *)lertick_exit, .dump = (void *)lertick_dump,
	       .dump_task  = (void *)lertick_dump_task,
	       .timeout_ms = STARVATION_MS, .name = "lertick");
