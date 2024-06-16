/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

const volatile u32 debug = 0;
const volatile u64 slice_ns = SCX_SLICE_DFL;
const volatile u64 max_exec_ns = 20 * SCX_SLICE_DFL;
const volatile u32 nr_possible_cpus = 1;
const volatile u32 nr_layers = 1;
const volatile bool smt_enabled = true;
const volatile s32 __sibling_cpu[MAX_CPUS];
const volatile unsigned char all_cpus[MAX_CPUS_U8];

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
struct layer layers[MAX_LAYERS];
u32 fallback_cpu;
static u32 preempt_cursor;

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

#include "util.bpf.c"

UEI_DEFINE(uei);

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static inline s32 prio_to_nice(s32 static_prio)
{
	/* See DEFAULT_PRIO and PRIO_TO_NICE in include/linux/sched/prio.h */
	return static_prio - 120;
}

static inline s32 sibling_cpu(s32 cpu)
{
	const volatile s32 *sib;

	sib = MEMBER_VPTR(__sibling_cpu, [cpu]);
	if (sib)
		return *sib;
	else
		return -1;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctxs SEC(".maps");

static struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cctx;
	u32 zero = 0;

	if (cpu < 0)
		cctx = bpf_map_lookup_elem(&cpu_ctxs, &zero);
	else
		cctx = bpf_map_lookup_percpu_elem(&cpu_ctxs, &zero, cpu);

	if (!cctx) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cctx;
}

static void gstat_inc(enum global_stat_idx idx, struct cpu_ctx *cctx)
{
	if (idx < 0 || idx >= NR_GSTATS) {
		scx_bpf_error("invalid global stat idx %d", idx);
		return;
	}

	cctx->gstats[idx]++;
}

static void lstat_add(enum layer_stat_idx idx, struct layer *layer,
		      struct cpu_ctx *cctx, s64 delta)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*cctx, .lstats[layer->idx][idx])))
		(*vptr) += delta;
	else
		scx_bpf_error("invalid layer or stat idxs: %d, %d", idx, layer->idx);
}

static void lstat_inc(enum layer_stat_idx idx, struct layer *layer,
		      struct cpu_ctx *cctx)
{
	lstat_add(idx, layer, cctx, 1);
}

struct lock_wrapper {
	struct bpf_spin_lock	lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct lock_wrapper);
	__uint(max_entries, MAX_LAYERS);
	__uint(map_flags, 0);
} layer_load_locks SEC(".maps");

static void adj_load(u32 layer_idx, s64 adj, u64 now)
{
	struct layer *layer;
	struct lock_wrapper *lockw;

	layer = MEMBER_VPTR(layers, [layer_idx]);
	lockw = bpf_map_lookup_elem(&layer_load_locks, &layer_idx);

	if (!layer || !lockw) {
		scx_bpf_error("Can't access layer%d or its load_lock", layer_idx);
		return;
	}

	bpf_spin_lock(&lockw->lock);
	layer->load += adj;
	ravg_accumulate(&layer->load_rd, layer->load, now, USAGE_HALF_LIFE);
	bpf_spin_unlock(&lockw->lock);

	if (debug && adj < 0 && (s64)layer->load < 0)
		scx_bpf_error("cpu%d layer%d load underflow (load=%lld adj=%lld)",
			      bpf_get_smp_processor_id(), layer_idx, layer->load, adj);
}

struct layer_cpumask_wrapper {
	struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct layer_cpumask_wrapper);
	__uint(max_entries, MAX_LAYERS);
	__uint(map_flags, 0);
} layer_cpumasks SEC(".maps");

static struct cpumask *lookup_layer_cpumask(int idx)
{
	struct layer_cpumask_wrapper *cpumaskw;

	if ((cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &idx))) {
		return (struct cpumask *)cpumaskw->cpumask;
	} else {
		scx_bpf_error("no layer_cpumask");
		return NULL;
	}
}

static void refresh_cpumasks(int idx)
{
	struct layer_cpumask_wrapper *cpumaskw;
	struct layer *layer;
	int cpu, total = 0;

	if (!__sync_val_compare_and_swap(&layers[idx].refresh_cpus, 1, 0))
		return;

	cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &idx);

	bpf_for(cpu, 0, nr_possible_cpus) {
		u8 *u8_ptr;

		if ((u8_ptr = MEMBER_VPTR(layers, [idx].cpus[cpu / 8]))) {
			/*
			 * XXX - The following test should be outside the loop
			 * but that makes the verifier think that
			 * cpumaskw->cpumask might be NULL in the loop.
			 */
			barrier_var(cpumaskw);
			if (!cpumaskw || !cpumaskw->cpumask) {
				scx_bpf_error("can't happen");
				return;
			}

			if (*u8_ptr & (1 << (cpu % 8))) {
				bpf_cpumask_set_cpu(cpu, cpumaskw->cpumask);
				total++;
			} else {
				bpf_cpumask_clear_cpu(cpu, cpumaskw->cpumask);
			}
		} else {
			scx_bpf_error("can't happen");
		}
	}

	// XXX - shouldn't be necessary
	layer = MEMBER_VPTR(layers, [idx]);
	if (!layer) {
		scx_bpf_error("can't happen");
		return;
	}

	layer->nr_cpus = total;
	__sync_fetch_and_add(&layer->cpus_seq, 1);
	trace("LAYER[%d] now has %d cpus, seq=%llu", idx, layer->nr_cpus, layer->cpus_seq);
}

SEC("fentry")
int BPF_PROG(sched_tick_fentry)
{
	int idx;

	if (bpf_get_smp_processor_id() == 0)
		bpf_for(idx, 0, nr_layers)
			refresh_cpumasks(idx);
	return 0;
}

struct task_ctx {
	int			pid;
	int			last_cpu;
	int			layer;
	bool			refresh_layer;
	u64			layer_cpus_seq;
	struct bpf_cpumask __kptr *layered_cpumask;

	bool			all_cpus_allowed;
	u64			runnable_at;
	u64			running_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

static struct task_ctx *lookup_task_ctx_may_fail(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx_may_fail(p);

	if (!tctx)
		scx_bpf_error("task_ctx lookup failed");

	return tctx;
}

static struct layer *lookup_layer(int idx)
{
	if (idx < 0 || idx >= nr_layers) {
		scx_bpf_error("invalid layer %d", idx);
		return NULL;
	}
	return &layers[idx];
}

/*
 * Because the layer membership is by the default hierarchy cgroups rather than
 * the CPU controller membership, we can't use ops.cgroup_move(). Let's iterate
 * the tasks manually and set refresh_layer.
 *
 * The iteration isn't synchronized and may fail spuriously. It's not a big
 * practical problem as process migrations are very rare in most modern systems.
 * That said, we eventually want this to be based on CPU controller membership.
 */
SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(tp_cgroup_attach_task, struct cgroup *cgrp, const char *cgrp_path,
	     struct task_struct *leader, bool threadgroup)
{
	struct list_head *thread_head;
	struct task_struct *next;
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx_may_fail(leader)))
		return 0;
	tctx->refresh_layer = true;

	if (!threadgroup)
		return 0;

	thread_head = &leader->signal->thread_head;

	if (!(next = bpf_task_acquire(leader))) {
		scx_bpf_error("failed to acquire leader");
		return 0;
	}

	bpf_repeat(MAX_TASKS) {
		struct task_struct *p;
		int pid;

		p = container_of(next->thread_node.next, struct task_struct, thread_node);
		bpf_task_release(next);

		if (&p->thread_node == thread_head) {
			next = NULL;
			break;
		}

		pid = BPF_CORE_READ(p, pid);
		next = bpf_task_from_pid(pid);
		if (!next) {
			bpf_printk("scx_layered: tp_cgroup_attach_task: thread iteration failed");
			break;
		}

		if ((tctx = lookup_task_ctx(next)))
			tctx->refresh_layer = true;
	}

	if (next)
		bpf_task_release(next);
	return 0;
}

SEC("tp_btf/task_rename")
int BPF_PROG(tp_task_rename, struct task_struct *p, const char *buf)
{
	struct task_ctx *tctx;

	if ((tctx = lookup_task_ctx_may_fail(p)))
		tctx->refresh_layer = true;
	return 0;
}

static void maybe_refresh_layered_cpumask(struct cpumask *layered_cpumask,
					  struct task_struct *p, struct task_ctx *tctx,
					  const struct cpumask *layer_cpumask)
{
	u64 layer_seq = layers->cpus_seq;

	if (tctx->layer_cpus_seq == layer_seq)
		return;

	/*
	 * XXX - We're assuming that the updated @layer_cpumask matching the new
	 * @layer_seq is visible which may not be true. For now, leave it as-is.
	 * Let's update once BPF grows enough memory ordering constructs.
	 */
	bpf_cpumask_and((struct bpf_cpumask *)layered_cpumask, layer_cpumask, p->cpus_ptr);
	tctx->layer_cpus_seq = layer_seq;
	trace("%s[%d] cpumask refreshed to seq %llu", p->comm, p->pid, layer_seq);
}

static s32 pick_idle_cpu_from(const struct cpumask *cand_cpumask, s32 prev_cpu,
			      const struct cpumask *idle_smtmask)
{
	bool prev_in_cand = bpf_cpumask_test_cpu(prev_cpu, cand_cpumask);
	s32 cpu;

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	if (smt_enabled) {
		if (prev_in_cand &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
			return prev_cpu;

		cpu = scx_bpf_pick_idle_cpu(cand_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			return cpu;
	}

	if (prev_in_cand && scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	return scx_bpf_pick_idle_cpu(cand_cpumask, 0);
}

static __always_inline
bool should_try_preempt_first(s32 cand, struct layer *layer,
			      const struct cpumask *layered_cpumask)
{
	struct cpu_ctx *cand_cctx, *sib_cctx;
	s32 sib;

	if (!layer->preempt || !layer->preempt_first)
		return false;

	if (!layer->open && !bpf_cpumask_test_cpu(cand, layered_cpumask))
		return false;

	if (!(cand_cctx = lookup_cpu_ctx(cand)) || cand_cctx->current_preempt)
		return false;

	if (layer->exclusive && (sib = sibling_cpu(cand)) >= 0 &&
	    (!(sib_cctx = lookup_cpu_ctx(sib)) || sib_cctx->current_preempt))
		return false;

	return true;
}

static __always_inline
s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
		  struct cpu_ctx *cctx, struct task_ctx *tctx, struct layer *layer,
		  bool from_selcpu)
{
	const struct cpumask *idle_smtmask;
	struct cpumask *layer_cpumask, *layered_cpumask;
	s32 cpu;

	/* look up everything we need */
	if (!(layered_cpumask = (struct cpumask *)tctx->layered_cpumask) ||
	    !(layer_cpumask = lookup_layer_cpumask(tctx->layer)))
		return -1;

	/* not much to do if bound to a single CPU */
	if (p->nr_cpus_allowed == 1 && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		if (!layer->open && !bpf_cpumask_test_cpu(prev_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);
		return prev_cpu;
	}

	maybe_refresh_layered_cpumask(layered_cpumask, p, tctx, layer_cpumask);

	/*
	 * If @p prefers to preempt @prev_cpu than finding an idle CPU and
	 * @prev_cpu is preemptible, tell the enqueue path to try to preempt
	 * @prev_cpu. The enqueue path will also retry to find an idle CPU if
	 * the preemption attempt fails.
	 */
	if (from_selcpu && should_try_preempt_first(prev_cpu, layer, layered_cpumask)) {
		cctx->try_preempt_first = true;
		return -1;
	}

	idle_smtmask = scx_bpf_get_idle_smtmask();

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	if ((cpu = pick_idle_cpu_from(layered_cpumask, prev_cpu,
				      idle_smtmask)) >= 0)
		goto out_put;

	/*
	 * If the layer is an open one, we can try the whole machine.
	 */
	if (layer->open &&
	    ((cpu = pick_idle_cpu_from(p->cpus_ptr, prev_cpu,
				       idle_smtmask)) >= 0)) {
		lstat_inc(LSTAT_OPEN_IDLE, layer, cctx);
		goto out_put;
	}

	cpu = -1;
out_put:
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;
}

s32 BPF_STRUCT_OPS(layered_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	s32 cpu;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return prev_cpu;

	/*
	 * We usually update the layer in layered_runnable() to avoid confusion.
	 * As layered_select_cpu() takes place before runnable, new tasks would
	 * still have -1 layer. Just return @prev_cpu.
	 */
	if (tctx->layer < 0 || !(layer = lookup_layer(tctx->layer)))
		return prev_cpu;

	cpu = pick_idle_cpu(p, prev_cpu, cctx, tctx, layer, true);

	if (cpu >= 0) {
		lstat_inc(LSTAT_SEL_LOCAL, layer, cctx);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	} else {
		return prev_cpu;
	}
}

static __always_inline
bool pick_idle_cpu_and_kick(struct task_struct *p, s32 task_cpu,
			    struct cpu_ctx *cctx, struct task_ctx *tctx,
			    struct layer *layer)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, task_cpu, cctx, tctx, layer, false);

	if (cpu >= 0) {
		lstat_inc(LSTAT_KICK, layer, cctx);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return true;
	} else {
		return false;
	}
}

static __always_inline
bool try_preempt(s32 cand, struct task_struct *p, struct cpu_ctx *cctx,
		 struct task_ctx *tctx, struct layer *layer, bool preempt_first)
{
	struct cpu_ctx *cand_cctx, *sib_cctx = NULL;
	s32 sib;

	if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
		return false;

	if (!(cand_cctx = lookup_cpu_ctx(cand)) || cand_cctx->current_preempt)
		return false;

	/*
	 * If exclusive, we want to make sure the sibling CPU, if there's
	 * one, is idle. However, if the sibling CPU is already running a
	 * preempt task, we shouldn't kick it out.
	 */
	if (layer->exclusive && (sib = sibling_cpu(cand)) >= 0 &&
	    (!(sib_cctx = lookup_cpu_ctx(sib)) || sib_cctx->current_preempt)) {
		lstat_inc(LSTAT_EXCL_COLLISION, layer, cctx);
		return false;
	}

	scx_bpf_kick_cpu(cand, SCX_KICK_PREEMPT);

	/*
	 * $sib_cctx is set iff @p is an exclusive task, a sibling CPU
	 * exists which is not running a preempt task. Let's preempt the
	 * sibling CPU so that it can become idle. The ->maybe_idle test is
	 * inaccurate and racy but should be good enough for best-effort
	 * optimization.
	 */
	if (sib_cctx && !sib_cctx->maybe_idle) {
		lstat_inc(LSTAT_EXCL_PREEMPT, layer, cctx);
		scx_bpf_kick_cpu(sib, SCX_KICK_PREEMPT);
	}

	if (!cand_cctx->maybe_idle) {
		lstat_inc(LSTAT_PREEMPT, layer, cctx);
		if (preempt_first)
			lstat_inc(LSTAT_PREEMPT_FIRST, layer, cctx);
	} else {
		lstat_inc(LSTAT_PREEMPT_IDLE, layer, cctx);
	}
	return true;
}

void BPF_STRUCT_OPS(layered_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u64 vtime = p->scx.dsq_vtime;
	bool try_preempt_first;
	u32 idx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(layer = lookup_layer(tctx->layer)))
		return;

	try_preempt_first = cctx->try_preempt_first;
	cctx->try_preempt_first = false;

	if (cctx->yielding) {
		lstat_inc(LSTAT_YIELD, layer, cctx);
		cctx->yielding = false;
	}

	if (enq_flags & SCX_ENQ_REENQ) {
		lstat_inc(LSTAT_ENQ_REENQ, layer, cctx);
	} else {
		if (enq_flags & SCX_ENQ_LAST) {
			lstat_inc(LSTAT_ENQ_LAST, layer, cctx);
			scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);
			return;
		}

		if (enq_flags & SCX_ENQ_WAKEUP)
			lstat_inc(LSTAT_ENQ_WAKEUP, layer, cctx);
		else
			lstat_inc(LSTAT_ENQ_EXPIRE, layer, cctx);
	}

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (vtime_before(vtime, layer->vtime_now - slice_ns))
		vtime = layer->vtime_now - slice_ns;

	/*
	 * Special-case per-cpu kthreads which aren't in a preempting layer so
	 * that they run between preempting and non-preempting layers. This is
	 * to give reasonable boost to per-cpu kthreads by default as they are
	 * usually important for system performance and responsiveness.
	 */
	if (!layer->preempt &&
	    (p->flags & PF_KTHREAD) && p->nr_cpus_allowed == 1) {
		struct cpumask *layer_cpumask;

		if (!layer->open &&
		    (layer_cpumask = lookup_layer_cpumask(tctx->layer)) &&
		    !bpf_cpumask_test_cpu(task_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);

		scx_bpf_dispatch(p, HI_FALLBACK_DSQ, slice_ns, enq_flags);
		goto find_cpu;
	}

	/*
	 * As an open or grouped layer is consumed from all CPUs, a task which
	 * belongs to such a layer can be safely put in the layer's DSQ
	 * regardless of its cpumask. However, a task with custom cpumask in a
	 * confined layer may fail to be consumed for an indefinite amount of
	 * time. Queue them to the fallback DSQ.
	 */
	if (!layer->open && !tctx->all_cpus_allowed) {
		lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);
		scx_bpf_dispatch(p, LO_FALLBACK_DSQ, slice_ns, enq_flags);
		goto find_cpu;
	}

	scx_bpf_dispatch_vtime(p, tctx->layer, slice_ns, vtime, enq_flags);

find_cpu:
	if (try_preempt_first) {
		/*
		 * @p prefers to preempt its previous CPU even when there are
		 * other idle CPUs.
		 */
		if (try_preempt(task_cpu, p, cctx, tctx, layer, true))
			return;
		/* we skipped idle CPU picking in select_cpu. Do it here. */
		if (pick_idle_cpu_and_kick(p, task_cpu, cctx, tctx, layer))
			return;
	} else {
		/*
		 * If we aren't in the wakeup path, layered_select_cpu() hasn't
		 * run and thus we haven't looked for and kicked an idle CPU.
		 * Let's do it now.
		 */
		if (!(enq_flags & SCX_ENQ_WAKEUP) &&
		    pick_idle_cpu_and_kick(p, task_cpu, cctx, tctx, layer))
			return;
		if (!layer->preempt)
			return;
		if (try_preempt(task_cpu, p, cctx, tctx, layer, false))
			return;
	}

	bpf_for(idx, 0, nr_possible_cpus) {
		s32 cand = (preempt_cursor + idx) % nr_possible_cpus;

		if (try_preempt(cand, p, cctx, tctx, layer, false)) {
			/*
			 * Round-robining doesn't have to be strict. Let's
			 * not bother with atomic ops on $preempt_cursor.
			 */
			preempt_cursor = (cand + 1) % nr_possible_cpus;
			return;
		}
	}

	lstat_inc(LSTAT_PREEMPT_FAIL, layer, cctx);
}

static bool keep_running(struct cpu_ctx *cctx, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct layer *layer;

	if (cctx->yielding || !max_exec_ns)
		return false;

	/* does it wanna? */
	if (!(p->scx.flags & SCX_TASK_QUEUED))
		goto no;

	if (!(tctx = lookup_task_ctx(p)) || !(layer = lookup_layer(tctx->layer)))
		goto no;

	/* @p has fully consumed its slice and still wants to run */
	cctx->ran_current_for += slice_ns;

	/*
	 * There wasn't anything in the local or global DSQ, but there may be
	 * tasks which are affine to this CPU in some other DSQs. Let's not run
	 * for too long.
	 */
	if (cctx->ran_current_for > max_exec_ns) {
		lstat_inc(LSTAT_KEEP_FAIL_MAX_EXEC, layer, cctx);
		goto no;
	}

	/*
	 * @p is eligible for continuing. We need to implement a better way to
	 * determine whether a layer is allowed to keep running. For now,
	 * implement something simple.
	 */
	if (layer->preempt) {
		/*
		 * @p is in an preempting layer. As long as the layer doesn't
		 * have tasks waiting, keep running it. If there are multiple
		 * competing preempting layers, this won't work well.
		 */
		if (!scx_bpf_dsq_nr_queued(layer->idx)) {
			lstat_inc(LSTAT_KEEP, layer, cctx);
			return true;
		}
	} else {
		const struct cpumask *idle_cpumask = scx_bpf_get_idle_cpumask();
		bool has_idle = false;

		/*
		 * If @p is in an open layer, keep running if there's any idle
		 * CPU. If confined, keep running iff the layer has idle CPUs.
		 */
		if (layer->open) {
			has_idle = !bpf_cpumask_empty(idle_cpumask);
		} else {
			struct cpumask *layer_cpumask;

			if ((layer_cpumask = lookup_layer_cpumask(layer->idx)))
				has_idle = bpf_cpumask_intersects(idle_cpumask,
								  layer_cpumask);
		}

		scx_bpf_put_idle_cpumask(idle_cpumask);

		if (has_idle) {
			lstat_inc(LSTAT_KEEP, layer, cctx);
			return true;
		}
	}

	lstat_inc(LSTAT_KEEP_FAIL_BUSY, layer, cctx);
no:
	cctx->ran_current_for = 0;
	return false;
}

void BPF_STRUCT_OPS(layered_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 sib = sibling_cpu(cpu);
	struct cpu_ctx *cctx, *sib_cctx;
	int idx;

	if (!(cctx = lookup_cpu_ctx(-1)))
		return;

	/*
	 * if @prev was on SCX and is still runnable, we are here because @prev
	 * has exhausted its slice. We may want to keep running it on this CPU
	 * rather than giving this CPU to another task and then try to schedule
	 * @prev somewhere else.
	 *
	 * Let's not dispatch any task if we want to keep running @prev. This
	 * will trigger the automatic local enq behavior which will put @prev on
	 * @cpu's local DSQ. A more straightforward way to implement this would
	 * be extending slice from ops.tick() but that's not available in older
	 * kernels, so let's make do with this for now.
	 */
	if (prev && keep_running(cctx, prev))
		return;

	/*
	 * If the sibling CPU is running an exclusive task, keep this CPU idle.
	 * This test is a racy test but should be good enough for best-effort
	 * optimization.
	 */
	if (sib >= 0 && (sib_cctx = lookup_cpu_ctx(sib)) &&
	    sib_cctx->current_exclusive) {
		gstat_inc(GSTAT_EXCL_IDLE, cctx);
		return;
	}

	/* consume preempting layers first */
	bpf_for(idx, 0, nr_layers)
		if (layers[idx].preempt && scx_bpf_consume(idx))
			return;

	if (scx_bpf_consume(HI_FALLBACK_DSQ))
		return;

	/* consume !open layers second */
	bpf_for(idx, 0, nr_layers) {
		struct layer *layer = &layers[idx];
		struct cpumask *layer_cpumask;

		/* consume matching layers */
		if (!(layer_cpumask = lookup_layer_cpumask(idx)))
			return;

		if (bpf_cpumask_test_cpu(cpu, layer_cpumask) ||
		    (cpu == fallback_cpu && layer->nr_cpus == 0)) {
			if (scx_bpf_consume(idx))
				return;
		}
	}

	/* consume !preempting open layers */
	bpf_for(idx, 0, nr_layers) {
		if (!layers[idx].preempt && layers[idx].open &&
		    scx_bpf_consume(idx))
			return;
	}

	scx_bpf_consume(LO_FALLBACK_DSQ);
}

static bool match_one(struct layer_match *match, struct task_struct *p, const char *cgrp_path)
{
	switch (match->kind) {
	case MATCH_CGROUP_PREFIX: {
		return match_prefix(match->cgroup_prefix, cgrp_path, MAX_PATH);
	}
	case MATCH_COMM_PREFIX: {
		char comm[MAX_COMM];
		memcpy(comm, p->comm, MAX_COMM);
		return match_prefix(match->comm_prefix, comm, MAX_COMM);
	}
	case MATCH_PCOMM_PREFIX: {
		char pcomm[MAX_COMM];

		memcpy(pcomm, p->group_leader->comm, MAX_COMM);
		return match_prefix(match->pcomm_prefix, pcomm, MAX_COMM);
	}
	case MATCH_NICE_ABOVE:
		return prio_to_nice((s32)p->static_prio) > match->nice;
	case MATCH_NICE_BELOW:
		return prio_to_nice((s32)p->static_prio) < match->nice;
	case MATCH_NICE_EQUALS:
		return prio_to_nice((s32)p->static_prio) == match->nice;
	default:
		scx_bpf_error("invalid match kind %d", match->kind);
		return false;
	}
}

static bool match_layer(struct layer *layer, struct task_struct *p, const char *cgrp_path)
{
	u32 nr_match_ors = layer->nr_match_ors;
	u64 or_idx, and_idx;

	if (nr_match_ors > MAX_LAYER_MATCH_ORS) {
		scx_bpf_error("too many ORs");
		return false;
	}

	bpf_for(or_idx, 0, nr_match_ors) {
		struct layer_match_ands *ands;
		bool matched = true;

		barrier_var(or_idx);
		if (or_idx >= MAX_LAYER_MATCH_ORS)
			return false; /* can't happen */
		ands = &layer->matches[or_idx];

		if (ands->nr_match_ands > NR_LAYER_MATCH_KINDS) {
			scx_bpf_error("too many ANDs");
			return false;
		}

		bpf_for(and_idx, 0, ands->nr_match_ands) {
			struct layer_match *match;

			barrier_var(and_idx);
			if (and_idx >= NR_LAYER_MATCH_KINDS)
				return false; /* can't happen */
			match = &ands->matches[and_idx];

			if (!match_one(match, p, cgrp_path)) {
				matched = false;
				break;
			}
		}

		if (matched)
			return true;
	}

	return false;
}

static void maybe_refresh_layer(struct task_struct *p, struct task_ctx *tctx)
{
	const char *cgrp_path;
	bool matched = false;
	u64 idx;	// XXX - int makes verifier unhappy

	if (!tctx->refresh_layer)
		return;
	tctx->refresh_layer = false;

	if (!(cgrp_path = format_cgrp_path(p->cgroups->dfl_cgrp)))
		return;

	if (tctx->layer >= 0 && tctx->layer < nr_layers)
		__sync_fetch_and_add(&layers[tctx->layer].nr_tasks, -1);

	bpf_for(idx, 0, nr_layers) {
		if (match_layer(&layers[idx], p, cgrp_path)) {
			matched = true;
			break;
		}
	}

	if (matched) {
		struct layer *layer = &layers[idx];

		tctx->layer = idx;
		tctx->layer_cpus_seq = layer->cpus_seq - 1;
		__sync_fetch_and_add(&layer->nr_tasks, 1);
		/*
		 * XXX - To be correct, we'd need to calculate the vtime
		 * delta in the previous layer, scale it by the load
		 * fraction difference and then offset from the new
		 * layer's vtime_now. For now, just do the simple thing
		 * and assume the offset to be zero.
		 *
		 * Revisit if high frequency dynamic layer switching
		 * needs to be supported.
		 */
		p->scx.dsq_vtime = layer->vtime_now;
	} else {
		scx_bpf_error("[%s]%d didn't match any layer", p->comm, p->pid);
	}

	if (tctx->layer < nr_layers - 1)
		trace("LAYER=%d %s[%d] cgrp=\"%s\"",
		      tctx->layer, p->comm, p->pid, cgrp_path);
}

void BPF_STRUCT_OPS(layered_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	tctx->runnable_at = now;
	maybe_refresh_layer(p, tctx);
	adj_load(tctx->layer, p->scx.weight, now);
}

void BPF_STRUCT_OPS(layered_running, struct task_struct *p)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(layer = lookup_layer(tctx->layer)))
		return;

	if (tctx->last_cpu >= 0 && tctx->last_cpu != task_cpu)
		lstat_inc(LSTAT_MIGRATION, layer, cctx);
	tctx->last_cpu = task_cpu;

	if (vtime_before(layer->vtime_now, p->scx.dsq_vtime))
		layer->vtime_now = p->scx.dsq_vtime;

	cctx->current_preempt = layer->preempt;
	cctx->current_exclusive = layer->exclusive;
	tctx->running_at = bpf_ktime_get_ns();

	/*
	 * If this CPU is transitioning from running an exclusive task to a
	 * non-exclusive one, the sibling CPU has likely been idle. Wake it up.
	 */
	if (cctx->prev_exclusive && !cctx->current_exclusive) {
		s32 sib = sibling_cpu(task_cpu);
		struct cpu_ctx *sib_cctx;

		/*
		 * %SCX_KICK_IDLE would be great here but we want to support
		 * older kernels. Let's use racy and inaccruate custom idle flag
		 * instead.
		 */
		if (sib >= 0 && (sib_cctx = lookup_cpu_ctx(sib)) &&
		    sib_cctx->maybe_idle) {
			gstat_inc(GSTAT_EXCL_WAKEUP, cctx);
			scx_bpf_kick_cpu(sib, 0);
		}
	}

	if (layer->perf > 0)
		__COMPAT_scx_bpf_cpuperf_set(task_cpu, layer->perf);

	cctx->maybe_idle = false;
}

void BPF_STRUCT_OPS(layered_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	s32 lidx;
	u64 used;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	lidx = tctx->layer;
	if (!(layer = lookup_layer(lidx)))
		return;

	used = bpf_ktime_get_ns() - tctx->running_at;
	if (used < layer->min_exec_ns) {
		lstat_inc(LSTAT_MIN_EXEC, layer, cctx);
		lstat_add(LSTAT_MIN_EXEC_NS, layer, cctx, layer->min_exec_ns - used);
		used = layer->min_exec_ns;
	}

	cctx->layer_cycles[lidx] += used;
	cctx->current_preempt = false;
	cctx->prev_exclusive = cctx->current_exclusive;
	cctx->current_exclusive = false;

	/* scale the execution time by the inverse of the weight and charge */
	if (cctx->yielding && used < slice_ns)
		used = slice_ns;
	p->scx.dsq_vtime += used * 100 / p->scx.weight;
	cctx->maybe_idle = true;
}

void BPF_STRUCT_OPS(layered_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	if ((tctx = lookup_task_ctx(p)))
		adj_load(tctx->layer, -(s64)p->scx.weight, bpf_ktime_get_ns());
}

bool BPF_STRUCT_OPS(layered_yield, struct task_struct *from, struct task_struct *to)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(from)) ||
	    !(layer = lookup_layer(tctx->layer)))
		return false;

	/*
	 * Special-case 0 yield_step_ns. Yiedling is completely ignored and
	 * the task is eligible for keep_running().
	 */
	if (!layer->yield_step_ns) {
		lstat_inc(LSTAT_YIELD_IGNORE, layer, cctx);
		return false;
	}

	if (from->scx.slice > layer->yield_step_ns) {
		from->scx.slice -= layer->yield_step_ns;
		lstat_inc(LSTAT_YIELD_IGNORE, layer, cctx);
	} else {
		from->scx.slice = 0;
		cctx->yielding = true;
	}

	return false;
}

void BPF_STRUCT_OPS(layered_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *tctx;

	if ((tctx = lookup_task_ctx(p)))
		tctx->refresh_layer = true;
}

void BPF_STRUCT_OPS(layered_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		return;
	}

	tctx->all_cpus_allowed =
		bpf_cpumask_subset((const struct cpumask *)all_cpumask, cpumask);
}

void BPF_STRUCT_OPS(layered_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}

s32 BPF_STRUCT_OPS(layered_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;

	/*
	 * XXX - We want BPF_NOEXIST but bpf_map_delete_elem() in .disable() may
	 * fail spuriously due to BPF recursion protection triggering
	 * unnecessarily.
	 */
	tctx = bpf_task_storage_get(&task_ctxs, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	cpumask = bpf_kptr_xchg(&tctx->layered_cpumask, cpumask);
	if (cpumask) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	tctx->pid = p->pid;
	tctx->last_cpu = -1;
	tctx->layer = -1;
	tctx->refresh_layer = true;

	if (all_cpumask)
		tctx->all_cpus_allowed =
			bpf_cpumask_subset((const struct cpumask *)all_cpumask, p->cpus_ptr);
	else
		scx_bpf_error("missing all_cpumask");

	/*
	 * We are matching cgroup hierarchy path directly rather than the CPU
	 * controller path. As the former isn't available during the scheduler
	 * fork path, let's delay the layer selection until the first
	 * runnable().
	 */

	return 0;
}

void BPF_STRUCT_OPS(layered_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	if (tctx->layer >= 0 && tctx->layer < nr_layers)
		__sync_fetch_and_add(&layers[tctx->layer].nr_tasks, -1);
}

static u64 dsq_first_runnable_for_ms(u64 dsq_id, u64 now)
{
	struct task_struct *p;

	__COMPAT_DSQ_FOR_EACH(p, dsq_id, 0) {
		struct task_ctx *tctx;

		if ((tctx = lookup_task_ctx(p)))
			return (now - tctx->runnable_at) / 1000000;
	}

	return 0;
}

static void dump_layer_cpumask(int idx)
{
	struct cpumask *layer_cpumask;
	s32 cpu;
	char buf[128] = "", *p;

	if (!(layer_cpumask = lookup_layer_cpumask(idx)))
		return;

	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (!(p = MEMBER_VPTR(buf, [idx++])))
			break;
		if (bpf_cpumask_test_cpu(cpu, layer_cpumask))
			*p++ = '0' + cpu % 10;
		else
			*p++ = '.';

		if ((cpu & 7) == 7) {
			if (!(p = MEMBER_VPTR(buf, [idx++])))
				break;
			*p++ = '|';
		}
	}
	buf[sizeof(buf) - 1] = '\0';

	scx_bpf_dump("%s", buf);
}

void BPF_STRUCT_OPS(layered_dump, struct scx_dump_ctx *dctx)
{
	u64 now = bpf_ktime_get_ns();
	int i;

	bpf_for(i, 0, nr_layers) {
		scx_bpf_dump("LAYER[%d] nr_cpus=%u nr_queued=%d -%llums cpus=",
			     i, layers[i].nr_cpus, scx_bpf_dsq_nr_queued(i),
			     dsq_first_runnable_for_ms(i, now));
		dump_layer_cpumask(i);
		scx_bpf_dump("\n");
	}

	scx_bpf_dump("HI_FALLBACK nr_queued=%d -%llums\n",
		     scx_bpf_dsq_nr_queued(HI_FALLBACK_DSQ),
		     dsq_first_runnable_for_ms(HI_FALLBACK_DSQ, now));
	scx_bpf_dump("LO_FALLBACK nr_queued=%d -%llums\n",
		     scx_bpf_dsq_nr_queued(LO_FALLBACK_DSQ),
		     dsq_first_runnable_for_ms(LO_FALLBACK_DSQ, now));
}

s32 BPF_STRUCT_OPS_SLEEPABLE(layered_init)
{
	struct bpf_cpumask *cpumask;
	int i, j, k, nr_online_cpus, ret;

	ret = scx_bpf_create_dsq(HI_FALLBACK_DSQ, -1);
	if (ret < 0)
		return ret;

	ret = scx_bpf_create_dsq(LO_FALLBACK_DSQ, -1);
	if (ret < 0)
		return ret;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	nr_online_cpus = 0;
	bpf_for(i, 0, nr_possible_cpus) {
		const volatile u8 *u8_ptr;

		if ((u8_ptr = MEMBER_VPTR(all_cpus, [i / 8]))) {
			if (*u8_ptr & (1 << (i % 8))) {
				bpf_cpumask_set_cpu(i, cpumask);
				nr_online_cpus++;
			}
		} else {
			return -EINVAL;
		}
	}

	cpumask = bpf_kptr_xchg(&all_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	dbg("CFG: Dumping configuration, nr_online_cpus=%d smt_enabled=%d",
	    nr_online_cpus, smt_enabled);

	bpf_for(i, 0, nr_layers) {
		struct layer *layer = &layers[i];

		dbg("CFG LAYER[%d] min_exec_ns=%lu open=%d preempt=%d exclusive=%d",
		    i, layer->min_exec_ns, layer->open, layer->preempt,
		    layer->exclusive);

		if (layer->nr_match_ors > MAX_LAYER_MATCH_ORS) {
			scx_bpf_error("too many ORs");
			return -EINVAL;
		}

		bpf_for(j, 0, layer->nr_match_ors) {
			struct layer_match_ands *ands = MEMBER_VPTR(layers, [i].matches[j]);
			if (!ands) {
				scx_bpf_error("shouldn't happen");
				return -EINVAL;
			}

			if (ands->nr_match_ands > NR_LAYER_MATCH_KINDS) {
				scx_bpf_error("too many ANDs");
				return -EINVAL;
			}

			dbg("CFG   OR[%02d]", j);

			bpf_for(k, 0, ands->nr_match_ands) {
				char header[32];
				u64 header_data[1] = { k };
				struct layer_match *match;

				bpf_snprintf(header, sizeof(header), "CFG     AND[%02d]:",
					     header_data, sizeof(header_data));

				match = MEMBER_VPTR(layers, [i].matches[j].matches[k]);
				if (!match) {
					scx_bpf_error("shouldn't happen");
					return -EINVAL;
				}

				switch (match->kind) {
				case MATCH_CGROUP_PREFIX:
					dbg("%s CGROUP_PREFIX \"%s\"", header, match->cgroup_prefix);
					break;
				case MATCH_COMM_PREFIX:
					dbg("%s COMM_PREFIX \"%s\"", header, match->comm_prefix);
					break;
				case MATCH_PCOMM_PREFIX:
					dbg("%s PCOMM_PREFIX \"%s\"", header, match->pcomm_prefix);
					break;
				case MATCH_NICE_ABOVE:
					dbg("%s NICE_ABOVE %d", header, match->nice);
					break;
				case MATCH_NICE_BELOW:
					dbg("%s NICE_BELOW %d", header, match->nice);
					break;
				case MATCH_NICE_EQUALS:
					dbg("%s NICE_EQUALS %d", header, match->nice);
					break;
				default:
					scx_bpf_error("%s Invalid kind", header);
					return -EINVAL;
				}
			}
			if (ands->nr_match_ands == 0)
				dbg("CFG     DEFAULT");
		}
	}

	bpf_for(i, 0, nr_layers) {
		struct layer_cpumask_wrapper *cpumaskw;

		layers[i].idx = i;

		ret = scx_bpf_create_dsq(i, -1);
		if (ret < 0)
			return ret;

		if (!(cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &i)))
			return -ENOENT;

		cpumask = bpf_cpumask_create();
		if (!cpumask)
			return -ENOMEM;

		/*
		 * Start all layers with full cpumask so that everything runs
		 * everywhere. This will soon be updated by refresh_cpumasks()
		 * once the scheduler starts running.
		 */
		bpf_cpumask_setall(cpumask);

		cpumask = bpf_kptr_xchg(&cpumaskw->cpumask, cpumask);
		if (cpumask)
			bpf_cpumask_release(cpumask);
	}

	return 0;
}

void BPF_STRUCT_OPS(layered_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(layered,
	       .select_cpu		= (void *)layered_select_cpu,
	       .enqueue			= (void *)layered_enqueue,
	       .dispatch		= (void *)layered_dispatch,
	       .runnable		= (void *)layered_runnable,
	       .running			= (void *)layered_running,
	       .stopping		= (void *)layered_stopping,
	       .quiescent		= (void *)layered_quiescent,
	       .yield			= (void *)layered_yield,
	       .set_weight		= (void *)layered_set_weight,
	       .set_cpumask		= (void *)layered_set_cpumask,
	       .cpu_release		= (void *)layered_cpu_release,
	       .init_task		= (void *)layered_init_task,
	       .exit_task		= (void *)layered_exit_task,
	       .dump			= (void *)layered_dump,
	       .init			= (void *)layered_init,
	       .exit			= (void *)layered_exit,
	       .flags			= SCX_OPS_ENQ_LAST,
	       .name			= "layered");
