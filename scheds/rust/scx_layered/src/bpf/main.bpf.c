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
const volatile u32 nr_possible_cpus = 1;
const volatile u32 nr_layers = 1;
const volatile bool smt_enabled = true;
const volatile unsigned char all_cpus[MAX_CPUS_U8];

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
struct layer layers[MAX_LAYERS];
u32 fallback_cpu;
static u32 preempt_cursor;

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

#include "util.bpf.c"

struct user_exit_info uei;

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
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

static void lstat_inc(enum layer_stat_idx idx, struct layer *layer, struct cpu_ctx *cctx)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*cctx, .lstats[layer->idx][idx])))
		(*vptr)++;
	else
		scx_bpf_error("invalid layer or stat idxs: %d, %d", idx, layer->idx);
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

SEC("fentry/scheduler_tick")
int scheduler_tick_fentry(const void *ctx)
{
	int idx;

	if (bpf_get_smp_processor_id() == 0)
		bpf_for(idx, 0, nr_layers)
			refresh_cpumasks(idx);
	return 0;
}

struct task_ctx {
	int			pid;

	int			layer;
	bool			refresh_layer;
	u64			layer_cpus_seq;
	struct bpf_cpumask __kptr *layered_cpumask;

	bool			all_cpus_allowed;
	bool			dispatch_local;
	u64			started_running_at;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, struct task_ctx);
	__uint(max_entries, MAX_TASKS);
	__uint(map_flags, 0);
} task_ctxs SEC(".maps");

struct task_ctx *lookup_task_ctx_may_fail(struct task_struct *p)
{
	s32 pid = p->pid;

	return bpf_map_lookup_elem(&task_ctxs, &pid);
}

struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 pid = p->pid;

	if ((tctx = bpf_map_lookup_elem(&task_ctxs, &pid))) {
		return tctx;
	} else {
		scx_bpf_error("task_ctx lookup failed");
		return NULL;
	}
}

struct layer *lookup_layer(int idx)
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
	int leader_pid = leader->pid;

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
			      const struct cpumask *idle_cpumask,
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

s32 BPF_STRUCT_OPS(layered_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct cpumask *idle_cpumask, *idle_smtmask;
	struct cpumask *layer_cpumask, *layered_cpumask;
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	s32 cpu;

	/* look up everything we need */
	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(layered_cpumask = (struct cpumask *)tctx->layered_cpumask))
		return prev_cpu;

	/*
	 * We usually update the layer in layered_runnable() to avoid confusing.
	 * As layered_select_cpu() takes place before runnable, new tasks would
	 * still have -1 layer. Just return @prev_cpu.
	 */
	if (tctx->layer < 0)
		return prev_cpu;

	if (!(layer = lookup_layer(tctx->layer)) ||
	    !(layer_cpumask = lookup_layer_cpumask(tctx->layer)))
		return prev_cpu;

	if (!(idle_cpumask = scx_bpf_get_idle_cpumask()))
		return prev_cpu;

	if (!(idle_smtmask = scx_bpf_get_idle_smtmask())) {
		cpu = prev_cpu;
		goto out_put_idle_cpumask;
	}

	/* not much to do if bound to a single CPU */
	if (p->nr_cpus_allowed == 1) {
		cpu = prev_cpu;
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			if (!bpf_cpumask_test_cpu(cpu, layer_cpumask))
				lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);
			goto dispatch_local;
		} else {
			goto out_put_cpumasks;
		}
	}

	maybe_refresh_layered_cpumask(layered_cpumask, p, tctx, layer_cpumask);

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	if ((cpu = pick_idle_cpu_from(layered_cpumask, prev_cpu,
				      idle_cpumask, idle_smtmask)) >= 0)
		goto dispatch_local;

	/*
	 * If the layer is an open one, we can try the whole machine.
	 */
	if (layer->open &&
	    ((cpu = pick_idle_cpu_from(p->cpus_ptr, prev_cpu,
				       idle_cpumask, idle_smtmask)) >= 0)) {
		lstat_inc(LSTAT_OPEN_IDLE, layer, cctx);
		goto dispatch_local;
	}

	cpu = prev_cpu;
	goto out_put_cpumasks;

dispatch_local:
	tctx->dispatch_local = true;
out_put_cpumasks:
	scx_bpf_put_idle_cpumask(idle_smtmask);
out_put_idle_cpumask:
	scx_bpf_put_idle_cpumask(idle_cpumask);
	return cpu;
}

void BPF_STRUCT_OPS(layered_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	u64 vtime = p->scx.dsq_vtime;
	u32 idx;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(layer = lookup_layer(tctx->layer)))
		return;

	if (tctx->dispatch_local) {
		tctx->dispatch_local = false;
		lstat_inc(LSTAT_LOCAL, layer, cctx);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	lstat_inc(LSTAT_GLOBAL, layer, cctx);

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	if (vtime_before(vtime, layer->vtime_now - slice_ns))
		vtime = layer->vtime_now - slice_ns;

	if (!tctx->all_cpus_allowed) {
		lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
		return;
	}

	scx_bpf_dispatch_vtime(p, tctx->layer, slice_ns, vtime, enq_flags);

	if (!layer->preempt)
		return;

	bpf_for(idx, 0, nr_possible_cpus) {
		struct cpu_ctx *cand_cctx;
		u32 cpu = (preempt_cursor + idx) % nr_possible_cpus;

		if (!all_cpumask ||
		    !bpf_cpumask_test_cpu(cpu, (const struct cpumask *)all_cpumask))
			continue;
		if (!(cand_cctx = lookup_cpu_ctx(cpu)) || cand_cctx->current_preempt)
			continue;

		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);

		/*
		 * Round-robining doesn't have to be strict. Let's not bother
		 * with atomic ops on $preempt_cursor.
		 */
		preempt_cursor = (cpu + 1) % nr_possible_cpus;

		lstat_inc(LSTAT_PREEMPT, layer, cctx);
		break;
	}
}

void BPF_STRUCT_OPS(layered_dispatch, s32 cpu, struct task_struct *prev)
{
	int idx;

	/* consume preempting layers first */
	bpf_for(idx, 0, nr_layers)
		if (layers[idx].preempt && scx_bpf_consume(idx))
			return;

	/* consume !open layers second */
	bpf_for(idx, 0, nr_layers) {
		struct layer *layer = &layers[idx];
		struct cpumask *layer_cpumask;

		if (layer->open)
			continue;

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
	case MATCH_NICE_ABOVE:
		return (s32)p->static_prio - 120 > match->nice_above_or_below;
	case MATCH_NICE_BELOW:
		return (s32)p->static_prio - 120 < match->nice_above_or_below;
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

	maybe_refresh_layer(p, tctx);

	adj_load(tctx->layer, p->scx.weight, now);
}

void BPF_STRUCT_OPS(layered_running, struct task_struct *p)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(layer = lookup_layer(tctx->layer)))
		return;

	if (vtime_before(layer->vtime_now, p->scx.dsq_vtime))
		layer->vtime_now = p->scx.dsq_vtime;

	cctx->current_preempt = layer->preempt;
	tctx->started_running_at = bpf_ktime_get_ns();
}

void BPF_STRUCT_OPS(layered_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	u64 used;
	u32 layer;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	layer = tctx->layer;
	if (layer >= nr_layers) {
		scx_bpf_error("invalid layer %u", layer);
		return;
	}

	used = bpf_ktime_get_ns() - tctx->started_running_at;
	cctx->layer_cycles[layer] += used;
	cctx->current_preempt = false;

	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime += used * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(layered_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	if ((tctx = lookup_task_ctx(p)))
		adj_load(tctx->layer, -(s64)p->scx.weight, bpf_ktime_get_ns());
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

s32 BPF_STRUCT_OPS(layered_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx tctx_init = {
		.pid = p->pid,
		.layer = -1,
		.refresh_layer = true,
	};
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;
	s32 pid = p->pid;
	s32 ret;

	if (all_cpumask)
		tctx_init.all_cpus_allowed =
			bpf_cpumask_subset((const struct cpumask *)all_cpumask, p->cpus_ptr);
	else
		scx_bpf_error("missing all_cpumask");

	/*
	 * XXX - We want BPF_NOEXIST but bpf_map_delete_elem() in .disable() may
	 * fail spuriously due to BPF recursion protection triggering
	 * unnecessarily.
	 */
	if ((ret = bpf_map_update_elem(&task_ctxs, &pid, &tctx_init, 0 /*BPF_NOEXIST*/))) {
		scx_bpf_error("task_ctx allocation failure, ret=%d", ret);
		return ret;
	}

	/*
	 * Read the entry from the map immediately so we can add the cpumask
	 * with bpf_kptr_xchg().
	 */
	if (!(tctx = lookup_task_ctx(p)))
		return -ENOENT;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		bpf_map_delete_elem(&task_ctxs, &pid);
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&tctx->layered_cpumask, cpumask);
	if (cpumask) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		bpf_map_delete_elem(&task_ctxs, &pid);
		return -EINVAL;
	}

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
	s32 pid = p->pid;
	int ret;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	if (tctx->layer >= 0 && tctx->layer < nr_layers)
		__sync_fetch_and_add(&layers[tctx->layer].nr_tasks, -1);

	/*
	 * XXX - There's no reason delete should fail here but BPF's recursion
	 * protection can unnecessarily fail the operation. The fact that
	 * deletions aren't reliable means that we sometimes leak task_ctx and
	 * can't use BPF_NOEXIST on allocation in .prep_enable().
	 */
	ret = bpf_map_delete_elem(&task_ctxs, &pid);
	if (ret)
		gstat_inc(GSTAT_TASK_CTX_FREE_FAILED, cctx);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(layered_init)
{
	struct bpf_cpumask *cpumask;
	int i, j, k, nr_online_cpus, ret;

	scx_bpf_switch_all();

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

		dbg("CFG LAYER[%d] open=%d preempt=%d",
		    i, layer->open, layer->preempt);

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
				case MATCH_NICE_ABOVE:
					dbg("%s NICE_ABOVE %d", header, match->nice_above_or_below);
					break;
				case MATCH_NICE_BELOW:
					dbg("%s NICE_BELOW %d", header, match->nice_above_or_below);
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
			return -ENONET;

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
	uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops layered = {
	.select_cpu		= (void *)layered_select_cpu,
	.enqueue		= (void *)layered_enqueue,
	.dispatch		= (void *)layered_dispatch,
	.runnable		= (void *)layered_runnable,
	.running		= (void *)layered_running,
	.stopping		= (void *)layered_stopping,
	.quiescent		= (void *)layered_quiescent,
	.set_weight		= (void *)layered_set_weight,
	.set_cpumask		= (void *)layered_set_cpumask,
	.init_task		= (void *)layered_init_task,
	.exit_task		= (void *)layered_exit_task,
	.init			= (void *)layered_init,
	.exit			= (void *)layered_exit,
	.name			= "layered",
};
