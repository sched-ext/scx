/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#define LSP_INC
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"
#include "timer.bpf.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern unsigned CONFIG_HZ __kconfig;

const volatile u32 debug;
const volatile s32 layered_tgid;
const volatile u64 slice_ns;
const volatile u64 max_exec_ns;
const volatile u32 nr_possible_cpus = 1;
const volatile u64 numa_cpumasks[MAX_NUMA_NODES][MAX_CPUS / 64];
const volatile u32 llc_numa_id_map[MAX_LLCS];
const volatile u32 cpu_llc_id_map[MAX_CPUS];
const volatile u32 nr_layers = 1;
const volatile u32 nr_nodes = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_llcs = 32;	/* !0 for veristat, set during init */
const volatile bool smt_enabled = true;
const volatile bool has_little_cores = true;
const volatile bool xnuma_preemption = false;
const volatile s32 __sibling_cpu[MAX_CPUS];
const volatile bool monitor_disable = false;
const volatile unsigned char all_cpus[MAX_CPUS_U8];
const volatile u32 layer_iteration_order[MAX_LAYERS];
const volatile u32 nr_open_preempt_layers;	/* open/grouped && preempt */
const volatile u32 nr_open_layers;		/* open/grouped && !preempt */

/* Flag to enable or disable antistall feature */
const volatile bool enable_antistall = true;
/* Delay permitted, in seconds, before antistall activates */
const volatile u64 antistall_sec = 3;
const u32 zero_u32 = 0;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
private(big_cpumask) struct bpf_cpumask __kptr *big_cpumask;
struct layer layers[MAX_LAYERS];
u32 fallback_cpu;
static u32 preempt_cursor;

u32 empty_layer_ids[MAX_LAYERS];
u32 nr_empty_layer_ids;

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

static __always_inline struct layer *lookup_layer(u32 id)
{
	if (id >= nr_layers) {
		scx_bpf_error("invalid layer %d", id);
		return NULL;
	}
	return &layers[id];
}

static __always_inline u64 layer_slice_ns(struct layer *layer)
{
	return layer->slice_ns > 0 ? layer->slice_ns : slice_ns;
}

static __always_inline
int rotate_layer_id(u32 base_layer_id, u32 rotation)
{
	if (base_layer_id >= MAX_LAYERS)
		return rotation;
	return (base_layer_id + rotation) % nr_layers;
}

static __always_inline
u32 rotate_llc_id(u32 base_llc_id, u32 rotation)
{
	return (base_llc_id + rotation) % nr_llcs;
}

// return the dsq id for the layer based on the LLC id.
static __noinline u64 layer_dsq_id(u32 layer_id, u32 llc_id)
{
	if (nr_llcs == 1)
		return layer_id;
	else
		return (layer_id * nr_llcs) + llc_id;
}

// XXX - older kernels get confused by RCU state when subprogs are called from
// sleepable functions. Use __always_inline.
static __always_inline u32 cpu_to_llc_id(s32 cpu_id)
{
        const volatile u32 *llc_ptr;

        llc_ptr = MEMBER_VPTR(cpu_llc_id_map, [cpu_id]);
        if (!llc_ptr) {
                scx_bpf_error("Couldn't look up llc ID for cpu %d", cpu_id);
                return 0;
        }
        return *llc_ptr;
}

u32 llc_node_id(u32 llc_id)
{
        const volatile u32 *llc_ptr;

        llc_ptr = MEMBER_VPTR(llc_numa_id_map, [llc_id]);
        if (!llc_ptr) {
                scx_bpf_error("Couldn't look up llc ID for %d", llc_id);
                return 0;
        }
        return *llc_ptr;
}

static u64 llc_hi_fallback_dsq_id(u32 llc_id)
{
	return HI_FALLBACK_DSQ_BASE + llc_id;
}

static inline bool is_fallback_dsq(u64 dsq_id)
{
	return dsq_id > HI_FALLBACK_DSQ_BASE && dsq_id <= LO_FALLBACK_DSQ;
}

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctxs SEC(".maps");

static struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cpuc;

	if (cpu < 0)
		cpuc = bpf_map_lookup_elem(&cpu_ctxs, &zero_u32);
	else
		cpuc = bpf_map_lookup_percpu_elem(&cpu_ctxs, &zero_u32, cpu);

	if (!cpuc) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cpuc;
}

// XXX - Converting this to bss array triggers verifier bugs. See
// BpfStats::read(). Should also be cacheline aligned which doesn't work with
// the array map.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NUMA_NODES);
	__uint(map_flags, 0);
} node_data SEC(".maps");

static struct node_ctx *lookup_node_ctx(u32 node)
{
	struct node_ctx *nodec;

	if (!(nodec = bpf_map_lookup_elem(&node_data, &node)))
		scx_bpf_error("no node_ctx");
	return nodec;
}

// XXX - Converting this to bss array triggers verifier bugs. See
// BpfStats::read(). Should also be cacheline aligned which doesn't work with
// the array map.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct llc_ctx);
	__uint(max_entries, MAX_LLCS);
	__uint(map_flags, 0);
} llc_data SEC(".maps");

static struct llc_ctx *lookup_llc_ctx(u32 llc_id)
{
	struct llc_ctx *llcc;

	if (!(llcc = bpf_map_lookup_elem(&llc_data, &llc_id)))
		scx_bpf_error("no llc_ctx");
	return llcc;
}

static void gstat_inc(u32 id, struct cpu_ctx *cpuc)
{
	if (id >= NR_GSTATS) {
		scx_bpf_error("invalid global stat id %d", id);
		return;
	}

	cpuc->gstats[id]++;
}

static void lstat_add(u32 id, struct layer *layer, struct cpu_ctx *cpuc, s64 delta)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*cpuc, .lstats[layer->id][id])))
		(*vptr) += delta;
	else
		scx_bpf_error("invalid layer or stat ids: %d, %d", id, layer->id);
}

static void lstat_inc(u32 id, struct layer *layer, struct cpu_ctx *cpuc)
{
	lstat_add(id, layer, cpuc, 1);
}

struct lock_wrapper {
	struct bpf_spin_lock	lock;
};

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

static struct cpumask *lookup_layer_cpumask(u32 layer_id)
{
	struct layer_cpumask_wrapper *cpumaskw;

	if ((cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &layer_id))) {
		return (struct cpumask *)cpumaskw->cpumask;
	} else {
		scx_bpf_error("no layer_cpumask");
		return NULL;
	}
}

/*
 * To determine whether to protect owned usage on this CPU, track owned and open
 * usages since the past two periods so that we are always considering at least
 * one full period.
 */
static void cpuc_shift_owned_open_usages(struct cpu_ctx *cpuc)
{
	cpuc->prev_owned_usage[0] = cpuc->prev_owned_usage[1];
	cpuc->prev_owned_usage[1] = cpuc->owned_usage;
	cpuc->prev_open_usage[0] = cpuc->prev_open_usage[1];
	cpuc->prev_open_usage[1] = cpuc->open_usage;
}

/* called before refresh_layer_cpumasks() on every period */
SEC("syscall")
int BPF_PROG(shift_owned_open_usages)
{
	struct cpu_ctx *cpuc;
	s32 cpu;

	bpf_for(cpu, 0, nr_possible_cpus)
		if ((cpuc = lookup_cpu_ctx(cpu)))
			cpuc_shift_owned_open_usages(cpuc);
	return 0;
}

/*
 * Returns if any cpus were added to the layer.
 */
static bool refresh_cpumasks(u32 layer_id)
{
	struct bpf_cpumask *layer_cpumask;
	struct layer_cpumask_wrapper *cpumaskw;
	struct layer *layer;
	struct cpu_ctx *cpuc;
	int cpu, total = 0;

	layer = MEMBER_VPTR(layers, [layer_id]);
	if (!layer) {
		scx_bpf_error("can't happen");
		return false;
	}

	if (!__sync_val_compare_and_swap(&layer->refresh_cpus, 1, 0))
		return false;

	bpf_rcu_read_lock();
	if (!(cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &layer_id)) ||
	    !(layer_cpumask = cpumaskw->cpumask)) {
		bpf_rcu_read_unlock();
		scx_bpf_error("can't happen");
		return false;
	}

	bpf_for(cpu, 0, nr_possible_cpus) {
		u8 *u8_ptr;

		if (!(cpuc = lookup_cpu_ctx(cpu))) {
			bpf_rcu_read_unlock();
			return false;
		}

		if ((u8_ptr = MEMBER_VPTR(layers, [layer_id].cpus[cpu / 8]))) {
			if (*u8_ptr & (1 << (cpu % 8))) {
				/*
				 * If $cpu has been assigned to a new layer,
				 * history from the last period doesn't mean
				 * anything. Shift it away.
				 */
				if (cpuc->layer_id != layer_id)
					cpuc_shift_owned_open_usages(cpuc);
				cpuc->layer_id = layer_id;
				bpf_cpumask_set_cpu(cpu, layer_cpumask);
				total++;

				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			} else {
				if (cpuc->layer_id == layer_id)
					cpuc->layer_id = MAX_LAYERS;
				bpf_cpumask_clear_cpu(cpu, layer_cpumask);
			}
		} else {
			scx_bpf_error("can't happen");
		}
	}


	layer->nr_cpus = total;
	__sync_fetch_and_add(&layer->cpus_seq, 1);
	bpf_rcu_read_unlock();
	trace("LAYER[%d] now has %d cpus, seq=%llu", layer_id, layer->nr_cpus, layer->cpus_seq);
	return total > 0;
}

/*
 * Refreshes all layer cpumasks, this is called via BPF_PROG_RUN from userspace.
 */
SEC("syscall")
int BPF_PROG(refresh_layer_cpumasks)
{
	u32 id;

	bpf_for(id, 0, nr_layers)
		refresh_cpumasks(id);

	return 0;
}

struct cached_cpus {
	s64			id;
	u64			seq;
};

struct task_ctx {
	int			pid;
	int			last_cpu;
	u32			layer_id;
	pid_t			last_waker;
	bool			refresh_layer;
	struct cached_cpus	layered_cpus;
	/*
	 * XXX: Old kernels can't track a bpf_cpumask on nested structs
	 */
	struct bpf_cpumask __kptr *layered_mask;
	struct cached_cpus	layered_cpus_llc;
	struct bpf_cpumask __kptr *layered_llc_mask;
	struct cached_cpus	layered_cpus_node;
	struct bpf_cpumask __kptr *layered_node_mask;
	bool			all_cpus_allowed;
	u64			runnable_at;
	u64			running_at;
	u64			runtime_avg;
	u32			llc_id;
	u32			qrt_llc_id;	/* for llcc->queue_runtime */
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
	struct task_ctx *taskc = lookup_task_ctx_may_fail(p);

	if (!taskc)
		scx_bpf_error("task_ctx lookup failed");

	return taskc;
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
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx_may_fail(leader)))
		return 0;
	taskc->refresh_layer = true;

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

		if ((taskc = lookup_task_ctx(next)))
			taskc->refresh_layer = true;
	}

	if (next)
		bpf_task_release(next);
	return 0;
}

SEC("tp_btf/task_rename")
int BPF_PROG(tp_task_rename, struct task_struct *p, const char *buf)
{
	struct task_ctx *taskc;

	if ((taskc = lookup_task_ctx_may_fail(p)))
		taskc->refresh_layer = true;
	return 0;
}

static bool should_refresh_cached_cpus(struct cached_cpus *ccpus, s64 id, u64 cpus_seq)
{
	return ccpus->id != id || ccpus->seq != cpus_seq;
}

static __always_inline
void refresh_cached_cpus(struct bpf_cpumask *mask,
			 struct cached_cpus *ccpus,
			 s64 id, u64 cpus_seq,
			 const struct cpumask *cpus_a,
			 const struct cpumask *cpus_b)
{
	if (unlikely(!mask || !cpus_a || !cpus_b)) {
		scx_bpf_error("NULL ccpus->mask or cpus_a/b");
		return;
	}

	/*
	 * XXX - We're assuming that the updated @layer_cpumask matching the new
	 * @layer_seq is visible which may not be true. For now, leave it as-is.
	 * Let's update once BPF grows enough memory ordering constructs.
	 */
	bpf_cpumask_and(mask, cpus_a, cpus_b);
	ccpus->id = id;
	ccpus->seq = cpus_seq;
}

static void maybe_refresh_layered_cpus(struct task_struct *p, struct task_ctx *taskc,
				       const struct cpumask *layer_cpumask,
				       u64 cpus_seq)
{
	if (should_refresh_cached_cpus(&taskc->layered_cpus, 0, cpus_seq)) {
		refresh_cached_cpus(taskc->layered_mask, &taskc->layered_cpus, 0, cpus_seq,
				    p->cpus_ptr, layer_cpumask);
		trace("%s[%d] layered cpumask refreshed to seq=%llu",
		      p->comm, p->pid, taskc->layered_cpus.seq);
	}
}

static void maybe_refresh_layered_cpus_llc(struct task_struct *p, struct task_ctx *taskc,
					   const struct cpumask *layer_cpumask,
					   s32 llc_id, u64 cpus_seq)
{
	if (should_refresh_cached_cpus(&taskc->layered_cpus_llc, llc_id, cpus_seq)) {
		struct llc_ctx *llcc;

		if (!(llcc = lookup_llc_ctx(llc_id)))
			return;
		refresh_cached_cpus(taskc->layered_llc_mask,
				    &taskc->layered_cpus_llc, llc_id, cpus_seq,
				    cast_mask(taskc->layered_mask),
				    cast_mask(llcc->cpumask));
		trace("%s[%d] layered llc cpumask refreshed to llc=%d seq=%llu",
		      p->comm, p->pid, taskc->layered_cpus_llc.id, taskc->layered_cpus_llc.seq);
	}
}

static void maybe_refresh_layered_cpus_node(struct task_struct *p, struct task_ctx *taskc,
					    const struct cpumask *layer_cpumask,
					    s32 node_id, u64 cpus_seq)
{
	if (should_refresh_cached_cpus(&taskc->layered_cpus_node, node_id, cpus_seq)) {
		struct node_ctx *nodec;

		if (!(nodec = lookup_node_ctx(node_id)))
			return;
		refresh_cached_cpus(taskc->layered_node_mask,
				    &taskc->layered_cpus_node, node_id, cpus_seq,
				    cast_mask(taskc->layered_mask),
				    cast_mask(nodec->cpumask));
		trace("%s[%d] layered node cpumask refreshed to node=%d seq=%llu",
		      p->comm, p->pid, taskc->layered_cpus_node.id, taskc->layered_cpus_node.seq);
	}
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
	struct cpu_ctx *cand_cpuc, *sib_cpuc;
	s32 sib;

	if (!layer->preempt || !layer->preempt_first)
		return false;

	if (layer->kind == LAYER_KIND_CONFINED &&
	    !bpf_cpumask_test_cpu(cand, layered_cpumask))
		return false;

	if (!(cand_cpuc = lookup_cpu_ctx(cand)) || cand_cpuc->current_preempt)
		return false;

	if (layer->exclusive && (sib = sibling_cpu(cand)) >= 0 &&
	    (!(sib_cpuc = lookup_cpu_ctx(sib)) || sib_cpuc->current_preempt))
		return false;

	return true;
}

static __always_inline
s32 pick_idle_big_little(struct layer *layer, struct task_ctx *taskc,
			 const struct cpumask *idle_smtmask, s32 prev_cpu)
{
	s32 cpu = -1;

	if (!has_little_cores || !big_cpumask)
		return cpu;

	struct bpf_cpumask *tmp_cpumask;
	if (!taskc->layered_mask || !big_cpumask)
		return cpu;

	if (!(tmp_cpumask = bpf_cpumask_create()))
		return cpu;

	switch (layer->growth_algo) {
	case GROWTH_ALGO_BIG_LITTLE: {
		if (!taskc->layered_mask || !big_cpumask)
			goto out_put;

		bpf_cpumask_and(tmp_cpumask, cast_mask(taskc->layered_mask),
				cast_mask(big_cpumask));
		cpu = pick_idle_cpu_from(cast_mask(tmp_cpumask),
					 prev_cpu, idle_smtmask);
		goto out_put;
	}
	case GROWTH_ALGO_LITTLE_BIG: {
		bpf_cpumask_setall(tmp_cpumask);
		if (!tmp_cpumask || !big_cpumask)
			goto out_put;
		bpf_cpumask_xor(tmp_cpumask, cast_mask(big_cpumask),
				cast_mask(tmp_cpumask));
		if (!tmp_cpumask || !taskc->layered_mask)
			goto out_put;
		bpf_cpumask_and(tmp_cpumask, cast_mask(taskc->layered_mask),
				cast_mask(tmp_cpumask));
		cpu = pick_idle_cpu_from(cast_mask(tmp_cpumask),
					 prev_cpu, idle_smtmask);
		goto out_put;
	}
	default:
		goto out_put;
	}

out_put:
	bpf_cpumask_release(tmp_cpumask);
	return cpu;
}

static __always_inline
s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu,
		  struct cpu_ctx *cpuc, struct task_ctx *taskc, struct layer *layer,
		  bool from_selcpu)
{
	const struct cpumask *idle_smtmask, *layer_cpumask, *layered_cpumask, *cpumask;
	struct cpu_ctx *prev_cpuc;
	u32 layer_id = layer->id;
	u64 cpus_seq;
	s32 cpu;

	if (layer_id >= MAX_LAYERS || !(layer_cpumask = lookup_layer_cpumask(layer_id)))
		return -1;

	/* not much to do if bound to a single CPU */
	if (p->nr_cpus_allowed == 1 && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		if (layer->kind == LAYER_KIND_CONFINED &&
		    !bpf_cpumask_test_cpu(prev_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cpuc);
		return prev_cpu;
	}

	cpus_seq = READ_ONCE(layers->cpus_seq);

	/*
	 * If @p prefers to preempt @prev_cpu than finding an idle CPU and
	 * @prev_cpu is preemptible, tell the enqueue path to try to preempt
	 * @prev_cpu. The enqueue path will also retry to find an idle CPU if
	 * the preemption attempt fails.
	 */
	maybe_refresh_layered_cpus(p, taskc, layer_cpumask, cpus_seq);
	if (!(layered_cpumask = cast_mask(taskc->layered_mask)))
		return -1;
	if (from_selcpu && should_try_preempt_first(prev_cpu, layer, layered_cpumask)) {
		cpuc->try_preempt_first = true;
		return -1;
	}

	/*
	 * When a layer stays saturated, there's no point in repeatedly
	 * searching for an idle CPU at different levels. Short-circuit by
	 * testing whether there are any eligible CPUs first.
	 */
	if (READ_ONCE(layer->check_no_idle)) {
		bool has_idle;

		cpumask = scx_bpf_get_idle_cpumask();

		if (layer->kind == LAYER_KIND_CONFINED)
			has_idle = bpf_cpumask_intersects(layered_cpumask, cpumask);
		else
			has_idle = bpf_cpumask_intersects(p->cpus_ptr, cpumask);

		scx_bpf_put_idle_cpumask(cpumask);
		if (!has_idle)
			return -1;
	}

	if ((nr_llcs > 1 || nr_nodes > 1) &&
	    !(prev_cpuc = lookup_cpu_ctx(prev_cpu)))
		return -1;
	if (!(idle_smtmask = scx_bpf_get_idle_smtmask()))
		return -1;

	/*
	 * If the system has a big/little architecture and uses any related
	 * layer growth algos try to find a cpu in that topology first.
	 */
	cpu = pick_idle_big_little(layer, taskc, idle_smtmask, prev_cpu);
	if (cpu >=0)
		goto out_put;

	/*
	 * Try a CPU in the current LLC
	 */
	if (nr_llcs > 1) {
		struct llc_ctx *prev_llcc;

		maybe_refresh_layered_cpus_llc(p, taskc, layer_cpumask,
					       prev_cpuc->llc_id, cpus_seq);
		if (!(cpumask = cast_mask(taskc->layered_llc_mask))) {
			cpu = -1;
			goto out_put;
		}
		if ((cpu = pick_idle_cpu_from(cpumask, prev_cpu, idle_smtmask)) >= 0)
			goto out_put;

		if (!(prev_llcc = lookup_llc_ctx(prev_cpuc->llc_id)) ||
		    prev_llcc->queued_runtime[layer_id] <= layer->xllc_mig_min_ns) {
			lstat_inc(LSTAT_XLLC_MIGRATION_SKIP, layer, cpuc);
			cpu = -1;
			goto out_put;
		}
	}

	/*
	 * Next try a CPU in the current node
	 */
	if (nr_nodes > 1) {
		maybe_refresh_layered_cpus_node(p, taskc, layer_cpumask,
						prev_cpuc->node_id, cpus_seq);
		if (!(cpumask = cast_mask(taskc->layered_node_mask))) {
			cpu = -1;
			goto out_put;
		}
		if ((cpu = pick_idle_cpu_from(cpumask, prev_cpu, idle_smtmask)) >= 0)
			goto out_put;
	}

	if ((cpu = pick_idle_cpu_from(layered_cpumask, prev_cpu, idle_smtmask)) >= 0)
		goto out_put;

	/*
	 * If the layer is an open one, we can try the whole machine.
	 */
	if (layer->kind != LAYER_KIND_CONFINED &&
	    ((cpu = pick_idle_cpu_from(p->cpus_ptr, prev_cpu, idle_smtmask) >= 0))) {
		lstat_inc(LSTAT_OPEN_IDLE, layer, cpuc);
		goto out_put;
	}

	cpu = -1;

out_put:
	/*
	 * Update check_no_idle. Cleared if any idle CPU is found. Set if no
	 * idle CPU is found for a task without affinity restriction. Use
	 * READ/WRITE_ONCE() dance to avoid unnecessarily write-claiming the
	 * cacheline.
	 */
	if (cpu >= 0) {
		if (READ_ONCE(layer->check_no_idle))
			WRITE_ONCE(layer->check_no_idle, false);
	} else if (taskc->all_cpus_allowed) {
		if (!READ_ONCE(layer->check_no_idle))
			WRITE_ONCE(layer->check_no_idle, true);
	}

	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;
}

static __always_inline
bool maybe_update_task_llc(struct task_struct *p, struct task_ctx *taskc, s32 new_cpu)
{
	u32 new_llc_id = cpu_to_llc_id(new_cpu);
	struct llc_ctx *prev_llcc, *new_llcc;
	u32 layer_id;
	s64 vtime_delta;

	if (taskc->llc_id == new_llc_id)
		return false;

	layer_id = taskc->layer_id;

	if (layer_id >= MAX_LAYERS ||
	    !(prev_llcc = lookup_llc_ctx(taskc->llc_id)) ||
	    !(new_llcc = lookup_llc_ctx(new_llc_id)))
		return false;

	vtime_delta = p->scx.dsq_vtime - prev_llcc->vtime_now[layer_id];
	p->scx.dsq_vtime = new_llcc->vtime_now[layer_id] + vtime_delta;

	taskc->llc_id = new_llc_id;
	return true;
}

s32 BPF_STRUCT_OPS(layered_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	struct layer *layer;
	s32 cpu;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	/*
	 * We usually update the layer in layered_runnable() to avoid confusion.
	 * As layered_select_cpu() takes place before runnable, new tasks would
	 * still have MAX_LAYERS layer. Just return @prev_cpu.
	 */
	if (taskc->layer_id == MAX_LAYERS || !(layer = lookup_layer(taskc->layer_id)))
		return prev_cpu;

	cpu = pick_idle_cpu(p, prev_cpu, cpuc, taskc, layer, true);

	if (cpu >= 0) {
		lstat_inc(LSTAT_SEL_LOCAL, layer, cpuc);
		u64 slice_ns = layer_slice_ns(layer);
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, 0);
		return cpu;
	} else {
		return prev_cpu;
	}
}

static __always_inline
bool pick_idle_cpu_and_kick(struct task_struct *p, s32 task_cpu,
			    struct cpu_ctx *cpuc, struct task_ctx *taskc,
			    struct layer *layer)
{
	s32 cpu;

	cpu = pick_idle_cpu(p, task_cpu, cpuc, taskc, layer, false);

	if (cpu >= 0) {
		lstat_inc(LSTAT_KICK, layer, cpuc);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return true;
	} else {
		return false;
	}
}

static __always_inline
bool try_preempt_cpu(s32 cand, struct task_struct *p, struct cpu_ctx *cpuc,
		     struct task_ctx *taskc, struct layer *layer,
		     bool preempt_first)
{
	struct cpu_ctx *cand_cpuc, *sib_cpuc = NULL;
	s32 sib;

	if (cand >= nr_possible_cpus || !bpf_cpumask_test_cpu(cand, p->cpus_ptr))
		return false;

	if (!(cand_cpuc = lookup_cpu_ctx(cand)) || cand_cpuc->current_preempt ||
	    (cand_cpuc->protect_owned && cand_cpuc->running_owned))
		return false;

	/*
	 * If exclusive, we want to make sure the sibling CPU, if there's
	 * one, is idle. However, if the sibling CPU is already running a
	 * preempt task, we shouldn't kick it out.
	 */
	if (layer->exclusive && (sib = sibling_cpu(cand)) >= 0 &&
	    (!(sib_cpuc = lookup_cpu_ctx(sib)) || sib_cpuc->current_preempt)) {
		lstat_inc(LSTAT_EXCL_COLLISION, layer, cpuc);
		return false;
	}

	scx_bpf_kick_cpu(cand, SCX_KICK_PREEMPT);

	/*
	 * $sib_cpuc is set if @p is an exclusive task, a sibling CPU
	 * exists which is not running a preempt task. Let's preempt the
	 * sibling CPU so that it can become idle. The ->maybe_idle test is
	 * inaccurate and racy but should be good enough for best-effort
	 * optimization.
	 */
	if (sib_cpuc && !sib_cpuc->maybe_idle) {
		lstat_inc(LSTAT_EXCL_PREEMPT, layer, cpuc);
		scx_bpf_kick_cpu(sib, SCX_KICK_PREEMPT);
	}

	if (!cand_cpuc->maybe_idle) {
		lstat_inc(LSTAT_PREEMPT, layer, cpuc);
		if (preempt_first)
			lstat_inc(LSTAT_PREEMPT_FIRST, layer, cpuc);
	} else {
		lstat_inc(LSTAT_PREEMPT_IDLE, layer, cpuc);
	}
	return true;
}

static __always_inline
void try_preempt(s32 task_cpu, struct task_struct *p, struct task_ctx *taskc,
		 bool preempt_first, u64 enq_flags)
{
	struct cpu_ctx *cpuc, *task_cpuc;
	struct layer *layer;
	struct cpu_prox_map *pmap;
	s32 i;

	if (!(layer = lookup_layer(taskc->layer_id)) ||
	    !(cpuc = lookup_cpu_ctx(-1)) ||
	    !(task_cpuc = lookup_cpu_ctx(task_cpu)))
		return;

	if (preempt_first) {
		/*
		 * @p prefers to preempt its previous CPU even when there are
		 * other idle CPUs.
		 */
		if (try_preempt_cpu(task_cpu, p, cpuc, taskc, layer, true))
			return;
		/* we skipped idle CPU picking in select_cpu. Do it here. */
		if (pick_idle_cpu_and_kick(p, task_cpu, cpuc, taskc, layer))
			return;
	} else {
		/*
		 * If we aren't in the wakeup path, layered_select_cpu() hasn't
		 * run and thus we haven't looked for and kicked an idle CPU.
		 * Let's do it now.
		 */
		if (!(enq_flags & SCX_ENQ_WAKEUP) &&
		    pick_idle_cpu_and_kick(p, task_cpu, cpuc, taskc, layer))
			return;
		if (!layer->preempt)
			return;
		if (try_preempt_cpu(task_cpu, p, cpuc, taskc, layer, false))
			return;
	}

	pmap = &task_cpuc->prox_map;

	bpf_for(i, 1, MAX_CPUS) {
		if (i >= pmap->sys_end)
			break;
		u16 *cpu_p = MEMBER_VPTR(pmap->cpus, [i]);
		if (cpu_p && try_preempt_cpu(*cpu_p, p, cpuc, taskc, layer, false))
			return;
	}

	lstat_inc(LSTAT_PREEMPT_FAIL, layer, cpuc);
}

void BPF_STRUCT_OPS(layered_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc, *task_cpuc;
	struct task_ctx *taskc;
	struct llc_ctx *llcc;
	struct layer *layer;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u64 vtime = p->scx.dsq_vtime;
	u32 layer_id;
	bool try_preempt_first;
	u64 queued_runtime;
	u64 *lstats;

	if (!(cpuc = lookup_cpu_ctx(-1)) ||
	    !(task_cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(taskc = lookup_task_ctx(p)) ||
	    !(llcc = lookup_llc_ctx(task_cpuc->llc_id)))
		return;

	layer_id = taskc->layer_id;

	if (!(layer = lookup_layer(layer_id)))
		return;

	try_preempt_first = cpuc->try_preempt_first;
	cpuc->try_preempt_first = false;
	u64 slice_ns = layer_slice_ns(layer);

	if (cpuc->yielding) {
		lstat_inc(LSTAT_YIELD, layer, cpuc);
		cpuc->yielding = false;
	}

	if (enq_flags & SCX_ENQ_REENQ) {
		lstat_inc(LSTAT_ENQ_REENQ, layer, cpuc);
	} else {
		if (enq_flags & SCX_ENQ_WAKEUP)
			lstat_inc(LSTAT_ENQ_WAKEUP, layer, cpuc);
		else
			lstat_inc(LSTAT_ENQ_EXPIRE, layer, cpuc);
	}

	/*
	 * Limit the amount of budget that an idling task can accumulate
	 * to one slice.
	 */
	maybe_update_task_llc(p, taskc, task_cpu);
	if (vtime_before(vtime, llcc->vtime_now[layer_id] - slice_ns))
		vtime = llcc->vtime_now[layer_id] - slice_ns;

	/*
	 * Special-case per-cpu kthreads and scx_layered userspace so that they
	 * run before preempting layers. This is to guarantee timely execution
	 * of layered userspace code and give boost to per-cpu kthreads as they
	 * are usually important for system performance and responsiveness.
	 */
	if (((p->flags & PF_KTHREAD) && p->nr_cpus_allowed < nr_possible_cpus) ||
	    p->tgid == layered_tgid) {
		struct cpumask *layer_cpumask;

		if (layer->kind == LAYER_KIND_CONFINED &&
		    (layer_cpumask = lookup_layer_cpumask(taskc->layer_id)) &&
		    !bpf_cpumask_test_cpu(task_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cpuc);

		scx_bpf_dispatch(p, task_cpuc->hi_fallback_dsq_id, slice_ns, enq_flags);
		goto preempt;
	}

	/*
	 * As an open or grouped layer is consumed from all CPUs, a task which
	 * belongs to such a layer can be safely put in the layer's DSQ
	 * regardless of its cpumask. However, a task with custom cpumask in a
	 * confined layer may fail to be consumed for an indefinite amount of
	 * time. Queue them to the fallback DSQ.
	 */
	if (layer->kind == LAYER_KIND_CONFINED && !taskc->all_cpus_allowed) {
		lstat_inc(LSTAT_AFFN_VIOL, layer, cpuc);
		/*
		 * We were previously dispatching to LO_FALLBACK_DSQ for any
		 * affinitized, non-PCPU kthreads, but found that starvation
		 * became an issue when the system was under heavy load.
		 *
		 * Longer term, we can address this by implementing layer
		 * weights and applying that to fallback DSQs to avoid
		 * starvation. For now, we just dispatch all affinitized tasks
		 * to the LLC local HI_FALLBACK_DSQ to avoid this starvation
		 * issue.
		 */
		scx_bpf_dispatch(p, task_cpuc->hi_fallback_dsq_id, slice_ns, enq_flags);
		goto preempt;
	}

	/*
	 * A task can be enqueued more than once before going through
	 * ops.running() if the task's property changes which dequeues and
	 * re-enqueues the task. The task does not go through ops.runnable()
	 * again in such cases, so layer association would remain the same.
	 *
	 * It'd be nice if ops.dequeue() could be used to adjust queued_runtime
	 * but ops.dequeue() is not called for tasks on a DSQ. Detect the
	 * condition here and subtract the previous contribution.
	 */
	if (taskc->qrt_llc_id < MAX_LLCS) {
		struct llc_ctx *prev_llcc;

		if (!(prev_llcc = lookup_llc_ctx(taskc->qrt_llc_id)))
			return;
		__sync_fetch_and_sub(&prev_llcc->queued_runtime[layer_id], taskc->runtime_avg);
	}

	taskc->qrt_llc_id = task_cpuc->llc_id;
	queued_runtime = __sync_fetch_and_add(&llcc->queued_runtime[layer_id],
					      taskc->runtime_avg);
	queued_runtime += taskc->runtime_avg;

	lstats = llcc->lstats[layer_id];

	// racy, don't care
	lstats[LLC_LSTAT_LAT] =
		((LAYER_LAT_DECAY_FACTOR - 1) * lstats[LLC_LSTAT_LAT] + queued_runtime) /
		LAYER_LAT_DECAY_FACTOR;
	lstats[LLC_LSTAT_CNT]++;

	scx_bpf_dispatch_vtime(p, layer_dsq_id(layer_id, task_cpuc->llc_id),
			       slice_ns, vtime, enq_flags);

preempt:
	try_preempt(task_cpu, p, taskc, try_preempt_first, enq_flags);
}

static bool keep_running(struct cpu_ctx *cpuc, struct task_struct *p)
{
	struct task_ctx *taskc;
	struct layer *layer;

	if (cpuc->yielding || !max_exec_ns)
		return false;

	/* does it wanna? */
	if (!(p->scx.flags & SCX_TASK_QUEUED))
		goto no;

	if (!(taskc = lookup_task_ctx(p)) || !(layer = lookup_layer(taskc->layer_id)))
		goto no;

	u64 slice_ns = layer_slice_ns(layer);
	/* @p has fully consumed its slice and still wants to run */
	cpuc->ran_current_for += slice_ns;

	/*
	 * There wasn't anything in the local or global DSQ, but there may be
	 * tasks which are affine to this CPU in some other DSQs. Let's not run
	 * for too long.
	 */
	if (cpuc->ran_current_for > max_exec_ns) {
		lstat_inc(LSTAT_KEEP_FAIL_MAX_EXEC, layer, cpuc);
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
		u32 dsq_id = layer_dsq_id(layer->id, cpuc->llc_id);
		if (!scx_bpf_dsq_nr_queued(dsq_id)) {
			p->scx.slice = slice_ns;
			lstat_inc(LSTAT_KEEP, layer, cpuc);
			return true;
		}
	} else {
		const struct cpumask *idle_cpumask = scx_bpf_get_idle_cpumask();
		bool has_idle = false;

		/*
		 * If @p is in an open layer, keep running if there's any idle
		 * CPU. If confined, keep running if and only if the layer has
		 * idle CPUs.
		 */
		if (layer->kind != LAYER_KIND_CONFINED) {
			has_idle = !bpf_cpumask_empty(idle_cpumask);
		} else {
			struct cpumask *layer_cpumask;

			if ((layer_cpumask = lookup_layer_cpumask(layer->id)))
				has_idle = bpf_cpumask_intersects(idle_cpumask,
								  layer_cpumask);
		}

		scx_bpf_put_idle_cpumask(idle_cpumask);

		if (has_idle) {
			p->scx.slice = slice_ns;
			lstat_inc(LSTAT_KEEP, layer, cpuc);
			return true;
		}
	}

	lstat_inc(LSTAT_KEEP_FAIL_BUSY, layer, cpuc);
no:
	cpuc->ran_current_for = 0;
	return false;
}

/* Mapping of cpu to most delayed DSQ it can consume */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} antistall_cpu_dsq SEC(".maps");

/* Mapping cpu to delay of highest delayed DSQ it can consume */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} antistall_cpu_max_delay SEC(".maps");

/**
 * get_delay_sec() - get runnable_at delay of a task_struct in seconds.
 * @p: task_struct *p
 * @jiffies_now: time from which to measure delay, in jiffies.
 *
 * Return: runnable_at delay, if any exists, in seconds.
 */
int get_delay_sec(struct task_struct *p, u64 jiffies_now)
{
	u64 runnable_at, delta_secs;
	runnable_at = READ_ONCE(p->scx.runnable_at);

	if (vtime_before(runnable_at, jiffies_now)) {
		delta_secs = (jiffies_now - runnable_at) / CONFIG_HZ;
	} else {
		delta_secs = 0;
	}

	return delta_secs;
}

/**
 * antistall_consume() - consume delayed DSQ
 * @cpuc: cpu context
 *
 * This function consumes a delayed DSQ. This is meant to be called
 * from dispatch, before any other logic which could result in a
 * DSQ being consumed.
 *
 * This is meant to prevent issues such as DSQs with affinitized tasks
 * stalling when all CPUs which can process them are continually consuming
 * other DSQs.
 *
 * Return: bool indicating if a DSQ was consumed or not.
 */
bool antistall_consume(struct cpu_ctx *cpuc)
{
	u64 *antistall_dsq, jiffies_now, cur_delay;
	bool consumed;
	struct task_struct *p;

	cur_delay = 0;
	consumed = false;

	if (!enable_antistall || !cpuc)
		return false;

	antistall_dsq = bpf_map_lookup_elem(&antistall_cpu_dsq, &zero_u32);

	if (!antistall_dsq) {
		scx_bpf_error("cant happen");
		return false;
	}

	if (*antistall_dsq == SCX_DSQ_INVALID)
		return false;

	consumed = scx_bpf_consume(*antistall_dsq);

	if (!consumed)
		goto reset;

	jiffies_now = bpf_jiffies64();

	bpf_for_each(scx_dsq, p, *antistall_dsq, 0) {
		cur_delay = get_delay_sec(p, jiffies_now);

		if (cur_delay > antistall_sec)
			return consumed;

		goto reset;
	}

reset:
	trace("antistall reset DSQ[%llu] SELECTED_CPU[%llu] DELAY[%llu]",
	      *antistall_dsq, cpuc->cpu, cur_delay);
	*antistall_dsq = SCX_DSQ_INVALID;
	return consumed;
}

static __always_inline bool try_consume_layer(u32 layer_id, struct cpu_ctx *cpuc,
					      struct llc_ctx *llcc)
{
	struct llc_prox_map *llc_pmap = &llcc->prox_map;
	struct layer *layer;
	bool xllc_mig_skipped = false;
	u32 u;

	if (!(layer = lookup_layer(layer_id)))
		return false;

	bpf_for(u, 0, llc_pmap->sys_end) {
		u16 *llc_idp;

		if (!(llc_idp = MEMBER_VPTR(llc_pmap->llcs, [u]))) {
			scx_bpf_error("llc_pmap->sys_end=%u too big", llc_pmap->sys_end);
			return false;
		}

		if (u > 0) {
			struct llc_ctx *remote_llcc;

			if (!(remote_llcc = lookup_llc_ctx(*llc_idp)))
				return false;

			if (remote_llcc->queued_runtime[layer_id] <= layer->xllc_mig_min_ns) {
				xllc_mig_skipped = true;
				continue;
			}
		}

		if (scx_bpf_consume(layer_dsq_id(layer_id, *llc_idp)))
			return true;
	}

	if (xllc_mig_skipped)
		lstat_inc(LSTAT_XLLC_MIGRATION_SKIP, layer, cpuc);

	return false;
}

static __always_inline
bool try_consume_layers(u32 *layer_order, u32 nr, u32 exclude_layer_id,
			struct cpu_ctx *cpuc, struct llc_ctx *llcc)
{
	u32 u;

	if (nr >= MAX_LAYERS) {
		scx_bpf_error("nr=%u too high", nr);
		return false;
	}

	bpf_for(u, 0, nr) {
		u32 layer_id = layer_order[u];

		if (layer_id == exclude_layer_id)
			continue;

		if (try_consume_layer(layer_id, cpuc, llcc))
			return true;
	}

	return false;
}

void BPF_STRUCT_OPS(layered_dispatch, s32 cpu, struct task_struct *prev)
{
	struct layer *owner_layer = NULL;
	struct cpu_ctx *cpuc, *sib_cpuc;
	struct llc_ctx *llcc;
	bool tried_owner = false;
	s32 sib = sibling_cpu(cpu);

	if (!(cpuc = lookup_cpu_ctx(-1)))
		return;

	if (antistall_consume(cpuc))
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
	if (prev && keep_running(cpuc, prev))
		return;

	/*
	 * If the sibling CPU is running an exclusive task, keep this CPU idle.
	 * This test is a racy test but should be good enough for best-effort
	 * optimization.
	 */
	if (sib >= 0 && (sib_cpuc = lookup_cpu_ctx(sib)) &&
	    sib_cpuc->current_exclusive) {
		gstat_inc(GSTAT_EXCL_IDLE, cpuc);
		return;
	}

	if (!(llcc = lookup_llc_ctx(cpuc->llc_id)))
		return;

	if (cpuc->layer_id < MAX_LAYERS)
		owner_layer = &layers[cpuc->layer_id];

	/*
	 * Always consume hi_fallback_dsq_id first for kthreads. This ends up
	 * prioritizing tasks with custom affinities which will be solved by
	 * implementing starvation prevention for lo fallback and queueing them
	 * there.
	 */
	if (scx_bpf_consume(cpuc->hi_fallback_dsq_id))
		return;

	/*
	 * Prioritize empty layers on the fallback CPU. empty_layer_ids array
	 * can be resized asynchronously by userland. As unoccupied slots are
	 * filled with MAX_LAYERS, excluding IDs matching MAX_LAYERS makes it
	 * safe.
	 */
	if (cpuc->cpu == fallback_cpu &&
	    try_consume_layers(empty_layer_ids, nr_empty_layer_ids,
			       MAX_LAYERS, cpuc, llcc)) {
	}

	/* owner before preempt layers if protected or preempting */
	if (owner_layer && (cpuc->protect_owned || owner_layer->preempt)) {
		if (try_consume_layer(owner_layer->id, cpuc, llcc))
			return;
		tried_owner = true;
	}

	/* grouped/open preempt layers */
	if (try_consume_layers(cpuc->open_preempt_layer_order, nr_open_preempt_layers,
			       cpuc->layer_id, cpuc, llcc))
		return;

	/* try owner if not tried yet */
	if (owner_layer && !tried_owner &&
	    try_consume_layer(owner_layer->id, cpuc, llcc))
		return;

	/* grouped/open non-preempt layers */
	if (try_consume_layers(cpuc->open_layer_order, nr_open_layers,
			       cpuc->layer_id, cpuc, llcc))
		return;

	scx_bpf_consume(LO_FALLBACK_DSQ);
}

static __noinline bool match_one(struct layer_match *match,
				 struct task_struct *p, const char *cgrp_path)
{
	bool result = false;
	const struct cred *cred;

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
	case MATCH_USER_ID_EQUALS:
		bpf_rcu_read_lock();
		cred = p->real_cred;
		if (cred)
			result = cred->euid.val == match->user_id;
		bpf_rcu_read_unlock();
		return result;
	case MATCH_GROUP_ID_EQUALS:
		bpf_rcu_read_lock();
		cred = p->real_cred;
		if (cred)
			result = cred->egid.val == match->group_id;
		bpf_rcu_read_unlock();
		return result;
	case MATCH_PID_EQUALS:
		return p->pid == match->pid;
	case MATCH_PPID_EQUALS:
		return p->real_parent->pid == match->ppid;
	case MATCH_TGID_EQUALS:
		return p->tgid == match->tgid;
	default:
		scx_bpf_error("invalid match kind %d", match->kind);
		return result;
	}
}

int match_layer(u32 layer_id, pid_t pid, const char *cgrp_path)
{

	struct task_struct *p;
	struct layer *layer;
	u32 nr_match_ors;
	u64 or_id, and_id;

	p = bpf_task_from_pid(pid);
	if (!p)
		return -EINVAL;

	if (layer_id >= nr_layers)
		goto err;

	layer = &layers[layer_id];
	nr_match_ors = layer->nr_match_ors;

	if (nr_match_ors > MAX_LAYER_MATCH_ORS)
		goto err;

	bpf_for(or_id, 0, nr_match_ors) {
		struct layer_match_ands *ands;
		bool matched = true;

		barrier_var(or_id);
		if (or_id >= MAX_LAYER_MATCH_ORS)
			goto err;

		ands = &layer->matches[or_id];

		if (ands->nr_match_ands > NR_LAYER_MATCH_KINDS)
			goto err;

		bpf_for(and_id, 0, ands->nr_match_ands) {
			struct layer_match *match;

			barrier_var(and_id);
			if (and_id >= NR_LAYER_MATCH_KINDS)
				goto err;

			match = &ands->matches[and_id];
			if (!match_one(match, p, cgrp_path)) {
				matched = false;
				break;
			}
		}

		if (matched) {
			bpf_task_release(p);
			return 0;
		}
	}

	bpf_task_release(p);
	return -ENOENT;

err:
	bpf_task_release(p);
	return -EINVAL;
}

static void maybe_refresh_layer(struct task_struct *p, struct task_ctx *taskc)
{
	const char *cgrp_path;
	bool matched = false;
	u64 layer_id;	// XXX - int makes verifier unhappy
	pid_t pid = p->pid;

	if (!taskc->refresh_layer)
		return;
	taskc->refresh_layer = false;

	if (!(cgrp_path = format_cgrp_path(p->cgroups->dfl_cgrp)))
		return;

	if (taskc->layer_id >= 0 && taskc->layer_id < nr_layers)
		__sync_fetch_and_add(&layers[taskc->layer_id].nr_tasks, -1);

	bpf_for(layer_id, 0, nr_layers) {
		if (match_layer(layer_id, pid, cgrp_path) == 0) {
			matched = true;
			break;
		}
	}

	if (matched) {
		struct layer *layer = &layers[layer_id];
		struct cpu_ctx *cpuc;
		struct llc_ctx *llcc;

		if (!(cpuc = lookup_cpu_ctx(scx_bpf_task_cpu(p))) ||
		    !(llcc = lookup_llc_ctx(cpuc->llc_id)))
			return;

		taskc->layer_id = layer_id;
		taskc->llc_id = cpuc->llc_id;
		taskc->layered_cpus.seq = layer->cpus_seq - 1;
		taskc->layered_cpus_llc.seq = layer->cpus_seq - 1;
		taskc->layered_cpus_node.seq = layer->cpus_seq - 1;
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
		p->scx.dsq_vtime = llcc->vtime_now[layer_id];
	} else {
		scx_bpf_error("[%s]%d didn't match any layer", p->comm, p->pid);
	}

	if (taskc->layer_id < nr_layers - 1)
		trace("LAYER=%d %s[%d] cgrp=\"%s\"",
		      taskc->layer_id, p->comm, p->pid, cgrp_path);
}

static s32 create_save_cpumask(struct bpf_cpumask **kptr)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(kptr, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	return 0;
}

static s32 create_node(u32 node_id)
{
	u32 cpu;
	struct bpf_cpumask *cpumask;
	struct node_ctx *nodec;
	struct cpu_ctx *cpuc;
	s32 ret;

	if (!(nodec = lookup_node_ctx(node_id)))
		return -ENOENT;
	nodec->id = node_id;

	ret = create_save_cpumask(&nodec->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = nodec->cpumask;
	if (!cpumask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to lookup node cpumask");
		return -ENOENT;
	}

	bpf_for(cpu, 0, nr_possible_cpus) {
		const volatile u64 *nmask;

		nmask = MEMBER_VPTR(numa_cpumasks, [node_id][cpu / 64]);
		if (!nmask) {
			scx_bpf_error("array index error");
			ret = -ENOENT;
			break;
		}

		if (*nmask & (1LLU << (cpu % 64))) {
			bpf_cpumask_set_cpu(cpu, cpumask);
			if (!(cpuc = lookup_cpu_ctx(cpu))) {
				scx_bpf_error("cpu ctx error");
				ret = -ENOENT;
				break;
			}

			cpuc->node_id = node_id;
			nodec->nr_cpus++;
			nodec->llc_mask |= (1LLU << node_id);
		}
	}

	dbg("CFG creating node %d with %d cpus", node_id, nodec->nr_cpus);
	bpf_rcu_read_unlock();
	return ret;
}

static s32 create_llc(u32 llc_id)
{
	struct bpf_cpumask *cpumask;
	struct llc_ctx *llcc;
	struct cpu_ctx *cpuc;
	struct llc_prox_map *pmap;
	u32 cpu;
	s32 i, ret;

	if (!(llcc = lookup_llc_ctx(llc_id)))
		return -ENOENT;
	llcc->id = llc_id;

	ret = create_save_cpumask(&llcc->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = llcc->cpumask;
	if (!cpumask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to lookup node cpumask");
		return -ENOENT;
	}

	bpf_for(cpu, 0, nr_possible_cpus) {
		if (!(cpuc = lookup_cpu_ctx(cpu))) {
			bpf_rcu_read_unlock();
			scx_bpf_error("cpu ctx error");
			return -ENOENT;
		}

		if (cpu_to_llc_id(cpu) != llc_id)
			continue;

		bpf_cpumask_set_cpu(cpu, cpumask);
		llcc->nr_cpus++;
		cpuc->llc_id = llc_id;
		cpuc->hi_fallback_dsq_id = llc_hi_fallback_dsq_id(llc_id);
	}

	dbg("CFG creating llc %d with %d cpus", llc_id, llcc->nr_cpus);
	bpf_rcu_read_unlock();

	pmap = &llcc->prox_map;
	dbg("CFG: LLC[%d] prox_map node/sys=%d/%d",
	    llc_id, pmap->node_end, pmap->sys_end);
	if (pmap->sys_end > nr_possible_cpus || pmap->sys_end > MAX_CPUS) {
		scx_bpf_error("CPU %d  proximity map too long", cpu);
		return -EINVAL;
	}

	bpf_for(i, 0, pmap->sys_end) {
		u16 *p = MEMBER_VPTR(pmap->llcs, [i]);
		if (p)
			dbg("CFG: LLC[%d] prox[%d]=%d", cpu, i, *p);
	}
	return ret;
}

static __always_inline
void on_wakeup(struct task_struct *p, struct task_ctx *taskc)
{
	struct cpu_ctx *cpuc;
	struct layer *layer;
	struct task_ctx *waker_taskc;
	struct task_struct *waker;

	if (!(cpuc = lookup_cpu_ctx(-1)) ||
	    !(layer = lookup_layer(taskc->layer_id)))
		return;

	if (!(waker = bpf_get_current_task_btf()) ||
	    !(waker_taskc = lookup_task_ctx_may_fail(waker)))
		return;

	// TODO: add handling for per layer wakers
	if (taskc->layer_id == waker_taskc->layer_id)
		return;

	if (taskc->last_waker == waker->pid)
		lstat_inc(LSTAT_XLAYER_REWAKE, layer, cpuc);

	taskc->last_waker = waker->pid;
	lstat_inc(LSTAT_XLAYER_WAKE, layer, cpuc);
}


void BPF_STRUCT_OPS(layered_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;
	u64 now = bpf_ktime_get_ns();

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->runnable_at = now;
	maybe_refresh_layer(p, taskc);

	if (enq_flags & SCX_ENQ_WAKEUP)
		on_wakeup(p, taskc);
}

void BPF_STRUCT_OPS(layered_running, struct task_struct *p)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	struct layer *layer;
	struct node_ctx *nodec;
	struct llc_ctx *llcc;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u64 now = bpf_ktime_get_ns();
	u32 layer_id;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(llcc = lookup_llc_ctx(cpuc->llc_id)) ||
	    !(taskc = lookup_task_ctx(p)))
		return;

	layer_id = taskc->layer_id;
	if (!(layer = lookup_layer(layer_id)))
		return;

	if (taskc->qrt_llc_id < MAX_LLCS) {
		struct llc_ctx *prev_llcc;

		if (!(prev_llcc = lookup_llc_ctx(taskc->qrt_llc_id)))
			return;

		__sync_fetch_and_sub(&prev_llcc->queued_runtime[layer_id], taskc->runtime_avg);
		taskc->qrt_llc_id = MAX_LLCS;
	}

	if (taskc->last_cpu >= 0 && taskc->last_cpu != task_cpu) {
		lstat_inc(LSTAT_MIGRATION, layer, cpuc);
		if (!(nodec = lookup_node_ctx(cpuc->node_id)))
			return;
		if (nodec->cpumask &&
		    !bpf_cpumask_test_cpu(taskc->last_cpu, cast_mask(nodec->cpumask)))
			lstat_inc(LSTAT_XNUMA_MIGRATION, layer, cpuc);
		if (llcc->cpumask &&
		    !bpf_cpumask_test_cpu(taskc->last_cpu, cast_mask(llcc->cpumask)))
			lstat_inc(LSTAT_XLLC_MIGRATION, layer, cpuc);
	}
	taskc->last_cpu = task_cpu;

	maybe_update_task_llc(p, taskc, task_cpu);
	if (vtime_before(llcc->vtime_now[layer_id], p->scx.dsq_vtime))
		llcc->vtime_now[layer_id] = p->scx.dsq_vtime;

	cpuc->current_preempt = layer->preempt;
	cpuc->current_exclusive = layer->exclusive;
	cpuc->task_layer_id = taskc->layer_id;
	cpuc->running_at = now;
	taskc->running_at = now;

	/*
	 * A CPU is running an owned task if the task is on the layer owning the
	 * CPU or the CPU is the fallback and the layer is empty.
	 */
	cpuc->running_owned = taskc->layer_id == cpuc->layer_id ||
		(cpuc->cpu == fallback_cpu && !layer->nr_cpus);

	/*
	 * If this CPU is transitioning from running an exclusive task to a
	 * non-exclusive one, the sibling CPU has likely been idle. Wake it up.
	 */
	if (cpuc->prev_exclusive && !cpuc->current_exclusive) {
		s32 sib = sibling_cpu(task_cpu);
		struct cpu_ctx *sib_cpuc;

		/*
		 * %SCX_KICK_IDLE would be great here but we want to support
		 * older kernels. Let's use racy and inaccruate custom idle flag
		 * instead.
		 */
		if (sib >= 0 && (sib_cpuc = lookup_cpu_ctx(sib)) &&
		    sib_cpuc->maybe_idle) {
			gstat_inc(GSTAT_EXCL_WAKEUP, cpuc);
			scx_bpf_kick_cpu(sib, 0);
		}
	}

	if (layer->perf > 0 && cpuc->perf != layer->perf) {
		scx_bpf_cpuperf_set(task_cpu, layer->perf);
		cpuc->perf = layer->perf;
	}

	cpuc->maybe_idle = false;
}

void BPF_STRUCT_OPS(layered_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	struct layer *task_layer, *cpu_layer = NULL;
	u64 now = bpf_ktime_get_ns();
	bool is_fallback;
	s32 task_lid, target_ppk;
	u64 used, cpu_slice;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(p)))
		return;
	is_fallback = cpuc->cpu == fallback_cpu;

	task_lid = taskc->layer_id;
	if (!(task_layer = lookup_layer(task_lid)))
		return;

	if (cpuc->layer_id != MAX_LAYERS &&
	    !(cpu_layer = lookup_layer(cpuc->layer_id)))
		return;

	used = now - taskc->running_at;

	taskc->runtime_avg =
		((RUNTIME_DECAY_FACTOR - 1) * taskc->runtime_avg + used) /
		RUNTIME_DECAY_FACTOR;

	if (cpuc->running_owned) {
		cpuc->layer_usages[task_lid][LAYER_USAGE_OWNED] += used;
		if (cpuc->protect_owned)
			cpuc->layer_usages[task_lid][LAYER_USAGE_PROTECTED] += used;
		cpuc->owned_usage += used;
	} else {
		cpuc->layer_usages[task_lid][LAYER_USAGE_OPEN] += used;
		cpuc->open_usage += used;
	}

	/*
	 * Owned execution protection.
	 */
	if (cpu_layer) {
		target_ppk = cpu_layer->owned_usage_target_ppk;
		cpu_slice = layer_slice_ns(cpu_layer);
	} else {
		target_ppk = 0;
		cpu_slice = slice_ns;
	}

	/*
	 * For the fallback CPU, execution for layers without any CPU counts as
	 * owned. Guarantee that at least half of the fallback CPU is used for
	 * empty execution so that empty layers can easily ramp up even when
	 * there are saturating preempt layers. Note that a fallback DSQ may
	 * belong to a layer under saturation. In such cases, tasks from both
	 * the owner and empty layers would count as owned with empty layers
	 * being prioritized.
	 */
	if (is_fallback && target_ppk < 512)
		target_ppk = 512;

	/*
	 * Apply owned protection iff the CPU stayed saturated for longer than
	 * twice the default slice.
	 */
	if (target_ppk &&
	    (cpuc->owned_usage + cpuc->open_usage) - cpuc->usage_at_idle > 2 * cpu_slice) {
		u64 owned = cpuc->owned_usage - cpuc->prev_owned_usage[0];
		u64 open = cpuc->open_usage - cpuc->prev_open_usage[0];

		cpuc->protect_owned = 1024 * owned / (owned + open) <= target_ppk;
	} else {
		cpuc->protect_owned = false;
	}

	cpuc->current_preempt = false;
	cpuc->prev_exclusive = cpuc->current_exclusive;
	cpuc->current_exclusive = false;
	cpuc->task_layer_id = MAX_LAYERS;

	/*
	 * Apply min_exec_us, scale the execution time by the inverse of the
	 * weight and charge.
	 */
	if (used < task_layer->min_exec_ns) {
		lstat_inc(LSTAT_MIN_EXEC, task_layer, cpuc);
		lstat_add(LSTAT_MIN_EXEC_NS, task_layer, cpuc, task_layer->min_exec_ns - used);
		used = task_layer->min_exec_ns;
	}

	if (cpuc->yielding && used < slice_ns)
		used = slice_ns;
	p->scx.dsq_vtime += used * 100 / p->scx.weight;
	cpuc->maybe_idle = true;
}

bool BPF_STRUCT_OPS(layered_yield, struct task_struct *from, struct task_struct *to)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;
	struct layer *layer;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(from)) ||
	    !(layer = lookup_layer(taskc->layer_id)))
		return false;

	/*
	 * Special-case 0 yield_step_ns. Yiedling is completely ignored and
	 * the task is eligible for keep_running().
	 */
	if (!layer->yield_step_ns) {
		lstat_inc(LSTAT_YIELD_IGNORE, layer, cpuc);
		return false;
	}

	if (from->scx.slice > layer->yield_step_ns) {
		from->scx.slice -= layer->yield_step_ns;
		lstat_inc(LSTAT_YIELD_IGNORE, layer, cpuc);
	} else {
		from->scx.slice = 0;
		cpuc->yielding = true;
	}

	return false;
}

void BPF_STRUCT_OPS(layered_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc;

	if ((taskc = lookup_task_ctx(p)))
		taskc->refresh_layer = true;
}

void BPF_STRUCT_OPS(layered_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		return;
	}

	taskc->all_cpus_allowed =
		bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);
}

void BPF_STRUCT_OPS(layered_update_idle, s32 cpu, bool idle)
{
	struct cpu_ctx *cpuc;

	if (!idle || !(cpuc = lookup_cpu_ctx(cpu)))
		return;

	cpuc->protect_owned = false;
	cpuc->usage_at_idle = cpuc->owned_usage + cpuc->open_usage;
}

void BPF_STRUCT_OPS(layered_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
}

static int init_cached_cpus(struct cached_cpus *ccpus)
{
	ccpus->id = -1;

	return 0;
}

s32 BPF_STRUCT_OPS(layered_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *taskc;
	struct bpf_cpumask *cpumask;
	s32 ret;

	/*
	 * XXX - We want BPF_NOEXIST but bpf_map_delete_elem() in .disable() may
	 * fail spuriously due to BPF recursion protection triggering
	 * unnecessarily.
	 */
	taskc = bpf_task_storage_get(&task_ctxs, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc) {
		scx_bpf_error("task_ctx allocation failure");
		return -ENOMEM;
	}

	// Layer setup
	ret = init_cached_cpus(&taskc->layered_cpus);
	if (ret)
		return ret;
	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&taskc->layered_mask, cpumask))) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	// LLC setup
	ret = init_cached_cpus(&taskc->layered_cpus_llc);
	if (ret)
		return ret;

	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&taskc->layered_llc_mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	// Node setup
	ret = init_cached_cpus(&taskc->layered_cpus_node);
	if (ret)
		return ret;

	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&taskc->layered_node_mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	taskc->pid = p->pid;
	taskc->last_cpu = -1;
	taskc->layer_id = MAX_LAYERS;
	taskc->refresh_layer = true;
	taskc->llc_id = MAX_LLCS;
	taskc->qrt_llc_id = MAX_LLCS;

	/*
	 * Start runtime_avg at some arbitrary sane-ish value. If this becomes a
	 * problem, we can track per-parent avg new task initial runtime avg and
	 * used that instead.
	 */
	taskc->runtime_avg = slice_ns / 4;

	if (all_cpumask)
		taskc->all_cpus_allowed =
			bpf_cpumask_subset(cast_mask(all_cpumask), p->cpus_ptr);
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
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;

	if (args->cancelled) {
		return;
	}

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(p)))
		return;

	if (taskc->layer_id < nr_layers)
		__sync_fetch_and_add(&layers[taskc->layer_id].nr_tasks, -1);
}

static u64 dsq_first_runnable_for_ms(u64 dsq_id, u64 now)
{
	struct task_struct *p;

	if (dsq_id > LO_FALLBACK_DSQ)
		return 0;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		struct task_ctx *taskc;

		if ((taskc = lookup_task_ctx(p)))
			return (now - taskc->runnable_at) / 1000000;
	}

	return 0;
}

static void dump_layer_cpumask(int id)
{
	struct cpumask *layer_cpumask;
	s32 cpu;
	char buf[128] = "", *p;

	if (!(layer_cpumask = lookup_layer_cpumask(id)))
		return;

	bpf_for(cpu, 0, scx_bpf_nr_cpu_ids()) {
		if (!(p = MEMBER_VPTR(buf, [id++])))
			break;
		if (bpf_cpumask_test_cpu(cpu, layer_cpumask))
			*p++ = '0' + cpu % 10;
		else
			*p++ = '.';

		if ((cpu & 7) == 7) {
			if (!(p = MEMBER_VPTR(buf, [id++])))
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
	u64 dsq_id;
	int i, j, id;
	struct layer *layer;

	scx_bpf_dump_header();

	bpf_for(i, 0, nr_layers) {
		layer = lookup_layer(i);
		if (!layer) {
			scx_bpf_error("unabled to lookup layer %d", i);
			continue;
		}

		bpf_for(j, 0, nr_llcs) {
			if (!(layer->llc_mask & (1 << j)))
				continue;

			id = layer_dsq_id(layer->id, j);
			scx_bpf_dump("LAYER[%d][%s]DSQ[%d] nr_cpus=%u nr_queued=%d -%llums cpus=",
				     i, layer->name, id, layer->nr_cpus,
				     scx_bpf_dsq_nr_queued(id),
				     dsq_first_runnable_for_ms(id, now));
			scx_bpf_dump("\n");
		}
		dump_layer_cpumask(i);
		scx_bpf_dump("\n");
	}
	bpf_for(i, 0, nr_llcs) {
		dsq_id = llc_hi_fallback_dsq_id(i);
		scx_bpf_dump("HI_FALLBACK[%llu] nr_queued=%d -%llums\n",
			     dsq_id, scx_bpf_dsq_nr_queued(dsq_id),
			     dsq_first_runnable_for_ms(dsq_id, now));
	}
	scx_bpf_dump("LO_FALLBACK nr_queued=%d -%llums\n",
		     scx_bpf_dsq_nr_queued(LO_FALLBACK_DSQ),
		     dsq_first_runnable_for_ms(LO_FALLBACK_DSQ, now));
}


/*
 * Timer related setup
 */

static bool layered_monitor(void)
{
	if (monitor_disable)
		return false;

	// TODO: implement monitor

	// always rerun the monitor
	return true;
}

/**
 * antistall_set() - set antistall flags.
 * @dsq_id: Dsq to check for delayed tasks.
 * @jiffies_now: Time to check against in jiffies.
 *
 * This function sets entries in antistall_cpu_dsq used by antistall.
 * It checks the given DSQ to see if delay exceeds antistall_sec.
 * It tries to find a CPU satisfying the constraints of "can run the first
 * task in the provided DSQ" and "is not already flagged for use in antistall".
 * If it cannot find such a CPU to flag, it will try to flag a CPU flagged to
 * process another with a lesser delay if one exists.
 */
u64 antistall_set(u64 dsq_id, u64 jiffies_now)
{
	struct task_struct *__p, *p = NULL;
	struct task_ctx *taskc;
	s32 cpu;
	u64 *antistall_dsq, *delay, cur_delay;
	int pass;

	if (!dsq_id || !jiffies_now)
		return 0;

	// verifier
	bpf_rcu_read_lock();
	bpf_for_each(scx_dsq, __p, dsq_id, 0) {
		/* XXX verifier workaround: drop the following block later */
		if (p)
			bpf_task_release(p);
		if (!(p = bpf_task_from_pid(__p->pid)))
			continue;

		if (!(taskc = lookup_task_ctx(p)))
			goto unlock;

		cur_delay = get_delay_sec(p, jiffies_now);
		if (cur_delay <= antistall_sec)
			// check head task in dsq
			goto unlock;

		#pragma unroll
		for (pass = 0; pass < 2; ++pass) bpf_for(cpu, 0, nr_possible_cpus) {
			const struct cpumask *cpumask;

			if (!(cpumask = cast_mask(taskc->layered_mask)))
				goto unlock;

			/* for affinity violating tasks, target all allowed CPUs */
			if (bpf_cpumask_empty(cpumask))
				cpumask = p->cpus_ptr;

			if (!bpf_cpumask_test_cpu(cpu, cpumask))
				continue;

			antistall_dsq = bpf_map_lookup_percpu_elem(&antistall_cpu_dsq, &zero_u32, cpu);
			delay = bpf_map_lookup_percpu_elem(&antistall_cpu_max_delay, &zero_u32, cpu);

			if (!antistall_dsq || !delay) {
				scx_bpf_error("cant happen");
				goto unlock;
			}

			if ((pass == 0 && *antistall_dsq == SCX_DSQ_INVALID) ||
			    (pass != 0 && *delay < cur_delay)) {
				trace("antistall set DSQ[%llu] SELECTED_CPU[%llu] DELAY[%llu]", dsq_id, cpu, cur_delay);
				*delay = cur_delay;
				*antistall_dsq = dsq_id;
				goto unlock;
			}
		}

		goto unlock;
	}

unlock:
	if (p)
		bpf_task_release(p);
	bpf_rcu_read_unlock();
	return 0;
}

/**
 * antistall_scan() - call antistall_set on all DSQs.
 *
 * This function calls antistall_set on all DSQs.
 * This is where antistall figures out what work, if any, needs
 * to be prioritized to keep runnable_at delay at or below antistall_sec.
 */
static bool antistall_scan(void)
{
	s32 llc;
	u64 layer_id;
	u64 jiffies_now;

	if (!enable_antistall)
		return true;

	jiffies_now = bpf_jiffies64();

	bpf_for(layer_id, 0, nr_layers)
		bpf_for(llc, 0, nr_llcs)
			antistall_set(layer_dsq_id(layer_id, llc), jiffies_now);

	bpf_for(llc, 0, nr_llcs)
		antistall_set(llc_hi_fallback_dsq_id(llc), jiffies_now);

	antistall_set(LO_FALLBACK_DSQ, jiffies_now);

	antistall_set(HI_FALLBACK_DSQ_BASE, jiffies_now);

	return true;
}

static bool run_timer_cb(int key)
{
	switch (key) {
	case LAYERED_MONITOR:
		return layered_monitor();
	case ANTISTALL_TIMER:
		return antistall_scan();
	case NOOP_TIMER:
	case MAX_TIMERS:
	default:
		return false;
	}
}

struct layered_timer layered_timers[MAX_TIMERS] = {
	{15LLU * NSEC_PER_SEC, CLOCK_BOOTTIME, 0},
	{1LLU * NSEC_PER_SEC, CLOCK_BOOTTIME, 0},
	{0LLU, CLOCK_BOOTTIME, 0},
};

// TODO: separate this out to a separate compilation unit
#include "timer.bpf.c"

/*
 * Initializes per-layer specific data structures.
 */
static s32 init_layer(int layer_id, u64 *fallback_dsq_id)
{
	struct bpf_cpumask *cpumask;
	struct layer_cpumask_wrapper *cpumaskw;
	struct layer *layer = &layers[layer_id];
	int i, j, ret;

	dbg("CFG LAYER[%d][%s] min_exec_ns=%lu open=%d preempt=%d exclusive=%d",
	    layer_id, layer->name, layer->min_exec_ns,
	    layer->kind != LAYER_KIND_CONFINED,
	    layer->preempt, layer->exclusive);

	layer->id = layer_id;

	if (layer->nr_match_ors > MAX_LAYER_MATCH_ORS) {
		scx_bpf_error("too many ORs");
		return -EINVAL;
	}

	bpf_for(i, 0, layer->nr_match_ors) {
		struct layer_match_ands *ands = MEMBER_VPTR(layers, [layer_id].matches[i]);
		if (!ands) {
			scx_bpf_error("shouldn't happen");
			return -EINVAL;
		}

		if (ands->nr_match_ands > NR_LAYER_MATCH_KINDS) {
			scx_bpf_error("too many ANDs");
			return -EINVAL;
		}

		dbg("CFG   OR[%02d]", i);

		bpf_for(j, 0, ands->nr_match_ands) {
			char header[32];
			u64 header_data[1] = { j };
			struct layer_match *match;

			bpf_snprintf(header, sizeof(header), "CFG     AND[%02d]:",
				     header_data, sizeof(header_data));

			match = MEMBER_VPTR(layers, [layer_id].matches[i].matches[j]);
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
			case MATCH_USER_ID_EQUALS:
				dbg("%s USER_ID %u", header, match->user_id);
				break;
			case MATCH_GROUP_ID_EQUALS:
				dbg("%s GROUP_ID %u", header, match->group_id);
				break;
			case MATCH_PID_EQUALS:
				dbg("%s PID %u", header, match->pid);
				break;
			case MATCH_PPID_EQUALS:
				dbg("%s PPID %u", header, match->ppid);
				break;
			case MATCH_TGID_EQUALS:
				dbg("%s TGID %u", header, match->tgid);
				break;
			default:
				scx_bpf_error("%s Invalid kind", header);
				return -EINVAL;
			}
		}
		if (ands->nr_match_ands == 0)
			dbg("CFG     DEFAULT");
	}

	if (!(cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &layer_id)))
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

	// create the dsqs for the layer
	bpf_for(i, 0, nr_llcs) {
		int node_id = llc_node_id(i);
		dbg("CFG creating dsq %llu for layer %d %s on node %d in llc %d",
		    *fallback_dsq_id, layer_id, layer->name, node_id, i);
		ret = scx_bpf_create_dsq(*fallback_dsq_id, node_id);
		if (ret < 0)
			return ret;
		(*fallback_dsq_id)++;
	}

	return 0;
}

/*
 * Initializes per CPU data structures.
 */
static s32 init_cpu(s32 cpu, int *nr_online_cpus,
		    struct bpf_cpumask *cpumask,
		    struct bpf_cpumask *tmp_big_cpumask)
{
	const volatile u8 *u8_ptr;
	struct cpu_ctx *cpuc;
	struct cpu_prox_map *pmap;
	u64 *init_antistall_dsq;
	int i;

	init_antistall_dsq = bpf_map_lookup_percpu_elem(&antistall_cpu_dsq,
							&zero_u32, cpu);
	if (init_antistall_dsq) {
		*init_antistall_dsq = SCX_DSQ_INVALID;
	}

	if (!(cpuc = lookup_cpu_ctx(cpu))) {
		return -ENOMEM;
	}
	cpuc->task_layer_id = MAX_LAYERS;

	if ((u8_ptr = MEMBER_VPTR(all_cpus, [cpu / 8]))) {
		if (*u8_ptr & (1 << (cpu % 8))) {
			bpf_cpumask_set_cpu(cpu, cpumask);
			(*nr_online_cpus)++;
			if (cpuc->is_big)
				bpf_cpumask_set_cpu(cpu, tmp_big_cpumask);
		}
	} else {
		return -EINVAL;
	}

	pmap = &cpuc->prox_map;
	dbg("CFG: CPU[%d] prox_map core/llc/node/sys=%d/%d/%d/%d",
	    cpu, pmap->core_end, pmap->llc_end, pmap->node_end, pmap->sys_end);
	if (pmap->sys_end > nr_possible_cpus || pmap->sys_end > MAX_CPUS) {
		scx_bpf_error("CPU %d  proximity map too long", cpu);
		return -EINVAL;
	}

	// too much output, overruns trace buf, maybe come up with a way to compact
	if (cpu == 0) {
		bpf_for(i, 0, pmap->sys_end) {
			u16 *p = MEMBER_VPTR(pmap->cpus, [i]);
			if (p)
				dbg("CFG: CPU[%d] prox[%d]=%d", cpu, i, *p);
		}
	}

	bpf_for(i, 0, nr_open_preempt_layers)
		dbg("CFG: CPU[%d] open_preempt_layer_order[%d]=%d",
		    cpu, i, cpuc->open_preempt_layer_order[i]);
	bpf_for(i, 0, nr_open_layers)
		dbg("CFG: CPU[%d] open_preempt_order[%d]=%d",
		    cpu, i, cpuc->open_layer_order[i]);

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(layered_init)
{
	struct bpf_cpumask *cpumask, *tmp_big_cpumask;
	int i, nr_online_cpus, ret;

	ret = scx_bpf_create_dsq(LO_FALLBACK_DSQ, -1);
	if (ret < 0)
		return ret;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	tmp_big_cpumask = bpf_cpumask_create();
	if (!tmp_big_cpumask) {
		bpf_cpumask_release(cpumask);
		return -ENOMEM;
	}

	nr_online_cpus = 0;
	bpf_for(i, 0, nr_possible_cpus) {
		ret = init_cpu(i, &nr_online_cpus, cpumask, tmp_big_cpumask);
		if (ret != 0) {
			bpf_cpumask_release(cpumask);
			bpf_cpumask_release(tmp_big_cpumask);
			return ret;
		}
	}

	cpumask = bpf_kptr_xchg(&all_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	tmp_big_cpumask = bpf_kptr_xchg(&big_cpumask, tmp_big_cpumask);
	if (tmp_big_cpumask)
		bpf_cpumask_release(tmp_big_cpumask);

	bpf_for(i, 0, nr_nodes) {
		ret = create_node(i);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, nr_llcs) {
		ret = create_llc(i);
		if (ret)
			return ret;
		ret = scx_bpf_create_dsq(llc_hi_fallback_dsq_id(i), llc_node_id(i));
		if (ret < 0)
			return ret;
	}

	dbg("CFG: Dumping configuration, nr_online_cpus=%d smt_enabled=%d little_cores=%d",
	    nr_online_cpus, smt_enabled, has_little_cores);

	u64 fallback_dsq_id = 0;
	bpf_for(i, 0, nr_layers) {
		ret = init_layer(i, &fallback_dsq_id);
		if (ret != 0)
			return ret;
	}

	ret = start_layered_timers();
	if (ret < 0)
		return ret;

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
	       .yield			= (void *)layered_yield,
	       .set_weight		= (void *)layered_set_weight,
	       .set_cpumask		= (void *)layered_set_cpumask,
	       .update_idle		= (void *)layered_update_idle,
	       .cpu_release		= (void *)layered_cpu_release,
	       .init_task		= (void *)layered_init_task,
	       .exit_task		= (void *)layered_exit_task,
	       .dump			= (void *)layered_dump,
	       .init			= (void *)layered_init,
	       .exit			= (void *)layered_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "layered");
