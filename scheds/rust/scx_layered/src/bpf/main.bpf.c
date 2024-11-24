/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#define LSP_INC
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/ravg_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
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

const volatile u32 debug = 0;
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
const volatile bool disable_topology = false;
const volatile bool xnuma_preemption = false;
const volatile bool local_llc_iteration = true;
const volatile s32 __sibling_cpu[MAX_CPUS];
const volatile bool monitor_disable = false;
const volatile unsigned char all_cpus[MAX_CPUS_U8];
const volatile u32 layer_iteration_order[MAX_LAYERS];
/* Flag to enable or disable antistall feature */
const volatile bool enable_antistall = true;
/* Delay permitted, in seconds, before antistall activates */
const volatile u64 antistall_sec = 3;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
private(big_cpumask) struct bpf_cpumask __kptr *big_cpumask;
struct layer layers[MAX_LAYERS];
u32 fallback_cpu;
static u32 preempt_cursor;

extern unsigned CONFIG_HZ __kconfig;

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

static struct layer *lookup_layer(u32 id)
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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct cache_ctx);
	__uint(max_entries, MAX_LLCS);
	__uint(map_flags, 0);
} cache_data SEC(".maps");

static struct cache_ctx *lookup_cache_ctx(u32 cache_id)
{
	struct cache_ctx *cachec;

	if (!(cachec = bpf_map_lookup_elem(&cache_data, &cache_id)))
		scx_bpf_error("no cache_ctx");
	return cachec;
}

static void gstat_inc(u32 id, struct cpu_ctx *cctx)
{
	if (id >= NR_GSTATS) {
		scx_bpf_error("invalid global stat id %d", id);
		return;
	}

	cctx->gstats[id]++;
}

static void lstat_add(u32 id, struct layer *layer, struct cpu_ctx *cctx, s64 delta)
{
	u64 *vptr;

	if ((vptr = MEMBER_VPTR(*cctx, .lstats[layer->id][id])))
		(*vptr) += delta;
	else
		scx_bpf_error("invalid layer or stat ids: %d, %d", id, layer->id);
}

static void lstat_inc(u32 id, struct layer *layer, struct cpu_ctx *cctx)
{
	lstat_add(id, layer, cctx, 1);
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

static void adj_load(u32 layer_id, s64 adj, u64 now)
{
	struct layer *layer;
	struct lock_wrapper *lockw;

	layer = MEMBER_VPTR(layers, [layer_id]);
	lockw = bpf_map_lookup_elem(&layer_load_locks, &layer_id);

	if (!layer || !lockw) {
		scx_bpf_error("Can't access layer%d or its load_lock", layer_id);
		return;
	}

	bpf_spin_lock(&lockw->lock);
	layer->load += adj;
	ravg_accumulate(&layer->load_rd, layer->load, now, USAGE_HALF_LIFE);
	bpf_spin_unlock(&lockw->lock);

	if (debug && adj < 0 && (s64)layer->load < 0)
		scx_bpf_error("cpu%d layer%d load underflow (load=%lld adj=%lld)",
			      bpf_get_smp_processor_id(), layer_id, layer->load, adj);
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
 * Returns if any cpus were added to the layer.
 */
static bool refresh_cpumasks(u32 layer_id)
{
	struct bpf_cpumask *layer_cpumask;
	struct layer_cpumask_wrapper *cpumaskw;
	struct layer *layer;
	struct cpu_ctx *cctx;
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

		if (!(cctx = lookup_cpu_ctx(cpu))) {
			bpf_rcu_read_unlock();
			scx_bpf_error("unknown cpu");
			return false;
		}

		if ((u8_ptr = MEMBER_VPTR(layers, [layer_id].cpus[cpu / 8]))) {
			if (*u8_ptr & (1 << (cpu % 8))) {
				bpf_cpumask_set_cpu(cpu, layer_cpumask);
				total++;
			} else {
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

// TODO: Refactor includes that have circular dependencies. This import must be
// defined after some helpers, but before it's helpers are used.
#include "cost.bpf.c"

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
	u64			last_dsq;
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

static void maybe_refresh_layered_cpus(struct task_struct *p, struct task_ctx *tctx,
				       const struct cpumask *layer_cpumask,
				       u64 cpus_seq)
{
	if (should_refresh_cached_cpus(&tctx->layered_cpus, 0, cpus_seq)) {
		refresh_cached_cpus(tctx->layered_mask, &tctx->layered_cpus, 0, cpus_seq,
				    p->cpus_ptr, layer_cpumask);
		trace("%s[%d] layered cpumask refreshed to seq=%llu",
		      p->comm, p->pid, tctx->layered_cpus.seq);
	}
}

static void maybe_refresh_layered_cpus_llc(struct task_struct *p, struct task_ctx *tctx,
					   const struct cpumask *layer_cpumask,
					   s32 llc_id, u64 cpus_seq)
{
	if (should_refresh_cached_cpus(&tctx->layered_cpus_llc, llc_id, cpus_seq)) {
		struct cache_ctx *cachec;

		if (!(cachec = lookup_cache_ctx(llc_id)))
			return;
		refresh_cached_cpus(tctx->layered_llc_mask,
				    &tctx->layered_cpus_llc, llc_id, cpus_seq,
				    cast_mask(tctx->layered_mask),
				    cast_mask(cachec->cpumask));
		trace("%s[%d] layered llc cpumask refreshed to llc=%d seq=%llu",
		      p->comm, p->pid, tctx->layered_cpus_llc.id, tctx->layered_cpus_llc.seq);
	}
}

static void maybe_refresh_layered_cpus_node(struct task_struct *p, struct task_ctx *tctx,
					    const struct cpumask *layer_cpumask,
					    s32 node_id, u64 cpus_seq)
{
	if (should_refresh_cached_cpus(&tctx->layered_cpus_node, node_id, cpus_seq)) {
		struct node_ctx *nodec;

		if (!(nodec = lookup_node_ctx(node_id)))
			return;
		refresh_cached_cpus(tctx->layered_node_mask,
				    &tctx->layered_cpus_node, node_id, cpus_seq,
				    cast_mask(tctx->layered_mask),
				    cast_mask(nodec->cpumask));
		trace("%s[%d] layered node cpumask refreshed to node=%d seq=%llu",
		      p->comm, p->pid, tctx->layered_cpus_node.id, tctx->layered_cpus_node.seq);
	}
}

static s32 pick_idle_cpu_from(const struct cpumask *cand_cpumask, s32 prev_cpu,
			      const struct cpumask *idle_smtmask, bool pref_idle_smt)
{
	bool prev_in_cand = bpf_cpumask_test_cpu(prev_cpu, cand_cpumask);
	s32 cpu;

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	if (smt_enabled && !pref_idle_smt) {
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

	if (layer->kind == LAYER_KIND_CONFINED &&
	    !bpf_cpumask_test_cpu(cand, layered_cpumask))
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
	const struct cpumask *idle_smtmask, *layer_cpumask, *layered_cpumask, *cpumask;
	struct cpu_ctx *prev_cctx;
	u64 cpus_seq;
	s32 cpu;

	if (!(layer_cpumask = lookup_layer_cpumask(tctx->layer_id)))
		return -1;

	/* not much to do if bound to a single CPU */
	if (p->nr_cpus_allowed == 1 && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		if (layer->kind == LAYER_KIND_CONFINED &&
		    !bpf_cpumask_test_cpu(prev_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);
		return prev_cpu;
	}

	cpus_seq = READ_ONCE(layers->cpus_seq);

	/*
	 * If @p prefers to preempt @prev_cpu than finding an idle CPU and
	 * @prev_cpu is preemptible, tell the enqueue path to try to preempt
	 * @prev_cpu. The enqueue path will also retry to find an idle CPU if
	 * the preemption attempt fails.
	 */
	maybe_refresh_layered_cpus(p, tctx, layer_cpumask, cpus_seq);
	if (!(layered_cpumask = cast_mask(tctx->layered_mask)))
		return -1;
	if (from_selcpu && should_try_preempt_first(prev_cpu, layer, layered_cpumask)) {
		cctx->try_preempt_first = true;
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
	    !(prev_cctx = lookup_cpu_ctx(prev_cpu)))
		return -1;
	if (!(idle_smtmask = scx_bpf_get_idle_smtmask()))
		return -1;

	/*
	 * Try a CPU in the current LLC
	 */
	if (nr_llcs > 1) {
		maybe_refresh_layered_cpus_llc(p, tctx, layer_cpumask,
					       prev_cctx->cache_id, cpus_seq);
		if (!(cpumask = cast_mask(tctx->layered_llc_mask))) {
			cpu = -1;
			goto out_put;
		}
		if ((cpu = pick_idle_cpu_from(cpumask, prev_cpu, idle_smtmask,
					      layer->idle_smt)) >= 0)
			goto out_put;
	}

	/*
	 * If the layer uses BigLittle growth algo try a big cpu.
	 * TODO - Cache layered_cpus.mask & big_cpumask.
	 */
	if (has_little_cores && big_cpumask &&
	    layer->growth_algo == GROWTH_ALGO_BIG_LITTLE) {
		struct bpf_cpumask *tmp_cpumask;

		if (!(tmp_cpumask = bpf_cpumask_create())) {
			cpu = -1;
			goto out_put;
		}
		bpf_cpumask_and(tmp_cpumask, cast_mask(tctx->layered_mask),
				cast_mask(big_cpumask));
		cpu = pick_idle_cpu_from(cast_mask(tmp_cpumask),
					 prev_cpu, idle_smtmask,
					 layer->idle_smt);
		bpf_cpumask_release(tmp_cpumask);
		if (cpu >= 0)
			goto out_put;
	}

	/*
	 * Next try a CPU in the current node
	 */
	if (nr_nodes > 1) {
		maybe_refresh_layered_cpus_node(p, tctx, layer_cpumask,
						prev_cctx->node_id, cpus_seq);
		if (!(cpumask = cast_mask(tctx->layered_node_mask))) {
			cpu = -1;
			goto out_put;
		}
		if ((cpu = pick_idle_cpu_from(cpumask, prev_cpu, idle_smtmask,
					      layer->idle_smt)) >= 0)
			goto out_put;
	}

	if ((cpu = pick_idle_cpu_from(layered_cpumask, prev_cpu,
				      idle_smtmask, layer->idle_smt)) >= 0)
		goto out_put;

	/*
	 * If the layer is an open one, we can try the whole machine.
	 */
	if (layer->kind != LAYER_KIND_CONFINED &&
	    ((cpu = pick_idle_cpu_from(p->cpus_ptr, prev_cpu,
				       idle_smtmask, layer->idle_smt)) >= 0)) {
		lstat_inc(LSTAT_OPEN_IDLE, layer, cctx);
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
	} else if (tctx->all_cpus_allowed) {
		if (!READ_ONCE(layer->check_no_idle))
			WRITE_ONCE(layer->check_no_idle, true);
	}

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
	 * still have MAX_LAYERS layer. Just return @prev_cpu.
	 */
	if (tctx->layer_id == MAX_LAYERS || !(layer = lookup_layer(tctx->layer_id)))
		return prev_cpu;

	cpu = pick_idle_cpu(p, prev_cpu, cctx, tctx, layer, true);

	if (cpu >= 0) {
		lstat_inc(LSTAT_SEL_LOCAL, layer, cctx);
		u64 slice_ns = layer_slice_ns(layer);
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
bool try_preempt_cpu(s32 cand, struct task_struct *p, struct cpu_ctx *cctx,
		     struct task_ctx *tctx, struct layer *layer,
		     bool preempt_first)
{
	struct cost *costc;
	struct cpu_ctx *cand_cctx, *sib_cctx = NULL;
	s32 sib;

	if (cand >= nr_possible_cpus || !bpf_cpumask_test_cpu(cand, p->cpus_ptr))
		return false;

	if (!(cand_cctx = lookup_cpu_ctx(cand)) || cand_cctx->current_preempt)
		return false;

	if (!(costc = lookup_cpu_cost(cand)) ||
	    has_budget(costc, layer) == 0 ||
	    !has_preempt_budget(costc, cand_cctx->task_layer_id, tctx->layer_id)) {
		trace("COST layer %s not enough budget to preempt", layer->name);
		return false;
	}

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
	 * $sib_cctx is set if @p is an exclusive task, a sibling CPU
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

static __always_inline
void try_preempt(s32 task_cpu, struct task_struct *p, struct task_ctx *tctx,
		 bool preempt_first, u64 enq_flags)
{
	struct cpu_ctx *cpuc, *task_cpuc;
	struct layer *layer;
	s32 i;

	if (!(layer = lookup_layer(tctx->layer_id)) ||
	    !(cpuc = lookup_cpu_ctx(-1)) ||
	    !(task_cpuc = lookup_cpu_ctx(task_cpu)))
		return;

	if (preempt_first) {
		/*
		 * @p prefers to preempt its previous CPU even when there are
		 * other idle CPUs.
		 */
		if (try_preempt_cpu(task_cpu, p, cpuc, tctx, layer, true))
			return;
		/* we skipped idle CPU picking in select_cpu. Do it here. */
		if (pick_idle_cpu_and_kick(p, task_cpu, cpuc, tctx, layer))
			return;
	} else {
		/*
		 * If we aren't in the wakeup path, layered_select_cpu() hasn't
		 * run and thus we haven't looked for and kicked an idle CPU.
		 * Let's do it now.
		 */
		if (!(enq_flags & SCX_ENQ_WAKEUP) &&
		    pick_idle_cpu_and_kick(p, task_cpu, cpuc, tctx, layer))
			return;
		if (!layer->preempt)
			return;
		if (try_preempt_cpu(task_cpu, p, cpuc, tctx, layer, false))
			return;
	}

	struct cpu_prox_map *pmap = &task_cpuc->prox_map;

	bpf_for(i, 1, MAX_CPUS) {
		if (i >= pmap->sys_end)
			break;
		u16 *cpu_p = MEMBER_VPTR(pmap->cpus, [i]);
		if (cpu_p && try_preempt_cpu(*cpu_p, p, cpuc, tctx, layer, false))
			return;
	}

	lstat_inc(LSTAT_PREEMPT_FAIL, layer, cpuc);
}

void BPF_STRUCT_OPS(layered_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cctx, *task_cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	s32 task_cpu = scx_bpf_task_cpu(p);
	u64 vtime = p->scx.dsq_vtime;
	bool try_preempt_first;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(task_cctx = lookup_cpu_ctx(task_cpu)) ||
	    !(tctx = lookup_task_ctx(p)) || !(layer = lookup_layer(tctx->layer_id)))
		return;

	try_preempt_first = cctx->try_preempt_first;
	cctx->try_preempt_first = false;
	u64 slice_ns = layer_slice_ns(layer);

	if (cctx->yielding) {
		lstat_inc(LSTAT_YIELD, layer, cctx);
		cctx->yielding = false;
	}

	if (enq_flags & SCX_ENQ_REENQ) {
		lstat_inc(LSTAT_ENQ_REENQ, layer, cctx);
	} else {
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
	    (p->flags & PF_KTHREAD) && p->nr_cpus_allowed < nr_possible_cpus) {
		struct cpumask *layer_cpumask;

		if (layer->kind == LAYER_KIND_CONFINED &&
		    (layer_cpumask = lookup_layer_cpumask(tctx->layer_id)) &&
		    !bpf_cpumask_test_cpu(task_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);

		tctx->last_dsq = task_cctx->hi_fallback_dsq_id;
		scx_bpf_dispatch(p, tctx->last_dsq, slice_ns, enq_flags);
		goto preempt;
	}

	/*
	 * As an open or grouped layer is consumed from all CPUs, a task which
	 * belongs to such a layer can be safely put in the layer's DSQ
	 * regardless of its cpumask. However, a task with custom cpumask in a
	 * confined layer may fail to be consumed for an indefinite amount of
	 * time. Queue them to the fallback DSQ.
	 */
	if (layer->kind == LAYER_KIND_CONFINED && !tctx->all_cpus_allowed) {
		lstat_inc(LSTAT_AFFN_VIOL, layer, cctx);
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
		tctx->last_dsq = task_cctx->hi_fallback_dsq_id;
		scx_bpf_dispatch(p, tctx->last_dsq, slice_ns, enq_flags);
		goto preempt;
	}

	tctx->last_dsq = layer_dsq_id(layer->id, task_cctx->cache_id);
	scx_bpf_dispatch_vtime(p, tctx->last_dsq, slice_ns, vtime, enq_flags);

preempt:
	try_preempt(task_cpu, p, tctx, try_preempt_first, enq_flags);
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

	if (!(tctx = lookup_task_ctx(p)) || !(layer = lookup_layer(tctx->layer_id)))
		goto no;

	u64 slice_ns = layer_slice_ns(layer);
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
		u32 dsq_id = layer_dsq_id(layer->id, cctx->cache_id);
		if (!scx_bpf_dsq_nr_queued(dsq_id)) {
			p->scx.slice = slice_ns;
			lstat_inc(LSTAT_KEEP, layer, cctx);
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
			lstat_inc(LSTAT_KEEP, layer, cctx);
			return true;
		}
	}

	lstat_inc(LSTAT_KEEP_FAIL_BUSY, layer, cctx);
no:
	cctx->ran_current_for = 0;
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
 * @cpu: cpu number
 * @cctx: cpu context
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
bool antistall_consume(s32 cpu, struct cpu_ctx *cctx)
{
	u64 *antistall_dsq, jiffies_now, cur_delay;
	u32 zero;
	bool consumed;
	struct task_struct *p;

	cur_delay = 0;
	consumed = false;
	zero = 0;

	if (!enable_antistall)
		return false;

	if (!cctx || !cctx->task_layer_id || !cpu)
		return false;

	antistall_dsq = bpf_map_lookup_elem(&antistall_cpu_dsq, &zero);

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
	      *antistall_dsq, cpu, cur_delay);
	*antistall_dsq = SCX_DSQ_INVALID;
	return consumed;
}

static __noinline
void layered_dispatch_no_topo(s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx, *sib_cctx;
	struct layer *layer;
	struct cost *costc;
	u32 u, layer_id;
	s32 sib = sibling_cpu(cpu);

	if (!(cctx = lookup_cpu_ctx(-1)) || !(costc = lookup_cpu_cost(cpu)))
		return;

	if (antistall_consume(cpu, cctx))
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
	bpf_for(u, 0, nr_layers) {
		layer_id = rotate_layer_id(costc->pref_layer, u);
		if (layer_id >= nr_layers) {
			scx_bpf_error("can't happen");
			return;
		}
		layer = MEMBER_VPTR(layers, [layer_id]);
		if (has_budget(costc, layer) == 0)
			continue;
		if (layer->preempt && scx_bpf_consume(layer_id))
			return;
	}

	if (scx_bpf_consume(cctx->hi_fallback_dsq_id))
		return;

	/* consume !open layers second */
	bpf_for(u, 0, nr_layers) {
		layer_id = rotate_layer_id(costc->pref_layer, u);
		if (layer_id >= nr_layers) {
			scx_bpf_error("can't happen");
			return;
		}
		layer = MEMBER_VPTR(layers, [layer_id]);
		if (has_budget(costc, layer) == 0)
			continue;
		struct cpumask *layer_cpumask;

		/* consume matching layers */
		if (!(layer_cpumask = lookup_layer_cpumask(layer_id)))
			return;

		if (bpf_cpumask_test_cpu(cpu, layer_cpumask) ||
		    (cpu == fallback_cpu && layer->nr_cpus == 0)) {
			if (scx_bpf_consume(layer_id))
				return;
		}
	}

	/* consume !preempting open layers */
	bpf_for(u, 0, nr_layers) {
		layer_id = rotate_layer_id(costc->pref_layer, u);
		if (layer_id >= nr_layers) {
			scx_bpf_error("can't happen");
			return;
		}
		layer = MEMBER_VPTR(layers, [layer_id]);
		if (has_budget(costc, layer) == 0)
			continue;
		if (!layer->preempt && layer->kind != LAYER_KIND_CONFINED &&
		    scx_bpf_consume(layer_id))
			return;
	}

	scx_bpf_consume(LO_FALLBACK_DSQ);
}

__weak int consume_preempting(struct cost *costc, u32 my_llc_id)
{
	struct layer *layer;
	u64 dsq_id;
	u32 u, v, layer_id;

	if (!costc)
		return -EINVAL;

	if (local_llc_iteration) {
		bpf_for(u, 0, nr_llcs) {
			u32 llc_id = rotate_llc_id(my_llc_id, u);
			bpf_for(v, 0, nr_layers) {
				layer_id = rotate_layer_id(costc->pref_layer, v);
				if (layer_id >= nr_layers) {
					scx_bpf_error("can't happen");
					return -EINVAL;
				}
				layer = MEMBER_VPTR(layers, [layer_id]);
				if (!layer->preempt || has_budget(costc, layer) == 0)
					continue;
				dsq_id = layer_dsq_id(layer_id, llc_id);
				if (scx_bpf_consume(dsq_id))
					return 0;
			}
		}
	} else {
		bpf_for(u, 0, nr_layers) {
			layer_id = rotate_layer_id(costc->pref_layer, u);
			if (layer_id >= nr_layers) {
				scx_bpf_error("can't happen");
				return -EINVAL;
			}
			layer = MEMBER_VPTR(layers, [layer_id]);
			if (!layer->preempt || has_budget(costc, layer) == 0)
				continue;

			bpf_for(v, 0, nr_llcs) {
				u32 llc_id = rotate_llc_id(my_llc_id, v);
				dsq_id = layer_dsq_id(layer_id, llc_id);
				if (scx_bpf_consume(dsq_id))
					return 0;
			}
		}
	}

	return -ENOENT;
}

static __noinline int consume_non_open(struct cost *costc, s32 cpu, u32 my_llc_id)
{
	struct layer *layer;
	u64 dsq_id;
	u32 u, v, layer_id;

	if (!costc)
		return -EINVAL;

	if (local_llc_iteration) {
		bpf_for(u, 0, nr_llcs) {
			u32 llc_id = rotate_llc_id(my_llc_id, u);
			bpf_for(v, 0, nr_layers) {
				layer_id = rotate_layer_id(costc->pref_layer, v);
				if (layer_id >= nr_layers) {
					scx_bpf_error("can't happen");
					return -EINVAL;
				}
				layer = MEMBER_VPTR(layers, [layer_id]);
				if (has_budget(costc, layer) == 0)
					continue;

				struct cpumask *layer_cpumask;
				if (!(layer_cpumask = lookup_layer_cpumask(layer_id)))
					return -ENOENT;

				if (!bpf_cpumask_test_cpu(cpu, layer_cpumask) &&
				    (cpu > nr_possible_cpus ||
				     cpu != fallback_cpu ||
				     layer->nr_cpus != 0))
					continue;

				dsq_id = layer_dsq_id(layer_id, llc_id);
				if (scx_bpf_consume(dsq_id))
					return 0;
			}
		}
	} else {
		bpf_for(u, 0, nr_layers) {
			layer_id = rotate_layer_id(costc->pref_layer, u);
			if (layer_id >= nr_layers) {
				scx_bpf_error("can't happen");
				return -EINVAL;
			}
			layer = MEMBER_VPTR(layers, [layer_id]);
			if (has_budget(costc, layer) == 0)
				continue;

			struct cpumask *layer_cpumask;
			if (!(layer_cpumask = lookup_layer_cpumask(layer_id)))
				return -ENOENT;
			if (!bpf_cpumask_test_cpu(cpu, layer_cpumask) &&
			    (cpu > nr_possible_cpus || cpu != fallback_cpu ||
			    layer->nr_cpus != 0))
				continue;

			bpf_for(v, 0, nr_llcs) {
				u32 llc_id = rotate_llc_id(my_llc_id, v);
				dsq_id = layer_dsq_id(layer_id, llc_id);

				if (scx_bpf_consume(dsq_id))
					return 0;
			}
		}
	}

	return -ENOENT;
}

__weak int consume_open_no_preempt(struct cost *costc, u32 my_llc_id)
{
	struct layer *layer;
	u64 dsq_id;
	u32 u, v, llc_id, layer_id;

	if (!costc)
		return -EINVAL;

	if (local_llc_iteration) {
		bpf_for(u, 0, nr_llcs) {
			u32 llc_id = rotate_llc_id(my_llc_id, u);
			bpf_for(v, 0, nr_layers) {
				layer_id = rotate_layer_id(costc->pref_layer, v);
				if (layer_id >= nr_layers) {
					scx_bpf_error("can't happen");
					return -EINVAL;
				}
				layer = MEMBER_VPTR(layers, [layer_id]);
				if (has_budget(costc, layer) == 0)
					continue;
				if (layer->preempt || layer->kind == LAYER_KIND_CONFINED)
					continue;

				dsq_id = layer_dsq_id(layer_id, llc_id);
				if (scx_bpf_consume(dsq_id))
					return 0;
			}
		}
	} else {
		bpf_for(u, 0, nr_layers) {
			layer_id = rotate_layer_id(costc->pref_layer, u);
			if (layer_id >= nr_layers) {
				scx_bpf_error("can't happen");
				return -EINVAL;
			}
			layer = MEMBER_VPTR(layers, [layer_id]);
			if (has_budget(costc, layer) == 0)
				continue;
			if (layer->preempt || layer->kind == LAYER_KIND_CONFINED)
				continue;
			bpf_for(v, 0, nr_llcs) {
				u32 llc_id = rotate_llc_id(my_llc_id, v);
				dsq_id = layer_dsq_id(layer_id, llc_id);

				if (scx_bpf_consume(dsq_id))
					return 0;
			}
		}
	}

	return -ENOENT;
}

void BPF_STRUCT_OPS(layered_dispatch, s32 cpu, struct task_struct *prev)
{
	if (disable_topology)
		return layered_dispatch_no_topo(cpu, prev);

	struct cpu_ctx *cctx, *sib_cctx;
	struct cost *costc;
	s32 sib = sibling_cpu(cpu);

	if (!(cctx = lookup_cpu_ctx(-1)) ||
	    !(costc = lookup_cpu_cost(cpu)))
		return;

	if (antistall_consume(cpu, cctx))
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
	if (consume_preempting(costc, cctx->cache_id) == 0)
		return;

	if (scx_bpf_consume(cctx->hi_fallback_dsq_id))
		return;

	/* consume !open layers second */
	if (consume_non_open(costc, cpu, cctx->cache_id) == 0)
		return;

	/* consume !preempting open layers */
	if (consume_open_no_preempt(costc, cctx->cache_id) == 0)
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

static void maybe_refresh_layer(struct task_struct *p, struct task_ctx *tctx)
{
	const char *cgrp_path;
	bool matched = false;
	u64 id;	// XXX - int makes verifier unhappy
	pid_t pid = p->pid;

	if (!tctx->refresh_layer)
		return;
	tctx->refresh_layer = false;

	if (!(cgrp_path = format_cgrp_path(p->cgroups->dfl_cgrp)))
		return;

	if (tctx->layer_id >= 0 && tctx->layer_id < nr_layers)
		__sync_fetch_and_add(&layers[tctx->layer_id].nr_tasks, -1);

	bpf_for(id, 0, nr_layers) {
		if (match_layer(id, pid, cgrp_path) == 0) {
			matched = true;
			break;
		}
	}

	if (matched) {
		struct layer *layer = &layers[id];

		tctx->layer_id = id;
		tctx->layered_cpus.seq = layer->cpus_seq - 1;
		tctx->layered_cpus_llc.seq = layer->cpus_seq - 1;
		tctx->layered_cpus_node.seq = layer->cpus_seq - 1;
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

	if (tctx->layer_id < nr_layers - 1)
		trace("LAYER=%d %s[%d] cgrp=\"%s\"",
		      tctx->layer_id, p->comm, p->pid, cgrp_path);
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
	struct cpu_ctx *cctx;
	s32 ret;

	nodec = bpf_map_lookup_elem(&node_data, &node_id);
	if (!nodec) {
		/* Should never happen, it's created statically at load time. */
		scx_bpf_error("No node%u", node_id);
		return -ENOENT;
	}
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
			if (!(cctx = lookup_cpu_ctx(cpu))) {
				scx_bpf_error("cpu ctx error");
				ret = -ENOENT;
				break;
			}

			cctx->node_id = node_id;
			nodec->nr_cpus++;
			nodec->llc_mask &= (1LLU << node_id);
		}
	}

	dbg("CFG creating node %d with %d cpus", node_id, nodec->nr_cpus);
	bpf_rcu_read_unlock();
	return ret;
}

static s32 create_cache(u32 cache_id)
{
	u32 cpu, llc_id;
	struct bpf_cpumask *cpumask;
	struct cache_ctx *cachec;
	struct cpu_ctx *cctx;
	s32 ret;

	cachec = bpf_map_lookup_elem(&cache_data, &cache_id);
	if (!cachec) {
		scx_bpf_error("No cache%u", cache_id);
		return -ENOENT;
	}
	cachec->id = cache_id;

	ret = create_save_cpumask(&cachec->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = cachec->cpumask;
	if (!cpumask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to lookup node cpumask");
		return -ENOENT;
	}

	bpf_for(cpu, 0, nr_possible_cpus) {
		if (!(cctx = lookup_cpu_ctx(cpu))) {
			bpf_rcu_read_unlock();
			scx_bpf_error("cpu ctx error");
			return -ENOENT;
		}

		llc_id = cpu_to_llc_id(cpu);
		if (llc_id != cache_id)
			continue;

		bpf_cpumask_set_cpu(cpu, cpumask);
		cachec->nr_cpus++;
		cctx->cache_id = cache_id;
		cctx->hi_fallback_dsq_id = llc_hi_fallback_dsq_id(cache_id);
	}

	dbg("CFG creating cache %d with %d cpus", cache_id, cachec->nr_cpus);
	bpf_rcu_read_unlock();
	return ret;
}

static __always_inline
void on_wakeup(struct task_struct *p, struct task_ctx *tctx)
{
	struct cpu_ctx *cctx;
	struct layer *layer;
	struct task_ctx *waker_tctx;
	struct task_struct *waker;

	if (!(cctx = lookup_cpu_ctx(-1)) ||
	    !(layer = lookup_layer(tctx->layer_id)))
		return;

	if (!(waker = bpf_get_current_task_btf()) ||
	    !(waker_tctx = lookup_task_ctx_may_fail(waker)))
		return;

	// TODO: add handling for per layer wakers
	if (tctx->layer_id == waker_tctx->layer_id)
		return;

	if (tctx->last_waker == waker->pid)
		lstat_inc(LSTAT_XLAYER_REWAKE, layer, cctx);

	tctx->last_waker = waker->pid;
	lstat_inc(LSTAT_XLAYER_WAKE, layer, cctx);
}


void BPF_STRUCT_OPS(layered_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now = bpf_ktime_get_ns();

	if (!(tctx = lookup_task_ctx(p)))
		return;

	tctx->runnable_at = now;
	maybe_refresh_layer(p, tctx);
	adj_load(tctx->layer_id, p->scx.weight, now);

	if (enq_flags & SCX_ENQ_WAKEUP)
		on_wakeup(p, tctx);
}

void BPF_STRUCT_OPS(layered_running, struct task_struct *p)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	struct node_ctx *nodec;
	struct cache_ctx *cachec;
	s32 task_cpu = scx_bpf_task_cpu(p);

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)) ||
	    !(layer = lookup_layer(tctx->layer_id)))
		return;

	if (tctx->last_cpu >= 0 && tctx->last_cpu != task_cpu) {
		lstat_inc(LSTAT_MIGRATION, layer, cctx);
		if (!(nodec = lookup_node_ctx(cctx->node_id)))
			return;
		if (nodec->cpumask &&
		    !bpf_cpumask_test_cpu(tctx->last_cpu, cast_mask(nodec->cpumask)))
			lstat_inc(LSTAT_XNUMA_MIGRATION, layer, cctx);
		if (!(cachec = lookup_cache_ctx(cctx->cache_id)))
			return;
		if (cachec->cpumask &&
		    !bpf_cpumask_test_cpu(tctx->last_cpu, cast_mask(cachec->cpumask)))
			lstat_inc(LSTAT_XLLC_MIGRATION, layer, cctx);
	}
	tctx->last_cpu = task_cpu;

	if (vtime_before(layer->vtime_now, p->scx.dsq_vtime))
		layer->vtime_now = p->scx.dsq_vtime;

	cctx->current_preempt = layer->preempt;
	cctx->current_exclusive = layer->exclusive;
	tctx->running_at = bpf_ktime_get_ns();
	cctx->task_layer_id = tctx->layer_id;

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

	if (layer->perf > 0 && cctx->perf != layer->perf) {
		scx_bpf_cpuperf_set(task_cpu, layer->perf);
		cctx->perf = layer->perf;
	}

	cctx->maybe_idle = false;
}

void BPF_STRUCT_OPS(layered_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;
	struct cost *costc;
	u32 budget_id;
	s32 lid;
	u64 used;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	lid = tctx->layer_id;
	if (!(layer = lookup_layer(lid)) || !(costc = lookup_cpu_cost(-1)))
		return;

	used = bpf_ktime_get_ns() - tctx->running_at;

	// If the task ran on the hi fallback dsq then the cost should be
	// charged to it.
	if (is_fallback_dsq(tctx->last_dsq)) {
		budget_id = fallback_dsq_cost_id(tctx->last_dsq);
	} else {
		budget_id = layer->id;
	}

	u64 slice_ns = layer_slice_ns(layer);
	record_cpu_cost(costc, budget_id, (s64)used, slice_ns);

	cctx->layer_usages[lid] += used;
	cctx->current_preempt = false;
	cctx->prev_exclusive = cctx->current_exclusive;
	cctx->current_exclusive = false;

	/*
	 * Apply min_exec_us, scale the execution time by the inverse of the
	 * weight and charge.
	 */
	if (used < layer->min_exec_ns) {
		lstat_inc(LSTAT_MIN_EXEC, layer, cctx);
		lstat_add(LSTAT_MIN_EXEC_NS, layer, cctx, layer->min_exec_ns - used);
		used = layer->min_exec_ns;
	}

	if (cctx->yielding && used < slice_ns)
		used = slice_ns;
	p->scx.dsq_vtime += used * 100 / p->scx.weight;
	cctx->maybe_idle = true;
}

void BPF_STRUCT_OPS(layered_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	if ((tctx = lookup_task_ctx(p)))
		adj_load(tctx->layer_id, -(s64)p->scx.weight, bpf_ktime_get_ns());
}

bool BPF_STRUCT_OPS(layered_yield, struct task_struct *from, struct task_struct *to)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct layer *layer;

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(from)) ||
	    !(layer = lookup_layer(tctx->layer_id)))
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
		bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);
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
	struct task_ctx *tctx;
	struct bpf_cpumask *cpumask;
	s32 ret;

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

	// Layer setup
	ret = init_cached_cpus(&tctx->layered_cpus);
	if (ret)
		return ret;
	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&tctx->layered_mask, cpumask))) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	// LLC setup
	ret = init_cached_cpus(&tctx->layered_cpus_llc);
	if (ret)
		return ret;

	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&tctx->layered_llc_mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	// Node setup
	ret = init_cached_cpus(&tctx->layered_cpus_node);
	if (ret)
		return ret;

	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&tctx->layered_node_mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	tctx->pid = p->pid;
	tctx->last_cpu = -1;
	tctx->layer_id = MAX_LAYERS;
	tctx->refresh_layer = true;

	if (all_cpumask)
		tctx->all_cpus_allowed =
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
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	if (args->cancelled) {
		return;
	}

	if (!(cctx = lookup_cpu_ctx(-1)) || !(tctx = lookup_task_ctx(p)))
		return;

	if (tctx->layer_id < nr_layers)
		__sync_fetch_and_add(&layers[tctx->layer_id].nr_tasks, -1);
}

static u64 dsq_first_runnable_for_ms(u64 dsq_id, u64 now)
{
	struct task_struct *p;

	if (dsq_id > LO_FALLBACK_DSQ)
		return 0;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		struct task_ctx *tctx;

		if ((tctx = lookup_task_ctx(p)))
			return (now - tctx->runnable_at) / 1000000;
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

int dump_cost(void)
{
	int i, j;
	struct cost *costc;
	struct layer *layer;

	// Lookup global cost
	if (!(costc = lookup_cost(0))) {
		scx_bpf_error("unabled to lookup cost ");
		return -EINVAL;
	}
	bpf_for(j, 0, nr_layers) {
		layer = lookup_layer(j);
		if (!layer) {
			scx_bpf_error("unabled to lookup layer %d", j);
			continue;
		}
		scx_bpf_dump("COST GLOBAL[%d][%s] budget=%lld capacity=%lld\n",
			     j, layer->name,
			     costc->budget[j], costc->capacity[j]);
	}
	// fallback DSQs
	bpf_for(i, 0, nr_llcs) {
		u64 dsq_id = llc_hi_fallback_dsq_id(i);
		u32 budget_id = fallback_dsq_cost_id(dsq_id);
		scx_bpf_dump("COST FALLBACK[%llu][%d] budget=%lld capacity=%lld\n",
			     dsq_id, budget_id,
			     costc->budget[budget_id], costc->capacity[budget_id]);
	}

	// Per CPU costs
	bpf_for(i, 0, nr_possible_cpus) {
		if (!(costc = lookup_cpu_cost(i))) {
			scx_bpf_error("unabled to lookup layer %d", i);
			continue;
		}
		bpf_for(j, 0, nr_layers) {
			layer = lookup_layer(j);
			if (!layer) {
				scx_bpf_error("unabled to lookup layer %d", i);
				continue;
			}
			scx_bpf_dump("COST CPU[%d][%d][%s] budget=%lld capacity=%lld\n",
				     i, j, layer->name,
				     costc->budget[j], costc->capacity[j]);
		}
		bpf_for(j, 0, nr_llcs) {
			u64 dsq_id = llc_hi_fallback_dsq_id(j);
			u32 budget_id = fallback_dsq_cost_id(dsq_id);
			if (budget_id >= MAX_GLOBAL_BUDGETS)
				continue;
			scx_bpf_dump("COST CPU[%d]FALLBACK[%llu][%d] budget=%lld capacity=%lld\n",
				     i, dsq_id, budget_id,
				     costc->budget[budget_id], costc->capacity[budget_id]);
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(layered_dump, struct scx_dump_ctx *dctx)
{
	u64 now = bpf_ktime_get_ns();
	u64 dsq_id;
	int i, j, id;
	struct layer *layer;

	bpf_for(i, 0, nr_layers) {
		layer = lookup_layer(i);
		if (!layer) {
			scx_bpf_error("unabled to lookup layer %d", i);
			continue;
		}

		bpf_for(j, 0, nr_llcs) {
			if (!(layer->cache_mask & (1 << j)))
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

	dump_cost();
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
	struct task_ctx *tctx;
	s32 cpu;
	u64 *antistall_dsq, *delay, cur_delay;
	int pass;
	u32 zero;

	zero = 0;

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

		if (!(tctx = lookup_task_ctx(p)))
			goto unlock;

		cur_delay = get_delay_sec(p, jiffies_now);
		if (cur_delay <= antistall_sec)
			// check head task in dsq
			goto unlock;

		#pragma unroll
		for (pass = 0; pass < 2; ++pass) bpf_for(cpu, 0, nr_possible_cpus) {
			const struct cpumask *cpumask;

			if (!(cpumask = cast_mask(tctx->layered_mask)))
				goto unlock;

			/* for affinity violating tasks, target all allowed CPUs */
			if (bpf_cpumask_empty(cpumask))
				cpumask = p->cpus_ptr;

			if (!bpf_cpumask_test_cpu(cpu, cpumask))
				continue;

			antistall_dsq = bpf_map_lookup_percpu_elem(&antistall_cpu_dsq, &zero, cpu);
			delay = bpf_map_lookup_percpu_elem(&antistall_cpu_max_delay, &zero, cpu);

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


s32 BPF_STRUCT_OPS_SLEEPABLE(layered_init)
{
	struct bpf_cpumask *cpumask, *tmp_big_cpumask;
	struct cpu_ctx *cctx;
	int i, j, k, nr_online_cpus, ret;
	u64 *init_antistall_dsq;
	u32 zero;

	zero = 0;

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
		const volatile u8 *u8_ptr;

		init_antistall_dsq = bpf_map_lookup_percpu_elem(&antistall_cpu_dsq,
								&zero, i);
		if (init_antistall_dsq) {
			*init_antistall_dsq = SCX_DSQ_INVALID;
		}

		if (!(cctx = lookup_cpu_ctx(i))) {
			bpf_cpumask_release(cpumask);
			bpf_cpumask_release(tmp_big_cpumask);
			return -ENOMEM;
		}
		cctx->task_layer_id = MAX_LAYERS;

		if ((u8_ptr = MEMBER_VPTR(all_cpus, [i / 8]))) {
			if (*u8_ptr & (1 << (i % 8))) {
				bpf_cpumask_set_cpu(i, cpumask);
				nr_online_cpus++;
				if (cctx->is_big)
					bpf_cpumask_set_cpu(i, tmp_big_cpumask);
			}
		} else {
			return -EINVAL;
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
		ret = create_cache(i);
		if (ret)
			return ret;
		ret = scx_bpf_create_dsq(llc_hi_fallback_dsq_id(i), llc_node_id(i));
		if (ret < 0)
			return ret;
	}

	dbg("CFG: Dumping CPU proxity map");
	bpf_for(i, 0, nr_possible_cpus) {
		struct cpu_ctx *cpuc;
		struct cpu_prox_map *pmap;

		cpuc = lookup_cpu_ctx(i);
		if (!cpuc) {
			scx_bpf_error("CPU[%d] no context", i);
			return -EINVAL;
		}
		pmap = &cpuc->prox_map;

		dbg("CFG: CPU[%d] core/llc/node/sys=%d/%d/%d/%d",
		    i, pmap->core_end, pmap->llc_end, pmap->node_end, pmap->sys_end);
		if (pmap->sys_end > nr_possible_cpus || pmap->sys_end > MAX_CPUS) {
			scx_bpf_error("CPU %d  proximity map too long", i);
			return -EINVAL;
		}
#if 0	// too much output, overruns trace buf, maybe come up with a way to compact
		bpf_for(j, 0, pmap->sys_end) {
			u16 *p = MEMBER_VPTR(pmap->cpus, [j]);
			if (p)
				dbg("CFG: CPU[%d] prox[%d]=%d", i, j, pmap->cpus[j]);
		}
#endif
	}

	dbg("CFG: Dumping configuration, nr_online_cpus=%d smt_enabled=%d little_cores=%d",
	    nr_online_cpus, smt_enabled, has_little_cores);

	bpf_for(i, 0, nr_layers) {
		struct layer *layer = &layers[i];

		dbg("CFG LAYER[%d][%s] min_exec_ns=%lu open=%d preempt=%d exclusive=%d",
		    i, layer->name, layer->min_exec_ns,
		    layer->kind != LAYER_KIND_CONFINED,
		    layer->preempt, layer->exclusive);

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
	}

	u64 llc_dsq_id = 0;
	bpf_for(i, 0, nr_layers) {
		struct layer_cpumask_wrapper *cpumaskw;

		layers[i].id = i;
		struct layer *layer = &layers[i];

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

		// create the dsqs for the layer
		bpf_for(j, 0, nr_llcs) {
			int node_id = llc_node_id(i);
			dbg("CFG creating dsq %llu for layer %d %s on node %d in llc %d",
			    llc_dsq_id, i, layer->name, node_id, j);
			ret = scx_bpf_create_dsq(llc_dsq_id, node_id);
			if (ret < 0)
				return ret;
			llc_dsq_id++;
		}
	}
	initialize_budgets(15LLU * NSEC_PER_SEC);
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
	       .name			= "layered");
