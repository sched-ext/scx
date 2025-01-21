/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/namespace_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/namespace_impl.bpf.h>
#endif

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "intf.h"
#include "timer.bpf.h"
#include "util.bpf.h"

char _license[] SEC("license") = "GPL";

extern unsigned CONFIG_HZ __kconfig;

const volatile u32 debug;
const volatile u64 slice_ns;
const volatile u64 max_exec_ns;
const volatile u32 nr_cpu_ids = 1;
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
const volatile u32 nr_op_layers;	/* open && preempt */
const volatile u32 nr_on_layers;	/* open && !preempt */
const volatile u32 nr_gp_layers;	/* grouped && preempt */
const volatile u32 nr_gn_layers;	/* grouped && !preempt */
const volatile u64 min_open_layer_disallow_open_after_ns;
const volatile u64 min_open_layer_disallow_preempt_after_ns;
const volatile u64 lo_fb_wait_ns = 5000000;	/* !0 for veristat */
const volatile u32 lo_fb_share_ppk = 128;	/* !0 for veristat */
const volatile bool percpu_kthread_preempt = true;
volatile u64 layer_refresh_seq_avgruntime;

/* Flag to enable or disable antistall feature */
const volatile bool enable_antistall = true;
const volatile bool enable_gpu_support = false;
/* Delay permitted, in seconds, before antistall activates */
const volatile u64 antistall_sec = 3;
const u32 zero_u32 = 0;

private(unprotected_cpumask) struct bpf_cpumask __kptr *unprotected_cpumask;
u64 unprotected_seq = 0;

private(all_cpumask) struct bpf_cpumask __kptr *all_cpumask;
private(big_cpumask) struct bpf_cpumask __kptr *big_cpumask;
struct layer layers[MAX_LAYERS];
u32 fallback_cpu;
u32 layered_root_tgid = 0;

u32 empty_layer_ids[MAX_LAYERS];
u32 nr_empty_layer_ids;
static u32 do_refresh_layer_cpumasks = 0;

UEI_DEFINE(uei);

static inline s32 prio_to_nice(s32 static_prio)
{
	/* See DEFAULT_PRIO and PRIO_TO_NICE in include/linux/sched/prio.h */
	return static_prio - 120;
}

static inline bool is_preempt_kthread(struct task_struct *p)
{
	return percpu_kthread_preempt && (p->flags & PF_KTHREAD) &&
		p->nr_cpus_allowed == 1;
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

// return the dsq id for the layer based on the LLC id.
static __noinline u64 layer_dsq_id(u32 layer_id, u32 llc_id)
{
	return ((u64)layer_id << DSQ_ID_LAYER_SHIFT) | llc_id;
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

static u64 hi_fb_dsq_id(u32 llc_id)
{
	return HI_FB_DSQ_BASE | llc_id;
}

static u64 lo_fb_dsq_id(u32 llc_id)
{
	return LO_FB_DSQ_BASE | llc_id;
}

static __always_inline bool is_scheduler_task(struct task_struct *p)
{
	return (u32)p->tgid == layered_root_tgid;
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

static bool cpuc_in_layer(struct cpu_ctx *cpuc, struct layer *layer)
{
	if (layer->kind == LAYER_KIND_OPEN)
		return cpuc->in_open_layers;
	else
		return cpuc->layer_id == layer->id;
}


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_GPU_PIDS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} gpu_tgid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_GPU_PIDS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} gpu_tid SEC(".maps");

int save_gpu_tgid_pid() {
	if (!enable_gpu_support)
		return 0;
	u64 pid_tgid;
	u32 pid, tid, zero;
	zero = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = pid_tgid;
	bpf_map_update_elem(&gpu_tid, &tid, &zero, BPF_ANY);
	bpf_map_update_elem(&gpu_tgid, &pid, &zero, BPF_ANY);
	return 0;
}

SEC("?kprobe/nvidia_poll")
int kprobe_nvidia_poll() {
	return save_gpu_tgid_pid();
}

SEC("?kprobe/nvidia_open")
int kprobe_nvidia_open() {
	return save_gpu_tgid_pid();
}

SEC("?kprobe/nvidia_mmap")
int kprobe_nvidia_mmap() {
	return save_gpu_tgid_pid();
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

static void gstat_add(u32 id, struct cpu_ctx *cpuc, s64 delta)
{
	if (id >= NR_GSTATS) {
		scx_bpf_error("invalid global stat id %d", id);
		return;
	}

	cpuc->gstats[id] += delta;
}

static void gstat_inc(u32 id, struct cpu_ctx *cpuc)
{
	gstat_add(id, cpuc, 1);
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

static void layer_llc_drain_enable(struct layer *layer, u32 llc_id)
{
	__sync_or_and_fetch(&layer->llcs_to_drain, 1LLU << llc_id);
}

static void layer_llc_drain_disable(struct layer *layer, u32 llc_id)
{
	__sync_and_and_fetch(&layer->llcs_to_drain, ~(1LLU << llc_id));
}

static inline bool refresh_layer_cpuc(struct cpu_ctx *cpuc, struct layer *layer)
{
	/* a CPU can be shared by multiple open layers */
	cpuc->in_open_layers = (layer->kind == LAYER_KIND_OPEN);
	cpuc->layer_id = (layer->kind == LAYER_KIND_OPEN) ? MAX_LAYERS : layer->id;

	if (cpuc->is_protected == layer->is_protected)
		return false;

	cpuc->is_protected = layer->is_protected;
	if (unlikely(!unprotected_cpumask)) {
		scx_bpf_error("unprotected_cpumask not initialized");
		return false;
	}

	/* The mask tracks _unprotected_ CPUs to simplify bitops. */
	if (cpuc->is_protected)
		bpf_cpumask_clear_cpu(cpuc->cpu, unprotected_cpumask);
	else
		bpf_cpumask_set_cpu(cpuc->cpu, unprotected_cpumask);

	return true;
}

/*
 * Returns if any cpus were added to the layer.
 */
static void refresh_cpumasks(u32 layer_id)
{
	struct bpf_cpumask *layer_cpumask;
	struct layer_cpumask_wrapper *cpumaskw;
	bool protected_changed = false;
	struct layer *layer;
	struct cpu_ctx *cpuc;
	int cpu, llc_id;

	layer = MEMBER_VPTR(layers, [layer_id]);
	if (!layer) {
		scx_bpf_error("can't happen");
		return;
	}

	if (!__sync_val_compare_and_swap(&layer->refresh_cpus, 1, 0))
		return;

	bpf_rcu_read_lock();
	if (!(cpumaskw = bpf_map_lookup_elem(&layer_cpumasks, &layer_id)) ||
	    !(layer_cpumask = cpumaskw->cpumask)) {
		bpf_rcu_read_unlock();
		scx_bpf_error("can't happen");
		return;
	}

	bpf_for(cpu, 0, nr_possible_cpus) {
		u8 *u8_ptr;

		if (!(cpuc = lookup_cpu_ctx(cpu))) {
			bpf_rcu_read_unlock();
			return;
		}

		if ((u8_ptr = MEMBER_VPTR(layers, [layer_id].cpus[cpu / 8]))) {
			if (*u8_ptr & (1 << (cpu % 8))) {
				protected_changed = refresh_layer_cpuc(cpuc, layer) || protected_changed;

				bpf_cpumask_set_cpu(cpu, layer_cpumask);
			} else {
				if (layer->kind == LAYER_KIND_OPEN)
					cpuc->in_open_layers = false;
				else if (cpuc->layer_id == layer_id)
					cpuc->layer_id = MAX_LAYERS;
				bpf_cpumask_clear_cpu(cpu, layer_cpumask);
			}
		} else {
			scx_bpf_error("can't happen");
		}
	}

	bpf_rcu_read_unlock();

	if (protected_changed)
		__sync_fetch_and_add(&unprotected_seq, 1);

	__sync_fetch_and_add(&layer->cpus_seq, 1);	/* MB, see below */
	trace("LAYER[%d] now has %d cpus, seq=%llu", layer_id, layer->nr_cpus, layer->cpus_seq);

	/*
	 * layer->nr_llc_cpus[] were updated by the userspace and we've passed a
	 * full MB in the above layer->cpus_seq update. This is interlocked with
	 * layered_enqueue() to guarantee that a task is never left in an empty
	 * LLC without draining enabled. Either they see 0 nr_llcs_cpus and
	 * enable drain or we see the task it enqueued and enable drain.
	 */
	bpf_for(llc_id, 0, nr_llcs) {
		if (layer->nr_llc_cpus[llc_id])
			layer_llc_drain_disable(layer, llc_id);
		else if (scx_bpf_dsq_nr_queued(layer_dsq_id(layer->id, llc_id)))
			layer_llc_drain_enable(layer, llc_id);
	}

	bpf_for(cpu, 0, nr_possible_cpus) {
		if (!(cpuc = lookup_cpu_ctx(cpu)))
			return;
		if (cpuc_in_layer(cpuc, layer))
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}
}

static bool maybe_refresh_layer_cpumasks()
{
	u32 id;

	if (!__sync_lock_test_and_set(&do_refresh_layer_cpumasks, 0))
		return false;

	bpf_for(id, 0, nr_layers)
		refresh_cpumasks(id);

	return true;
}

/*
 * Refreshes all layer cpumasks, this is called via BPF_PROG_RUN from userspace.
 */
SEC("syscall")
__weak s32 BPF_PROG(refresh_layer_cpumasks)
{
	__sync_fetch_and_or(&do_refresh_layer_cpumasks, 1);
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
	struct cached_cpus	layered_cpus_unprotected;
	struct bpf_cpumask __kptr *layered_unprotected_mask;
	bool			all_cpus_allowed;
	bool			cpus_node_aligned;
	u64			runnable_at;
	u64			running_at;
	u64			runtime_avg;
	u64			dsq_id;
	u32			llc_id;

	/* for llcc->queue_runtime */
	u32			qrt_layer_id;
	u32			qrt_llc_id;

	char 			join_layer[SCXCMD_COMLEN];
	u64			layer_refresh_seq;
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

static int handle_cmd(struct task_ctx *taskc, struct scx_cmd *cmd)
{

	_Static_assert(sizeof(*cmd) == MAX_COMM, "scx_cmd has wrong size");

	/* Is this a valid command? */
	if (cmd->prefix != SCXCMD_PREFIX)
		return 0;

	switch (cmd->opcode) {
	case SCXCMD_OP_NONE:
		break;

	case SCXCMD_OP_JOIN:
		__builtin_memcpy(taskc->join_layer, cmd->cmd, SCXCMD_COMLEN);
		break;

	case SCXCMD_OP_LEAVE:
		__builtin_memset(taskc->join_layer, 0, SCXCMD_COMLEN);
		break;

	default:
		break;
	}

	return 0;
}


SEC("tp_btf/task_rename")
int BPF_PROG(tp_task_rename, struct task_struct *p, const char *buf)
{
	struct task_ctx *taskc;
	struct scx_cmd cmd;
	int ret;

	if (!(taskc = lookup_task_ctx_may_fail(p))) {
		bpf_printk("could not find task on rename");
		return -EINVAL;
	}

	taskc->refresh_layer = true;

	ret = bpf_probe_read_str(&cmd, sizeof(cmd), buf);
	if (ret < 0) {
		bpf_printk("could not new task name on rename");
		return -EINVAL;
	}

	handle_cmd(taskc, &cmd);

	return 0;
}

/*
 * Initializes the scheduler to support running in a pid namespace.
 */
SEC("syscall")
int BPF_PROG(initialize_pid_namespace)
{
	struct task_struct *p;

	if (!(p = (struct task_struct*)bpf_get_current_task_btf()))
		return -ENOENT;

	layered_root_tgid = BPF_PROBE_READ(p, tgid);
	trace("CFG layered running with tgid: %d", layered_root_tgid);

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

static void maybe_refresh_layered_cpus_unprotected(struct task_struct *p, struct task_ctx *taskc,
		const struct cpumask *layer_cpumask)
{
	struct bpf_cpumask *task_cpumask = taskc->layered_unprotected_mask;
	u64 cpus_seq = READ_ONCE(unprotected_seq);

	/* Do we have our own unprotected CPU mask? */
	if (!task_cpumask || !layer_cpumask || !unprotected_cpumask)
		return;

	if (should_refresh_cached_cpus(&taskc->layered_cpus_unprotected, 0, cpus_seq)) {
		bpf_cpumask_or(task_cpumask, cast_mask(unprotected_cpumask), layer_cpumask);
		bpf_cpumask_and(task_cpumask, cast_mask(task_cpumask), p->cpus_ptr);

		taskc->layered_cpus_unprotected.id = 0;
		taskc->layered_cpus_unprotected.seq = cpus_seq;

		trace("%s[%d] layered allowed cpumask refreshed to seq=%llu",
		      p->comm, p->pid, taskc->layered_cpus_unprotected.seq);
	}
}

static s32 pick_idle_cpu_from(const struct cpumask *cand_cpumask, s32 prev_cpu,
			      const struct cpumask *idle_smtmask, const struct layer *layer)
{
	bool prev_in_cand;
	s32 cpu;

	if (unlikely(!cand_cpumask || !idle_smtmask))
		return -1;

	prev_in_cand = bpf_cpumask_test_cpu(prev_cpu, cand_cpumask);

	/*
	 * If CPU has SMT, any wholly idle CPU is likely a better pick than
	 * partially idle @prev_cpu.
	 */
	if (smt_enabled) {

		// try prev if prev_over_idle_core
		if (prev_in_cand &&
			layer->prev_over_idle_core) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
				return prev_cpu;
			prev_in_cand = false;
		}

		// try prev if smt sibling empty
		if (prev_in_cand && bpf_cpumask_test_cpu(prev_cpu, idle_smtmask)) {
			if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
				return prev_cpu;
			prev_in_cand = false;
		}

		// try any idle core
		cpu = scx_bpf_pick_idle_cpu(cand_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0)
			return cpu;
	}

	// try prev if not previously tried and failed
	if (prev_in_cand &&
		scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	// return any idle cpu
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
					 prev_cpu, idle_smtmask, layer);
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
					 prev_cpu, idle_smtmask, layer);
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
	bool is_float = layer->task_place == PLACEMENT_FLOAT;
	struct bpf_cpumask *unprot_mask;
	struct cpu_ctx *prev_cpuc;
	u32 layer_id = layer->id;
	u64 cpus_seq;
	s32 cpu;

	if (layer_id >= MAX_LAYERS || !(layer_cpumask = lookup_layer_cpumask(layer_id)))
		return -1;

	if (layer->periodically_refresh && taskc->layer_refresh_seq < layer_refresh_seq_avgruntime)
		taskc->refresh_layer = true;

	/*
	 * Not much to do if bound to a single CPU. Explicitly handle migration
	 * disabled tasks for kernels before SCX_OPS_ENQ_MIGRATION_DISABLED.
	 */
	if (!is_float && (p->nr_cpus_allowed == 1 || is_migration_disabled(p))) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			if (layer->kind == LAYER_KIND_CONFINED &&
			    !bpf_cpumask_test_cpu(prev_cpu, layer_cpumask))
				lstat_inc(LSTAT_AFFN_VIOL, layer, cpuc);
			return prev_cpu;
		} else {
			return -1;
		}
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

		if (layer->kind == LAYER_KIND_CONFINED) {
			has_idle = bpf_cpumask_intersects(layered_cpumask, cpumask);
		} else {
			maybe_refresh_layered_cpus_unprotected(p, taskc, layered_cpumask);
			/*
			 * Use the task's idle unprotected mask if available, otherwise
			 * use the global one.
			 */
			unprot_mask = taskc->layered_unprotected_mask;
			if (!unprot_mask)
				unprot_mask = unprotected_cpumask;

			if (unlikely(!unprot_mask)) {
				scx_bpf_error("unprotected_cpumask not initialized");
				scx_bpf_put_idle_cpumask(cpumask);
				return -1;
			}

			has_idle = bpf_cpumask_intersects(cast_mask(unprot_mask), cpumask);
		}

		scx_bpf_put_idle_cpumask(cpumask);
		if (!has_idle)
			return -1;
	}

	if ((nr_llcs > 1 || nr_nodes > 1) &&
	    !(prev_cpuc = lookup_cpu_ctx(prev_cpu)))
		return -1;
	if (!(idle_smtmask = scx_bpf_get_idle_smtmask()))
		return -1;

	if (is_float)
		goto no_locality;

	/*
	 * If the system has a big/little architecture and uses any related
	 * layer growth algos try to find a cpu in that topology first.
	 */
	cpu = pick_idle_big_little(layer, taskc, idle_smtmask, prev_cpu);
	if (cpu >=0)
		goto out_put;

	/*
	 * Try a CPU in the previous LLC.
	 */
	if (nr_llcs > 1) {
		struct llc_ctx *prev_llcc;

		maybe_refresh_layered_cpus_llc(p, taskc, layer_cpumask,
					       prev_cpuc->llc_id, cpus_seq);
		if (!(cpumask = cast_mask(taskc->layered_llc_mask))) {
			cpu = -1;
			goto out_put;
		}
		if ((cpu = pick_idle_cpu_from(cpumask, prev_cpu, idle_smtmask, layer)) >= 0)
			goto out_put;

		if (!(prev_llcc = lookup_llc_ctx(prev_cpuc->llc_id)) ||
		    prev_llcc->queued_runtime[layer_id] < layer->xllc_mig_min_ns) {
			lstat_inc(LSTAT_XLLC_MIGRATION_SKIP, layer, cpuc);
			cpu = -1;
			goto out_put;
		}
	}

no_locality:
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
		if ((cpu = pick_idle_cpu_from(cpumask, prev_cpu, idle_smtmask, layer)) >= 0)
			goto out_put;
	}

	if ((cpu = pick_idle_cpu_from(layered_cpumask, prev_cpu, idle_smtmask, layer)) >= 0)
		goto out_put;

	/*
	 * If the layer is an open one, we can try the whole machine.
	 */
	if (layer->kind != LAYER_KIND_CONFINED) {
	    maybe_refresh_layered_cpus_unprotected(p, taskc, layered_cpumask);
	    unprot_mask = taskc->layered_unprotected_mask;
	    if (!unprot_mask)
		    unprot_mask = unprotected_cpumask;

	    if ((cpu = pick_idle_cpu_from(cast_mask(unprot_mask), prev_cpu, idle_smtmask, layer)) >= 0) {
		lstat_inc(LSTAT_OPEN_IDLE, layer, cpuc);
		goto out_put;
	    }
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

	maybe_refresh_layer_cpumasks();
	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(p)))
		return prev_cpu;

	/*
	 * We usually update the layer in layered_runnable() to avoid confusion.
	 * As layered_select_cpu() takes place before runnable, new tasks would
	 * still have MAX_LAYERS layer. Just return @prev_cpu.
	 */
	if (taskc->layer_id == MAX_LAYERS || !(layer = lookup_layer(taskc->layer_id)))
		return prev_cpu;

	if (layer->task_place == PLACEMENT_STICK)
		cpu = prev_cpu;
	else
		cpu = pick_idle_cpu(p, prev_cpu, cpuc, taskc, layer, true);

	if (cpu >= 0) {
		lstat_inc(LSTAT_SEL_LOCAL, layer, cpuc);
		taskc->dsq_id = SCX_DSQ_LOCAL;
		scx_bpf_dsq_insert(p, taskc->dsq_id, layer->slice_ns, 0);
		return cpu;
	}

	return prev_cpu;
}

/*
 * XXX - It'd be better to get @cpuc and @enq_flags from the caller but that
 * goes beyond the maximum number of supported arguments and __always_inline
 * causes verification fail with "invalid size of register spill". Lookup cpuc
 * before use and ignore extra enq_flags.
 */
static bool try_preempt_cpu(s32 cand, struct task_struct *p, struct task_ctx *taskc,
			    struct layer *layer, bool preempt_first)
{
	struct cpu_ctx *cpuc, *cand_cpuc, *sib_cpuc = NULL;
	s32 sib;

	if (cand >= nr_possible_cpus || !bpf_cpumask_test_cpu(cand, p->cpus_ptr))
		return false;

	if (!(cand_cpuc = lookup_cpu_ctx(cand)))
		return false;

	if (cand_cpuc->current_preempt)
		return false;

	/*
	 * Don't preempt if protection against is in effect. However, open
	 * layers share CPUs and using the same mechanism between non-preempt
	 * and preempt open layers doesn't make sense. Exclude for now.
	 */
	if (cand_cpuc->protect_owned_preempt && cand_cpuc->running_owned &&
	    !(layer->kind == LAYER_KIND_OPEN && cand_cpuc->running_open))
		return false;

	/*
	 * If exclusive, we want to make sure the sibling CPU, if there's
	 * one, is idle. However, if the sibling CPU is already running a
	 * preempt task, we shouldn't kick it out.
	 */
	if (layer->exclusive && (sib = sibling_cpu(cand)) >= 0 &&
	    (!(sib_cpuc = lookup_cpu_ctx(sib)) || sib_cpuc->current_preempt)) {
		if (!(cpuc = lookup_cpu_ctx(-1)))
			return false;
		lstat_inc(LSTAT_EXCL_COLLISION, layer, cpuc);
		return false;
	}

	/* preempt */
	taskc->dsq_id = SCX_DSQ_LOCAL_ON | cand;
	scx_bpf_dsq_insert(p, taskc->dsq_id, layer->slice_ns, SCX_ENQ_PREEMPT);

	if (!(cpuc = lookup_cpu_ctx(-1)))
		return true;
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

static void task_uncharge_qrt(struct task_ctx *taskc)
{
	struct llc_ctx *llcc;
	u32 layer_id = taskc->qrt_layer_id;

	if (layer_id >= MAX_LAYERS || !(llcc = lookup_llc_ctx(taskc->qrt_llc_id)))
		return;

	__sync_fetch_and_sub(&llcc->queued_runtime[layer_id], taskc->runtime_avg);
	taskc->qrt_layer_id = MAX_LAYERS;
	taskc->qrt_llc_id = MAX_LLCS;
}

static void layer_kick_idle_cpu(struct layer *layer)
{
	const struct cpumask *layer_cpumask, *idle_smtmask;;
	s32 cpu;

	if (!(layer_cpumask = lookup_layer_cpumask(layer->id)) ||
	    !(idle_smtmask = scx_bpf_get_idle_smtmask()))
		return;

	if ((cpu = pick_idle_cpu_from(layer_cpumask, 0, idle_smtmask, layer)) >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

	scx_bpf_put_idle_cpumask(idle_smtmask);
}

void BPF_STRUCT_OPS(layered_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct cpu_ctx *cpuc, *task_cpuc;
	struct task_ctx *taskc;
	struct llc_ctx *llcc;
	struct layer *layer;
	bool wakeup = enq_flags & SCX_ENQ_WAKEUP;
	s32 cpu, task_cpu = scx_bpf_task_cpu(p);
	u64 vtime = p->scx.dsq_vtime;
	u32 llc_id, layer_id;
	bool yielding, try_preempt_first;
	u64 queued_runtime;
	u64 *lstats;

	maybe_refresh_layer_cpumasks();
	if (!(cpuc = lookup_cpu_ctx(-1)) ||
	    !(task_cpuc = lookup_cpu_ctx(task_cpu)) ||
	    !(taskc = lookup_task_ctx(p)))
		return;

	layer_id = taskc->layer_id;
	if (!(layer = lookup_layer(layer_id)))
		return;

	if (enq_flags & SCX_ENQ_REENQ) {
		lstat_inc(LSTAT_ENQ_REENQ, layer, cpuc);
	} else {
		if (wakeup)
			lstat_inc(LSTAT_ENQ_WAKEUP, layer, cpuc);
		else
			lstat_inc(LSTAT_ENQ_EXPIRE, layer, cpuc);
	}

	yielding = cpuc->yielding;
	if (yielding) {
		lstat_inc(LSTAT_YIELD, layer, cpuc);
		cpuc->yielding = false;
	}

	try_preempt_first = cpuc->try_preempt_first;
	cpuc->try_preempt_first = false;

	/*
	 * Does @p prefer to preempt its previous CPU even when there are other
	 * idle CPUs? If @p was already on the CPU (!wakeup), layered_dispatch()
	 * already decided that @p shouldn't continue running on it. Don't
	 * override the decision.
	 */
	if (try_preempt_first && wakeup && !yielding &&
	    try_preempt_cpu(task_cpu, p, taskc, layer, true))
		return;

	/*
	 * If select_cpu() was skipped, try direct dispatching to an idle CPU.
	 */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags) || try_preempt_first) {
		cpu = pick_idle_cpu(p, task_cpu, cpuc, taskc, layer, false);
		if (cpu >= 0) {
			lstat_inc(LSTAT_ENQ_LOCAL, layer, cpuc);
			taskc->dsq_id = SCX_DSQ_LOCAL_ON | cpu;
			scx_bpf_dsq_insert(p, taskc->dsq_id, layer->slice_ns, 0);
			return;
		}
	}

	if (!(task_cpuc = lookup_cpu_ctx(task_cpu)))
		return;

	/*
	 * No idle CPU, try preempting.
	 */
	if ((layer->preempt || is_preempt_kthread(p)) && !yielding) {
		/*
		 * See try_preempt_first block above for explanation on the
		 * wakeup test.
		 */
		if (!try_preempt_first && wakeup &&
		    try_preempt_cpu(task_cpu, p, taskc, layer, false))
			return;

		if (p->nr_cpus_allowed > 1) {
			struct cpu_prox_map *pmap = &task_cpuc->prox_map;

			bpf_for(cpu, 1, MAX_CPUS) {
				if (cpu >= pmap->sys_end)
					break;
				u16 *cpu_p = MEMBER_VPTR(pmap->cpus, [cpu]);
				if (cpu_p && try_preempt_cpu(*cpu_p, p, taskc, layer, false))
					return;
			}
		}

		lstat_inc(LSTAT_PREEMPT_FAIL, layer, cpuc);
	}

	/*
	 * No idle CPU, no preemption, insert into the DSQ. First, update the
	 * associated LLC and limit the amount of budget that an idling task can
	 * accumulate to one slice.
	 */
	llc_id = task_cpuc->llc_id;
	if (llc_id >= MAX_LLCS || !(llcc = lookup_llc_ctx(llc_id)))
		return;

	maybe_update_task_llc(p, taskc, task_cpu);
	if (time_before(vtime, llcc->vtime_now[layer_id] - layer->slice_ns))
		vtime = llcc->vtime_now[layer_id] - layer->slice_ns;

	/*
	 * Special-case per-cpu kthreads and scx_layered userspace so that they
	 * run before preempting layers. This is to guarantee timely execution
	 * of layered userspace code and give boost to per-cpu kthreads as they
	 * are usually important for system performance and responsiveness.
	 */
	if (((p->flags & PF_KTHREAD) && p->nr_cpus_allowed < nr_possible_cpus) ||
	    is_scheduler_task(p)) {
		struct cpumask *layer_cpumask;

		if (layer->kind == LAYER_KIND_CONFINED &&
		    (layer_cpumask = lookup_layer_cpumask(taskc->layer_id)) &&
		    !bpf_cpumask_test_cpu(task_cpu, layer_cpumask))
			lstat_inc(LSTAT_AFFN_VIOL, layer, cpuc);

		if (p->nr_cpus_allowed == 1)
			taskc->dsq_id = SCX_DSQ_LOCAL;
		else
			taskc->dsq_id = task_cpuc->hi_fb_dsq_id;

		scx_bpf_dsq_insert(p, taskc->dsq_id, layer->slice_ns, enq_flags);
		return;
	}

	/*
	 * Tasks with custom affinities or from empty layers can stall if put
	 * into layer DSQs. Put them into a low fallback DSQ which is guaranteed
	 * the lo_fb_share_ppk fraction of each CPU once the tasks have been
	 * queued on it longer than lo_fb_wait_ns.
	 *
	 * When racing against layer CPU allocation updates, tasks with full
	 * affninty may end up in the DSQs of an empty layer. They are handled
	 * by the fallback_cpu.
	 *
	 * FIXME: ->allow_node_aligned is a hack to support node-affine tasks
	 * without making the whole scheduler node aware and should only be used
	 * with open layers on non-saturated machines to avoid possible stalls.
	 */
	if ((!taskc->all_cpus_allowed &&
	     !(layer->allow_node_aligned && taskc->cpus_node_aligned)) ||
	    !layer->nr_cpus) {
		taskc->dsq_id = task_cpuc->lo_fb_dsq_id;
		/*
		 * Start a new lo fallback queued region if the DSQ is empty.
		 * While the following is racy, all that's needed is at least
		 * one of the racing updates to succeed, which is guaranteed.
		 */
		if (!scx_bpf_dsq_nr_queued(taskc->dsq_id))
			llcc->lo_fb_seq++;
		scx_bpf_dsq_insert(p, taskc->dsq_id, layer->slice_ns, enq_flags);
		return;
	}

	/*
	 * A task can be enqueued more than once before going through
	 * ops.running() if the task's property changes which dequeues and
	 * re-enqueues the task. The task does not go through ops.runnable()
	 * again in such cases, so layer association would remain the same.
	 *
	 * XXX: It'd be nice if ops.dequeue() could be used to adjust
	 * queued_runtime but ops.dequeue() is not called for tasks on a
	 * DSQ. Detect the condition here and subtract the previous
	 * contribution.
	 */
	task_uncharge_qrt(taskc);

	taskc->qrt_layer_id = layer_id;
	taskc->qrt_llc_id = llc_id;
	queued_runtime = __sync_fetch_and_add(&llcc->queued_runtime[layer_id],
					      taskc->runtime_avg);
	queued_runtime += taskc->runtime_avg;

	lstats = llcc->lstats[layer_id];

	/* racy, don't care */
	lstats[LLC_LSTAT_LAT] =
		((LAYER_LAT_DECAY_FACTOR - 1) * lstats[LLC_LSTAT_LAT] + queued_runtime) /
		LAYER_LAT_DECAY_FACTOR;
	lstats[LLC_LSTAT_CNT]++;

	taskc->dsq_id = layer_dsq_id(layer_id, llc_id);
	if (layer->fifo)
		scx_bpf_dsq_insert(p, taskc->dsq_id, layer->slice_ns, enq_flags);
	else
		scx_bpf_dsq_insert_vtime(p, taskc->dsq_id, layer->slice_ns, vtime, enq_flags);

	/*
	 * Interlocked with refresh_cpumasks(). scx_bpf_dsq_insert[_vtime]()
	 * always goes through spin lock/unlock and has enough barriers to
	 * guarantee that either they see the task we enqueeud or we see zero
	 * nr_llc_cpus.
	 *
	 * Also interlocked with opportunistic disabling in
	 * try_drain_layer_llcs(). See there.
	 */
	if (!layer->nr_llc_cpus[llc_id]) {
		layer_llc_drain_enable(layer, llc_id);
		layer_kick_idle_cpu(layer);
	}
}

static void account_used(struct cpu_ctx *cpuc, struct task_ctx *taskc, u64 now)
{
	s32 task_lid;
	u64 used;

	used = now - cpuc->used_at;
	if (!used)
		return;

	task_lid = taskc->layer_id;
	if (unlikely(task_lid >= nr_layers)) {
		scx_bpf_error("invalid layer %d", task_lid);
		return;
	}

	cpuc->used_at = now;
	cpuc->usage += used;

	/*
	 * protect_owned/preempt accounting is a bit wrong in that they charge
	 * the execution duration to the layer that just ran which may be
	 * different from the layer that is protected on the CPU. Oh well...
	 */
	if (cpuc->running_owned) {
		cpuc->layer_usages[task_lid][LAYER_USAGE_OWNED] += used;
		if (cpuc->protect_owned)
			cpuc->layer_usages[task_lid][LAYER_USAGE_PROTECTED] += used;
		if (cpuc->protect_owned_preempt)
			cpuc->layer_usages[task_lid][LAYER_USAGE_PROTECTED_PREEMPT] += used;
	} else {
		cpuc->layer_usages[task_lid][LAYER_USAGE_OPEN] += used;
	}

	if (taskc->dsq_id & HI_FB_DSQ_BASE)
		gstat_add(GSTAT_HI_FB_USAGE, cpuc, used);
	else if (taskc->dsq_id & LO_FB_DSQ_BASE)
		gstat_add(GSTAT_LO_FB_USAGE, cpuc, used);

	if (cpuc->running_fallback)
		gstat_add(GSTAT_FB_CPU_USAGE, cpuc, used);
}

static bool keep_running(struct cpu_ctx *cpuc, struct task_struct *p)
{
	struct task_ctx *taskc;
	struct layer *layer;

	if (cpuc->yielding || !max_exec_ns)
		goto no;

	/* does it wanna? */
	if (!(p->scx.flags & SCX_TASK_QUEUED))
		goto no;

	if (!(taskc = lookup_task_ctx(p)) || !(layer = lookup_layer(taskc->layer_id)))
		goto no;

	/* tasks running in low fallback doesn't get to continue */
	if (taskc->dsq_id & LO_FB_DSQ_BASE)
		goto no;

	/* if hi_fb has tasks pending, don't keep running the current one */
	if (scx_bpf_dsq_nr_queued(cpuc->hi_fb_dsq_id))
		goto no;

	/* @p has fully consumed its slice and still wants to run */
	cpuc->ran_current_for += layer->slice_ns;

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
			p->scx.slice = layer->slice_ns;
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
			p->scx.slice = layer->slice_ns;
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

	if (time_before(runnable_at, jiffies_now)) {
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

	consumed = scx_bpf_dsq_move_to_local(*antistall_dsq);

	if (!consumed)
		goto reset;

	gstat_inc(GSTAT_ANTISTALL, cpuc);

	jiffies_now = bpf_jiffies64();

	bpf_for_each(scx_dsq, p, *antistall_dsq, 0) {
		cur_delay = get_delay_sec(p, jiffies_now);

		if (cur_delay > antistall_sec) {
			return consumed;
		}

		goto reset;
	}

reset:
	trace("antistall reset DSQ[%llu] SELECTED_CPU[%llu] DELAY[%llu]",
	      *antistall_dsq, cpuc->cpu, cur_delay);
	*antistall_dsq = SCX_DSQ_INVALID;
	return consumed;
}

static bool try_drain_layer_llcs(struct layer *layer, struct cpu_ctx *cpuc)
{
	u32 cnt = layer->llc_drain_cnt++;
	u32 u;

	/* alternate between prioritizing draining and owned */
	if (cnt & 1)
		return false;

	lstat_inc(LSTAT_LLC_DRAIN_TRY, layer, cpuc);

	bpf_for(u, 0, nr_llcs) {
		u32 llc_id = (u + cnt / 2) % nr_llcs;
		u64 dsq_id = layer_dsq_id(layer->id, llc_id);
		u32 *vptr;
		bool disabled = false, consumed;

		if (!(layer->llcs_to_drain & (1LLU << llc_id)))
			continue;

		if ((vptr = MEMBER_VPTR(layer->nr_llc_cpus, [llc_id])) && *vptr)
			continue;

		/*
		 * Draining is relatively expensive and we want to turn it off
		 * as soon as possible. However, we can't turn it off after
		 * consuming as we can race against enabling and end up turning
		 * off draining and leave the new task in the unserviced DSQ.
		 *
		 * Instead, turn it off if it's likely that the DSQ is going to
		 * be empty after consuming and re-enable afterwards if
		 * necessary to guarantee that draining never stays disabled
		 * with tasks in the DSQ.
		 */
		if (scx_bpf_dsq_nr_queued(dsq_id) <= 1) {
			layer_llc_drain_disable(layer, llc_id);
			disabled = true;
		}

		consumed = scx_bpf_dsq_move_to_local(dsq_id);

		/*
		 * Interlocked with enabling in layered_enqueue(). Either we see
		 * increased nr_queued or they see disable and re-enable. Note
		 * that we can race against nr_llc_cpus update or other draining
		 * CPUs and re-enable unnecessarily. Doesn't matter. Will be
		 * re-tried on the next draining attempt.
		 */
		if (disabled && scx_bpf_dsq_nr_queued(dsq_id))
			layer_llc_drain_enable(layer, llc_id);

		if (consumed) {
			lstat_inc(LSTAT_LLC_DRAIN, layer, cpuc);
			return true;
		}
	}

	return false;
}

static __always_inline bool try_consume_layer(u32 layer_id, struct cpu_ctx *cpuc,
					      struct llc_ctx *llcc)
{
	struct llc_prox_map *llc_pmap = &llcc->prox_map;
	struct layer *layer;
	u32 nid = llc_node_id(llcc->id);
	bool xllc_mig_skipped = false;
	bool skip_remote_node;
	u32 u;

	if (!(layer = lookup_layer(layer_id)))
		return false;

	skip_remote_node = layer->skip_remote_node;

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

			if (skip_remote_node && nid != llc_node_id(remote_llcc->id)) {
				lstat_inc(LSTAT_SKIP_REMOTE_NODE, layer, cpuc);
				continue;
			}

			if (remote_llcc->queued_runtime[layer_id] < layer->xllc_mig_min_ns) {
				xllc_mig_skipped = true;
				continue;
			}
		}

		if (scx_bpf_dsq_move_to_local(layer_dsq_id(layer_id, *llc_idp)))
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
	struct cpu_ctx *cpuc, *sib_cpuc;
	struct llc_ctx *llcc;
	bool tried_preempting = false, tried_lo_fb = false;
	s32 sib = sibling_cpu(cpu);
	u32 nr_ogp_layers = nr_op_layers + nr_gp_layers;
	u32 nr_ogn_layers = nr_on_layers + nr_gn_layers;

	maybe_refresh_layer_cpumasks();

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

	/* always consume hi_fb_dsq_id first for kthreads */
	if (scx_bpf_dsq_move_to_local(cpuc->hi_fb_dsq_id))
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
		cpuc->running_fallback = true;
		return;
	}

	/*
	 * Low fallback DSQ execution is forced upto lo_fb_share_ppk fraction
	 * after the DSQ had tasks queued for longer than lo_fb_wait_ns.
	 */
	if (scx_bpf_dsq_nr_queued(cpuc->lo_fb_dsq_id)) {
		u64 now = scx_bpf_now();
		u64 dur, usage;

		/*
		 * llcc->lo_fb_seq is bumped whenever the low fallback DSQ
		 * transitions from empty, which triggers a new lo_fb_wait_ns
		 * window on each CPU. CPUs would reach here at different times
		 * hopefully avoiding thundering herd.
		 */
		if (cpuc->lo_fb_seq != llcc->lo_fb_seq) {
			cpuc->lo_fb_seq_at = now;
			cpuc->lo_fb_usage_base = cpuc->gstats[GSTAT_LO_FB_USAGE];
			cpuc->lo_fb_seq = llcc->lo_fb_seq;
		}

		/*
		 * lo_fb_share_ppk is applied only after lo_fb_wait_ns has
		 * passed. Always add lo_fb_wait_ns to usage so that the wait
		 * period doesn't contribute to the execution budget.
		 */
		dur = now - cpuc->lo_fb_seq_at;
		usage = cpuc->gstats[GSTAT_LO_FB_USAGE] + lo_fb_wait_ns -
			cpuc->lo_fb_usage_base;

		if (dur > lo_fb_wait_ns && 1024 * usage < lo_fb_share_ppk * dur) {
			if (scx_bpf_dsq_move_to_local(cpuc->lo_fb_dsq_id))
				return;
			tried_lo_fb = true;
		}
	}

	if (cpuc->in_open_layers) {
		/*
		 * CPU is in an open layer.
		 */
		if (cpuc->protect_owned) {
			if (try_consume_layers(cpuc->op_layer_order, nr_op_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
			if (try_consume_layers(cpuc->on_layer_order, nr_on_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
			if (try_consume_layers(cpuc->gp_layer_order, nr_gp_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
			if (try_consume_layers(cpuc->gn_layer_order, nr_gn_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
		} else {
			if (try_consume_layers(cpuc->op_layer_order, nr_op_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
			if (try_consume_layers(cpuc->gp_layer_order, nr_gp_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
			if (try_consume_layers(cpuc->ogn_layer_order, nr_ogn_layers,
					       MAX_LAYERS, cpuc, llcc))
				return;
		}
	} else {
		/*
		 * CPU is in a grouped or confined layer or not assigned.
		 */
		struct layer *owner_layer = NULL;

		if (cpuc->layer_id < MAX_LAYERS)
			owner_layer = &layers[cpuc->layer_id];

		/*
		 * Grouped/open preempt layers first if there's no owner layer
		 * or the owner layer is not protected or preempting.
		 */
		if (!owner_layer || (!owner_layer->is_protected && !cpuc->protect_owned && !owner_layer->preempt)) {
			if (try_consume_layers(cpuc->ogp_layer_order, nr_ogp_layers,
					       cpuc->layer_id, cpuc, llcc))
				return;

			tried_preempting = true;
		}

		/* owner layer */
		if (owner_layer) {
			if (owner_layer->llcs_to_drain &&
			    try_drain_layer_llcs(owner_layer, cpuc))
				return;
			if (try_consume_layer(owner_layer->id, cpuc, llcc))
				return;

			/* CPU is in a protected layer, do not pull from other layers. */
			if (owner_layer->is_protected)
				return;
		}

		/* try grouped/open preempting if not tried yet */
		if (!tried_preempting &&
		    try_consume_layers(cpuc->ogp_layer_order, nr_ogp_layers,
				       cpuc->layer_id, cpuc, llcc))
			return;

		/* grouped/open non-preempt layers */
		if (try_consume_layers(cpuc->ogn_layer_order, nr_ogn_layers,
				       cpuc->layer_id, cpuc, llcc))
			return;
	}

	if (!tried_lo_fb && scx_bpf_dsq_move_to_local(cpuc->lo_fb_dsq_id))
		return;
}

void BPF_STRUCT_OPS(layered_tick, struct task_struct *p)
{
	struct cpu_ctx *cpuc;
	struct task_ctx *taskc;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(p)))
		return;

	account_used(cpuc, taskc, scx_bpf_now());
}

static __noinline bool match_one(struct layer_match *match,
				 struct task_struct *p, const char *cgrp_path)
{
	bool result = false;
	const struct cred *cred;

	switch (match->kind) {
	case MATCH_CGROUP_PREFIX: {
		return match_prefix_suffix(match->cgroup_prefix, cgrp_path, false);
	}
	case MATCH_CGROUP_SUFFIX: {
		return match_prefix_suffix(match->cgroup_suffix, cgrp_path, true);
	}
	case MATCH_COMM_PREFIX: {
		char comm[MAX_COMM];
		__builtin_memcpy(comm, p->comm, MAX_COMM);
		return match_prefix_suffix(match->comm_prefix, comm, false);
	}
	case MATCH_PCOMM_PREFIX: {
		char pcomm[MAX_COMM];

		__builtin_memcpy(pcomm, p->group_leader->comm, MAX_COMM);
		return match_prefix_suffix(match->pcomm_prefix, pcomm, false);
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
	case MATCH_NSPID_EQUALS: {
		// To do namespace pid matching we need to translate the root
		// pid from bpf side to the namespace pid.
		bpf_rcu_read_lock();
		struct pid *p_pid = get_task_pid_ptr(p, PIDTYPE_PID);
		struct pid_namespace *pid_ns = get_task_pid_ns(p, PIDTYPE_TGID);
		if (!p_pid || !pid_ns) {
			bpf_rcu_read_unlock();
			return result;
		}
		pid_t nspid = get_pid_nr_ns(p_pid, pid_ns);
		u64 nsid = BPF_CORE_READ(pid_ns, ns.inum);
		bpf_rcu_read_unlock();
		return (u32)nspid == match->pid && nsid == match->nsid;
	}
	case MATCH_NS_EQUALS: {
		bpf_rcu_read_lock();
		struct pid *p_pid = get_task_pid_ptr(p, PIDTYPE_PID);
		struct pid_namespace *pid_ns = get_task_pid_ns(p, PIDTYPE_TGID);
		if (!p_pid || !pid_ns) {
			bpf_rcu_read_unlock();
			return result;
		}
		u64 nsid = BPF_CORE_READ(pid_ns, ns.inum);
		bpf_rcu_read_unlock();
		return nsid == match->nsid;
	}
	case MATCH_SCXCMD_JOIN: {
		struct task_ctx *taskc = lookup_task_ctx_may_fail(p);
		if (!taskc) {
			scx_bpf_error("could not find task");
			return false;
		}

		/* The empty string means "no join command". */
		if (!taskc->join_layer[0])
			return false;

		return match_prefix_suffix(match->comm_prefix, taskc->join_layer,
			false);
	}
	case MATCH_IS_GROUP_LEADER: {
		// There is nuance to this around exec(2)s and group leader swaps.
		// See https://github.com/sched-ext/scx/issues/610 for more details.
		return (p->tgid == p->pid) == match->is_group_leader;
	}
	case MATCH_IS_KTHREAD:
		return p->flags & PF_KTHREAD;
	case MATCH_USED_GPU_TID: {
			u32 tid;
			bool pid_present = false;

			if (!enable_gpu_support)
				scx_bpf_error("UsedGpuTid requires --enable_gpu_support");

			tid = p->pid;

			if (bpf_map_lookup_elem(&gpu_tid, &tid))
				pid_present = true;

			return pid_present == match->used_gpu_tid;
	}
	case MATCH_USED_GPU_PID: {
			u32 tgid;
			bool pid_present = false;

			if (!enable_gpu_support)
				scx_bpf_error("UsedGpuPid requires --enable_gpu_support");

			tgid = p->tgid;

			if (bpf_map_lookup_elem(&gpu_tgid, &tgid))
				pid_present = true;

			return pid_present == match->used_gpu_pid;
	}
	case MATCH_AVG_RUNTIME: {
			struct task_ctx *taskc = lookup_task_ctx_may_fail(p);
			if (!taskc) {
				scx_bpf_error("could not find task");
				return false;
			}

			u64 avg_runtime_us = taskc->runtime_avg / 1000;

			if (!taskc) {
				scx_bpf_error("could not find task");
				return false;
			}

			/* To match, we must get min <= time < max. */
			return match->min_avg_runtime_us <= avg_runtime_us &&
				avg_runtime_us < match->max_avg_runtime_us;
	}

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
			if (!(match_one(match, p, cgrp_path) == !match->exclude)) {
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
	taskc->layer_refresh_seq = layer_refresh_seq_avgruntime;

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
		taskc->layered_cpus.seq = -1;
		taskc->layered_cpus_llc.seq = -1;
		taskc->layered_cpus_node.seq = -1;
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
		cpuc->hi_fb_dsq_id = hi_fb_dsq_id(llc_id);
		cpuc->lo_fb_dsq_id = lo_fb_dsq_id(llc_id);
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
	u64 now = scx_bpf_now();

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
	u64 now = scx_bpf_now();
	u32 layer_id;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(llcc = lookup_llc_ctx(cpuc->llc_id)) ||
	    !(taskc = lookup_task_ctx(p)))
		return;

	layer_id = taskc->layer_id;
	if (!(layer = lookup_layer(layer_id)))
		return;

	task_uncharge_qrt(taskc);

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
	if (time_before(llcc->vtime_now[layer_id], p->scx.dsq_vtime))
		llcc->vtime_now[layer_id] = p->scx.dsq_vtime;

	cpuc->current_preempt = layer->preempt || is_preempt_kthread(p);
	cpuc->current_exclusive = layer->exclusive;
	cpuc->task_layer_id = taskc->layer_id;
	cpuc->used_at = now;
	taskc->running_at = now;
	cpuc->is_protected = layer->is_protected;

	/* running an owned task if the task is on the layer owning the CPU */
	if (layer->kind == LAYER_KIND_OPEN) {
		cpuc->running_owned = cpuc->in_open_layers;
		cpuc->running_open = true;
	} else {
		cpuc->running_owned = taskc->layer_id == cpuc->layer_id;
		cpuc->running_open = false;
	}

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
	struct layer *task_layer;
	u64 now = scx_bpf_now();
	u64 usage_since_idle;
	s32 task_lid;
	u64 runtime;

	if (!(cpuc = lookup_cpu_ctx(-1)) || !(taskc = lookup_task_ctx(p)))
		return;

	task_lid = taskc->layer_id;
	if (!(task_layer = lookup_layer(task_lid)))
		return;

	runtime = now - taskc->running_at;
	taskc->runtime_avg =
		((RUNTIME_DECAY_FACTOR - 1) * taskc->runtime_avg + runtime) /
		RUNTIME_DECAY_FACTOR;

	account_used(cpuc, taskc, now);

	if (taskc->dsq_id & HI_FB_DSQ_BASE)
		gstat_inc(GSTAT_HI_FB_EVENTS, cpuc);
	else if (taskc->dsq_id & LO_FB_DSQ_BASE)
		gstat_inc(GSTAT_LO_FB_EVENTS, cpuc);

	/*
	 * Owned execution protection. Apply iff the CPU stayed saturated for
	 * longer than twice the slice.
	 */
	usage_since_idle = cpuc->usage - cpuc->usage_at_idle;

	cpuc->protect_owned = false;
	cpuc->protect_owned_preempt = false;
	cpuc->is_protected = false;

	if (cpuc->in_open_layers) {
		if (task_layer->kind == LAYER_KIND_OPEN && !task_layer->preempt) {
			cpuc->protect_owned = usage_since_idle > min_open_layer_disallow_open_after_ns;
			cpuc->protect_owned_preempt = usage_since_idle > min_open_layer_disallow_preempt_after_ns;
		}
	} else {
		struct layer *cpu_layer = NULL;

		if (cpuc->layer_id != MAX_LAYERS &&
		    !(cpu_layer = lookup_layer(cpuc->layer_id)))
			return;

		if (cpu_layer) {
			cpuc->protect_owned = usage_since_idle > cpu_layer->disallow_open_after_ns;
			cpuc->protect_owned_preempt = usage_since_idle > cpu_layer->disallow_preempt_after_ns;
		}
	}

	cpuc->running_fallback = false;
	cpuc->current_preempt = false;
	cpuc->prev_exclusive = cpuc->current_exclusive;
	cpuc->current_exclusive = false;
	cpuc->task_layer_id = MAX_LAYERS;

	/*
	 * Apply min_exec_us, scale the execution time by the inverse of the
	 * weight and charge.
	 */
	if (runtime < task_layer->min_exec_ns) {
		lstat_inc(LSTAT_MIN_EXEC, task_layer, cpuc);
		lstat_add(LSTAT_MIN_EXEC_NS, task_layer, cpuc, task_layer->min_exec_ns - runtime);
		runtime = task_layer->min_exec_ns;
	}

	if (cpuc->yielding && runtime < task_layer->slice_ns)
		runtime = task_layer->slice_ns;
	p->scx.dsq_vtime += runtime * 100 / p->scx.weight;
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

static void refresh_cpus_flags(struct task_ctx *taskc,
			       const struct cpumask *cpumask)
{
	u32 node_id;

	if (!all_cpumask) {
		scx_bpf_error("NULL all_cpumask");
		return;
	}

	taskc->all_cpus_allowed = bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);

	taskc->cpus_node_aligned = true;

	bpf_for(node_id, 0, nr_nodes) {
		struct node_ctx *nodec;
		const struct cpumask *node_cpumask;

		if (!(nodec = lookup_node_ctx(node_id)) ||
		    !(node_cpumask = cast_mask(nodec->cpumask)))
			return;

		/* not llc aligned if partially overlaps */
		if (bpf_cpumask_intersects(node_cpumask, cpumask) &&
		    !bpf_cpumask_subset(node_cpumask, cpumask)) {
			taskc->cpus_node_aligned = false;
			break;
		}
	}
}

static int init_cached_cpus(struct cached_cpus *ccpus)
{
	ccpus->id = -1;

	return 0;
}

static int maybe_init_task_unprotected_mask(struct task_struct *p, struct task_ctx *taskc)
{
	struct bpf_cpumask *cpumask;
	int ret;

	/* We don't need our own mask, we have no placement restrictions. */
	if (bpf_cpumask_full(p->cpus_ptr))
		return 0;

	/* Already initialized. */
	if (taskc->layered_unprotected_mask)
		return 0;

	ret = init_cached_cpus(&taskc->layered_cpus_unprotected);
	if (ret)
		return ret;

	if (!(cpumask = bpf_cpumask_create()))
		return -ENOMEM;

	if ((cpumask = bpf_kptr_xchg(&taskc->layered_unprotected_mask, cpumask))) {
		bpf_cpumask_release(cpumask);
		return -EINVAL;
	}

	return 0;
}

void BPF_STRUCT_OPS(layered_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	refresh_cpus_flags(taskc, cpumask);

	/* invalidate all cached cpumasks */
	taskc->layered_cpus.seq = -1;
	taskc->layered_cpus_llc.seq = -1;
	taskc->layered_cpus_node.seq = -1;
	taskc->layered_cpus_unprotected.seq = -1;

	maybe_init_task_unprotected_mask(p, taskc);
}

void BPF_STRUCT_OPS(layered_update_idle, s32 cpu, bool idle)
{
	struct cpu_ctx *cpuc;

	if (!idle || !(cpuc = lookup_cpu_ctx(cpu)))
		return;

	cpuc->protect_owned = false;
	cpuc->usage_at_idle = cpuc->usage;
}

void BPF_STRUCT_OPS(layered_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	scx_bpf_reenqueue_local();
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

	// Unprotected CPU idle mask setup if necessary
	ret = maybe_init_task_unprotected_mask(p, taskc);
	if (ret)
		return ret;

	taskc->pid = p->pid;
	taskc->last_cpu = -1;
	taskc->layer_id = MAX_LAYERS;
	taskc->refresh_layer = true;
	taskc->llc_id = MAX_LLCS;
	taskc->qrt_layer_id = MAX_LLCS;
	taskc->qrt_llc_id = MAX_LLCS;

	/*
	 * Start runtime_avg at some arbitrary sane-ish value. If this becomes a
	 * problem, we can track per-parent avg new task initial runtime avg and
	 * used that instead.
	 */
	taskc->runtime_avg = slice_ns / 4;

	refresh_cpus_flags(taskc, p->cpus_ptr);

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

void BPF_STRUCT_OPS(layered_disable, struct task_struct *p)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	/*
	 * XXX: Ideally, this should be in ops.dequeue(). See
	 * layered_enqueue().
	 */
	task_uncharge_qrt(taskc);
}

static s64 dsq_first_runnable_at_ms(u64 dsq_id, u64 now)
{
	struct task_struct *p;

	bpf_for_each(scx_dsq, p, dsq_id, 0) {
		struct task_ctx *taskc;

		if ((taskc = lookup_task_ctx(p))) {
			u64 runnable_at = taskc->runnable_at;

			if (runnable_at >= now)
				return ((taskc->runnable_at - now) / 1000000);
			else
				return -((now - taskc->runnable_at) / 1000000);
		}
	}

	return 0;
}

__hidden void dump_cpumask_word(s32 word, struct cpumask *cpumask)
{
	u32 u, v = 0;

	bpf_for(u, 0, 32) {
		s32 cpu = 32 * word + u;
		if (cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(cpu, cpumask))
			v |= 1 << u;
	}
	scx_bpf_dump("%08x", v);
}

static void dump_layer_cpumask(int id)
{
	struct cpumask *layer_cpumask;
	u32 word, nr_words = (nr_cpu_ids + 31) / 32;

	if (!(layer_cpumask = lookup_layer_cpumask(id)))
		return;

	bpf_for(word, 0, nr_words) {
		if (word)
			scx_bpf_dump(",");
		dump_cpumask_word(nr_words - word - 1, layer_cpumask);
	}
}

void BPF_STRUCT_OPS(layered_dump, struct scx_dump_ctx *dctx)
{
	u64 now = scx_bpf_now();
	u64 dsq_id;
	int i, j;
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

			dsq_id = layer_dsq_id(layer->id, j);
			scx_bpf_dump("LAYER[%d](%s)-DSQ[%llx] nr_cpus=%u nr_queued=%d %+lldms\n",
				     i, layer->name, dsq_id, layer->nr_cpus,
				     scx_bpf_dsq_nr_queued(dsq_id),
				     dsq_first_runnable_at_ms(dsq_id, now));
		}
		scx_bpf_dump("LAYER[%d](%s) CPUS=", i, layer->name);
		dump_layer_cpumask(i);
		scx_bpf_dump("\n");
	}
	bpf_for(i, 0, nr_llcs) {
		dsq_id = hi_fb_dsq_id(i);
		scx_bpf_dump("HI_[%llx] nr_queued=%d %+lldms\n",
			     dsq_id, scx_bpf_dsq_nr_queued(dsq_id),
			     dsq_first_runnable_at_ms(dsq_id, now));
		dsq_id = lo_fb_dsq_id(i);
		scx_bpf_dump("LO_FALLBACK[%llx] nr_queued=%d %+lldms\n",
			     dsq_id, scx_bpf_dsq_nr_queued(dsq_id),
			     dsq_first_runnable_at_ms(dsq_id, now));
	}
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

	bpf_for(llc, 0, nr_llcs) {
		antistall_set(hi_fb_dsq_id(llc), jiffies_now);
		antistall_set(lo_fb_dsq_id(llc), jiffies_now);
	}

	return true;
}

bool run_timer_cb(int key)
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

/*
 * Initializes per-layer specific data structures.
 */
static s32 init_layer(int layer_id)
{
	struct bpf_cpumask *cpumask;
	struct layer_cpumask_wrapper *cpumaskw;
	struct layer *layer = &layers[layer_id];
	int i, j, ret;

	dbg("CFG LAYER[%d][%s] min_exec_ns=%lu open=%d preempt=%d exclusive=%d",
	    layer_id, layer->name, layer->min_exec_ns,
	    layer->kind != LAYER_KIND_CONFINED,
	    layer->preempt, layer->exclusive);
	dbg("CFG      disallow_open/preempt_after/protected=%lu/%lu/%d",
	    layer->disallow_open_after_ns, layer->disallow_preempt_after_ns,
	    layer->is_protected);

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
			case MATCH_NSPID_EQUALS:
				dbg("%s NSID %lld PID %d",
				    header, match->nsid, match->pid);
				break;
			case MATCH_NS_EQUALS:
				dbg("%s NSID %lld", header, match->nsid);
				break;
			case MATCH_SCXCMD_JOIN:
				dbg("%s SCXCMD_JOIN \"%s\"", header, match->comm_prefix);
				break;
			case MATCH_IS_GROUP_LEADER:
				dbg("%s IS_GROUP_LEADER %d", header, match->is_group_leader);
				break;
			case MATCH_IS_KTHREAD:
				dbg("%s IS_KTHREAD %d", header, match->is_kthread);
				break;
			case MATCH_USED_GPU_TID:
				dbg("%s GPU_TID %d", header, match->used_gpu_tid);
				break;
			case MATCH_USED_GPU_PID:
				dbg("%s GPU_PID %d", header, match->used_gpu_pid);
				break;
			case MATCH_AVG_RUNTIME:
				layer->periodically_refresh = true;
				dbg("%s AVG_RUNTIME [%lluus, %lluus)", header,
					match->min_avg_runtime_us,
					match->max_avg_runtime_us);
			case MATCH_CGROUP_SUFFIX:
				dbg("%s CGROUP_SUFFIX \"%s\"", header, match->cgroup_suffix);
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
		u64 dsq_id = layer_dsq_id(layer_id, i);
		int node_id = llc_node_id(i);

		dbg("CFG creating DSQ 0x%llx for layer %d %s on LLC %d (node %d)",
		    dsq_id, layer_id, layer->name, i, node_id);
		ret = scx_bpf_create_dsq(dsq_id, node_id);
		if (ret < 0)
			return ret;
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

	bpf_for(i, 0, nr_op_layers + nr_gp_layers)
		dbg("CFG: CPU[%d] ogp_layer_order[%d]=%d",
		    cpu, i, cpuc->ogp_layer_order[i]);
	bpf_for(i, 0, nr_on_layers + nr_gn_layers)
		dbg("CFG: CPU[%d] ogn_layer_order[%d]=%d",
		    cpu, i, cpuc->ogn_layer_order[i]);

	bpf_for(i, 0, nr_op_layers)
		dbg("CFG: CPU[%d] op_layer_order[%d]=%d",
		    cpu, i, cpuc->op_layer_order[i]);
	bpf_for(i, 0, nr_on_layers)
		dbg("CFG: CPU[%d] on_layer_order[%d]=%d",
		    cpu, i, cpuc->on_layer_order[i]);
	bpf_for(i, 0, nr_gp_layers)
		dbg("CFG: CPU[%d] gp_layer_order[%d]=%d",
		    cpu, i, cpuc->gp_layer_order[i]);
	bpf_for(i, 0, nr_gn_layers)
		dbg("CFG: CPU[%d] gn_layer_order[%d]=%d",
		    cpu, i, cpuc->gn_layer_order[i]);

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(layered_init)
{
	struct bpf_cpumask *cpumask, *tmp_big_cpumask, *tmp_unprotected_cpumask;
	int i, nr_online_cpus, ret;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	tmp_big_cpumask = bpf_cpumask_create();
	if (!tmp_big_cpumask) {
		bpf_cpumask_release(cpumask);
		return -ENOMEM;
	}

	tmp_unprotected_cpumask = bpf_cpumask_create();
	if (!tmp_unprotected_cpumask) {
		bpf_cpumask_release(tmp_big_cpumask);
		bpf_cpumask_release(cpumask);
		return -ENOMEM;
	}

	nr_online_cpus = 0;
	bpf_for(i, 0, nr_possible_cpus) {
		ret = init_cpu(i, &nr_online_cpus, cpumask, tmp_big_cpumask);
		if (ret != 0) {
			bpf_cpumask_release(cpumask);
			bpf_cpumask_release(tmp_big_cpumask);
			bpf_cpumask_release(tmp_unprotected_cpumask);
			return ret;
		}
	}

	cpumask = bpf_kptr_xchg(&all_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	tmp_big_cpumask = bpf_kptr_xchg(&big_cpumask, tmp_big_cpumask);
	if (tmp_big_cpumask)
		bpf_cpumask_release(tmp_big_cpumask);

	tmp_unprotected_cpumask = bpf_kptr_xchg(&unprotected_cpumask, tmp_unprotected_cpumask);
	if (tmp_unprotected_cpumask)
		bpf_cpumask_release(tmp_unprotected_cpumask);

	bpf_for(i, 0, nr_nodes) {
		ret = create_node(i);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, nr_llcs) {
		ret = create_llc(i);
		if (ret)
			return ret;
	}

	dbg("CFG: Dumping configuration, nr_online_cpus=%d smt_enabled=%d little_cores=%d",
	    nr_online_cpus, smt_enabled, has_little_cores);
	dbg("CFG: min_open_layer_disallow_open/preempt_after=%lu/%lu",
	    min_open_layer_disallow_open_after_ns, min_open_layer_disallow_preempt_after_ns);

	bpf_for(i, 0, nr_layers) {
		ret = init_layer(i);
		if (ret != 0)
			return ret;
	}

	bpf_for(i, 0, nr_llcs) {
		u64 dsq_id;

		dsq_id = hi_fb_dsq_id(i);
		dbg("CFG creating hi fallback DSQ 0x%llx on LLC %d", dsq_id, i);
		ret = scx_bpf_create_dsq(dsq_id, llc_node_id(i));
		if (ret < 0)
			return ret;

		dsq_id = lo_fb_dsq_id(i);
		dbg("CFG creating lo fallback DSQ 0x%llx on LLC %d", dsq_id, i);
		ret = scx_bpf_create_dsq(dsq_id, llc_node_id(i));
		if (ret < 0)
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
	       .tick			= (void *)layered_tick,
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
	       .disable			= (void *)layered_disable,
	       .dump			= (void *)layered_dump,
	       .init			= (void *)layered_init,
	       .exit			= (void *)layered_exit,
	       .flags			= SCX_OPS_KEEP_BUILTIN_IDLE,
	       .name			= "layered");
