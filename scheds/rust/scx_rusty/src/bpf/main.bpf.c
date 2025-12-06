/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_rusty is a multi-domain BPF / userspace hybrid scheduler where the BPF
 * part does simple round robin in each domain and the userspace part
 * calculates the load factor of each domain and tells the BPF part how to load
 * balance the domains.
 *
 * Every task has an entry in the task_data map which lists which domain the
 * task belongs to. When a task first enters the system (rusty_prep_enable),
 * they are round-robined to a domain.
 *
 * rusty_select_cpu is the primary scheduling logic, invoked when a task
 * becomes runnable. A task's target_dom field is populated by userspace to inform 
 * the BPF scheduler that a task should be migrated to a new domain. Otherwise, 
 * the task is scheduled in priority order as follows:
 * * The current core if the task was woken up synchronously and there are idle
 *   cpus in the system
 * * The previous core, if idle
 * * The pinned-to core if the task is pinned to a specific core
 * * Any idle cpu in the domain
 *
 * If none of the above conditions are met, then the task is enqueued to a
 * dispatch queue corresponding to the domain (rusty_enqueue).
 *
 * rusty_dispatch will attempt to consume a task from its domain's
 * corresponding dispatch queue (this occurs after scheduling any tasks directly
 * assigned to it due to the logic in rusty_select_cpu). If no task is found,
 * then greedy load stealing will attempt to find a task on another dispatch
 * queue to run.
 *
 * Load balancing is almost entirely handled by userspace. BPF populates the
 * task weight, dom mask and current dom in the task map and executes the
 * load balance based on userspace's setting of the target_dom field.
 */

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "ravg_impl.bpf.h"
#include "sdt_task.h"
#include "intf.h"
#include "types.h"
#include "lb_domain.h"

#include <scx/bpf_arena_common.bpf.h>
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * const volatiles are set during initialization and treated as consts by the
 * jit compiler.
 */

/*
 * Domains and cpus
 */
const volatile u32 nr_doms = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_nodes = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_cpu_ids = 64;	/* !0 for veristat, set during init */
const volatile u32 cpu_dom_id_map[MAX_CPUS];
const volatile u32 dom_numa_id_map[MAX_DOMS];
const volatile u64 dom_cpumasks[MAX_DOMS][MAX_CPUS / 64];
const volatile u64 numa_cpumasks[MAX_NUMA_NODES][MAX_CPUS / 64];
const volatile u32 load_half_life = 1000000000	/* 1s */;

const volatile bool kthreads_local;
const volatile bool fifo_sched = false;
const volatile bool direct_greedy_numa;
const volatile bool mempolicy_affinity;
const volatile u32 greedy_threshold;
const volatile u32 greedy_threshold_x_numa;
const volatile u32 rusty_perf_mode;
const volatile u32 debug;

/* base slice duration */
volatile u64 slice_ns;

struct bpfmask_wrapper {
	struct bpf_cpumask __kptr *instance;
};

struct rusty_percpu_storage {
	struct bpf_cpumask __kptr *bpfmask;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct rusty_percpu_storage);
	__uint(max_entries, 1);
} scx_percpu_bpfmask_map SEC(".maps");

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

static int scx_rusty_percpu_storage_init(void)
{
	void *map = &scx_percpu_bpfmask_map;
	struct rusty_percpu_storage *storage;
	const u32 zero = 0;
	int ret, i;

	bpf_for (i, 0, nr_cpu_ids) {
		storage = bpf_map_lookup_percpu_elem(map, &zero, i);
		if (!storage) {
			/* Should be impossible. */
			scx_bpf_error("Did not find map entry");
			return -EINVAL;
		}

		ret = create_save_cpumask(&storage->bpfmask);
		if (ret)
			return ret;
	}

	return 0;
}

static struct bpf_cpumask *scx_percpu_bpfmask(void)
{
	struct rusty_percpu_storage *storage;
	void *map = &scx_percpu_bpfmask_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		scx_bpf_error("Did not find map entry");
		return NULL;
	}

	if (!storage->bpfmask)
		scx_bpf_error("Did not properly initialize singleton");

	return storage->bpfmask;
}

/*
 * Per-CPU context
 */
struct pcpu_ctx {
	u32 dom_rr_cur; /* used when scanning other doms */
	u32 dom_id;
	/*
	 * Add some padding so that libbpf-rs can generate the rest of the
	 * padding to CACHELINE_SIZE. This is necessary for now because most
	 * versions of rust can't generate Default impls for arrays of more
	 * than 32 elements, so if the struct requires more than 32 bytes of
	 * padding, rustc will error out.
	 *
	 * This is currently being fixed in libbpf-cargo, so we should be able
	 * to remove this workaround soon.
	 */
	u32 pad[8];
} __attribute__((aligned(CACHELINE_SIZE)));

struct pcpu_ctx pcpu_ctx[MAX_CPUS];

/*
 * Numa node context
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NUMA_NODES);
	__uint(map_flags, 0);
} node_data SEC(".maps");

struct lock_wrapper {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct lock_wrapper);
	__uint(max_entries, MAX_DOMS * LB_LOAD_BUCKETS);
	__uint(map_flags, 0);
} dom_dcycle_locks SEC(".maps");

const u64 ravg_1 = 1 << RAVG_FRAC_BITS;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct task_struct *);
	__type(value, struct bpfmask_wrapper);
	__uint(max_entries, 1000000);
	__uint(map_flags, 0);
} task_masks SEC(".maps");

static struct task_ctx *try_lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx __arena *taskc = sdt_task_data(p);
	cast_kern(taskc);
	return (struct task_ctx *)taskc;
}

static struct bpf_cpumask *lookup_task_bpfmask(struct task_struct *p)
{
	struct bpfmask_wrapper *wrapper;

	wrapper = bpf_map_lookup_elem(&task_masks, &p);
	if (!wrapper) {
		scx_bpf_error("lookup_mask_bpfmask failed for task %p", p);
		return NULL;
	}

	return wrapper->instance;
}

static struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = try_lookup_task_ctx(p);
	if (!taskc)
		scx_bpf_error("task_ctx lookup failed for task %p", p);

	return taskc;
}

static struct task_ctx *lookup_task_ctx_mask(struct task_struct *p, struct bpf_cpumask **p_cpumaskp)
{
	struct task_ctx *taskc;

	if (p_cpumaskp == NULL) {
		scx_bpf_error("no mask pointer provided");
		return NULL;
	}

	taskc = lookup_task_ctx(p);
	if (!taskc)
		scx_bpf_error("task_ctx lookup failed for task %p", p);

	*p_cpumaskp = lookup_task_bpfmask(p);
	if (*p_cpumaskp == NULL)
		scx_bpf_error("task bpf_cpumask lookup failed for task %p", p);

	return taskc;
}

static dom_ptr task_domain(struct task_ctx *taskc)
{
	dom_ptr domc = taskc->domc;

	cast_kern(domc);

	return domc;
}

static struct pcpu_ctx *lookup_pcpu_ctx(s32 cpu)
{
	struct pcpu_ctx *pcpuc;

	pcpuc = MEMBER_VPTR(pcpu_ctx, [cpu]);
	if (!pcpuc)
		scx_bpf_error("Failed to lookup pcpu ctx for %d", cpu);

	return pcpuc;
}

static inline u32 weight_to_bucket_idx(u32 weight)
{
	/* Weight is calculated linearly, and is within range of [1, 10000] */
	return weight * LB_LOAD_BUCKETS / LB_MAX_WEIGHT;
}

static void task_load_adj(struct task_ctx *taskc,
			  u64 now, bool runnable)
{
	taskc->runnable = runnable;
	ravg_accumulate(&taskc->dcyc_rd, taskc->runnable, now, load_half_life);
}

static struct bucket_ctx *lookup_dom_bucket(dom_ptr dom_ctx,
					    u32 weight, u32 *bucket_id)
{
	u32 idx = weight_to_bucket_idx(weight);
	struct bucket_ctx *bucket;

	*bucket_id = idx;
	bucket = (struct bucket_ctx *)&dom_ctx->buckets[idx];
	if (bucket)
		return bucket;

	scx_bpf_error("Failed to lookup dom bucket");
	return NULL;
}

static struct lock_wrapper *lookup_dom_bkt_lock(u32 dom_id, u32 weight)
{
	u32 idx = dom_id * LB_LOAD_BUCKETS + weight_to_bucket_idx(weight);
	struct lock_wrapper *lockw;

	lockw = bpf_map_lookup_elem(&dom_dcycle_locks, &idx);
	if (lockw)
		return lockw;

	scx_bpf_error("Failed to lookup dom lock");
	return NULL;
}


static u64 scale_up_fair(u64 value, u64 weight)
{
	return value * weight / 100;
}

static u64 scale_inverse_fair(u64 value, u64 weight)
{
	return value * 100 / weight;
}

static void dom_dcycle_adj(dom_ptr domc, u32 weight, u64 now, bool runnable)
{
	struct bucket_ctx *bucket;
	struct lock_wrapper *lockw;
	s64 adj = runnable ? 1 : -1;
	u32 bucket_idx = 0;
	u32 dom_id;

	cast_kern(domc);

	dom_id = domc->id;

	bucket = lookup_dom_bucket(domc, weight, &bucket_idx);
	lockw = lookup_dom_bkt_lock(dom_id, weight);

	if (!bucket || !lockw)
		return;

	bpf_spin_lock(&lockw->lock);
	bucket->dcycle += adj;
	ravg_accumulate(&bucket->rd, bucket->dcycle, now, load_half_life);
	bpf_spin_unlock(&lockw->lock);

	if (adj < 0 && (s64)bucket->dcycle < 0)
		scx_bpf_error("cpu%d dom%u bucket%u load underflow (dcycle=%lld adj=%lld)",
			      bpf_get_smp_processor_id(), dom_id, bucket_idx,
			      bucket->dcycle, adj);

	if (debug >=2 &&
	    (!domc->dbg_dcycle_printed_at || now - domc->dbg_dcycle_printed_at >= 1000000000)) {
		bpf_printk("DCYCLE ADJ dom=%u bucket=%u adj=%lld dcycle=%u avg_dcycle=%llu",
			   dom_id, bucket_idx, adj, bucket->dcycle,
			   ravg_read(&bucket->rd, now, load_half_life) >> RAVG_FRAC_BITS);
		domc->dbg_dcycle_printed_at = now;
	}
}

static void dom_dcycle_xfer_task(struct task_struct *p, struct task_ctx *taskc,
			         dom_ptr from_domc,
				 dom_ptr to_domc, u64 now)
{
	struct bucket_ctx *from_bucket, *to_bucket;
	u32 idx = 0, weight = taskc->weight;
	struct lock_wrapper *from_lockw, *to_lockw;
	struct ravg_data task_dcyc_rd;
	u64 from_dcycle[2], to_dcycle[2], task_dcycle;

	from_lockw = lookup_dom_bkt_lock(from_domc->id, weight);
	to_lockw = lookup_dom_bkt_lock(to_domc->id, weight);
	if (!from_lockw || !to_lockw)
		return;

	from_bucket = lookup_dom_bucket(from_domc, weight, &idx);
	to_bucket = lookup_dom_bucket(to_domc, weight, &idx);
	if (!from_bucket || !to_bucket)
		return;

	/*
	 * @p is moving from @from_domc to @to_domc. Its duty cycle
	 * contribution in the relevant bucket of @from_domc should be moved
	 * together to the corresponding bucket in @to_dom_id. We only track
	 * duty cycle from BPF. Load is computed in user space when performing
	 * load balancing.
	 */
	ravg_accumulate(&taskc->dcyc_rd, taskc->runnable, now, load_half_life);
	task_dcyc_rd = taskc->dcyc_rd;
	if (debug >= 2)
		task_dcycle = ravg_read(&task_dcyc_rd, now, load_half_life);

	/* transfer out of @from_domc */
	bpf_spin_lock(&from_lockw->lock);
	if (taskc->runnable)
		from_bucket->dcycle--;

	if (debug >= 2)
		from_dcycle[0] = ravg_read(&from_bucket->rd, now, load_half_life);

	ravg_transfer(&from_bucket->rd, from_bucket->dcycle,
		      &task_dcyc_rd, taskc->runnable, load_half_life, false);

	if (debug >= 2)
		from_dcycle[1] = ravg_read(&from_bucket->rd, now, load_half_life);

	bpf_spin_unlock(&from_lockw->lock);

	/* transfer into @to_domc */
	bpf_spin_lock(&to_lockw->lock);
	if (taskc->runnable)
		to_bucket->dcycle++;

	if (debug >= 2)
		to_dcycle[0] = ravg_read(&to_bucket->rd, now, load_half_life);

	ravg_transfer(&to_bucket->rd, to_bucket->dcycle,
		      &task_dcyc_rd, taskc->runnable, load_half_life, true);

	if (debug >= 2)
		to_dcycle[1] = ravg_read(&to_bucket->rd, now, load_half_life);

	bpf_spin_unlock(&to_lockw->lock);

	if (debug >= 2)
		bpf_printk("XFER DCYCLE dom%u->%u task=%lu from=%lu->%lu to=%lu->%lu",
			   from_domc->id, to_domc->id,
			   task_dcycle >> RAVG_FRAC_BITS,
			   from_dcycle[0] >> RAVG_FRAC_BITS,
			   from_dcycle[1] >> RAVG_FRAC_BITS,
			   to_dcycle[0] >> RAVG_FRAC_BITS,
			   to_dcycle[1] >> RAVG_FRAC_BITS);
}

static u64 dom_min_vruntime(dom_ptr domc)
{
	return READ_ONCE(domc->min_vruntime);
}

int dom_xfer_task(struct task_struct *p __arg_trusted, u32 new_dom_id, u64 now)
{
	dom_ptr from_domc, to_domc;
	struct task_ctx *taskc;

	taskc = lookup_task_ctx(p);
	if (!taskc)
		return 0;

	from_domc = task_domain(taskc);
	to_domc = lookup_dom_ctx(new_dom_id);

	if (!from_domc || !to_domc || !taskc)
		return 0;

	dom_dcycle_xfer_task(p, taskc, from_domc, to_domc, now);
	return 0;
}

/*
 * Statistics
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, RUSTY_NR_STATS);
} stats SEC(".maps");

static inline void stat_add(enum stat_idx idx, u64 addend)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += addend;
}

/*
 * Userspace tuner will frequently update the following struct with tuning
 * parameters and bump its gen. refresh_tune_params() converts them into forms
 * that can be used directly in the scheduling paths.
 */
struct tune_input{
	u64 genn;
	u64 slice_ns;
	u64 direct_greedy_cpumask[MAX_CPUS / 64];
	u64 kick_greedy_cpumask[MAX_CPUS / 64];
} tune_input;

u64 tune_params_gen;
private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *direct_greedy_cpumask;
private(A) struct bpf_cpumask __kptr *kick_greedy_cpumask;

static u32 cpu_to_dom_id(s32 cpu)
{
	const volatile u32 *dom_idp;

	dom_idp = MEMBER_VPTR(cpu_dom_id_map, [cpu]);
	if (!dom_idp)
		return MAX_DOMS;

	return *dom_idp;
}

static inline bool is_offline_cpu(s32 cpu)
{
	return cpu_to_dom_id(cpu) > MAX_DOMS;
}

static void refresh_tune_params(void)
{
	s32 cpu;

	if (tune_params_gen == tune_input.genn)
		return;

	tune_params_gen = tune_input.genn;
	slice_ns = tune_input.slice_ns;

	bpf_for(cpu, 0, nr_cpu_ids) {
		u32 dom_id = cpu_to_dom_id(cpu);
		struct lb_domain *lb_domain;

		if (is_offline_cpu(cpu))
			continue;

		if (!(lb_domain = lb_domain_get(dom_id)))
			return;

		if (tune_input.direct_greedy_cpumask[cpu / 64] & (1LLU << (cpu % 64))) {
			if (direct_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, direct_greedy_cpumask);
			if (lb_domain->direct_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, lb_domain->direct_greedy_cpumask);
		} else {
			if (direct_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, direct_greedy_cpumask);
			if (lb_domain->direct_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, lb_domain->direct_greedy_cpumask);
		}

		if (tune_input.kick_greedy_cpumask[cpu / 64] & (1LLU << (cpu % 64))) {
			if (kick_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, kick_greedy_cpumask);
		} else {
			if (kick_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, kick_greedy_cpumask);
		}
	}
}

static u64 min(u64 a, u64 b)
{
	return a <= b ? a : b;
}

/*
 * ** Taken directly from fair.c in the Linux kernel **
 *
 * We use this table to inversely scale deadline according to a task's
 * calculated latency factor. We preserve the comment directly from the table
 * in fair.c:
 *
 * "Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)"
 */
const int sched_prio_to_weight[DL_MAX_LAT_PRIO + 1] = {
 /* -20 */     88761,     71755,     56483,     46273,     36291,
 /* -15 */     29154,     23254,     18705,     14949,     11916,
 /* -10 */      9548,      7620,      6100,      4904,      3906,
 /*  -5 */      3121,      2501,      1991,      1586,      1277,
 /*   0 */      1024,       820,       655,       526,       423,
 /*   5 */       335,       272,       215,       172,       137,
 /*  10 */       110,        87,        70,        56,        45,
 /*  15 */        36,        29,        23,        18,        15,
};

static __noinline u64 sched_prio_to_latency_weight(u64 prio)
{
	if (prio >= DL_MAX_LAT_PRIO) {
		scx_bpf_error("Invalid prio index");
		return 0;
	}

	return sched_prio_to_weight[DL_MAX_LAT_PRIO - prio - 1];
}

static u64 task_compute_dl(struct task_struct *p, struct task_ctx *taskc,
			   u64 enq_flags)
{
	u64 waker_freq, blocked_freq;
	u64 lat_prio, lat_scale, avg_run_raw, avg_run;
	u64 freq_factor;

	/*
	 * Determine the latency criticality of a task, and scale a task's
	 * deadline accordingly. Much of this is inspired by the logic in
	 * scx_lavd that was originally conceived and implemented by Changwoo
	 * Min. Though the implementations for determining latency criticality
	 * are quite different in many ways, individuals familiar with both
	 * schedulers will feel an eerie sense of deja-vu. The details of
	 * interactivity boosting for rusty are described below.
	 */

	/*
	 * We begin by calculating the following interactivity factors for a
	 * task:
	 *
	 * - waker_freq: The frequency with which a task wakes up other tasks.
	 *		 A high waker frequency generally implies a producer
	 *		 task that is at the beginning and/or middle of a work
	 *		 chain.
	 *
	 * - blocked_freq: The frequency with which a task is blocked. A high
	 *		   blocked frequency indicates a consumer task that is
	 *		   at the middle and/or end of a work chain.
	 *
	 * A task that is high in both frequencies indicates what is often the
	 * most latency-critical interactive task: a task that functions both
	 * as a producer and a consumer by being in the _middle_ of a work
	 * chain.
	 *
	 * We want to prioritize running these tasks, as they are likely to
	 * have a disproporionate impact on the latency (and possibly
	 * throughput) of the workload they are enabling due to Amdahl's law.
	 * For example, say that you have a workload where 50% of the workload
	 * is serialized by a producer and consumer task (25% each), and the
	 * latter 50% is serviced in parallel by n CPU hogging tasks. If either
	 * the producer or consumer is improved by a factor of x, it improves
	 * the latency of the entire workload by:
	 *
	 *	S_lat(x) = 1 / ((1 - .25) + (.25 / x))
	 *
	 * Say that we improve wakeup latency by 2x for either task, the
	 * latency improvement would be:
	 *
	 *	S_lat(2) = 1 / ((1 - .25) + (.25 / 2))
	 *		 = 1 / (.75 + .125)
	 *		 = 1 / .875
	 *		~= 14.2%
	 *
	 * If we instead improve wakeup latency by 2x for all the n parallel
	 * tasks in the latter 50% of the workload window, the improvement
	 * would be:
	 *
	 *	S_lat(2) = 1 / ((1 - .5) + (.5 / 2))
	 *		 = 1 / (.5 + .25)
	 *		 = 1 / .75
	 *		~= 33%
	 *
	 * This is also significant, but the returns are amortized across all
	 * of those tasks. Thus, by giving a latency boost to the producer /
	 * consumer tasks, we optimize for the case of scheduling tasks that
	 * are on the critical path for serial workchains, and have a
	 * disproportionate impact on the latency of a workload.
	 *
	 * We multiply the frequencies of wait_freq and waker_freq somewhat
	 * arbitrarily, based on observed performance for audio and gaming
	 * interactive workloads.
	 */
	waker_freq = min(taskc->waker_freq, DL_FREQ_FT_MAX);
	blocked_freq = min(taskc->blocked_freq, DL_FREQ_FT_MAX);
	freq_factor = blocked_freq * waker_freq * waker_freq;

	/*
	 * Scale the frequency factor according to the task's weight. A task
	 * with higher weight is given a higher frequency factor than a task
	 * with a lower weight.
	 */
	freq_factor = scale_up_fair(freq_factor, p->scx.weight);

	/*
	 * The above frequencies roughly follow an exponential distribution, so
	 * use log2_u64() to linearize it to a boost priority that we can then
	 * scale to a weight factor below.
	 */
	lat_prio = log2_u64(freq_factor + 1);
	lat_prio = min(lat_prio, DL_MAX_LAT_PRIO);

	/*
	 * Next calculate a task's average runtime, and apply it to deadline
	 * accordingly. A task with a large runtime is penalized from an
	 * interactivity standpoint, for obvious reasons.
	 *
	 * As with waker and blocked frequencies above, this follows an
	 * exponential distribution. We inversely scale to account for
	 * empirical observations which seem to bring it roughly to the same
	 * order of magnitude as the blocker and waker frequencies above.
	 *
	 * We inversely scale the task's averge_runtime to cause tasks with
	 * lower weight to receive a harsher penalty for long runtimes, and
	 * vice versa for tasks with lower weight.
	 */
	avg_run_raw = taskc->avg_runtime / DL_RUNTIME_SCALE;
	avg_run_raw = min(avg_run_raw, DL_MAX_LATENCY_NS);
	avg_run_raw = scale_inverse_fair(avg_run_raw, p->scx.weight);
	avg_run = log2_u64(avg_run_raw + 1);

	if (avg_run < lat_prio) {
		/* Equivalent to lat_prio = log(freq_factor / avg_run_raw) */
		lat_prio -= avg_run;
	} else {
		lat_prio = 0;
	}

	/*
	 * Ultimately, what we're trying to arrive at is a single value
	 * 'lat_prio' that we can use to compute the weight that we use to
	 * scale a task's average runtime as below.
	 *
	 * To summarize what we've done above, we compute this lat_prio as the
	 * sum of a task's frequency factor, minus an average runtime factor.
	 * Both factors are scaled according to a task's weight.
	 *
	 * Today, we're just interpreting lat_prio as a niceness value, but
	 * this can and almost certainly will likely change to something more
	 * generic and/or continuous and flexible so that it can also
	 * accommodate cgroups.
	 */
	lat_scale = sched_prio_to_latency_weight(lat_prio);
	lat_scale = min(lat_scale, LB_MAX_WEIGHT);

	/*
	 * Finally, with our 'lat_scale' weight, we compute the length of the
	 * task's request as:
	 *
	 * r_i = avg_runtime * 100 / lat_scale
	 *
	 * In other words, the "CPU request length" which is used to determine
	 * the actual absolute vtime that the task is dispatched with.
	 */
	return scale_inverse_fair(taskc->avg_runtime, lat_scale);
}

static void clamp_task_vtime(struct task_struct *p, struct task_ctx *taskc, u64 enq_flags)
{
	u64 dom_vruntime, min_vruntime;
	dom_ptr domc;

	if (!(domc = task_domain(taskc)))
		return;

	dom_vruntime = dom_min_vruntime(domc);
	min_vruntime = dom_vruntime - slice_ns;
	/*
	 * Allow an idling task to accumulate at most one slice worth of
	 * vruntime budget. This prevents e.g. a task for sleeping for 1 day,
	 * and then coming back and having essentially full use of the CPU for
	 * an entire day until it's caught up to the other tasks' vtimes.
	 */
	if (time_before(p->scx.dsq_vtime, min_vruntime)) {
		p->scx.dsq_vtime = min_vruntime;
		taskc->deadline = p->scx.dsq_vtime + task_compute_dl(p, taskc, enq_flags);
		stat_add(RUSTY_STAT_DL_CLAMP, 1);
	} else {
		stat_add(RUSTY_STAT_DL_PRESET, 1);
	}
}

static bool task_set_domain(struct task_struct *p __arg_trusted,
			    u32 new_dom_id, bool init_dsq_vtime)
{
	dom_ptr old_domc, new_domc;
	struct bpf_cpumask *d_cpumask, *t_cpumask;
	struct lb_domain *new_lb_domain;
	struct task_ctx *taskc;
	u32 old_dom_id;

	taskc = lookup_task_ctx_mask(p, &t_cpumask);
	if (!taskc || !t_cpumask) {
		scx_bpf_error("Failed to look up task cpumask");
		return false;
	}

	old_dom_id = taskc->target_dom;
	old_domc = lookup_dom_ctx(old_dom_id);
	if (!old_domc)
		return false;

	if (new_dom_id == NO_DOM_FOUND) {
		bpf_cpumask_clear(t_cpumask);
		return !(p->scx.flags & SCX_TASK_QUEUED);
	}

	new_domc = try_lookup_dom_ctx_arena(new_dom_id);
	if (!new_domc)
		return false;

	new_lb_domain = lb_domain_get(new_dom_id);
	if (!new_lb_domain) {
		scx_bpf_error("no lb_domain for dom%d\n", new_dom_id);
		return false;
	}

	d_cpumask = new_lb_domain->cpumask;
	if (!d_cpumask) {
		scx_bpf_error("Failed to get dom%u cpumask kptr",
			      new_dom_id);
		return false;
	}


	/*
	 * set_cpumask might have happened between userspace requesting LB and
	 * here and @p might not be able to run in @dom_id anymore. Verify.
	 */
	if (bpf_cpumask_intersects(cast_mask(d_cpumask), p->cpus_ptr)) {
		u64 now = scx_bpf_now();

		if (!init_dsq_vtime)
			dom_xfer_task(p, new_dom_id, now);

		taskc->target_dom = new_dom_id;
		taskc->domc = new_domc;

		cast_kern(new_domc);
		p->scx.dsq_vtime = dom_min_vruntime(new_domc);
		taskc->deadline = p->scx.dsq_vtime +
				  scale_inverse_fair(taskc->avg_runtime, taskc->weight);
		bpf_cpumask_and(t_cpumask, cast_mask(d_cpumask), p->cpus_ptr);
	}

	return taskc->target_dom == new_dom_id;
}


static s32 try_sync_wakeup(struct task_struct *p, struct task_ctx *taskc,
			   s32 prev_cpu)
{
	struct task_struct *current = (void *)bpf_get_current_task_btf();
	s32 cpu;
	const struct cpumask *idle_cpumask;
	bool share_llc, has_idle;
	struct lb_domain *lb_domain;
	struct bpf_cpumask *d_cpumask;
	struct pcpu_ctx *pcpuc;

	cpu = bpf_get_smp_processor_id();
	pcpuc = lookup_pcpu_ctx(cpu);
	if (!pcpuc)
		return -ENOENT;

	lb_domain = lb_domain_get(pcpuc->dom_id);
	if (!lb_domain)
		return -ENOENT;

	d_cpumask = lb_domain->cpumask;
	if (!d_cpumask) {
		scx_bpf_error("Failed to acquire dom%u cpumask kptr",
				taskc->target_dom);
		return -ENOENT;
	}

	idle_cpumask = scx_bpf_get_idle_cpumask();

	share_llc = bpf_cpumask_test_cpu(prev_cpu, cast_mask(d_cpumask));
	if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_SYNC_PREV_IDLE, 1);

		cpu = prev_cpu;
		goto out;
	}

	has_idle = bpf_cpumask_intersects(cast_mask(d_cpumask), idle_cpumask);

	if (has_idle && bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
	    !(current->flags & PF_EXITING) && taskc->target_dom < MAX_DOMS &&
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0) {
		stat_add(RUSTY_STAT_WAKE_SYNC, 1);
		goto out;
	}

	cpu = -ENOENT;

out:
	scx_bpf_put_idle_cpumask(idle_cpumask);
	return cpu;
}

s32 BPF_STRUCT_OPS(rusty_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	const struct cpumask *idle_smtmask = scx_bpf_get_idle_smtmask();
	struct task_ctx *taskc;
	bool prev_domestic, has_idle_cores;
	struct bpf_cpumask *p_cpumask, *tmp_cpumask;
	s32 cpu;

	refresh_tune_params();

	if (!(taskc = lookup_task_ctx_mask(p, &p_cpumask)) || !p_cpumask)
		goto enoent;

	if (p->nr_cpus_allowed == 1) {
		cpu = prev_cpu;
		if (kthreads_local && (p->flags & PF_KTHREAD)) {
			stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		} else {
			stat_add(RUSTY_STAT_PINNED, 1);
		}
		goto direct;
	}

	/*
	 * If WAKE_SYNC and the machine isn't fully saturated, wake up @p to the
	 * local dsq of the waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		cpu = try_sync_wakeup(p, taskc, prev_cpu);
		if (cpu >= 0)
			goto direct;
	}

	has_idle_cores = !bpf_cpumask_empty(idle_smtmask);

	/* did @p get pulled out to a foreign domain by e.g. greedy execution? */
	prev_domestic = bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_cpumask));

	/*
	 * See if we want to keep @prev_cpu. We want to keep @prev_cpu if the
	 * whole physical core is idle. If the sibling[s] are busy, it's likely
	 * more advantageous to look for wholly idle cores first.
	 */
	if (prev_domestic) {
		if (bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			stat_add(RUSTY_STAT_PREV_IDLE, 1);
			cpu = prev_cpu;
			goto direct;
		}
	} else {
		/*
		 * @prev_cpu is foreign. Linger iff the domain isn't too busy as
		 * indicated by direct_greedy_cpumask. There may also be an idle
		 * CPU in the domestic domain
		 */
		if (direct_greedy_cpumask &&
		    bpf_cpumask_test_cpu(prev_cpu, cast_mask(direct_greedy_cpumask)) &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			stat_add(RUSTY_STAT_GREEDY_IDLE, 1);
			cpu = prev_cpu;
			goto direct;
		}
	}

	/*
	 * @prev_cpu didn't work out. Let's see whether there's an idle CPU @p
	 * can be directly dispatched to. We'll first try to find the best idle
	 * domestic CPU and then move onto foreign.
	 */

	/* If there is a domestic idle core, dispatch directly */
	if (has_idle_cores) {
		cpu = scx_bpf_pick_idle_cpu(cast_mask(p_cpumask), SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
			goto direct;
		}
	}

	/*
	 * If @prev_cpu was domestic and is idle itself even though the core
	 * isn't, picking @prev_cpu may improve L1/2 locality.
	 */
	if (prev_domestic && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		cpu = prev_cpu;
		goto direct;
	}

	/* If there is any domestic idle CPU, dispatch directly */
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_cpumask), 0);
	if (cpu >= 0) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		goto direct;
	}

	/*
	 * Domestic domain is fully booked. If there are CPUs which are idle and
	 * under-utilized, ignore domain boundaries (while still respecting NUMA
	 * boundaries) and push the task there. Try to find an idle core first.
	 */
	if (taskc->all_cpus && direct_greedy_cpumask &&
	    !bpf_cpumask_empty(cast_mask(direct_greedy_cpumask))) {
		u32 dom_id = cpu_to_dom_id(prev_cpu);
		dom_ptr domc;
		struct lb_domain *lb_domain;
		struct bpf_cpumask *tmp_direct_greedy, *node_mask;

		/*
		 * CPU may be offline e.g. CPU was removed via hotplugging and scheduler
		 * was restarted fast enough that default scheduler didn't get a chance
		 * to move the task to another CPU. In this case, we don't account for
		 * domain as we assume hotplugging is an infrequent operation. Thus,
		 * we move the task in the order of preference:
		 * 1. Move the task to idle CPU where greedy allocation is preferred
		 * 2. Move the task to any CPU where greedy allocation is preferred
		 * 3. Move the task to any CPU
		 */
		if (unlikely(is_offline_cpu(prev_cpu)))
			domc = NULL;
		else if (!(domc = lookup_dom_ctx(dom_id)))
			goto enoent;

		if (!(lb_domain = lb_domain_get(domc->id))) {
			scx_bpf_error("Failed to lookup domain map value");
			goto enoent;
		}

		tmp_direct_greedy = direct_greedy_cpumask;
		if (!tmp_direct_greedy) {
			scx_bpf_error("Failed to lookup direct_greedy mask");
			goto enoent;
		}
		/*
		 * By default, only look for an idle core in the current NUMA
		 * node when looking for direct greedy CPUs outside of the
		 * current domain. Stealing work temporarily is fine when
		 * you're going across domain boundaries, but it may be less
		 * desirable when crossing NUMA boundaries as the task's
		 * working set may end up spanning multiple NUMA nodes.
		 */
		if (!direct_greedy_numa && domc) {
			node_mask = lb_domain->node_cpumask;
			if (!node_mask) {
				scx_bpf_error("Failed to lookup node mask");
				goto enoent;
			}

			tmp_cpumask = scx_percpu_bpfmask();
			if (!tmp_cpumask) {
				scx_bpf_error("Failed to lookup tmp cpumask");
				goto enoent;
			}
			bpf_cpumask_and(tmp_cpumask,
					cast_mask(node_mask),
					cast_mask(tmp_direct_greedy));
			tmp_direct_greedy = tmp_cpumask;
		}

		/* Try to find an idle core in the previous and then any domain */
		if (has_idle_cores) {
			if (domc && lb_domain->direct_greedy_cpumask) {
				cpu = scx_bpf_pick_idle_cpu(cast_mask(lb_domain->direct_greedy_cpumask),
							    SCX_PICK_IDLE_CORE);
				if (cpu >= 0) {
					stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
					goto direct;
				}
			}

			if (direct_greedy_cpumask) {
				cpu = scx_bpf_pick_idle_cpu(cast_mask(tmp_direct_greedy),
							    SCX_PICK_IDLE_CORE);
				if (cpu >= 0) {
					stat_add(RUSTY_STAT_DIRECT_GREEDY_FAR, 1);
					goto direct;
				}
			}
		}

		/*
		 * No idle core. Is there any idle CPU?
		 */
		if (domc && lb_domain->direct_greedy_cpumask) {
			cpu = scx_bpf_pick_idle_cpu(cast_mask(lb_domain->direct_greedy_cpumask), 0);
			if (cpu >= 0) {
				stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
				goto direct;
			}
		}

		if (direct_greedy_cpumask) {
			cpu = scx_bpf_pick_idle_cpu(cast_mask(tmp_direct_greedy), 0);
			if (cpu >= 0) {
				stat_add(RUSTY_STAT_DIRECT_GREEDY_FAR, 1);
				goto direct;
			}
		}
	}

	/*
	 * We're going to queue on the domestic domain's DSQ. @prev_cpu may be
	 * in a different domain. Returning an out-of-domain CPU can lead to
	 * stalls as all in-domain CPUs may be idle by the time @p gets
	 * enqueued.
	 */
	if (prev_domestic) {
		cpu = prev_cpu;
	} else {
		cpu = bpf_cpumask_any_distribute(cast_mask(p_cpumask));
		if (cpu >= nr_cpu_ids)
			cpu = prev_cpu;
	}

	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;

direct:
	taskc->dispatch_local = true;
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;

enoent:
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return -ENOENT;
}

static void place_task_dl(struct task_struct *p, struct task_ctx *taskc,
			  u64 enq_flags)
{
	clamp_task_vtime(p, taskc, enq_flags);
	scx_bpf_dsq_insert_vtime(p, taskc->target_dom, slice_ns, taskc->deadline,
				 enq_flags);
}

void BPF_STRUCT_OPS(rusty_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct task_ctx *taskc;
	dom_ptr domc;
	struct bpf_cpumask *p_cpumask;
	s32 cpu = -1;

	if (!(taskc = lookup_task_ctx_mask(p, &p_cpumask)) || !p_cpumask)
		return;

	domc = task_domain(taskc);
	if (!domc)
		return;

	/*
	 * Migrate @p to a new domain if requested by userland by setting target_dom.
	 */
	if (domc->id != taskc->target_dom &&
	    task_set_domain(p, domc->id, false)) {
		stat_add(RUSTY_STAT_LOAD_BALANCE, 1);
		taskc->dispatch_local = false;
		cpu = bpf_cpumask_any_distribute(cast_mask(p_cpumask));
		if (cpu < nr_cpu_ids)
			scx_bpf_kick_cpu(cpu, 0);
		goto dom_queue;
	}

	if (taskc->dispatch_local) {
		taskc->dispatch_local = false;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	/*
	 * @p is about to be queued on its domain's dsq. However, @p may be on a
	 * foreign CPU due to a greedy execution and not have gone through
	 * ->select_cpu() if it's being enqueued e.g. after slice exhaustion. If
	 * so, @p would be queued on its domain's dsq but none of the CPUs in
	 * the domain would be woken up which can induce temporary execution
	 * stalls. Kick a domestic CPU if @p is on a foreign domain.
	 */
	if (!bpf_cpumask_test_cpu(scx_bpf_task_cpu(p), cast_mask(p_cpumask))) {
		cpu = bpf_cpumask_any_distribute(cast_mask(p_cpumask));
		if (cpu < nr_cpu_ids)
			scx_bpf_kick_cpu(cpu, 0);
		stat_add(RUSTY_STAT_REPATRIATE, 1);
	}

dom_queue:
	if (fifo_sched)
		scx_bpf_dsq_insert(p, taskc->target_dom, slice_ns, enq_flags);
	else
		place_task_dl(p, taskc, enq_flags);

	/*
	 * If there are CPUs which are idle and not saturated, wake them up to
	 * see whether they'd be able to steal the just queued task. This path
	 * is taken only if DIRECT_GREEDY didn't trigger in select_cpu().
	 *
	 * While both mechanisms serve very similar purposes, DIRECT_GREEDY
	 * emplaces the task in a foreign CPU directly while KICK_GREEDY just
	 * wakes up a foreign CPU which will then first try to execute from its
	 * domestic domain first before snooping foreign ones.
	 *
	 * While KICK_GREEDY is a more expensive way of accelerating greedy
	 * execution, DIRECT_GREEDY shows negative performance impacts when the
	 * CPUs are highly loaded while KICK_GREEDY doesn't. Even under fairly
	 * high utilization, KICK_GREEDY can slightly improve work-conservation.
	 */
	if (taskc->all_cpus) {
		const struct cpumask *idle_cpumask;

		idle_cpumask = scx_bpf_get_idle_cpumask();
		if (kick_greedy_cpumask) {
			cpu = bpf_cpumask_any_and_distribute(cast_mask(kick_greedy_cpumask), idle_cpumask);
			if (cpu >= nr_cpu_ids)
				cpu = -EBUSY;
		}
		scx_bpf_put_cpumask(idle_cpumask);

		if (cpu >= 0) {
			stat_add(RUSTY_STAT_KICK_GREEDY, 1);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		}
	}
}

static bool cpumask_intersects_domain(const struct cpumask *cpumask, u32 dom_id)
{
	struct lb_domain *lb_domain;
	struct bpf_cpumask *dmask;

	lb_domain = lb_domain_get(dom_id);
	if (!lb_domain)
		return false;

	dmask = lb_domain->cpumask;
	if (!dmask)
		return false;

	return bpf_cpumask_intersects(cpumask, cast_mask(dmask));
}

u32 dom_node_id(u32 dom_id)
{
	const volatile u32 *nid_ptr;

	nid_ptr = MEMBER_VPTR(dom_numa_id_map, [dom_id]);
	if (!nid_ptr) {
		scx_bpf_error("Couldn't look up node ID for %d", dom_id);
		return 0;
	}
	return *nid_ptr;
}

#if !defined(__TARGET_ARCH_arm64) && !defined(__aarch64__) && !defined(__TARGET_ARCH_riscv)
/*
 * Returns the dom mask for a node.
 */
static u64 node_dom_mask(u32 node_id)
{
	u64 mask = 0;
	u32 dom_id = 0;

	bpf_for(dom_id, 0, nr_doms) {
		if (dom_node_id(dom_id) != node_id)
			continue;

		mask |= 1LLU << dom_id;
	}

	return mask;
}

/*
 * Sets the preferred domain mask according to the mempolicy. See man(2)
 * set_mempolicy for more details on mempolicy.
 */
static void task_set_preferred_mempolicy_dom_mask(struct task_struct *p,
						  struct task_ctx *taskc)
{
	struct bpf_cpumask *p_cpumask;
	struct mempolicy *mempolicy;
	u32 node_id;
	u32 val = 0;
	void *mask;

	taskc->preferred_dom_mask = 0;

	mempolicy = BPF_CORE_READ(p, mempolicy);
	if (!mempolicy)
		return;

	p_cpumask = lookup_task_bpfmask(p);

	if (!mempolicy_affinity || !p_cpumask)
		return;

	if (!(mempolicy->mode & (MPOL_BIND|MPOL_PREFERRED|MPOL_PREFERRED_MANY)))
		return;

	// MPOL_BIND and MPOL_PREFERRED_MANY use the home_node field on the
	// mempolicy struct, so use that for now. In the future the memory
	// usage of the node can be checked to follow the same algorithm for
	// where memory allocations will occur.
	if ((int)mempolicy->home_node >= 0) {
		taskc->preferred_dom_mask =
			node_dom_mask((u32)mempolicy->home_node);
		return;
	}

	mask = BPF_CORE_READ(mempolicy, nodes.bits);
	if (bpf_core_read(&val, sizeof(val), mask))
		return;

	bpf_for(node_id, 0, nr_nodes) {
		if (!(val & 1 << node_id))
			continue;

		taskc->preferred_dom_mask |= node_dom_mask(node_id);
	}

	return;
}
#else

static void task_set_preferred_mempolicy_dom_mask(struct task_struct *p,
                                                 struct task_ctx *taskc)
{}

#endif


void BPF_STRUCT_OPS(rusty_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 curr_dom = cpu_to_dom_id(cpu), dom;
	struct pcpu_ctx *pcpuc;
	u32 my_node;

	/*
	 * In older kernels, we may receive an ops.dispatch() callback when a
	 * CPU is coming online during a hotplug _before_ the hotplug callback
	 * has been invoked. We're just going to exit in that hotplug callback,
	 * so let's just defer consuming here to avoid triggering a bad DSQ
	 * error in ext.c.
	 */
	if (unlikely(is_offline_cpu(cpu)))
		return;

	if (scx_bpf_dsq_move_to_local(curr_dom)) {
		stat_add(RUSTY_STAT_DSQ_DISPATCH, 1);
		return;
	}

	if (!greedy_threshold)
		return;

	pcpuc = lookup_pcpu_ctx(cpu);
	if (!pcpuc)
		return;

	my_node = dom_node_id(curr_dom);

	/* try to steal a task from domains on the current NUMA node */
	bpf_repeat(nr_doms - 1) {
		dom = pcpuc->dom_rr_cur++ % nr_doms;
		if (dom == curr_dom || dom_node_id(dom) != my_node)
			continue;

		if (scx_bpf_dsq_move_to_local(dom)) {
			stat_add(RUSTY_STAT_GREEDY_LOCAL, 1);
			return;
		}
	}

	if (!greedy_threshold_x_numa || nr_nodes == 1)
		return;

	/* try to steal a task from domains on other NUMA nodes */
	bpf_repeat(nr_doms - 1) {
		dom = pcpuc->dom_rr_cur++ % nr_doms;

		if (dom_node_id(dom) == my_node || dom == curr_dom ||
		    scx_bpf_dsq_nr_queued(dom) >= greedy_threshold_x_numa)
			continue;

		if (scx_bpf_dsq_move_to_local(dom)) {
			stat_add(RUSTY_STAT_GREEDY_XNUMA, 1);
			return;
		}
	}
}

/*
 * Exponential weighted moving average
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

static u64 update_freq(u64 freq, u64 interval)
{
	u64 new_freq;

	new_freq = (100 * NSEC_PER_MSEC) / interval;
	return calc_avg(freq, new_freq);
}

void BPF_STRUCT_OPS(rusty_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now(), interval;
	struct task_struct *waker;
	struct task_ctx *wakee_ctx, *waker_ctx;

	if (!(wakee_ctx = lookup_task_ctx(p)))
		return;

	wakee_ctx->is_kworker = p->flags & PF_WQ_WORKER;

	task_load_adj(wakee_ctx, now, true);
	dom_dcycle_adj(wakee_ctx->domc, wakee_ctx->weight, now, true);

	if (fifo_sched)
		return;

	wakee_ctx->sum_runtime = 0;

	waker = bpf_get_current_task_btf();
	if (!(waker_ctx = try_lookup_task_ctx(waker)))
		return;

	interval = now - waker_ctx->last_woke_at;
	waker_ctx->waker_freq = update_freq(waker_ctx->waker_freq, interval);
	waker_ctx->last_woke_at = now;
}

static void running_update_vtime(struct task_struct *p,
				 struct task_ctx *taskc,
				 dom_ptr domc)
{
	struct bpf_spin_lock * lock = lookup_dom_vtime_lock(domc);

	if (!lock)
		return;

	bpf_spin_lock(lock);
	if (time_before(dom_min_vruntime(domc), p->scx.dsq_vtime))
		WRITE_ONCE(domc->min_vruntime, p->scx.dsq_vtime);
	bpf_spin_unlock(lock);
}

void BPF_STRUCT_OPS(rusty_running, struct task_struct *p)
{
	task_ptr usrptr = (task_ptr)sdt_task_data(p);
	struct task_ctx *taskc;
	dom_ptr domc;
	u32 dap_gen;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	domc = task_domain(taskc);
	if (!domc) {
		scx_bpf_error("Invalid dom ID");
		return;
	}

	/*
	 * Record that @p has been active in @domc. Load balancer will only
	 * consider recently active tasks. Access synchronization rules aren't
	 * strict. We just need to be right most of the time.
	 */
	dap_gen = domc->active_tasks.genn;
	if (taskc->dom_active_tasks_gen != dap_gen) {
		u64 idx = __sync_fetch_and_add(&domc->active_tasks.write_idx, 1) %
			MAX_DOM_ACTIVE_TPTRS;

		if (idx >= MAX_DOM_ACTIVE_TPTRS) {
			scx_bpf_error("dom_active_tasks[%u][%llu] out of bounds indexing",
				      domc->id, idx);
			return;
		}

		usrptr = (task_ptr)sdt_task_data(p);
		cast_user(usrptr);

		domc->active_tasks.tasks[idx] = usrptr;
		taskc->dom_active_tasks_gen = dap_gen;
	}

	if (fifo_sched)
		return;

	running_update_vtime(p, taskc, domc);
	taskc->last_run_at = scx_bpf_now();
}

static void stopping_update_vtime(struct task_struct *p,
				  struct task_ctx *taskc,
				  dom_ptr domc)
{
	u64 now, delta;

	now = scx_bpf_now();
	delta = now - taskc->last_run_at;

	taskc->sum_runtime += delta;
	taskc->avg_runtime = calc_avg(taskc->avg_runtime, taskc->sum_runtime);

	p->scx.dsq_vtime += scale_inverse_fair(delta, p->scx.weight);
	taskc->deadline = p->scx.dsq_vtime + task_compute_dl(p, taskc, 0);
}

void BPF_STRUCT_OPS(rusty_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	dom_ptr domc;

	if (fifo_sched)
		return;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(domc = task_domain(taskc)))
		return;

	stopping_update_vtime(p, taskc, domc);
}

void BPF_STRUCT_OPS(rusty_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = scx_bpf_now(), interval;
	struct task_ctx *taskc;
	dom_ptr domc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(domc = task_domain(taskc)))
		return;

	task_load_adj(taskc, now, false);
	dom_dcycle_adj(domc, taskc->weight, now, false);

	if (fifo_sched)
		return;

	interval = now - taskc->last_blocked_at;
	taskc->blocked_freq = update_freq(taskc->blocked_freq, interval);
	taskc->last_blocked_at = now;
}

void BPF_STRUCT_OPS(rusty_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (debug >= 2)
		bpf_printk("%s[%p]: SET_WEIGHT %u -> %u", p->comm, p,
			   taskc->weight, weight);

	taskc->weight = weight;
}

static u32 task_pick_domain(struct task_ctx *taskc, struct task_struct *p,
			    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();
	u32 first_dom = NO_DOM_FOUND, dom, preferred_dom = NO_DOM_FOUND;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return NO_DOM_FOUND;

	taskc->dom_mask = 0;

	dom = pcpu_ctx[cpu].dom_rr_cur++;
	task_set_preferred_mempolicy_dom_mask(p, taskc);
	bpf_repeat(nr_doms) {
		dom = (dom + 1) % nr_doms;

		if (cpumask_intersects_domain(cpumask, dom)) {
			taskc->dom_mask |= 1LLU << dom;
			/*
			 * The starting point is round-robin'd and the first
			 * match should be spread across all the domains.
			 */
			if (first_dom == NO_DOM_FOUND)
				first_dom = dom;

			if (taskc->preferred_dom_mask == 0)
			       continue;

			if (((1LLU << dom) & taskc->preferred_dom_mask)
			    && preferred_dom == NO_DOM_FOUND)
				preferred_dom = dom;
		}
	}

	return preferred_dom != NO_DOM_FOUND ? preferred_dom: first_dom;
}

static void task_pick_and_set_domain(struct task_ctx *taskc,
				     struct task_struct *p,
				     const struct cpumask *cpumask,
				     bool init_dsq_vtime)
{
	u32 dom_id = 0;

	if (nr_doms > 1)
		dom_id = task_pick_domain(taskc, p, cpumask);

	if (!task_set_domain(p, dom_id, init_dsq_vtime))
		scx_bpf_error("Failed to set dom%d for %s[%p]",
			      dom_id, p->comm, p);
}

void BPF_STRUCT_OPS(rusty_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	task_pick_and_set_domain(taskc, p, cpumask, false);
	if (all_cpumask)
		taskc->all_cpus =
			bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rusty_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	u64 now = scx_bpf_now();
	struct task_struct *p_map;
	struct bpfmask_wrapper wrapper = {};
	struct bpfmask_wrapper *mask_map_value;
	struct task_ctx *taskc;
	long ret;

	taskc = (struct task_ctx *)sdt_task_alloc(p);
	if (!taskc)
		return -ENOMEM;

	*taskc = (struct task_ctx) {
		.dom_active_tasks_gen = -1,
		.last_blocked_at = now,
		.last_woke_at = now,
		.preferred_dom_mask = 0,
		.pid = p->pid,
	};

	if (debug >= 2)
		bpf_printk("%s[%p]: INIT (weight %u))", p->comm, p, p->scx.weight);


	/*
	 * XXX Passing a trusted pointer as a key to the map turns it into a
	 * scalar for the verifier, preventing us from using it further. Make
	 * a temporary copy of our struct task_struct to pass it to the map.
	 */
	p_map = p;

	ret = bpf_map_update_elem(&task_masks, &p_map, &wrapper, 0 /*BPF NOEXIST*/);
	if (ret) {
		sdt_task_free(p);
		return ret;
	}

	mask_map_value = bpf_map_lookup_elem(&task_masks, &p_map);
	if (!mask_map_value) {
		sdt_task_free(p);
		return -EINVAL;
	}

	ret = create_save_cpumask(&mask_map_value->instance);
	if (ret) {
		bpf_map_delete_elem(&task_masks, &p_map);
		sdt_task_free(p);
		return ret;
	}

	bpf_rcu_read_lock();
	task_pick_and_set_domain(taskc, p, p->cpus_ptr, true);
	bpf_rcu_read_unlock();

	return 0;
}

void BPF_STRUCT_OPS(rusty_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	long ret;

	sdt_task_free(p);

	/*
	 * XXX - There's no reason delete should fail here but BPF's recursion
	 * protection can unnecessarily fail the operation. The fact that
	 * deletions aren't reliable means that we sometimes leak bpf_cpumask and
	 * can't use BPF_NOEXIST on allocation in .prep_enable().
	 */
	ret = bpf_map_delete_elem(&task_masks, &p);
	if (ret) {
		stat_add(RUSTY_STAT_TASK_GET_ERR, 1);
		return;
	}

}

static s32 create_node(u32 node_id)
{
	u32 cpu;
	struct bpf_cpumask *cpumask;
	struct node_ctx *nodec;
	s32 ret;

	nodec = bpf_map_lookup_elem(&node_data, &node_id);
	if (!nodec) {
		/* Should never happen, it's created statically at load time. */
		scx_bpf_error("No node%u", node_id);
		return -ENOENT;
	}

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

	bpf_for(cpu, 0, MAX_CPUS) {
		const volatile u64 *nmask;

		nmask = MEMBER_VPTR(numa_cpumasks, [node_id][cpu / 64]);
		if (!nmask) {
			scx_bpf_error("array index error");
			ret = -ENOENT;
			break;
		}

		if (*nmask & (1LLU << (cpu % 64)))
			bpf_cpumask_set_cpu(cpu, cpumask);
	}

	bpf_rcu_read_unlock();
	return ret;
}

__weak s32 create_dom(u32 dom_id)
{
	dom_ptr domc;
	struct node_ctx *nodec;
	struct bpf_cpumask *dom_mask, *node_mask, *all_mask;
	struct lb_domain *lb_domain;
	u32 cpu, node_id;
	int perf;
	s32 ret;

	if (dom_id >= MAX_DOMS) {
		scx_bpf_error("Max dom ID %u exceeded (%u)", MAX_DOMS, dom_id);
		return -EINVAL;
	}

	node_id = dom_node_id(dom_id);

	domc = lb_domain_alloc(dom_id);
	if (!domc)
		return -ENOMEM;

	dom_ctxs[dom_id] = domc;
	cast_user(dom_ctxs[dom_id]);

	lb_domain = lb_domain_get(dom_id);
	if (!lb_domain) {
		scx_bpf_error("could not retrieve dom%d data\n", dom_id);
		lb_domain_free(domc);
		return -EINVAL;
	}

	ret = scx_bpf_create_dsq(dom_id, node_id);
	if (ret < 0) {
		scx_bpf_error("Failed to create dsq %u (%d)", dom_id, ret);
		return ret;
	}

	domc->id = dom_id;

	ret = create_save_cpumask(&lb_domain->cpumask);
	if (ret)
		return ret;

	bpf_printk("Created domain %d (%p)", dom_id, &lb_domain->cpumask);
	if (!lb_domain->cpumask)
		scx_bpf_error("NULL");

	bpf_rcu_read_lock();
	dom_mask = lb_domain->cpumask;
	all_mask = all_cpumask;
	if (!dom_mask || !all_mask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Could not find cpumask");
		return -ENOENT;
	}

	bpf_for(cpu, 0, MAX_CPUS) {
		const volatile u64 *dmask;
		bool cpu_in_domain;

		dmask = MEMBER_VPTR(dom_cpumasks, [dom_id][cpu / 64]);
		if (!dmask) {
			scx_bpf_error("array index error");
			ret = -ENOENT;
			break;
		}

		cpu_in_domain = *dmask & (1LLU << (cpu % 64));
		if (!cpu_in_domain)
			continue;

		bpf_cpumask_set_cpu(cpu, dom_mask);
		bpf_cpumask_set_cpu(cpu, all_mask);

		/*
		 * Perf has to be within [0, 1024]. Set it regardless
		 * of value to clean up any previous settings, since
		 * it persists even after removing the scheduler.
		 */
		perf = min(SCX_CPUPERF_ONE, rusty_perf_mode);
		scx_bpf_cpuperf_set(cpu, perf);
	}
	bpf_rcu_read_unlock();
	if (ret)
		return ret;

	ret = create_save_cpumask(&lb_domain->direct_greedy_cpumask);
	if (ret)
		return ret;

	nodec = bpf_map_lookup_elem(&node_data, &node_id);
	if (!nodec) {
		/* Should never happen, it's created statically at load time. */
		scx_bpf_error("No node%u", node_id);
		return -ENOENT;
	}
	ret = create_save_cpumask(&lb_domain->node_cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	node_mask = nodec->cpumask;
	dom_mask = lb_domain->node_cpumask;
	if (!node_mask || !dom_mask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("cpumask lookup failed");
		return -ENOENT;
	}
	bpf_cpumask_copy(dom_mask, cast_mask(node_mask));
	bpf_rcu_read_unlock();

	return 0;
}

static s32 initialize_cpu(s32 cpu)
{
	struct pcpu_ctx *pcpuc = lookup_pcpu_ctx(cpu);
	u32 i;

	if (!pcpuc)
		return -ENOENT;

	pcpuc->dom_rr_cur = cpu;
	bpf_for(i, 0, nr_doms) {
		bool in_dom;
		struct lb_domain *lb_domain;

		lb_domain = lb_domain_get(i);
		if (!lb_domain)
			return -ENOENT;

		bpf_rcu_read_lock();
		if (!lb_domain->cpumask) {
			bpf_rcu_read_unlock();
			scx_bpf_error("Failed to lookup dom node %d cpumask %p",
				i, &lb_domain->cpumask);
			return -ENOENT;
		}

		in_dom = bpf_cpumask_test_cpu(cpu, cast_mask(lb_domain->cpumask));
		bpf_rcu_read_unlock();
		if (in_dom) {
			pcpuc->dom_id = i;
			return 0;
		}
	}

	return -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rusty_init)
{
	s32 i, ret;

	ret = sdt_static_init(STATIC_ALLOC_PAGES_GRANULARITY);
	if (ret)
		return ret;

	ret = sdt_task_init(sizeof(struct task_ctx));
	if (ret)
		return ret;

	ret = lb_domain_init();
	if (ret)
		return ret;

	ret = create_save_cpumask(&all_cpumask);
	if (ret)
		return ret;

	ret = create_save_cpumask(&direct_greedy_cpumask);
	if (ret)
		return ret;

	ret = create_save_cpumask(&kick_greedy_cpumask);
	if (ret)
		return ret;

	ret = scx_rusty_percpu_storage_init();
	if (ret)
		return ret;

	bpf_for(i, 0, nr_nodes) {
		ret = create_node(i);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, nr_doms) {
		ret = create_dom(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		if (is_offline_cpu(i))
			continue;

		ret = initialize_cpu(i);
		if (ret)
			return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(rusty_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rusty,
	       .select_cpu		= (void *)rusty_select_cpu,
	       .enqueue			= (void *)rusty_enqueue,
	       .dispatch		= (void *)rusty_dispatch,
	       .runnable		= (void *)rusty_runnable,
	       .running			= (void *)rusty_running,
	       .stopping		= (void *)rusty_stopping,
	       .quiescent		= (void *)rusty_quiescent,
	       .set_weight		= (void *)rusty_set_weight,
	       .set_cpumask		= (void *)rusty_set_cpumask,
	       .init_task		= (void *)rusty_init_task,
	       .exit_task		= (void *)rusty_exit_task,
	       .init			= (void *)rusty_init,
	       .exit			= (void *)rusty_exit,
	       .timeout_ms		= 10000,
	       .name			= "rusty");
