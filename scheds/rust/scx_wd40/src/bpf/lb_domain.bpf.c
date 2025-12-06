/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */

#include <scx/common.bpf.h>
#include <lib/ravg.h>
#include <lib/cpumask.h>
#include <lib/sdt_task.h>
#include <lib/topology.h>

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#include <lib/cpumask.h>

#include "intf.h"
#include "types.h"
#include "lb_domain.h"

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

volatile scx_bitmap_t node_data[MAX_NUMA_NODES];

struct scx_stk lb_domain_allocator;

/*
 * Declared in its own section because loading the object otherwise fails
 * with the following error message (where bpf_bpf the fully linked object):
 *
 * [WARN] libbpf: map 'bpf_bpf.bss': failed to re-mmap() contents: -524
 * [WARN] libbpf: map 'bpf_bpf.bss': failed to create: unknown error (-524)(-524)
 * [WARN] libbpf: failed to load object 'bpf_bpf'
 */
private(LBDOMAIN_BUDDY) struct scx_buddy buddy;

#define LBALLOC_PAGES_PER_ALLOC (16)

__weak
int lb_domain_init(void)
{
	if (scx_buddy_init(&buddy, PAGE_SIZE)) {
		scx_bpf_error("failed to initialize buddy allocator");
		bpf_printk("failed to initialize buddy allocator");
	}

	return scx_stk_init(&lb_domain_allocator,
		sizeof(struct dom_ctx),
		LBALLOC_PAGES_PER_ALLOC);
}

__hidden
dom_ptr lb_domain_alloc(u32 dom_id)
{
	dom_ptr domc;

	domc = (dom_ptr)scx_stk_alloc(&lb_domain_allocator);
	if (!domc)
		return NULL;

	domc->cpumask = scx_bitmap_alloc();
	if (!domc->cpumask) {
		lb_domain_free(domc);
		return NULL;
	}

	domc->direct_greedy_cpumask = scx_bitmap_alloc();
	if (!domc->direct_greedy_cpumask) {
		scx_bitmap_free(domc->cpumask);
		lb_domain_free(domc);
		return NULL;
	}

	domc->node_cpumask = scx_bitmap_alloc();
	if (!domc->node_cpumask) {
		scx_bitmap_free(domc->direct_greedy_cpumask);
		scx_bitmap_free(domc->cpumask);
		lb_domain_free(domc);
		return NULL;
	}

	return domc;
}

__hidden
void lb_domain_free(dom_ptr domc)
{
	scx_arena_subprog_init();

	scx_bitmap_free(domc->node_cpumask);
	scx_bitmap_free(domc->direct_greedy_cpumask);
	scx_bitmap_free(domc->cpumask);

	scx_stk_free(&lb_domain_allocator, (void __arena *)domc);
}

__hidden
dom_ptr try_lookup_dom_ctx(u32 dom_id)
{
	if (dom_id >= MAX_DOMS)
		return NULL;

	return (dom_ptr)topo_nodes[TOPO_LLC][dom_id];
}

__hidden
dom_ptr lookup_dom_ctx(u32 dom_id)
{
	dom_ptr domc;

	domc = try_lookup_dom_ctx(dom_id);
	if (!domc)
		scx_bpf_error("Failed to lookup dom[%u]", dom_id);

	return domc;
}

static inline u32 weight_to_bucket_idx(u32 weight)
{
	/* Weight is calculated linearly, and is within range of [1, 10000] */
	return weight * LB_LOAD_BUCKETS / LB_MAX_WEIGHT;
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

__hidden
void dom_dcycle_adj(dom_ptr domc, u32 weight, u64 now, bool runnable)
{
	struct bucket_ctx *bucket;
	struct lock_wrapper *lockw;
	s64 adj = runnable ? 1 : -1;
	u32 bucket_idx = 0;
	u32 dom_id;

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



static int dom_dcycle_xfer_task(struct task_struct *p __arg_trusted, task_ptr taskc,
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
		return 0;

	from_bucket = lookup_dom_bucket(from_domc, weight, &idx);
	to_bucket = lookup_dom_bucket(to_domc, weight, &idx);
	if (!from_bucket || !to_bucket)
		return 0;

	/*
	 * @p is moving from @from_domc to @to_domc. Its duty cycle
	 * contribution in the relevant bucket of @from_domc should be moved
	 * together to the corresponding bucket in @to_dom_id. We only track
	 * duty cycle from BPF. Load is computed in user space when performing
	 * load balancing.
	 */
	ravg_accumulate(&task_dcyc_rd,  taskc->runnable, now, load_half_life);
	taskc->dcyc_rd = taskc->dcyc_rd;
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

	return 0;
}

int dom_xfer_task(struct task_struct *p __arg_trusted, u32 new_dom_id, u64 now)
{
	dom_ptr from_domc, to_domc;
	task_ptr taskc;

	taskc = (task_ptr)scx_task_data(p);
	if (!taskc)
		return 0;

	from_domc = taskc->domc;
	to_domc = lookup_dom_ctx(new_dom_id);

	dom_dcycle_xfer_task(p, taskc, from_domc, to_domc, now);
	return 0;
}

__weak s32 alloc_dom(u32 dom_id)
{
	dom_ptr domc;

	if (dom_id >= MAX_DOMS) {
		scx_bpf_error("Max dom ID %u exceeded (%u)", MAX_DOMS, dom_id);
		return -EINVAL;
	}

	domc = lb_domain_alloc(dom_id);
	if (!domc)
		return -ENOMEM;

	topo_nodes[TOPO_LLC][dom_id] = (u64)domc;

	return 0;
}

__hidden
s32 create_dom(u32 dom_id)
{
	dom_ptr domc;
	u32 node_id;
	s32 ret;

	/*
	 * XXX This is why we have to have a node struct, the sched_ext core
	 * uses them to match DSQs to NUMA nodes.
	 */
	node_id = dom_node_id(dom_id);

	ret = scx_bpf_create_dsq(dom_id, node_id);
	if (ret < 0) {
		scx_bpf_error("Failed to create dsq %u (%d)", dom_id, ret);
		return ret;
	}

	if (node_id >= MAX_NUMA_NODES) {
		scx_bpf_error("Invalid node %d %d", node_id, MAX_NUMA_NODES);
		return -ENOENT;
	}

	domc = lookup_dom_ctx(dom_id);
	domc->node_cpumask = node_data[node_id];

	return 0;
}
