/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "power.bpf.h"

u32 nr_cids;
struct scx_cmask __arena *online_cmask;
struct scx_cmask __arena *idle_cmask;
struct scx_cmask __arena *idle_smt_cmask;

enum {
	NR_GLOBAL_MASKS = 8,
	NR_CPU_MASKS = 7,
};

/* the scratch masks share one arena pool, @mask_sz bytes apart */
static struct scx_cmask __arena *pool_mask(u8 __arena *pool, u32 mask_sz, u32 slot)
{
	return (struct scx_cmask __arena *)(pool + slot * mask_sz);
}

/* only fresh zeroed mask-pool entries may use this initializer */
static __always_inline
void init_zeroed_mask(struct scx_cmask __arena *mask, u32 width)
{
	mask->nr_cids = width;
	mask->alloc_words = CMASK_NR_WORDS(width);
}

__hidden
int init_cid_masks(void)
{
	const struct scx_cmask __arena *online;
	struct cpu_ctx __arena *cpuc;
	struct scx_cid_topo topo;
	struct cpdom_ctx __arena *cpdomc;
	u8 __arena *pool;
	u32 pages, mask_sz;
	s32 cid, cpu, i, j;

	nr_cids = scx_bpf_nr_cids();
	if (!nr_cids || nr_cids > LAVD_CPU_ID_MAX)
		return -EINVAL;

	pages = div_round_up(nr_cids * sizeof(*cpu_ctxs), PAGE_SIZE);
	cpu_ctxs = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!cpu_ctxs)
		return -ENOMEM;

	mask_sz = sizeof(struct scx_cmask) + CMASK_NR_WORDS(nr_cids) * sizeof(u64);
	pages = div_round_up((NR_GLOBAL_MASKS + nr_cids * NR_CPU_MASKS) * mask_sz, PAGE_SIZE);
	pool = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!pool)
		return -ENOMEM;
	bpf_arena_for(i, 0, NR_GLOBAL_MASKS)
		init_zeroed_mask(pool_mask(pool, mask_sz, i), nr_cids);

	turbo_cpumask = pool_mask(pool, mask_sz, 0);
	big_cpumask = pool_mask(pool, mask_sz, 1);
	active_cpumask = pool_mask(pool, mask_sz, 2);
	ovrflw_cpumask = pool_mask(pool, mask_sz, 3);
	steady_cpumask = pool_mask(pool, mask_sz, 4);
	online_cmask = pool_mask(pool, mask_sz, 5);
	idle_cmask = pool_mask(pool, mask_sz, 6);
	idle_smt_cmask = pool_mask(pool, mask_sz, 7);

	bpf_arena_for(cid, 0, nr_cids) {
		cpu = scx_bpf_cid_to_cpu(cid);
		if (cpu < 0)
			return -ESRCH;
		if (cpu >= LAVD_CPU_ID_MAX)
			return -EINVAL;
		cpuc = &cpu_ctxs[cid];
		cpuc->cpu_id = cid;
		cpuc->raw_cpu = cpu;

		i = NR_GLOBAL_MASKS + cid * NR_CPU_MASKS;
		bpf_arena_for(j, 0, NR_CPU_MASKS)
			init_zeroed_mask(pool_mask(pool, mask_sz, i + j), nr_cids);
		cpuc->a_mask = pool_mask(pool, mask_sz, i);
		cpuc->o_mask = pool_mask(pool, mask_sz, i + 1);
		cpuc->temp_mask = pool_mask(pool, mask_sz, i + 2);
		cpuc->i_mask = pool_mask(pool, mask_sz, i + 3);
		cpuc->ia_mask = pool_mask(pool, mask_sz, i + 4);
		cpuc->io_mask = pool_mask(pool, mask_sz, i + 5);
		cpuc->iat_mask = pool_mask(pool, mask_sz, i + 6);

		/*
		 * A core's cids are contiguous, so its first cid names the core
		 * and a cid without topology is a core of its own.
		 */
		scx_bpf_cid_topo(cid, &topo);
		cpuc->core_cid = topo.core_cid >= 0 ? topo.core_cid : cid;
		cpu_ctxs[cpuc->core_cid].core_nr++;
	}
	bpf_arena_for(cid, 0, nr_cids) {
		cpuc = &cpu_ctxs[cid];
		cpuc->core_nr = cpu_ctxs[cpuc->core_cid].core_nr;
	}
	online = scx_bpf_online_cmask();
	if (!online)
		return -ENOENT;
	cmask_copy(online_cmask, online);
	cmask_copy(active_cpumask, online_cmask);
	nr_cpus_onln = cmask_weight(online_cmask);

	/*
	 * Translate the preference table and the domain bitmaps to cids in
	 * place. Their order and membership are lavd policy, not cid topology.
	 */
	bpf_arena_for(i, 0, LAVD_PCO_STATE_MAX) {
		bpf_arena_for(j, 0, nr_cpu_ids) {
			cid = scx_bpf_cpu_to_cid(pco_table[i][j]);
			if (cid < 0)
				return -EINVAL;
			pco_table[i][j] = cid;
		}
	}
	bpf_arena_for(i, 0, LAVD_CPDOM_MAX_NR) {
		cpdomc = get_cpdom_ctx(i);
		cmask_init(&cpdomc->cpus, 0, nr_cids);
		cmask_init(&cpdomc->online, 0, nr_cids);
		if (!cpdomc->is_valid)
			continue;
		bpf_arena_for(cid, 0, nr_cids) {
			cpu = scx_bpf_cid_to_cpu(cid);
			if (cpdomc->__cpumask[cpu / 64] & BIT_U64(cpu % 64))
				__cmask_set(cid, &cpdomc->cpus);
		}
	}
	return 0;
}

/**
 * claim_idle_cid - Claim an idle CID
 * @cid: candidate CID
 *
 * Return 1 if claimed, 0 if busy, or -ENOENT if its context is unavailable.
 */
__hidden
s32 claim_idle_cid(s32 cid)
{
	struct cpu_ctx __arena *cpuc = get_cpu_ctx_id(cid);

	asm volatile("" :: "r"(&arena));
	if (!cpuc)
		return -ENOENT;
	/* clear the whole core even when another picker wins */
	if (is_smt_active)
		cmask_clear_range(idle_smt_cmask, cpuc->core_cid, cpuc->core_nr);
	return cmask_test_and_clear(cid, idle_cmask);
}

/* finish the distributed scan before adding the idle-claim stack frame */
static __noinline
s32 scan_idle_cids(const struct scx_cmask __arena *idle,
		   const struct scx_cmask __arena *allowed)
{
	return cmask_any_and_distribute(idle, allowed);
}

__hidden
s32 pick_idle_cid(const struct scx_cmask __arena __arg_arena *allowed, u64 flags)
{
	s32 cid, claimed;

	asm volatile("" :: "r"(&arena));
	while (can_loop) {
		/* prefer whole cores even without CORE set */
		if (is_smt_active) {
			cid = scan_idle_cids(idle_smt_cmask, allowed);
			if (cid < nr_cids)
				goto found;
			if (flags & SCX_PICK_IDLE_CORE)
				return -EBUSY;
		}
		cid = scan_idle_cids(idle_cmask, allowed);
		if (cid >= nr_cids)
			return -EBUSY;
found:
		claimed = claim_idle_cid(cid);
		if (claimed > 0)
			return cid;
		if (claimed < 0)
			return -EBUSY;
	}
	return -EBUSY;
}

/*
 * The caller supplies the validated context for the notified cid. Both sibling
 * scans stay in this frame: the core range is fixed at init and bounded by the
 * cid limit, so together they visit at most twice LAVD_CPU_ID_MAX cids.
 */
__hidden __noinline
void update_idle_cid(struct cpu_ctx __arena __arg_arena *cpuc, bool idle)
{
	s32 cid = cpuc->cpu_id, sibling;

	asm volatile("" :: "r"(&arena));
	if (idle)
		cmask_set(cid, idle_cmask);
	else
		cmask_clear(cid, idle_cmask);
	if (!is_smt_active)
		return;
	if (idle) {
		/* offline siblings must not prevent a full-core idle claim */
		bpf_arena_for(sibling, cpuc->core_cid, cpuc->core_cid + cpuc->core_nr) {
			if (cmask_test(sibling, online_cmask) &&
			    !cmask_test(sibling, idle_cmask))
				return;
		}
		bpf_arena_for(sibling, cpuc->core_cid, cpuc->core_cid + cpuc->core_nr) {
			if (cmask_test(sibling, online_cmask))
				cmask_set(sibling, idle_smt_cmask);
		}
	} else {
		cmask_clear_range(idle_smt_cmask, cpuc->core_cid, cpuc->core_nr);
	}
}

void scx_cgroup_bw_kick_idle_cb(void)
{
	s32 cid = pick_idle_cid(online_cmask, SCX_PICK_IDLE_CORE);

	if (cid == -EBUSY)
		cid = pick_idle_cid(online_cmask, 0);
	if (cid >= 0)
		scx_bpf_kick_cid(cid, SCX_KICK_IDLE);
}
