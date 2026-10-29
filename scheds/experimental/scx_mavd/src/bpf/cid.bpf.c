/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "power.bpf.h"

u32 nr_cids;
struct scx_cmask __arena *online_cmask;
/* the revoke sweep's scratch mask, one sweep runs at a time */
struct scx_cmask __arena *sweep_cmask;

enum {
	NR_GLOBAL_MASKS = 7,
	NR_CPU_MASKS = 3,
};

/* the scratch masks share one arena pool, @mask_sz bytes apart */
static struct scx_cmask __arena *pool_mask(u8 __arena *pool, u32 mask_sz, u32 slot)
{
	return (struct scx_cmask __arena *)(pool + slot * mask_sz);
}

__hidden
int init_cid_masks(void)
{
	const struct scx_cmask __arena *online;
	struct scx_cid_topo topo;
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
		cmask_init(pool_mask(pool, mask_sz, i), 0, nr_cids);

	turbo_cmask = pool_mask(pool, mask_sz, 0);
	big_cmask = pool_mask(pool, mask_sz, 1);
	active_cmask = pool_mask(pool, mask_sz, 2);
	ovrflw_cmask = pool_mask(pool, mask_sz, 3);
	steady_cmask = pool_mask(pool, mask_sz, 4);
	online_cmask = pool_mask(pool, mask_sz, 5);
	sweep_cmask = pool_mask(pool, mask_sz, 6);

	bpf_arena_for(cid, 0, nr_cids) {
		struct cpu_ctx __arena *cpuc = get_cpu_ctx_id(cid);

		cpu = scx_bpf_cid_to_cpu(cid);
		cpuc->cid = cid;
		cpuc->kernel_cpu = cpu;

		i = NR_GLOBAL_MASKS + cid * NR_CPU_MASKS;
		bpf_arena_for(j, 0, NR_CPU_MASKS)
			cmask_init(pool_mask(pool, mask_sz, i + j), 0, nr_cids);
		cpuc->a_mask = pool_mask(pool, mask_sz, i);
		cpuc->o_mask = pool_mask(pool, mask_sz, i + 1);
		cpuc->temp_mask = pool_mask(pool, mask_sz, i + 2);

		/*
		 * A core's cids are contiguous, so its first cid names the core
		 * and a cid without topology is a core of its own.
		 */
		scx_bpf_cid_topo(cid, &topo);
		cpuc->core_cid = topo.core_cid >= 0 ? topo.core_cid : cid;
		cpu_ctxs[cpuc->core_cid].core_nr_cids++;
	}
	bpf_arena_for(cid, 0, nr_cids) {
		struct cpu_ctx __arena *cpuc = &cpu_ctxs[cid];

		cpuc->core_nr_cids = cpu_ctxs[cpuc->core_cid].core_nr_cids;
	}
	/* a sub starts with no cid, see lavd_sub_ecaps_updated() */
	if (!sub_mode) {
		online = scx_bpf_online_cmask();
		if (!online)
			return -ENOENT;
		cmask_copy(online_cmask, online);
	}
	cmask_copy(active_cmask, online_cmask);
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
		struct cpdom_ctx __arena *cpdomc = get_cpdom_ctx(i);

		cmask_init(&cpdomc->cpus, 0, nr_cids);
		cmask_init(&cpdomc->online, 0, nr_cids);
		cmask_init(&cpdomc->idle, 0, nr_cids);
		cmask_init(&cpdomc->idle_smt, 0, nr_cids);
		if (!cpdomc->is_valid)
			continue;
		bpf_arena_for(cid, 0, nr_cids) {
			cpu = scx_bpf_cid_to_cpu(cid);
			if (cpdomc->__cpumask[cpu >> 6] & BIT_U64(cpu & 63))
				__cmask_set(cid, &cpdomc->cpus);
		}
	}
	return 0;
}
