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
		cmask_init(pool_mask(pool, mask_sz, i), 0, nr_cids);

	turbo_cpumask = pool_mask(pool, mask_sz, 0);
	big_cpumask = pool_mask(pool, mask_sz, 1);
	active_cpumask = pool_mask(pool, mask_sz, 2);
	ovrflw_cpumask = pool_mask(pool, mask_sz, 3);
	steady_cpumask = pool_mask(pool, mask_sz, 4);
	online_cmask = pool_mask(pool, mask_sz, 5);
	idle_cmask = pool_mask(pool, mask_sz, 6);
	idle_smt_cmask = pool_mask(pool, mask_sz, 7);

	bpf_arena_for(cid, 0, nr_cids) {
		cpuc = get_cpu_ctx_id(cid);
		if (!cpuc)
			return -ESRCH;
		cpu = scx_bpf_cid_to_cpu(cid);
		if (cpu < 0 || cpu >= LAVD_CPU_ID_MAX)
			return -EINVAL;
		cpuc->cpu_id = cid;
		cpuc->kernel_cpu = cpu;

		i = NR_GLOBAL_MASKS + cid * NR_CPU_MASKS;
		bpf_arena_for(j, 0, NR_CPU_MASKS)
			cmask_init(pool_mask(pool, mask_sz, i + j), 0, nr_cids);
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
		cpu_ctxs[cpuc->core_cid].core_nr_cids++;
	}
	bpf_arena_for(cid, 0, nr_cids) {
		cpuc = &cpu_ctxs[cid];
		cpuc->core_nr_cids = cpu_ctxs[cpuc->core_cid].core_nr_cids;
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
			if (cpdomc->__cpumask[cpu >> 6] & BIT_U64(cpu & 63))
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
		cmask_clear_range(idle_smt_cmask, cpuc->core_cid, cpuc->core_nr_cids);
	return cmask_test_and_clear(cid, idle_cmask);
}

__hidden
s32 pick_idle_cid(const struct scx_cmask __arena __arg_arena *allowed, u64 flags)
{
	s32 cid, claimed;

	asm volatile("" :: "r"(&arena));
	while (can_loop) {
		/* prefer whole cores even without CORE set */
		if (is_smt_active) {
			cid = cmask_any_and_distribute(idle_smt_cmask, allowed);
			if (cid < nr_cids)
				goto found;
			if (flags & SCX_PICK_IDLE_CORE)
				return -EBUSY;
		}
		cid = cmask_any_and_distribute(idle_cmask, allowed);
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

__hidden
void update_idle_cid(s32 cid, bool idle)
{
	struct cpu_ctx __arena *cpuc = get_cpu_ctx_id(cid);
	s32 sibling;

	asm volatile("" :: "r"(&arena));
	if (!cpuc)
		return;
	if (idle)
		cmask_set(cid, idle_cmask);
	else
		cmask_clear(cid, idle_cmask);
	if (!is_smt_active)
		return;
	if (idle) {
		/* offline siblings must not prevent a full-core idle claim */
		bpf_arena_for(sibling, cpuc->core_cid, cpuc->core_cid + cpuc->core_nr_cids) {
			if (cmask_test(sibling, online_cmask) &&
			    !cmask_test(sibling, idle_cmask))
				return;
		}
		bpf_arena_for(sibling, cpuc->core_cid, cpuc->core_cid + cpuc->core_nr_cids) {
			if (cmask_test(sibling, online_cmask))
				cmask_set(sibling, idle_smt_cmask);
		}
	} else {
		cmask_clear_range(idle_smt_cmask, cpuc->core_cid, cpuc->core_nr_cids);
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
