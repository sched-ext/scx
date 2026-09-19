/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * The machine: the arena the tables are carved out of, what user space
 * reports about each CPU, and the topology of the cid space those tables
 * are indexed by. All of it runs once, before the scheduler is attached or
 * from ops.init().
 *
 * scx/percpu.bpf.h is included here and nowhere else: only the priority
 * query below reads a per-CPU kernel variable.
 */
#include "eevdf.bpf.h"
#include <scx/percpu.bpf.h>

/*
 * Scratch space for scx_bpf_cid_topo(), only used by ops.init(). It has
 * to be readable as a whole at the call, which stack slots that are never
 * read back are not.
 */
static struct scx_cid_topo init_topo;

/*
 * Fill the topology of every cid.
 *
 * Cids are assigned in topological order (node, then LLC, then core), so
 * the cids of a core, an LLC or a node are always contiguous. Walking the
 * cid space backwards means the highest cid of a range is visited first,
 * which is enough to derive the length of the range from its base, the
 * cid scx_bpf_cid_topo() reports for the domain.
 */
static void init_topology(void)
{
	s32 cur_core = -1, cur_llc = -1, cur_node = -1;
	u32 core_nr = 0, llc_nr = 0, node_nr = 0;
	u32 i;

	bpf_arena_for(i, 0, nr_cids) {
		struct scx_cid_topo *ct = &init_topo;
		s32 cid = nr_cids - 1 - i;
		struct cid_topo __arena *topo = cid_topo(cid);
		s32 cpu = scx_bpf_cid_to_cpu(cid);

		cid_ctx(cid)->busy_balance_cid = -1;
		cid_ctx(cid)->busy_balance_owner = -1;
		cid_pack(cid)->cid = cid;
		cid_ctx(cid)->active_balance_cid = -1;

		scx_bpf_cid_topo(cid, ct);

		topo->cpu = cpu >= 0 ? cpu : 0;
		if (cpu >= 0 && (u32)cpu < nr_cpu_ids) {
			topo->cap = cpu_cap_in[cpu];
			topo->place_tier = cpu_place_tier_in[cpu];
			topo->capacity_tier = cpu_capacity_tier_in[cpu];
			topo->smt_asym_packing = cpu_smt_asym_in[cpu];
		} else {
			topo->cap = 1;
			topo->place_tier = nr_place_tiers - 1;
			topo->capacity_tier = nr_capacity_tiers - 1;
			topo->smt_asym_packing = 0;
		}

		/*
		 * A cid without topology (a CPU that was offline when the
		 * cid space was built) is a core, an LLC and a node of its
		 * own.
		 */
		if (ct->core_cid < 0 || ct->llc_cid < 0 || ct->node_cid < 0) {
			topo->core_base = cid;
			topo->core_nr = 1;
			topo->llc_base = cid;
			topo->llc_nr = 1;
			topo->node_base = cid;
			topo->node_nr = 1;
			topo->fork_base = cid;
			topo->fork_nr = 1;
			topo->wake_affine_base = cid;
			topo->wake_affine_nr = 1;
			topo->asym_capacity_base = cid;
			topo->asym_capacity_nr = 1;
			continue;
		}

		if (ct->core_cid != cur_core) {
			cur_core = ct->core_cid;
			core_nr = cid + 1 - ct->core_cid;
		}
		if (ct->llc_cid != cur_llc) {
			cur_llc = ct->llc_cid;
			llc_nr = cid + 1 - ct->llc_cid;
		}
		if (ct->node_cid != cur_node) {
			cur_node = ct->node_cid;
			node_nr = cid + 1 - ct->node_cid;
		}

		topo->core_base = smt_enabled ? ct->core_cid : cid;
		topo->core_nr = smt_enabled ? core_nr : 1;
		topo->llc_base = ct->llc_cid;
		topo->llc_nr = llc_nr;
		topo->node_base = ct->node_cid;
		topo->node_nr = node_nr;

		{
			u32 fork_span = 0, wake_span = 0, asym_span = 0;
			u64 range;

			if (cpu >= 0 && (u32)cpu < nr_cpu_ids) {
				fork_span = cpu_fork_span_in[cpu];
				wake_span = cpu_wake_span_in[cpu];
				asym_span = cpu_asym_span_in[cpu];
			}
			range = topo_domain_range(topo, fork_span,
						  topo->node_nr);
			topo->fork_base = range;
			topo->fork_nr = range >> 32;
			range = topo_domain_range(topo, wake_span,
						  topo->llc_nr);
			topo->wake_affine_base = range;
			topo->wake_affine_nr = range >> 32;
			if (asym_span || force_asym_capacity) {
				range = topo_domain_range(topo, asym_span,
						  nr_cids);
				topo->asym_capacity_base = range;
				topo->asym_capacity_nr = range >> 32;
			} else {
				topo->asym_capacity_base = 0;
				topo->asym_capacity_nr = 0;
			}
		}
	}
}

/*
 * Carve @bytes out of the arena pages, @align aligned.
 */
static char __arena *arena_base;
static u64 arena_off, arena_size;

static void __arena *arena_carve(u64 bytes, u64 align)
{
	u64 off = (arena_off + align - 1) & ~(align - 1);

	if (off + bytes > arena_size)
		return NULL;
	arena_off = off + bytes;

	return (void __arena *)(arena_base + off);
}

/*
 * Size the arena for a cid space of @args->nr_cpus and
 * @args->nr_place_tiers packing tiers and @args->nr_capacity_tiers capacity
 * tiers, and carve the tables out of it.
 *
 * Run by user space after load and before attach: the tables have to be
 * in place before ops.init(), and the cid space, num_possible_cpus()
 * wide, is known before the scheduler is.
 */
SEC("syscall")
int eevdf_arena_init(struct eevdf_arena_args *args)
{
	u64 nr = args->nr_cpus, mask, bytes, pages;
	int ret;

	if (!nr || !args->nr_place_tiers || !args->nr_capacity_tiers)
		return -EINVAL;

	/*
	 * A cmask over the whole cid space, cache line aligned: the helpers
	 * ask for a word past the bits, see CMASK_NR_WORDS().
	 */
	mask = (sizeof(struct scx_cmask) + (u64)CMASK_NR_WORDS(nr) * sizeof(u64) + 63) & ~63ULL;
	bytes = nr * sizeof(struct cid_topo) + nr * sizeof(struct cid_ctx) +
		(3 + args->nr_place_tiers + args->nr_capacity_tiers) * mask +
		nr * (sizeof(struct core_sched_state) + sizeof(struct newidle_stats) +
		      sizeof(u64) +
		      6 * sizeof(u32)) + 13 * 64;
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	arena_base = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!arena_base)
		return -ENOMEM;
	arena_size = pages * PAGE_SIZE;
	arena_off = 0;

	topos = arena_carve(nr * sizeof(struct cid_topo), 64);
	cctxs = arena_carve(nr * sizeof(struct cid_ctx), 64);
	core_sched_states = arena_carve(nr * sizeof(struct core_sched_state), 64);
	newidle_stats = arena_carve(nr * sizeof(struct newidle_stats), 64);
	idle_cids = arena_carve(mask, 64);
	idle_core_llcs = arena_carve(mask, 64);
	queued_cids = arena_carve(mask, 64);
	place_tier_stride = mask;
	place_tier_cids = arena_carve(args->nr_place_tiers * mask, 64);
	capacity_tier_stride = mask;
	capacity_tier_cids = arena_carve(args->nr_capacity_tiers * mask, 64);
	cpu_cap_in = arena_carve(nr * sizeof(u64), 64);
	cpu_place_tier_in = arena_carve(nr * sizeof(u32), 64);
	cpu_capacity_tier_in = arena_carve(nr * sizeof(u32), 64);
	cpu_smt_asym_in = arena_carve(nr * sizeof(u32), 64);
	cpu_fork_span_in = arena_carve(nr * sizeof(u32), 64);
	cpu_wake_span_in = arena_carve(nr * sizeof(u32), 64);
	cpu_asym_span_in = arena_carve(nr * sizeof(u32), 64);
	if (!topos || !cctxs || !core_sched_states || !newidle_stats || !idle_cids ||
	    !idle_core_llcs || !queued_cids ||
	    !place_tier_cids || !capacity_tier_cids || !cpu_cap_in ||
	    !cpu_place_tier_in || !cpu_capacity_tier_in || !cpu_smt_asym_in ||
	    !cpu_fork_span_in || !cpu_wake_span_in || !cpu_asym_span_in)
		return -ENOMEM;
	ret = scx_alloc_init(&task_ctx_allocator, sizeof(struct task_ctx),
			     __alignof__(struct task_ctx));
	if (ret)
		return ret;

	nr_cids_max = nr;
	nr_place_tiers = args->nr_place_tiers;
	nr_capacity_tiers = args->nr_capacity_tiers;
	asym_capacity = args->asym_capacity;
	sched_asym_capacity = args->sched_asym_capacity;
	force_asym_capacity = args->force_asym_capacity;
	asym_packing = args->asym_packing;

	return 0;
}

/*
 * Report the capacity and its independent packing and capacity tiers in CPU
 * space. The cid layout is only known once the kernel has built it, so
 * ops.init() translates.
 */
SEC("syscall")
int eevdf_set_cpu(struct eevdf_cpu_args *args)
{
	u64 cpu = args->cpu;

	TOUCH_ARENA();

	if (!cpu_cap_in || cpu >= nr_cids_max ||
	    args->place_tier >= nr_place_tiers ||
	    args->capacity_tier >= nr_capacity_tiers)
		return -EINVAL;

	cpu_cap_in[cpu] = args->capacity;
	cpu_place_tier_in[cpu] = args->place_tier;
	cpu_capacity_tier_in[cpu] = args->capacity_tier;
	cpu_smt_asym_in[cpu] = args->smt_asym_packing;
	cpu_fork_span_in[cpu] = args->fork_span;
	cpu_wake_span_in[cpu] = args->wake_affine_span;
	cpu_asym_span_in[cpu] = args->asym_capacity_span;

	return 0;
}

/*
 * Return one CPU's SD_ASYM_PACKING state and arch_asym_cpu_priority().
 * Topology supplies the other scheduler-domain policy; packing has no stable
 * userspace ABI and is deliberately kept separate from CPU capacity.
 */
SEC("syscall")
int eevdf_get_cpu_priority(struct eevdf_cpu_priority_args *args)
{
	struct sched_domain *sd;
	u64 cpu = args->cpu;
	int priority;

	args->priority = 0;
	args->asym_packing = 0;
	args->smt_asym_packing = 0;
	if (cpu > INT_MAX || !&sched_core_priority || !&sd_asym_packing)
		return 0;

	priority = cpu_priority(cpu);
	sd = cpu_asym_packing_dom(cpu);
	if (priority < 0 || !sd)
		return 0;

	args->priority = priority;
	args->asym_packing = 1;
	bpf_repeat(16) {
		int flags;

		if (!sd)
			break;
		flags = BPF_CORE_READ(sd, flags);
		if ((flags & (SD_SHARE_CPUCAPACITY | SD_ASYM_PACKING)) ==
		    (SD_SHARE_CPUCAPACITY | SD_ASYM_PACKING)) {
			args->smt_asym_packing = 1;
			break;
		}
		sd = BPF_CORE_READ(sd, child);
	}
	return 0;
}
