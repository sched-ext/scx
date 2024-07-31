/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __DOMAINS_H
#define __DOMAINS_H

#ifndef SCX_MAIN_SCHED
#error "Should only be included from the main sched BPF C file"
#endif

#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

#include "intf.h"

const volatile u32 nr_cpu_ids = 64; /* !0 for veristat, set during init */
const volatile u32 nr_dom_ids = 64; /* !0 for veristat, set during init */

// XXX: Remove this map once we can set this in create_dom_sys(). See
// https://lore.kernel.org/all/20240731051437.69689-1-void@manifault.com/
// for more information.
const volatile u32 numa_dom_id_map[1024]; /* !0 for veristat, set during init */

struct dom_init_ctx {
	u32 dom_id;
	u64 mask[MAX_CPUS / 64];
};

struct dom_ctx {
	u32 id;
	struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct dom_ctx);
	__uint(map_flags, 0);
} dom_data SEC(".maps");

static struct dom_ctx *domains_try_lookup_dom(u32 dom_id)
{
	return bpf_map_lookup_elem(&dom_data, &dom_id);
}

static struct dom_ctx *domains_lookup_dom(u32 dom_id)
{
        struct dom_ctx *domc;

        domc = domains_try_lookup_dom(dom_id);
        if (!domc)
                scx_bpf_error("Failed to lookup dom[%u]", dom_id);

        return domc;
}

/* Called from the initialization path in the main scheduler */
static int domains_init_dom(u32 dom_id)
{
	u32 *numa_id = MEMBER_VPTR(numa_dom_id_map, [dom_id]);

	if (!numa_id)
		return -ENOENT;

	return scx_bpf_create_dsq(dom_id, *numa_id);
}

SEC("syscall")
int create_dom_sys(struct dom_init_ctx *input)
{
	struct bpf_cpumask *cpumask;
	struct dom_ctx *dom_ctx;
	u32 dom_id = input->dom_id;
	s32 cpu;

	dom_ctx = domains_lookup_dom(dom_id);
	if (!dom_ctx)
		return -ENOENT;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;

	bpf_for(cpu, 0, nr_cpu_ids) {
		u64 mask = input->mask[cpu / 64];

		if (mask & (1LLU << cpu))
			bpf_cpumask_set_cpu(cpu, cpumask);
	}

	cpumask = bpf_kptr_xchg(&dom_ctx->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("Previously initialized domain %u", dom_id);
		bpf_cpumask_release(cpumask);
		return -EEXIST;
	}

	return 0;
}

#endif /* __DOMAINS_H */
