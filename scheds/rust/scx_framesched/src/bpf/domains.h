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
#include "signatures.h"

const volatile u32 nr_cpu_ids = 64; /* !0 for veristat, set during init */
const volatile u32 nr_dom_ids = 64; /* !0 for veristat, set during init */

struct dom_init_ctx {
	u32 dom_id;
	u32 numa_id;
	u64 mask[MAX_CPUS / 64];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct dom_ctx);
	__uint(map_flags, 0);
} dom_data SEC(".maps");

static struct dom_ctx *domains_try_lookup_ctx(u32 dom_id)
{
	return bpf_map_lookup_elem(&dom_data, &dom_id);
}

static struct dom_ctx *domains_lookup_ctx(u32 dom_id)
{
        struct dom_ctx *domc;

        domc = domains_try_lookup_ctx(dom_id);
        if (unlikely(!domc))
                scx_bpf_error("Failed to lookup dom[%u]", dom_id);

        return domc;
}

static int domains_task_pick_dom(struct task_struct *p, struct task_ctx *taskc)
{
	struct pcpu_ctx *pcpuc;
	u32 idx;

	taskc->orphaned = false;
	taskc->pinned = false;
	taskc->dom_id = -1;
	pcpuc = pcpu_lookup_curr_ctx();
	if (!pcpuc)
		return -ENOENT;

	bpf_for(idx, 0, nr_dom_ids) {
		u32 dom = pcpuc->rr_idx++ % nr_dom_ids;
		struct dom_ctx *domc;
		const struct cpumask *d_mask;
		struct bpf_cpumask *t_mask;

		domc = domains_lookup_ctx(dom);
		if (!domc)
			return -ENOENT;

		bpf_rcu_read_lock();
		d_mask = cast_mask(domc->cpumask);
		t_mask = taskc->cpumask;
		if (unlikely(!d_mask || !t_mask)) {
			bpf_rcu_read_unlock();
			scx_bpf_error("%s[%d] mask not found for dom %u",
				      p->comm, p->pid, dom);
			return -ENOENT;
		}
		if (!bpf_cpumask_intersects(d_mask, p->cpus_ptr)) {
			bpf_rcu_read_unlock();
			continue;
		}
		taskc->dom_id = domc->id;
		bpf_cpumask_and(t_mask, d_mask, p->cpus_ptr);
		taskc->pinned = bpf_cpumask_subset(p->cpus_ptr, d_mask);
		bpf_rcu_read_unlock();
		dbg_log("%s[%d] intersected dom %u", p->comm,
			p->pid, dom);

		return 0;
	}

	taskc->orphaned = true;
	bpf_printk("%s[%d] orphaned", p->comm, p->pid);

	return -ENOENT;
}

SEC("syscall")
int create_dom_sys(struct dom_init_ctx *input)
{
	struct bpf_cpumask *cpumask;
	struct dom_ctx *dom_ctx;
	u32 dom_id = input->dom_id;
	s32 cpu;
	int err;

	dom_ctx = domains_lookup_ctx(dom_id);
	if (!dom_ctx)
		return -ENOENT;

	dom_ctx->id = dom_id;
	err = create_assign_cpumask(&dom_ctx->cpumask);
	if (err)
		return err;

	err = scx_bpf_create_dsq(dom_id, input->numa_id);
	if (err)
		return err;

	bpf_rcu_read_lock();
	cpumask = dom_ctx->cpumask;
	if (!cpumask) {
		err = -ENOENT;
		goto unlock_out;
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		u64 mask = input->mask[cpu / 64];
		struct pcpu_ctx *pcpuc;

		if (mask & (1LLU << cpu)) {
			dbg_log("CPU %d added to dom %u", cpu, dom_id)
			pcpuc = pcpu_lookup_ctx(cpu);
			if (!pcpuc) {
				err = -ENOENT;
				goto unlock_out;
			}

			bpf_cpumask_set_cpu(cpu, cpumask);
			if (pcpuc->capacity) {
				scx_bpf_error("cpu %d was already allocated to domain %u",
					      cpu, pcpuc->dom_id);
				err = -EEXIST;
				goto unlock_out;
			}

			pcpuc->capacity = scx_bpf_cpuperf_cap(cpu);
			pcpuc->dom_id = dom_id;
		}
	}

unlock_out:
	bpf_rcu_read_unlock();
	return err;
}

#endif /* __DOMAINS_H */
