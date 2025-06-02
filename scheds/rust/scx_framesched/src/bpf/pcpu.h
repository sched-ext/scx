/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __PCPU_H
#define __PCPU_H

#ifndef SCX_MAIN_SCHED
#error "Should only be included from the main sched BPF C file"
#endif

#include <scx/common.bpf.h>

#include "helpers.h"
#include "intf.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct pcpu_ctx);
	__uint(map_flags, 0);
} pcpu_data SEC(".maps");

static struct pcpu_ctx *pcpu_try_lookup_ctx(s32 cpu)
{
	return bpf_map_lookup_elem(&pcpu_data, &cpu);
}

static struct pcpu_ctx *pcpu_lookup_ctx(s32 cpu)
{
	struct pcpu_ctx *pcpuc;

	pcpuc = pcpu_try_lookup_ctx(cpu);
	if (unlikely(!pcpuc))
		scx_bpf_error("Failed to lookup pcpu ctx for cpu %d", cpu);

	return pcpuc;
}

static struct pcpu_ctx *pcpu_lookup_curr_ctx(void)
{
	return pcpu_lookup_ctx(bpf_get_smp_processor_id());
}

static __maybe_unused struct bpf_cpumask *pcpuc_get_mask(struct pcpu_ctx *pcpuc)
{
	struct bpf_cpumask *scratch;

	scratch = bpf_kptr_xchg(&pcpuc->scratch_mask, NULL);
	if (unlikely(!scratch)) {
		scx_bpf_error("CPU %d didn't have scratch mask", pcpuc->cpu);
		return NULL;
	}

	return scratch;
}

static __maybe_unused void pcpuc_release_mask(struct pcpu_ctx *pcpuc, struct bpf_cpumask *mask)
{
	struct bpf_cpumask *scratch;

	scratch = bpf_kptr_xchg(&pcpuc->scratch_mask, mask);
	if (unlikely(scratch))
		scx_bpf_error("CPU %d already had mask in release", pcpuc->cpu);
}

static int pcpu_init_ctx(s32 cpu)
{
	struct pcpu_ctx *pcpuc;

	pcpuc = pcpu_lookup_ctx(cpu);
	if (!pcpuc)
		return -ENOENT;

	if (!pcpuc->capacity) {
		scx_bpf_error("cpu %d was not assigned to a domain", cpu);
		return -ENOENT;
	}

	pcpuc->cpu = cpu;

	return create_assign_cpumask(&pcpuc->scratch_mask);
}

#endif /* __PCPU_H */
