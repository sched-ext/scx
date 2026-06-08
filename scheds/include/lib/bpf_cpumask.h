#pragma once

#include <scx/common.bpf.h>

/*
 * Lifecycle helpers for kernel "struct bpf_cpumask" kptrs.
 *
 * These wrap the bpf_cpumask_create()/bpf_kptr_xchg()/bpf_cpumask_release()
 * dance that schedulers otherwise hand-roll for every per-scheduler or
 * per-context cpumask. This header intentionally depends only on
 * <scx/common.bpf.h> (the kfunc prototypes) so it can be included anywhere a
 * bpf_cpumask is allocated, without pulling in the arena scx_bitmap library or
 * the per-CPU storage map (see lib/percpu.h).
 *
 * Note: this is distinct from lib/cpumask.h, which is an arena-resident bitmap
 * (scx_bitmap) reimplementation; here we only manage the kernel's kptr object.
 */

/*
 * Allocate a bpf_cpumask and install it into the given kptr slot, releasing any
 * mask the slot previously held. Returns 0 on success, -ENOMEM on failure.
 */
static s32 create_save_bpfmask(struct bpf_cpumask __kptr **kptr)
{
	struct bpf_cpumask *bpfmask;

	bpfmask = bpf_cpumask_create();
	if (!bpfmask)
		return -ENOMEM;

	bpfmask = bpf_kptr_xchg(kptr, bpfmask);
	if (bpfmask)
		bpf_cpumask_release(bpfmask);

	return 0;
}
