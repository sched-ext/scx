#pragma once

#include <scx/common.bpf.h>

struct rusty_percpu_storage {
	struct bpf_cpumask __kptr *bpfmask;
	scx_cpumask_t scxmask;
	cpumask_t cpumask;
};

/*
 * XXX Need protection against grabbing the same per-cpu temporary storage
 * twice, or this can lead to very nasty bugs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct rusty_percpu_storage);
	__uint(max_entries, 1);
} scx_percpu_storage_map __weak SEC(".maps");

static s32 create_save_scxmask(scx_cpumask_t *maskp)
{
	scx_cpumask_t mask;

	mask = scx_mask_alloc();
	if (!mask)
		return -ENOMEM;

	scxmask_clear(mask);

	*maskp = mask;

	return 0;
}

static s32 create_save_bpfmask(struct bpf_cpumask __kptr **kptr)
{
	struct bpf_cpumask *bpfmask;

	bpfmask = bpf_cpumask_create();
	if (!bpfmask) {
		scx_bpf_error("Failed to create bpfmask");
		return -ENOMEM;
	}

	bpfmask = bpf_kptr_xchg(kptr, bpfmask);
	if (bpfmask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(bpfmask);
	}

	return 0;
}

__weak int scx_rusty__storage_init_single(u32 cpu)
{
	struct rusty_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;
	int ret;

	storage = bpf_map_lookup_percpu_elem(map, &zero, cpu);
	if (!storage) {
		/* Should be impossible. */
		scx_bpf_error("Did not find map entry");
		return -EINVAL;
	}

	ret = create_save_bpfmask(&storage->bpfmask);
	if (ret)
		return ret;

	return create_save_scxmask(&storage->scxmask);
}

__weak int scx_percpu_storage_init(void)
{
	int ret, i;

	bpf_for(i, 0, nr_cpu_ids) {
		ret = scx_rusty__storage_init_single(i);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static struct bpf_cpumask *scx_percpu_bpfmask(void)
{
	struct rusty_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		scx_bpf_error("Did not find map entry");
		return NULL;
	}

	if (!storage->bpfmask)
		scx_bpf_error("Did not properly initialize singleton bpfmask");

	return storage->bpfmask;
}

static scx_cpumask_t scx_percpu_scxmask(void)
{
	struct rusty_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		scx_bpf_error("Did not find map entry");
		return NULL;
	}

	if (!storage->scxmask)
		scx_bpf_error("Did not properly initialize singleton scxmask");

	return storage->scxmask;
}

static cpumask_t *scx_percpu_cpumask(void)
{
	struct rusty_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		scx_bpf_error("Did not find map entry");
		return NULL;
	}

	return &storage->cpumask;
}
