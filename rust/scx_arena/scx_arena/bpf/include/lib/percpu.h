#pragma once

#include <scx/common.bpf.h>
#include <lib/cpumask.h>

struct scx_percpu_storage {
	struct bpf_cpumask __kptr *bpfmask;
	scx_bitmap_t scx_bitmap;
	cpumask_t cpumask;
	struct scx_bitmap scx_bitmap_stack;
};

/*
 * XXX Need protection against grabbing the same per-cpu temporary storage
 * twice, or this can lead to very nasty bugs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct scx_percpu_storage);
	__uint(max_entries, 1);
} scx_percpu_storage_map __weak SEC(".maps");

static s32 create_save_scx_bitmap(scx_bitmap_t *maskp)
{
	scx_bitmap_t mask;

	mask = scx_bitmap_alloc();
	if (!mask)
		return -ENOMEM;

	scx_bitmap_clear(mask);

	*maskp = mask;

	return 0;
}

static s32 create_save_bpfmask(struct bpf_cpumask __kptr **kptr)
{
	struct bpf_cpumask *bpfmask;

	bpfmask = bpf_cpumask_create();
	if (!bpfmask) {
		bpf_printk("Failed to create bpfmask");
		return -ENOMEM;
	}

	bpfmask = bpf_kptr_xchg(kptr, bpfmask);
	if (bpfmask) {
		bpf_printk("kptr already had cpumask");
		bpf_cpumask_release(bpfmask);
	}

	return 0;
}

__weak int scx_storage_init_single(u32 cpu)
{
	struct scx_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;
	int ret;

	storage = bpf_map_lookup_percpu_elem(map, &zero, cpu);
	if (!storage) {
		/* Should be impossible. */
		bpf_printk("Did not find map entry for cpu %d", cpu);
		return -EINVAL;
	}

	ret = create_save_bpfmask(&storage->bpfmask);
	if (ret)
		return ret;

	return create_save_scx_bitmap(&storage->scx_bitmap);
}

__weak int scx_percpu_storage_init(void)
{
	int ret, i;

	bpf_for(i, 0, nr_cpu_ids) {
		ret = scx_storage_init_single(i);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static __maybe_unused
struct bpf_cpumask *scx_percpu_bpfmask(void)
{
	struct scx_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		bpf_printk("Did not find map entry");
		return NULL;
	}

	if (!storage->bpfmask)
		bpf_printk("Did not properly initialize singleton bpfmask");

	return storage->bpfmask;
}

static __maybe_unused
scx_bitmap_t scx_percpu_scx_bitmap(void)
{
	struct scx_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		bpf_printk("Did not find map entry (bitmap)");
		return NULL;
	}

	if (!storage->scx_bitmap)
		bpf_printk("Did not properly initialize singleton scx_bitmap");

	return storage->scx_bitmap;
}

static __maybe_unused
cpumask_t *scx_percpu_cpumask(void)
{
	struct scx_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		bpf_printk("Did not find map entry");
		return NULL;
	}

	return &storage->cpumask;
}

static __maybe_unused
struct scx_bitmap *scx_percpu_scx_bitmap_stack(void)
{
	struct scx_percpu_storage *storage;
	void *map = &scx_percpu_storage_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		bpf_printk("Did not find map entry");
		return NULL;
	}

	return &storage->scx_bitmap_stack;
}
