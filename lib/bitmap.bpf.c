#include "scxtest/scx_test.h"
#include <scx/common.bpf.h>
#include <lib/arena.h>
#include <lib/cpumask.h>
#include <lib/sdt_task.h>

const volatile u32 nr_cpu_ids = NR_CPU_IDS_UNINIT;

static struct scx_allocator scx_bitmap_allocator;
size_t mask_size;

__weak
int scx_bitmap_init(__u64 total_mask_size)
{
	mask_size = div_round_up(total_mask_size, 8);

	return scx_alloc_init(&scx_bitmap_allocator, mask_size * 8 + sizeof(union sdt_id));
}

__weak
u64 scx_bitmap_alloc_internal(void)
{
	struct sdt_data __arena *data = NULL;
	scx_bitmap_t mask;
	int i;

	data = scx_alloc(&scx_bitmap_allocator);
	if (unlikely(!data))
		return (u64)(NULL);

	mask = (scx_bitmap_t)data->payload;
	mask->tid = data->tid;
	bpf_for(i, 0, mask_size) {
		mask->bits[i] = 0ULL;
	}

	return (u64)mask;
}

/*
 * XXXETSAL: Ideally these functions would have a void return type,
 * but as of 6.13 the verifier requires global functions to return a scalar.
 */

__weak
int scx_bitmap_free(scx_bitmap_t __arg_arena mask)
{
	scx_arena_subprog_init();

	scx_alloc_free_idx(&scx_bitmap_allocator, mask->tid.idx);
	return 0;
}

__weak
int scx_bitmap_copy_to_stack(struct scx_bitmap *dst, scx_bitmap_t __arg_arena src)
{
	int i;

	if (unlikely(!src || !dst)) {
		bpf_printk("invalid pointer args to pointer copy");
		return -EINVAL;
	}

	bpf_for(i, 0, mask_size) {
		if (i >= SCXMASK_NLONG || i < 0)
			return 0;
		dst->bits[i] = src->bits[i];
	}

	return 0;
}

__weak
int scx_bitmap_set_cpu(u32 cpu, scx_bitmap_t __arg_arena mask)
{
	mask->bits[cpu / 64] |= 1ULL << (cpu % 64);
	return 0;
}

__weak
int scx_bitmap_clear_cpu(u32 cpu, scx_bitmap_t __arg_arena mask)
{
	mask->bits[cpu / 64] &= ~(1ULL << (cpu % 64));
	return 0;
}

__weak
bool scx_bitmap_test_cpu(u32 cpu, scx_bitmap_t __arg_arena mask)
{
	return mask->bits[cpu / 64] & (1ULL << (cpu % 64));
}

__weak
bool scx_bitmap_test_and_clear_cpu(u32 cpu, scx_bitmap_t __arg_arena mask)
{
	u64 bit = 1ULL << (cpu % 64);
	u32 idx = cpu / 64;
	u64 actual;

	do {
		u64 old = mask->bits[idx];

		if (!(old & bit))
			return false;

		u64 new = old & ~bit;
		actual = cmpxchg(&mask->bits[idx], old, new);

		if (actual == old)
			return true;

	} while (can_loop);

	return false;
}

__weak
int scx_bitmap_clear(scx_bitmap_t __arg_arena mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		mask->bits[i] = 0;
	}

	return 0;
}

__weak
int scx_bitmap_and(scx_bitmap_t __arg_arena dst, scx_bitmap_t __arg_arena src1, scx_bitmap_t __arg_arena src2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->bits[i] = src1->bits[i] & src2->bits[i];
	}

	return 0;
}

__weak
int scx_bitmap_or(scx_bitmap_t __arg_arena dst, scx_bitmap_t __arg_arena src1, scx_bitmap_t __arg_arena src2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->bits[i] = src1->bits[i] | src2->bits[i];
	}

	return 0;
}

__weak
bool scx_bitmap_empty(scx_bitmap_t __arg_arena mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (mask->bits[i])
			return false;
	}

	return true;
}

__weak
int scx_bitmap_copy(scx_bitmap_t __arg_arena dst, scx_bitmap_t __arg_arena src)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->bits[i] = src->bits[i];
	}

	return 0;
}

__weak int
scx_bitmap_from_bpf(scx_bitmap_t __arg_arena scx_bitmap, const cpumask_t *bpfmask __arg_trusted)
{
	int i;

	for (i = 0; i < sizeof(cpumask_t) / 8 && can_loop; i++) {
		if (i >= mask_size)
			break;
		scx_bitmap->bits[i] = bpfmask->bits[i];
	}

	return 0;
}

__weak
bool scx_bitmap_subset(scx_bitmap_t __arg_arena big, scx_bitmap_t __arg_arena small)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (~big->bits[i] & small->bits[i])
			return false;
	}

	return true;
}

__weak
bool scx_bitmap_intersects(scx_bitmap_t __arg_arena arg1, scx_bitmap_t __arg_arena arg2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (arg1->bits[i] & arg2->bits[i])
			return true;
	}

	return false;
}

__weak
int scx_bitmap_print(scx_bitmap_t __arg_arena mask)
{
	int i;

	for (i = 0; i < mask_size && can_loop; i++)
		bpf_printk("%08x", mask->bits[i]);

	return 0;
}
