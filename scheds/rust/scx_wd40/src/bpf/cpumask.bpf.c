#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include "cpumask.h"
#include "percpu.h"

static struct sdt_allocator scx_bitmap_allocator;
size_t mask_size;

__weak
int scx_bitmap_init(__u64 total_mask_size)
{
	mask_size = div_round_up(total_mask_size, 8);

	return sdt_alloc_init(&scx_bitmap_allocator, mask_size * 8 + sizeof(union sdt_id));
}

__weak
u64 scx_bitmap_alloc_internal(void)
{
	struct sdt_data __arena *data = NULL;
	scx_bitmap_t mask;
	int i;

	data = sdt_alloc(&scx_bitmap_allocator);
	cast_kern(data);
	if (!data)
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
	sdt_subprog_init_arena();

	sdt_free_idx(&scx_bitmap_allocator, mask->tid.idx);
	return 0;
}

__weak
int scx_bitmap_copy_to_stack(struct scx_bitmap *dst, scx_bitmap_t __arg_arena src)
{
	int i;

	if (!src || !dst) {
		scx_bpf_error("invalid pointer args to pointer copy");
		return 0;
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
	mask->bits[cpu / 64] |= 1 << (cpu % 64);
	return 0;
}

__weak
int scx_bitmap_clear_cpu(u32 cpu, scx_bitmap_t __arg_arena mask)
{
	mask->bits[cpu / 64] &= 1 << ~(cpu % 64);
	return 0;
}

__weak
bool scx_bitmap_test_cpu(u32 cpu, scx_bitmap_t __arg_arena mask)
{
	return mask->bits[cpu / 64] & (1 << (cpu % 64));
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
			return true;
	}

	return true;
}

__weak int
scx_bitmap_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted,
		   scx_bitmap_t __arg_arena scx_bitmap)
{
	struct scx_bitmap *tmp;
	int ret, i;

	if (bpf_ksym_exists(bpf_cpumask_from_bpf_mem)) {
		tmp = scx_percpu_scx_bitmap_stack();
		scx_bitmap_copy_to_stack(tmp, scx_bitmap);

		ret = bpf_cpumask_from_bpf_mem(bpfmask, tmp, sizeof(*tmp));
		if (ret)
			scx_bpf_error("error");


		return 0;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		if (scx_bitmap_test_cpu(i, scx_bitmap))
			bpf_cpumask_set_cpu(i, bpfmask);
		else
			bpf_cpumask_clear_cpu(i, bpfmask);
	}

	return 0;
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
bool scx_bitmap_subset_cpumask(scx_bitmap_t __arg_arena big, const struct cpumask *small __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();
	int i;

	scx_bitmap_from_bpf(tmp, small);

	bpf_for(i, 0, mask_size) {
		if (~big->bits[i] & tmp->bits[i])
			return false;
	}

	return true;
}

__weak
bool scx_bitmap_intersects_cpumask(scx_bitmap_t __arg_arena scx, const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();
	int i;

	scx_bitmap_from_bpf(tmp, bpf);

	bpf_for(i, 0, mask_size) {
		if (scx->bits[i] & tmp->bits[i])
			return true;
	}

	return false;
}

__weak
int scx_bitmap_and_cpumask(scx_bitmap_t dst __arg_arena,
			       scx_bitmap_t scx __arg_arena,
			       const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, bpf);

	scx_bitmap_and(dst, scx, tmp);

	return 0;
}
