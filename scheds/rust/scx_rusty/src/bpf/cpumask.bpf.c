#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include "cpumask.h"
#include "percpu.h"

static struct sdt_allocator scx_mask_allocator;
size_t mask_size;

__weak
int scx_mask_init(__u64 total_mask_size)
{
	mask_size = div_round_up(total_mask_size, 8);

	return sdt_alloc_init(&scx_mask_allocator, mask_size * 8 + sizeof(union sdt_id));
}

__weak
u64 scx_mask_alloc_internal(void)
{
	struct sdt_data __arena *data = NULL;
	scx_cpumask_t mask;
	int i;

	data = sdt_alloc(&scx_mask_allocator);
	cast_kern(data);
	if (!data)
		return (u64)(NULL);

	mask = (scx_cpumask_t)data->payload;
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
int scx_mask_free(scx_cpumask_t __arg_arena mask)
{
	sdt_subprog_init_arena();

	sdt_free_idx(&scx_mask_allocator, mask->tid.idx);
	return 0;
}

__weak
int scxmask_copy_to_stack(struct scx_cpumask *dst, scx_cpumask_t __arg_arena src)
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
int scxmask_set_cpu(u32 cpu, scx_cpumask_t __arg_arena mask)
{
	mask->bits[cpu / 64] |= 1 << (cpu % 64);
	return 0;
}

__weak
int scxmask_clear_cpu(u32 cpu, scx_cpumask_t __arg_arena mask)
{
	mask->bits[cpu / 64] &= 1 << ~(cpu % 64);
	return 0;
}

__weak
bool scxmask_test_cpu(u32 cpu, scx_cpumask_t __arg_arena mask)
{
	return mask->bits[cpu / 64] & (1 << (cpu % 64));
}

__weak
int scxmask_clear(scx_cpumask_t __arg_arena mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		mask->bits[i] = 0;
	}

	return 0;
}

__weak
int scxmask_and(scx_cpumask_t __arg_arena dst, scx_cpumask_t __arg_arena src1, scx_cpumask_t __arg_arena src2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->bits[i] = src1->bits[i] & src2->bits[i];
	}

	return 0;
}

__weak
bool scxmask_empty(scx_cpumask_t __arg_arena mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (mask->bits[i])
			return true;
	}

	return true;
}

__weak int
scxmask_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted,
		   scx_cpumask_t __arg_arena scxmask)
{
	struct scx_cpumask *tmp;
	int ret, i;

	if (bpf_ksym_exists(bpf_cpumask_from_bpf_mem)) {
		tmp = scx_percpu_scxmask_stack();
		scxmask_copy_to_stack(tmp, scxmask);

		ret = bpf_cpumask_from_bpf_mem(bpfmask, tmp, sizeof(*tmp));
		if (ret)
			scx_bpf_error("error");


		return 0;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		if (scxmask_test_cpu(i, scxmask))
			bpf_cpumask_set_cpu(i, bpfmask);
		else
			bpf_cpumask_clear_cpu(i, bpfmask);
	}

	return 0;
}


__weak
int scxmask_copy(scx_cpumask_t __arg_arena dst, scx_cpumask_t __arg_arena src)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->bits[i] = src->bits[i];
	}

	return 0;
}

__weak int
scxmask_from_bpf(scx_cpumask_t __arg_arena scxmask, const cpumask_t *bpfmask __arg_trusted)
{
	int i;

	#pragma unroll
	for (i = 0; i < sizeof(cpumask_t) / 8; i++) {
		if (i >= mask_size)
			break;
		scxmask->bits[i] = bpfmask->bits[i];
	}

	return 0;
}

__weak
bool scxmask_subset_cpumask(scx_cpumask_t __arg_arena big, const struct cpumask *small __arg_trusted)
{
	scx_cpumask_t tmp = scx_percpu_scxmask();
	int i;

	scxmask_from_bpf(tmp, small);

	bpf_for(i, 0, mask_size) {
		if (~big->bits[i] & tmp->bits[i])
			return false;
	}

	return true;
}

__weak
bool scxmask_intersects_cpumask(scx_cpumask_t __arg_arena scx, const struct cpumask *bpf __arg_trusted)
{
	scx_cpumask_t tmp = scx_percpu_scxmask();
	int i;

	scxmask_from_bpf(tmp, bpf);

	bpf_for(i, 0, mask_size) {
		if (scx->bits[i] & tmp->bits[i])
			return true;
	}

	return false;
}

__weak
int scxmask_and_cpumask(scx_cpumask_t dst __arg_arena,
			       scx_cpumask_t scx __arg_arena,
			       const struct cpumask *bpf __arg_trusted)
{
	scx_cpumask_t tmp = scx_percpu_scxmask();

	scxmask_from_bpf(tmp, bpf);

	scxmask_and(dst, scx, tmp);

	return 0;
}
