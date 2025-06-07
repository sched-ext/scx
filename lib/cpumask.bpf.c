#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/percpu.h>

extern const volatile u32 nr_cpu_ids;

extern size_t mask_size;

static __always_inline s32
scx_bitmap_pick_any_cpu_once(scx_bitmap_t __arg_arena mask, u64 __arg_arena *start)
{
	u64 old, new;
	u64 ind, i;
	s32 cpu;

	if (unlikely(mask_size < SCXMASK_NLONG))
		return -EINVAL;

	bpf_for (i, 0, SCXMASK_NLONG) {
		if (i >= mask_size)
			break;

		ind = (*start + i) % mask_size;

		old = mask->bits[ind];
		if (!old)
			continue;

		cpu = scx_ffs(old);
		new = old & ~(1ULL << cpu);
		if (cmpxchg(&mask->bits[ind], old, new) == old)
			return -EAGAIN;

		*start = ind;

		return ind * 64 + cpu;
	}

	return -ENOSPC;
}

__weak s32
scx_bitmap_pick_any_cpu_from(scx_bitmap_t __arg_arena mask, u64 __arg_arena *start)
{
	s32 cpu;

	do {
		cpu = scx_bitmap_pick_any_cpu_once(mask, start);
	} while (cpu == -EAGAIN && can_loop);

	return cpu;
}

__weak s32
scx_bitmap_pick_any_cpu(scx_bitmap_t __arg_arena mask)
{
	u64 zero = 0;
	s32 cpu;

	do {
		cpu = scx_bitmap_pick_any_cpu_once(mask, &zero);
	} while (cpu == -EAGAIN && can_loop);

	return cpu;
}

__weak s32
scx_bitmap_vacate_cpu(scx_bitmap_t __arg_arena mask, s32 cpu)
{
	int off = (u32)cpu / 64;
	int ind = (u32)cpu % 64;

	if (cpu < 0 || cpu >= nr_cpu_ids) {
		scx_bpf_error("freeing invalid cpu");
		return -EINVAL;
	}

	if (off < 0 || off >= mask_size || off >= SCXMASK_NLONG) {
		scx_bpf_error("impossible out-of-bounds on free");
		return -EINVAL;
	}

	__sync_fetch_and_or(&mask->bits[off], 1 << ind);

	return 0;
}

__weak
bool scx_bitmap_subset_cpumask(scx_bitmap_t __arg_arena big, const struct cpumask *small __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, small);

	return scx_bitmap_subset(big, tmp);
}

__weak
bool scx_bitmap_intersects_cpumask(scx_bitmap_t __arg_arena scx, const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, bpf);

	return scx_bitmap_intersects(scx, tmp);
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

