#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>

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
		if (cmpxchg(&mask->bits[ind], old, new) != old)
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
	u64 old, new;

	if (cpu < 0 || cpu >= nr_cpu_ids) {
		bpf_printk("freeing invalid cpu");
		return -EINVAL;
	}

	if (off < 0 || off >= mask_size || off >= SCXMASK_NLONG) {
		bpf_printk("impossible out-of-bounds on free");
		return -EINVAL;
	}

	while (can_loop) {
		old = mask->bits[off];
		new = old | 1ULL << ind;
		if (cmpxchg(&mask->bits[off], old, new) == old)
			return 0;
	}

	return -EAGAIN;
}
