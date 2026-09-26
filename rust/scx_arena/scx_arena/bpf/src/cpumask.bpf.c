#include <scx/common.bpf.h>
#include <libarena/common.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>

const volatile u32 nr_cpu_ids = NR_CPU_IDS_UNINIT;

static __always_inline s32
scx_bitmap_pick_any_cpu_once(scx_bitmap_t __arg_arena mask, u64 __arg_arena *start)
{
	u64 old;
	u64 ind, i, nr_longs = SCX_BITMAP_NR_LONGS;
	s32 cpu;

	if (unlikely(nr_longs > SCXMASK_NLONG))
		return -EINVAL;

	bpf_for (i, 0, SCXMASK_NLONG) {
		if (i >= nr_longs)
			break;

		ind = (*start + i) % nr_longs;

		old = mask->bits[ind];
		if (!old)
			continue;

		/*
		 * 0-based index of the lowest set bit, matching the scx_ffs()
		 * this used to call. libarena's arena_ffs() returned
		 * 63 - index and is gone; only arena_fls() remains.
		 */
		cpu = __builtin_ffsll(old) - 1;
		if (!bmp_test_and_clear_bit(ind * BITS_PER_LONG_LONG + cpu, mask))
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

	if (cpu < 0 || cpu >= nr_cpu_ids) {
		bpf_printk("freeing invalid cpu");
		return -EINVAL;
	}

	if (off < 0 || off >= SCX_BITMAP_NR_LONGS || off >= SCXMASK_NLONG) {
		bpf_printk("impossible out-of-bounds on free");
		return -EINVAL;
	}

	bmp_set_bit(cpu, mask);
	return 0;
}
