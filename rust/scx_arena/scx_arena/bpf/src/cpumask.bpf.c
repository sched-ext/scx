#include <scx/common.bpf.h>
#include <libarena/common.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>

const volatile u32 nr_cpu_ids = NR_CPU_IDS_UNINIT;

static __always_inline s32
scx_bitmap_pick_any_cpu_once(scx_bitmap_t __arg_arena mask, u64 *start)
{
	u64 old;
	u64 ind, i;
	u64 nr_longs = SCX_BITMAP_NR_LONGS;
	s32 cpu;

	if (unlikely(!nr_longs))
		return -EINVAL;

	for (i = 0; i < nr_longs && can_loop; i++) {
		ind = (*start + i) % nr_longs;

		old = mask->bits[ind];
		if (!old)
			continue;

		cpu = __builtin_ffsll(old) - 1;
		if (!bmp_test_and_clear_bit(ind * BITS_PER_LONG_LONG + cpu, mask))
			return -EAGAIN;

		*start = ind;

		return ind * BITS_PER_LONG_LONG + cpu;
	}

	return -ENOSPC;
}

__weak s32
scx_bitmap_pick_any_cpu_from(scx_bitmap_t __arg_arena mask,
			     u64 __arena *start __arg_arena)
{
	u64 cursor;
	s32 cpu;

	if (!start)
		return -EINVAL;
	cursor = *start;

	do {
		cpu = scx_bitmap_pick_any_cpu_once(mask, &cursor);
	} while (cpu == -EAGAIN && can_loop);

	if (cpu >= 0)
		*start = cursor;

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
	if (cpu < 0 || cpu >= nr_cpu_ids) {
		bpf_printk("freeing invalid cpu");
		return -EINVAL;
	}

	bmp_set_bit(cpu, mask);
	return 0;
}
