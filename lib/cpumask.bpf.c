#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/percpu.h>

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

		cpu = scx_ffs(old);
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

static __always_inline int
bitmap_copy_to_stack(struct scx_bitmap_stack *dst, scx_bitmap_t __arg_arena src)
{
	u64 nr_longs = SCX_BITMAP_NR_LONGS;
	int i;

	if (unlikely(!src || !dst))
		return -EINVAL;

	bpf_for(i, 0, SCXMASK_NLONG) {
		if (i >= nr_longs)
			break;
		dst->bits[i] = src->bits[i];
	}

	return 0;
}

__weak int
scx_bitmap_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted,
		   scx_bitmap_t __arg_arena scx_bitmap)
{
	struct scx_bitmap_stack *tmp;
	int ret;

	tmp = scx_percpu_scx_bitmap_stack();
	ret = bitmap_copy_to_stack(tmp, scx_bitmap);
	if (ret)
		return ret;

	ret = __COMPAT_bpf_cpumask_populate((struct cpumask *)bpfmask, tmp->bits, sizeof(tmp->bits));
	if (unlikely(ret)) {
		bpf_printk("error %d when calling bpf_cpumask_populate", ret);
		return ret;
	}

	return 0;
}

__weak int
scx_bitmap_from_bpf(scx_bitmap_t __arg_arena bitmap, const cpumask_t *bpfmask __arg_trusted)
{
	u64 nr_longs = SCX_BITMAP_NR_LONGS;
	int i;

	for (i = 0; i < sizeof(cpumask_t) / sizeof(u64) && can_loop; i++) {
		if (i >= nr_longs)
			break;
		bitmap->bits[i] = bpfmask->bits[i];
	}

	return 0;
}

__weak
bool scx_bitmap_subset_cpumask(scx_bitmap_t __arg_arena big, const struct cpumask *small __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, small);

	return bmp_subset(SCX_BITMAP_NR_BITS, big, tmp);
}

__weak
bool scx_bitmap_intersects_cpumask(scx_bitmap_t __arg_arena scx, const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, bpf);

	return bmp_intersects(SCX_BITMAP_NR_BITS, scx, tmp);
}

__weak
int scx_bitmap_and_cpumask(scx_bitmap_t dst __arg_arena,
			       scx_bitmap_t scx __arg_arena,
			       const struct cpumask *bpf __arg_trusted)
{
	scx_bitmap_t tmp = scx_percpu_scx_bitmap();

	scx_bitmap_from_bpf(tmp, bpf);

	bmp_and(SCX_BITMAP_NR_BITS, dst, scx, tmp);

	return 0;
}

__weak
s32 scx_bitmap_pick_idle_cpu(scx_bitmap_t mask __arg_arena, int flags)
{
	struct bpf_cpumask __kptr *bpf = scx_percpu_bpfmask();
	s32 cpu;

	if (!bpf)
		return -1;

	scx_bitmap_to_bpf(bpf, mask);
	cpu = scx_bpf_pick_idle_cpu(cast_mask(bpf), flags);

	scx_bitmap_from_bpf(mask, cast_mask(bpf));

	return cpu;
}

__weak
s32 scx_bitmap_any_distribute(scx_bitmap_t mask __arg_arena)
{
	struct bpf_cpumask __kptr *bpf = scx_percpu_bpfmask();
	s32 cpu;

	if (!bpf)
		return -1;

	scx_bitmap_to_bpf(bpf, mask);
	cpu = bpf_cpumask_any_distribute(cast_mask(bpf));

	return cpu;
}

__weak
s32 scx_bitmap_any_and_distribute(scx_bitmap_t scx __arg_arena, const struct cpumask *bpf)
{
	struct bpf_cpumask *tmp = scx_percpu_bpfmask();
	s32 cpu;

	if (!bpf || !tmp)
		return -1;

	scx_bitmap_to_bpf(tmp, scx);
	cpu = bpf_cpumask_any_and_distribute(cast_mask(tmp), bpf);

	return cpu;
}
