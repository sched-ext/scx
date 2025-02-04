int bpf_cpumask_from_mem(struct bpf_cpumask *dst, void *src, size_t src__sz) __ksym __weak;
int bpf_cpumask_to_mem(void *dst, size_t dst__sz, struct bpf_cpumask *src) __ksym __weak;

extern const volatile u32 nr_cpu_ids;
size_t mask_size;

/* XXX HACK hardcoded MAX_CPUS / 8 from src/bpf/intf.h, right now this header is a mess */
struct scx_cpumask {
	union sdt_id tid;
	u8 mask[64];
};

typedef struct scx_cpumask __arena * __arg_arena scx_cpumask_t;

struct sdt_allocator scx_mask_allocator;

__weak
int scx_mask_init(__u64 total_mask_size)
{
	mask_size = total_mask_size;

	return sdt_alloc_init(&scx_mask_allocator, mask_size + sizeof(union sdt_id));
}

static
scx_cpumask_t scx_mask_alloc(void)
{
	struct sdt_data __arena *data = NULL;
	scx_cpumask_t mask;
	int i;

	data = sdt_alloc(&scx_mask_allocator);
	cast_kern(data);

	mask = (scx_cpumask_t)data->payload;
	mask->tid = data->tid;
	bpf_for(i, 0, mask_size) {
		mask->mask[i] = 0ULL;
	}

	return mask;
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
		if (i >= 64 || i < 0)
			return 0;
		dst->mask[i] = src->mask[i];
	}

	return 0;
}

__weak
int scxmask_set_cpu(u32 cpu, scx_cpumask_t __arg_arena mask)
{
	mask->mask[cpu / 8] |= 1 << (cpu % 8);
	return 0;
}

__weak
int scxmask_clear_cpu(u32 cpu, scx_cpumask_t __arg_arena mask)
{
	mask->mask[cpu / 8] &= 1 << ~(cpu % 8);
	return 0;
}

__weak
bool scxmask_test_cpu(u32 cpu, scx_cpumask_t __arg_arena mask)
{
	return mask->mask[cpu / 8] & (1 << (cpu % 8));
}

__weak
int scxmask_clear(scx_cpumask_t __arg_arena mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		mask->mask[i] = 0;
	}

	return 0;
}

__weak
int scxmask_and(scx_cpumask_t __arg_arena dst, scx_cpumask_t __arg_arena src1, scx_cpumask_t __arg_arena src2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->mask[i] = src1->mask[i] & src2->mask[i];
	}

	return 0;
}

__weak
bool scxmask_empty(scx_cpumask_t __arg_arena mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (mask->mask[i])
			return true;
	}

	return true;
}

static void
scxmask_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted,
		   scx_cpumask_t __arg_arena scxmask)
{
	struct scx_cpumask tmp;
	int ret, i;

	if (bpf_ksym_exists(bpf_cpumask_from_mem)) {
		scxmask_copy_to_stack(&tmp, scxmask);
		ret = bpf_cpumask_from_mem(bpfmask, &tmp, sizeof(tmp));
		if (ret)
			scx_bpf_error("error");

		return;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		if (scxmask_test_cpu(i, scxmask))
			bpf_cpumask_set_cpu(i, bpfmask);
		else
			bpf_cpumask_clear_cpu(i, bpfmask);
	}
}


/*
 * XXX Terrible implementations. We require a kfunc pair to do this properly.
 */
static void
scxmask_from_bpf(scx_cpumask_t __arg_arena scxmask,
		     const struct cpumask *bpfmask __arg_trusted)
{
	int i;

	bpf_for(i, 0, nr_cpu_ids) {
		if (bpf_cpumask_test_cpu(i, bpfmask))
			scxmask_set_cpu(i, scxmask);
		else
			scxmask_clear_cpu(i, scxmask);
	}

}

__weak
int scxmask_copy(scx_cpumask_t __arg_arena dst, scx_cpumask_t __arg_arena src)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->mask[i] = src->mask[i];
	}

	return 0;
}

static
bool scxmask_subset_cpumask(scx_cpumask_t __arg_arena big, const struct cpumask *small)
{
	int i;

	bpf_for(i, 0, nr_cpu_ids) {
		if (!scxmask_test_cpu(i, big) && bpf_cpumask_test_cpu(i, small))
			return false;
	}

	return true;
}

static
bool scxmask_intersects_cpumask(scx_cpumask_t __arg_arena scx, const struct cpumask *cpu)
{
	int i;

	bpf_for(i, 0, nr_cpu_ids) {
		if (scxmask_test_cpu(i, scx) && bpf_cpumask_test_cpu(i, cpu))
			return true;
	}

	return false;
}

static
int scxmask_and_cpumask(scx_cpumask_t dst __arg_arena,
			       scx_cpumask_t scx __arg_arena,
			       const struct cpumask *cpu __arg_trusted)
{
	int i;

	bpf_for(i, 0, nr_cpu_ids) {
		if (scxmask_test_cpu(i, scx) && bpf_cpumask_test_cpu(i, cpu))
			scxmask_set_cpu(i, dst);
		else
			scxmask_clear_cpu(i, dst);
	}

	return 0;
}
