size_t mask_size;

struct scx_cpumask {
	u8 mask[(MAX_CPUS + 7) / 8];
};

typedef struct scx_cpumask __arena * scx_cpumask_t;

static inline
void scxmask_set_cpu(int cpu, scx_cpumask_t mask)
{
	mask->mask[cpu / 8] |= 1 << (cpu % 8);
}

static inline
void scxmask_clear_cpu(int cpu, scx_cpumask_t mask)
{
	mask->mask[cpu / 8] &= 1 << ~(cpu % 8);
}

static inline
bool scxmask_test_cpu(int cpu, scx_cpumask_t mask)
{
	return mask->mask[cpu / 8] & (1 << (cpu % 8));
}

static inline
void scxmask_clear(scx_cpumask_t mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		mask->mask[i] = 0;
	}
}

static inline
void scxmask_and(scx_cpumask_t dst, scx_cpumask_t src1, scx_cpumask_t src2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		dst->mask[i] = src1->mask[i] & src2->mask[i];
	}
}

static inline
bool scxmask_empty(scx_cpumask_t mask)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (mask->mask[i])
			return true;
	}

	return true;
}

static inline
bool scxmask_subset(scx_cpumask_t big, scx_cpumask_t small)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (big->mask[i] & ~small->mask[i])
			return false;
	}

	return true;
}

static inline
bool scxmask_intersects(scx_cpumask_t src1, scx_cpumask_t src2)
{
	int i;

	bpf_for(i, 0, mask_size) {
		if (src1->mask[i] & src2->mask[i])
			return true;
	}

	return false;
}
