size_t mask_size;

struct scx_cpumask {
	union sdt_id tid;
	u8 mask[(MAX_CPUS + 7) / 8];
};

typedef struct scx_cpumask __arena * scx_cpumask_t;

struct sdt_allocator scx_mask_allocator;

static inline
int scx_mask_init(__u64 mask_size)
{
	return sdt_alloc_init(&scx_mask_allocator, mask_size + sizeof(union sdt_id));
}

static inline
scx_cpumask_t scx_mask_alloc(struct task_struct *p)
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

static inline
void scx_mask_free(scx_cpumask_t mask)
{
	sdt_subprog_init_arena();

	sdt_free_idx(&scx_mask_allocator, mask->tid.idx);
}


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

static inline
void scxmask_to_bpf(struct bpf_cpumask *bpfmask, scx_cpumask_t scxmask)
{
	scx_bpf_error("unimplemented");
}


static inline
void scxmask_from_bpf(scx_cpumask_t scxmask, struct bpf_cpumask *bpfmask)
{
	scx_bpf_error("unimplemented");
}

