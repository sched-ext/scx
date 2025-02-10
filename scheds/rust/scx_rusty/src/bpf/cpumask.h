#pragma once
#include <scx/common.bpf.h>

#include <lib/sdt_task.h>


int bpf_cpumask_from_bpf_mem(struct bpf_cpumask *dst, void *src, size_t src__sz) __ksym __weak;

#define SCXMASK_NLONG (512 / 8)

/* XXX HACK hardcoded MAX_CPUS / 64 from src/bpf/intf.h, right now this header is a mess */
struct scx_cpumask {
	union sdt_id tid;
	u64 bits[SCXMASK_NLONG];
};

typedef struct scx_cpumask __arena * __arg_arena scx_cpumask_t;

extern const volatile u32 nr_cpu_ids;

/* Mask size in 64-bit words. */
static size_t mask_size;

int scx_mask_init(__u64 total_mask_size);
u64 scx_mask_alloc_internal(void);
#define scx_mask_alloc() ( (scx_cpumask_t) scx_mask_alloc_internal() )
int scx_mask_free(scx_cpumask_t __arg_arena mask);

int scxmask_copy_to_stack(struct scx_cpumask *dst, scx_cpumask_t __arg_arena src);
int scxmask_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted, scx_cpumask_t __arg_arena scxmask);

int scxmask_set_cpu(u32 cpu, scx_cpumask_t __arg_arena mask);
int scxmask_clear_cpu(u32 cpu, scx_cpumask_t __arg_arena mask);
bool scxmask_test_cpu(u32 cpu, scx_cpumask_t __arg_arena mask);

int scxmask_clear(scx_cpumask_t __arg_arena mask);
int scxmask_and(scx_cpumask_t __arg_arena dst, scx_cpumask_t __arg_arena src1, scx_cpumask_t __arg_arena src2);
bool scxmask_empty(scx_cpumask_t __arg_arena mask);
int scxmask_copy(scx_cpumask_t __arg_arena dst, scx_cpumask_t __arg_arena src);

bool scxmask_intersects_cpumask(scx_cpumask_t __arg_arena scx, const struct cpumask *cpu);
bool scxmask_subset_cpumask(scx_cpumask_t __arg_arena big, const struct cpumask *small);
int scxmask_and_cpumask(scx_cpumask_t dst __arg_arena, scx_cpumask_t scx __arg_arena,
			       const struct cpumask *cpu __arg_trusted);

/*
 * XXXETSAL Turning this nonstatic causes a verification failure. Investigate
 * why - the verifier erroneously believes cpumask_t only has 8 elements.
 */
static int
scxmask_from_bpf(scx_cpumask_t __arg_arena scxmask, const struct cpumask __kptr *bpfmask __arg_trusted)
{
	size_t len = mask_size;
	int i;

	if (len > sizeof(cpumask_t) / 8)
		len = sizeof(cpumask_t) / 8;

	for (i = 0; i < len && can_loop; i++)
		scxmask->bits[i] = bpfmask->bits[i];

	return 0;
}
