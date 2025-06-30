#pragma once
#include <scx/common.bpf.h>

#include <lib/sdt_task.h>

#define SCXMASK_NLONG (512 / 8)

struct scx_bitmap {
	union sdt_id tid;
	u64 bits[SCXMASK_NLONG];
};

typedef struct scx_bitmap __arena * __arg_arena scx_bitmap_t;

const extern volatile u32 nr_cpu_ids;

/* Mask size in 64-bit words. */
extern size_t mask_size;

int scx_bitmap_init(__u64 total_mask_size);
u64 scx_bitmap_alloc_internal(void);
#define scx_bitmap_alloc() ( (scx_bitmap_t) scx_bitmap_alloc_internal() )
int scx_bitmap_free(scx_bitmap_t __arg_arena mask);

int scx_bitmap_copy_to_stack(struct scx_bitmap *dst, scx_bitmap_t __arg_arena src);
int scx_bitmap_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted, scx_bitmap_t __arg_arena scx_bitmap);

int scx_bitmap_set_cpu(u32 cpu, scx_bitmap_t __arg_arena mask);
int scx_bitmap_clear_cpu(u32 cpu, scx_bitmap_t __arg_arena mask);
bool scx_bitmap_test_cpu(u32 cpu, scx_bitmap_t __arg_arena mask);
bool scx_bitmap_test_and_clear_cpu(u32 cpu, scx_bitmap_t __arg_arena mask);

int scx_bitmap_clear(scx_bitmap_t __arg_arena mask);
int scx_bitmap_and(scx_bitmap_t __arg_arena dst, scx_bitmap_t __arg_arena src1, scx_bitmap_t __arg_arena src2);
int scx_bitmap_or(scx_bitmap_t __arg_arena dst, scx_bitmap_t __arg_arena src1, scx_bitmap_t __arg_arena src2);
bool scx_bitmap_empty(scx_bitmap_t __arg_arena mask);
int scx_bitmap_copy(scx_bitmap_t __arg_arena dst, scx_bitmap_t __arg_arena src);

int scx_bitmap_from_bpf(scx_bitmap_t __arg_arena scx_bitmap, const cpumask_t *bpfmask __arg_trusted);
int scx_bitmap_and_cpumask(scx_bitmap_t dst __arg_arena, scx_bitmap_t scx __arg_arena,
			       const struct cpumask *bpf __arg_trusted);

bool scx_bitmap_intersects(scx_bitmap_t __arg_arena arg1, scx_bitmap_t __arg_arena arg2);
bool scx_bitmap_intersects_cpumask(scx_bitmap_t __arg_arena scx, const struct cpumask *bpf __arg_trusted);
bool scx_bitmap_subset(scx_bitmap_t __arg_arena big, scx_bitmap_t __arg_arena small);
bool scx_bitmap_subset_cpumask(scx_bitmap_t __arg_arena big, const struct cpumask *small __arg_trusted);
int scx_bitmap_print(scx_bitmap_t __arg_arena mask);

s32 scx_bitmap_pick_idle_cpu(scx_bitmap_t mask __arg_arena, int flags);
s32 scx_bitmap_any_distribute(scx_bitmap_t mask __arg_arena);
s32 scx_bitmap_any_and_distribute(scx_bitmap_t scx __arg_arena, const struct cpumask *bpf);
s32 scx_bitmap_pick_any_cpu(scx_bitmap_t mask __arg_arena);
s32 scx_bitmap_pick_any_cpu_from(scx_bitmap_t __arg_arena mask, u64 __arg_arena *start);
s32 scx_bitmap_vacate_cpu(scx_bitmap_t __arg_arena mask, s32 cpu);
