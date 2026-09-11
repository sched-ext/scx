#pragma once
#include <scx/common.bpf.h>

#include <libarena/bitmap.h>

#define NR_CPU_IDS_UNINIT (~(u32)0)

#define SCXMASK_NBITS BYTES_TO_BITS(512)
#define SCXMASK_NLONG BITS_TO_LONG_LONGS(SCXMASK_NBITS)
#define SCX_BITMAP_NR_LONGS BITS_TO_LONG_LONGS(nr_cpu_ids)
#define SCX_BITMAP_NR_BITS (SCX_BITMAP_NR_LONGS * BITS_PER_LONG_LONG)

struct scx_bitmap_stack {
	u64 bits[SCXMASK_NLONG];
};

typedef struct arena_bitmap __arena * __arg_arena scx_bitmap_t;

const extern volatile u32 nr_cpu_ids;

int scx_bitmap_to_bpf(struct bpf_cpumask __kptr *bpfmask __arg_trusted, scx_bitmap_t __arg_arena scx_bitmap);
int scx_bitmap_from_bpf(scx_bitmap_t __arg_arena scx_bitmap, const cpumask_t *bpfmask __arg_trusted);
int scx_bitmap_and_cpumask(scx_bitmap_t dst __arg_arena, scx_bitmap_t scx __arg_arena,
			       const struct cpumask *bpf __arg_trusted);

bool scx_bitmap_intersects_cpumask(scx_bitmap_t __arg_arena scx, const struct cpumask *bpf __arg_trusted);
bool scx_bitmap_subset_cpumask(scx_bitmap_t __arg_arena big, const struct cpumask *small __arg_trusted);

s32 scx_bitmap_pick_idle_cpu(scx_bitmap_t mask __arg_arena, int flags);
s32 scx_bitmap_any_distribute(scx_bitmap_t mask __arg_arena);
s32 scx_bitmap_any_and_distribute(scx_bitmap_t scx __arg_arena, const struct cpumask *bpf);
s32 scx_bitmap_pick_any_cpu(scx_bitmap_t mask __arg_arena);
s32 scx_bitmap_pick_any_cpu_from(scx_bitmap_t __arg_arena mask, u64 __arg_arena *start);
s32 scx_bitmap_vacate_cpu(scx_bitmap_t __arg_arena mask, s32 cpu);
