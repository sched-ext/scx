#pragma once
#include <scx/common.bpf.h>

#include <libarena/bitmap.h>

#define NR_CPU_IDS_UNINIT (~(u32)0)

#define SCX_BITMAP_NR_LONGS BITS_TO_LONG_LONGS(nr_cpu_ids)
#define SCX_BITMAP_NR_BITS (SCX_BITMAP_NR_LONGS * BITS_PER_LONG_LONG)

typedef struct arena_bitmap __arena * __arg_arena scx_bitmap_t;

const extern volatile u32 nr_cpu_ids;

s32 scx_bitmap_pick_any_cpu(scx_bitmap_t mask __arg_arena);
s32 scx_bitmap_pick_any_cpu_from(scx_bitmap_t __arg_arena mask,
				 u64 __arena *start __arg_arena);
s32 scx_bitmap_vacate_cpu(scx_bitmap_t __arg_arena mask, s32 cpu);
