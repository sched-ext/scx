#ifndef __ALLOC_COMMON_H__
#define __ALLOC_COMMON_H__

#include <scx/bpf_arena_common.bpf.h>
#include "bpf_helpers_local.h"

#define arena_stdout(fmt, ...) bpf_stream_printk(1, (fmt), ##__VA_ARGS__)
#define arena_stderr(fmt, ...) bpf_stream_printk(2, (fmt), ##__VA_ARGS__)

#define DIAG() (arena_stderr("%s:%d\n", __func__, __LINE__))

static inline void
arena_bug_trigger(const char *func, const int line)
{
	volatile u8 __arena *nullptr = (u8 __arena *)0ULL;

	*nullptr = 0;
}

int scx_fls(__u64 word);

extern volatile u64 asan_violated;

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

#ifndef round_up
#define round_up(a, b) ((((a) + (b) - 1) / (b)) * b)
#endif

#endif /* __ALLOC_COMMON_H__ */
