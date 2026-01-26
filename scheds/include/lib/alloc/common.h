#pragma once

#ifdef __BPF__

#define BPF_NO_KFUNC_PROTOTYPES

#include <bpf_experimental.h>
#include <bpf_arena_common.h>
#include <bpf_arena_spin_lock.h>
#include "bpf_helpers_local.h"

#include <asm-generic/errno.h>

#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
#error "Arena allocators only require bpf_addr_space_cast feature"
#endif

#define arena_stdout(fmt, ...) bpf_stream_printk(1, (fmt), ##__VA_ARGS__)
#define arena_stderr(fmt, ...) bpf_stream_printk(2, (fmt), ##__VA_ARGS__)

#define DIAG() (arena_stderr("%s:%d\n", __func__, __LINE__))

static inline void
arena_bug_trigger(const char *func, const int line)
{
	volatile u8 __arena *nullptr = (u8 __arena *)0ULL;

	*nullptr = 0;
}

int arena_fls(__u64 word);

extern volatile u64 asan_violated;

#ifndef div_round_up
#define div_round_up(a, b) (((a) + (b) - 1) / (b))
#endif

#ifndef round_up
#define round_up(a, b) ((((a) + (b) - 1) / (b)) * b)
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

/* How many pages do we reserve at the beginning of the arena segment? */
#define RESERVE_ALLOC (8)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
#if defined(__TARGET_ARCH_arm64) || defined(__aarch64__)
	__uint(max_entries, 1 << 16); /* number of pages */
        __ulong(map_extra, (1ull << 32)); /* start of mmap() region */
#else
	__uint(max_entries, 1 << 20); /* number of pages */
        __ulong(map_extra, (1ull << 44)); /* start of mmap() region */
#endif
} arena __weak SEC(".maps");

#endif /* __BPF__ */

struct arena_get_base_args {
	void __arena *arena_base;
};

#ifdef __BPF__

SEC("syscall") __weak
int arena_get_base(struct arena_get_base_args *args)
{
	args->arena_base = arena_base(&arena);

	return 0;
}

SEC("syscall") __weak
int arena_alloc_reserve(void)
{
	return bpf_arena_reserve_pages(&arena, NULL, RESERVE_ALLOC);
}

__weak
int arena_fls(__u64 word)
{
	unsigned int num = 0;

	if (word & 0xffffffff00000000ULL) {
		num += 32;
		word >>= 32;
	}

	if (word & 0xffff0000) {
		num += 16;
		word >>= 16;
	}

	if (word & 0xff00) {
		num += 8;
		word >>= 8;
	}

	if (word & 0xf0) {
		num += 4;
		word >>= 4;
	}

	if (word & 0xc) {
		num += 2;
		word >>= 2;
	}

	if (word & 0x2) {
		num += 1;
	}

	return num;
}

#endif /* __BPF__ */
