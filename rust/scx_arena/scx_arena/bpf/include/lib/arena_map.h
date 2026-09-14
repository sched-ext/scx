#pragma once

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
