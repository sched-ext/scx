#pragma once

#ifdef __BPF__

#include <scx/common.bpf.h>
#include <scx/bpf_arena_common.bpf.h>

#define ASAN_SHADOW_SHIFT 3
#define ASAN_SHADOW_SCALE (1ULL << ASAN_SHADOW_SHIFT)
#define ASAN_GRANULE_MASK ((1ULL << ASAN_SHADOW_SHIFT) - 1)
#define ASAN_GRANULE(addr) ((s8)((u32)(u64)((addr)) & ASAN_GRANULE_MASK))

/* XXX Find the page size from the running kernel. */
#define PAGE_SHIFT (12)

#define __noasan __attribute__((no_sanitize("address"))) 

extern u64 __asan_shadow_memory_dynamic_address;

/* Defined as char * to get 1-byte granularity for pointer arithmetic. */
typedef s8 __arena s8a;

static inline 
s8a *mem_to_shadow(void __arena __arg_arena *addr)
{
	return (s8a *)(((u32)(u64)addr >> ASAN_SHADOW_SHIFT) + __asan_shadow_memory_dynamic_address);
}

static inline __noasan
s8 asan_shadow_value(void __arena __arg_arena *addr) 
{
	return *(s8a *)mem_to_shadow(addr);
}

int asan_poison(void __arena *addr, s8 val, size_t size);
int asan_unpoison(void __arena *addr, size_t size);
bool asan_shadow_set(void __arena *addr);
s8 asan_shadow_value(void __arena *addr);

/*
 * Dummy calls to ensure the ASAN runtime's BTF information is present
 * in every object file when compiling the runtime and local BPF code
 * separately. The runtime calls are injected into the LLVM IR file 
 */
#define DECLARE_ASAN_LOAD_STORE_SIZE(size)				\
	void __asan_store##size(void *addr);				\
	void __asan_store##size##_noabort(void *addr);	\
	void __asan_load##size(void *addr);				\
	void __asan_load##size##_noabort(void *addr);	\
	void __asan_report_store##size(void *addr);			\
	void __asan_report_store##size##_noabort(void *addr);		\
	void __asan_report_load##size(void *addr);			\
	void __asan_report_load##size##_noabort(void *addr);		

DECLARE_ASAN_LOAD_STORE_SIZE(1);
DECLARE_ASAN_LOAD_STORE_SIZE(2);
DECLARE_ASAN_LOAD_STORE_SIZE(4);
DECLARE_ASAN_LOAD_STORE_SIZE(8);

#define DECLARE_ASAN_LOAD_STORE(size)				\
	void __asan_store##size(void *addr);			\
	void __asan_store##size##_noabort(void *addr);		\
	void __asan_load##size(void *addr);			\
	void __asan_load##size##_noabort(void *addr);		\
	void __asan_report_store##size(void *addr);		\
	void __asan_report_store##size##_noabort(void *addr);	\
	void __asan_report_load##size(void *addr);		\
	void __asan_report_load##size##_noabort(void *addr);		

#define ASAN_DUMMY_CALLS_SIZE(size, arg)		\
do {							\
	__asan_store##size((arg));			\
	__asan_store##size##_noabort((arg));		\
	__asan_load##size((arg));			\
	__asan_load##size##_noabort((arg));		\
	__asan_report_store##size((arg));		\
	__asan_report_store##size##_noabort((arg));	\
	__asan_report_load##size((arg));		\
	__asan_report_load##size##_noabort((arg));	\
} while (0)	

#define ASAN_DUMMY_CALLS_ALL(arg)	\
do { 					\
	ASAN_DUMMY_CALLS_SIZE(1, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(2, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(4, (arg));	\
	ASAN_DUMMY_CALLS_SIZE(8, (arg));	\
} while (0)

__weak __attribute__((no_sanitize_address))
int asan_dummy_call() {
	/* Use the shadow map base to prevent it from being optimized out. */
	if (__asan_shadow_memory_dynamic_address) 
		ASAN_DUMMY_CALLS_ALL(NULL);

	return 0;
}

#endif /* __BPF__ */

struct asan_init_args {
	u64 arena_all_pages;
	u64 arena_globals_pages;
};

int asan_init(struct asan_init_args *args);

struct arena_base_args {
	void __arena *arena_base;
};
