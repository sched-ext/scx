#pragma once

#define ALLOC_SELFTEST(func, ...)		\
	do {				\
		int ret = func(__VA_ARGS__);	\
		if (ret) {		\
			bpf_printk("SELFTEST %s FAIL: %d", #func, ret);	\
			return ret;	\
		}			\
	} while (0)

int bump_selftest(void);
int buddy_selftest(void);
int stack_selftest(void);

#ifndef __BPF__

/* Dummy "definition" for userspace. */
#define arena_spinlock_t u64

#endif /* __BPF__ */
