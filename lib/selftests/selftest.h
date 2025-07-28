#pragma once

#define SCX_SELFTEST(func, ...)		\
	do {				\
		int ret = func(__VA_ARGS__);	\
		if (ret) {		\
			bpf_printk("SELFTEST %s FAIL: %d", #func, ret);	\
			return ret;	\
		}			\
	} while (0)

int scx_selftest_atq(void);
int scx_selftest_bitmap(void);
int scx_selftest_minheap(void);
int scx_selftest_topology(void);
int scx_selftest_btree(void);
