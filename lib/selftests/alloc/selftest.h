#pragma once

#define SCX_SELFTEST(func, ...)		\
	do {				\
		int ret = func(__VA_ARGS__);	\
		if (ret) {		\
			bpf_printk("SELFTEST %s FAIL: %d", #func, ret);	\
			return ret;	\
		}			\
	} while (0)

/* Each scheduler defines their own task_ctx. */
struct task_ctx_nonarena {
	u64 pid;
	u64 vtime;
};

typedef struct task_ctx_nonarena __arena task_ctx;

int scx_selftest_atq(void);
int scx_selftest_bitmap(void);
int scx_selftest_buddy(void);
int scx_selftest_lvqueue(void);
int scx_selftest_minheap(void);
int scx_selftest_stack(void);
int scx_selftest_static(void);
int scx_selftest_topology(void);
int scx_selftest_btree(void);
int scx_selftest_rbtree(void);

#ifndef __BPF__

/* Dummy "definition" for userspace. */
#define arena_spinlock_t u64
#define topo_ptr void *

#endif /* __BPF__ */
