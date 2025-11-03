#pragma once

#include <lib/atq.h>
#include <lib/rbtree.h>

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
	struct scx_task_common common;
	u64 pid;
	u64 vtime;
	struct rbnode rbnode;
	struct task_ctx_nonarena __arena *next;
};

typedef struct task_ctx_nonarena __arena task_ctx;

int scx_selftest_arena_topology_timer(void);
int scx_selftest_atq(void);
int scx_selftest_bitmap(void);
int scx_selftest_btree(void);
int scx_selftest_lvqueue(void);
int scx_selftest_minheap(void);
int scx_selftest_rbtree(void);
int scx_selftest_topology(void);

#ifndef __BPF__

/* Dummy "definition" for userspace. */
#define topo_ptr void *

#endif /* __BPF__ */
