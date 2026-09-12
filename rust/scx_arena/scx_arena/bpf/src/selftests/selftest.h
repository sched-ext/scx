#pragma once

#include <lib/atq.h>
#include <lib/rbtree.h>

/*
 * Test IDs for arena_selftest's selftest_run_id selector.
 * SCX_SELFTEST_ID_ALL (0) runs all tests; any other value runs only the
 * matching test.
 *
 * Values are explicitly numbered because this enum is mirrored in Rust as
 * SelfTestId in rust/scx_arena/selftests/src/main.rs. Keeping explicit numbers
 * makes mismatches between the two copies immediately visible: a wrong number
 * is a grep-time catch, whereas a wrong ordering would be a silent runtime
 * mismatch that is much harder to detect.
 *
 * We didn’t integrate arena_topology_timer, dhq, and bitmap for now since
 * they are still in progress.
 */
enum scx_selftest_id {
	SCX_SELFTEST_ID_ALL			= 0,
	SCX_SELFTEST_ID_ATQ			= 1,
	SCX_SELFTEST_ID_BTREE			= 2,
	SCX_SELFTEST_ID_LVQUEUE			= 3,
	SCX_SELFTEST_ID_MINHEAP			= 4,
	SCX_SELFTEST_ID_RBTREE			= 5,
	SCX_SELFTEST_ID_TOPOLOGY		= 6,
};

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
int scx_selftest_dhq(void);
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
