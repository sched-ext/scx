#pragma once

#include <lib/atq.h>
#include <libarena/rbtree.h>

/*
 * Each integrated suite is a SEC("syscall") program named arena_selftest_<suite>,
 * defined in its own st_<suite>.bpf.c. Userspace picks one by name, see
 * SUITES in rust/scx_arena/selftests/src/main.rs.
 *
 * arena_topology_timer, dhq, and bitmap are not integrated yet since they are
 * still in progress; their entry points stay plain functions below.
 */

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

/* Not-yet-integrated suites; the integrated ones are programs, not functions. */
int scx_selftest_arena_topology_timer(void);
int scx_selftest_dhq(void);
int scx_selftest_bitmap(void);

#ifndef __BPF__

/* Dummy "definition" for userspace. */
#define topo_ptr void *

#endif /* __BPF__ */
