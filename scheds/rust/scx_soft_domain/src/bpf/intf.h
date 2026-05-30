/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>

#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned short u16;
typedef int s32;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long long u64;
#else
#include <scx/common.bpf.h>
#endif

#ifndef MAX_NUMA_NODES
#define MAX_NUMA_NODES 8
#endif

#ifndef MAX_LLCS
#define MAX_LLCS 96
#endif

#ifndef MAX_LLC_ID
#define MAX_LLC_ID 16334
#endif

#ifndef MAX_CPUS
#define MAX_CPUS 640
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#define MAX_CPUS_PER_NODE 192
#define MAX_CPUS_PER_LLC 192
#define IRQ_THRESHOLD 307               /* 30% */
#define LOAD_THRESHOLD 614              /* 60% */
#define SCX_DSQ_ID_BASE 1000

typedef enum {
	ALLOW_LLC_CPUS  = 0,
	ALLOW_NODE_CPUS = 1,
	ALLOW_TASK_CPUS = 2,
} cpu_allow_mask_t;

#define CPUMASK_BYTES ((MAX_CPUS + 7) / 8)

struct task_ctx {
	u64 last_sum_exec;
	u64 last_running_ns;
	u64 last_stopping_ns;
	u64 last_runnable_ns;
	u64 runtime_ewma_sum_exec;
};

struct cpu_ctx {
	u32 cpu;
	u32 node_id;
	u32 llc_id;
	u32 llc_idx;
	u32 task_pid;
} __attribute__((aligned(8)));

struct llc_ctx {
	u32 id;
	u32 nr_cpus;
	u32 last_cpu_id;
	u8 cpumask[CPUMASK_BYTES];
	struct bpf_cpumask __kptr *bpf_cpumask;
} __attribute__((aligned(8)));

struct node_ctx {
	u32 id;
	u32 nr_llcs;
	u32 nr_cpus;
	u32 last_cpu_id;
	u32 last_llc_idx;
	u8 cpumask[CPUMASK_BYTES];
	struct bpf_cpumask __kptr *bpf_cpumask;
} __attribute__((aligned(8)));

struct topo_ctx {
	u32 nr_cpus;
	u32 nr_nodes;
	u32 nr_llcs;
	u32 last_cpu_id;
	u32 last_llc_id;
	u32 last_node_id;
} __attribute__((aligned(8)));

#endif /* __INTF_H */
