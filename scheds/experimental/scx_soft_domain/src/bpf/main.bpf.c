/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A soft_domain scheduler.
 *
 * This scheduler is designed to reduce cross-NUMA and cross-cluster memory
 * access overhead caused by CPU migration across NUMA nodes or clusters.
 * It keeps tasks on CPUs that preserve local memory affinity, improving
 * performance by reducing remote memory accesses and cross-node/cache traffic.
 */
#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include "intf.h"
char _license[] SEC("license") = "GPL";

const volatile u32 max_cpus = MAX_CPUS;
const volatile s32 allowed_node = -1;
const volatile char target_comm[TASK_COMM_LEN] = "";
static const __u16 pelt_subperiod_q10[9] = {
	1024, /*   0us */
	1021, /* 128us */
	1018, /* 256us */
	1016, /* 384us */
	1013, /* 512us */
	1010, /* 640us */
	1007, /* 768us */
	1005, /* 896us */
	1002  /* 1024us ~= 1 period */
};

static const __u16 pelt_period_q10[33] = {
	1024, /*  0 */
	1002, /*  1 */
	 981, /*  2 */
	 960, /*  3 */
	 939, /*  4 */
	 919, /*  5 */
	 899, /*  6 */
	 880, /*  7 */
	 861, /*  8 */
	 843, /*  9 */
	 825, /* 10 */
	 807, /* 11 */
	 790, /* 12 */
	 773, /* 13 */
	 756, /* 14 */
	 740, /* 15 */
	 724, /* 16 */
	 709, /* 17 */
	 693, /* 18 */
	 679, /* 19 */
	 664, /* 20 */
	 650, /* 21 */
	 636, /* 22 */
	 622, /* 23 */
	 609, /* 24 */
	 596, /* 25 */
	 583, /* 26 */
	 571, /* 27 */
	 558, /* 28 */
	 546, /* 29 */
	 535, /* 30 */
	 523, /* 31 */
	 512  /* 32 => 0.5 */
};

UEI_DEFINE(uei);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct cpu_ctx);
	__uint(max_entries, MAX_CPUS);
} cpu_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct llc_ctx);
	__uint(max_entries, MAX_LLC_ID);
} llc_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NUMA_NODES);
} node_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(struct topo_ctx));
	__uint(max_entries, 1);
} topo_ctxs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_LLCS);
	__type(key, u32);
	__type(value, u32);
} llc_cpu_idx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_LLCS * MAX_CPUS_PER_LLC);
	__type(key, u32);
	__type(value, u32);
} llc_sorted_cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_load_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u32);
	__type(value, s32);
	__uint(max_entries, 65535);
} cpus_selected SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, u32);
	__type(value, struct task_ctx);
} task_storage SEC(".maps");

static __maybe_unused struct cpu_ctx *lookup_cpu_ctx(int cpu)
{
	struct cpu_ctx *cpuc;

	cpuc = bpf_map_lookup_elem(&cpu_ctxs, &cpu);

	if (!cpuc) {
		scx_bpf_error("no cpu_ctx for cpu %d", cpu);
		return NULL;
	}

	return cpuc;
}

static struct node_ctx *lookup_node_ctx(uint32_t node)
{
	struct node_ctx *nodec;

	nodec = bpf_map_lookup_elem(&node_ctxs, &node);
	if (!nodec) {
		scx_bpf_error("no node_ctx for node %u", node);
		return NULL;
	}

	return nodec;
}

static struct llc_ctx *lookup_llc_ctx(uint32_t llc)
{
	struct llc_ctx *llcx;

	llcx = bpf_map_lookup_elem(&llc_ctxs, &llc);
	if (!llcx) {
		scx_bpf_error("no llc_ctx for llc %u", llc);
		return NULL;
	}

	return llcx;
}

static __always_inline s32 pick_next_idle_cpu_in_llc(u32 llc_idx)
{
	u32 key;
	u32 *cpu_idx_ptr;
	u32 next_cpu_idx;
	struct llc_ctx *llcx;
	u32 map_key;
	u32 *cpu_ptr;

	key = llc_idx;
	cpu_idx_ptr = bpf_map_lookup_elem(&llc_cpu_idx, &key);
	if (!cpu_idx_ptr) {
		return -1;
	}

	next_cpu_idx = __sync_fetch_and_add(cpu_idx_ptr, 1);
	llcx = lookup_llc_ctx(llc_idx);
	if (!llcx) {
		return -1;
	}

	next_cpu_idx = next_cpu_idx % llcx->nr_cpus;
	map_key = llc_idx * MAX_CPUS_PER_LLC + next_cpu_idx;
	cpu_ptr = bpf_map_lookup_elem(&llc_sorted_cpu_map, &map_key);
	if (!cpu_ptr) {
		return -1;
	}

	return (s32)*cpu_ptr;
}

static __always_inline s32 round_robin_select_llc_in_node(struct topo_ctx *topo, u32 node_id)
{
	u32 node_nr_llcs;
	u32 llc_start;
	u32 next_llc_idx;
	struct node_ctx *nodec;

	if (!topo || topo->nr_llcs <= 0 || topo->nr_nodes <= 0) {
		bpf_printk("topo nr_llcs/nr_nodes <= 0, topo info err.");
		return -1;
	}

	node_nr_llcs = topo->nr_llcs / topo->nr_nodes;
	if (node_nr_llcs == 0) {
		bpf_printk("node_nr_llcs == 0");
		return -EINVAL;
	}

	llc_start = node_id * node_nr_llcs;
	nodec = lookup_node_ctx(node_id);
	if (nodec) {
		next_llc_idx = __sync_fetch_and_add(&nodec->last_llc_idx, 1);
		next_llc_idx = llc_start + next_llc_idx % node_nr_llcs;
	} else {
		next_llc_idx = llc_start;
	}

	return next_llc_idx;
}

static __always_inline s32 round_robin_select_llc(struct topo_ctx *topo)
{
	u32 next_node_id;

	if (topo->nr_nodes > 0) {
		next_node_id = __sync_fetch_and_add(&topo->last_node_id, 1);
		next_node_id = next_node_id % topo->nr_nodes;
	} else {
		next_node_id = 0;
	}

	return round_robin_select_llc_in_node(topo, next_node_id);
}

static __always_inline s32 round_robin_select_cpu(struct topo_ctx *topo, u32 node_id, s32 cpu_allowed_flag)
{
	s32 llc_idx = 0;
	u32 next_cpu_id;
	struct llc_ctx *llcx;
	u32 cpu_start;

	if (cpu_allowed_flag == ALLOW_LLC_CPUS) {
		llc_idx = round_robin_select_llc(topo);
	} else if (cpu_allowed_flag == ALLOW_NODE_CPUS) {
		llc_idx = round_robin_select_llc_in_node(topo, node_id);
	}

	llcx = lookup_llc_ctx(llc_idx);
	if (!llcx || llcx->nr_cpus == 0) {
		bpf_printk("Invalid LLC or nr_cpus == 0");
		return -EINVAL;
	}

	cpu_start = llc_idx * llcx->nr_cpus;
	next_cpu_id = __sync_fetch_and_add(&llcx->last_cpu_id, 1);
	next_cpu_id = cpu_start + next_cpu_id % llcx->nr_cpus;

	return next_cpu_id;
}

static __always_inline u32 get_cpu_allowed_flag(struct topo_ctx *topo)
{
	if (allowed_node < 0) {
		return ALLOW_LLC_CPUS;
	}

	if (allowed_node > 0 && allowed_node < topo->nr_nodes) {
		return ALLOW_NODE_CPUS;
	}

	return ALLOW_TASK_CPUS;
}

static __always_inline bool scx_bpf_check_comm(struct task_struct *p)
{
	char comm[TASK_COMM_LEN];

	if (!p) {
		return false;
	}

	__builtin_memset(comm, 0, sizeof(comm));
	bpf_probe_read_kernel_str(comm, sizeof(comm), p->comm);

	/* If target_comm is not specified, tasks are scheduled for all. */
	if (target_comm[0] == '\0') {
		return true;
	}

	#pragma unroll
	for (int i = 0; i < TASK_COMM_LEN; i++) {
		if (comm[i] != target_comm[i]) {
			return false;
		}
		if (comm[i] == '\0') {
			break;
		}
	}

	return true;
}

static __always_inline void update_cpu_tasks_by_pid(u32 pid_key, s32 cpu_new)
{
	s32 *cpu_old = bpf_map_lookup_elem(&cpus_selected, &pid_key);
	struct cpu_ctx *cpuc_old;
	struct cpu_ctx *cpuc_new;

	if (cpu_old) {
		if (*cpu_old == cpu_new) {
			return;
		}

		cpuc_old = lookup_cpu_ctx(*cpu_old);
		if (cpuc_old) {
			cpuc_old->task_pid = 0;
		}
	}

	cpuc_new = lookup_cpu_ctx(cpu_new);
	if (cpuc_new) {
		cpuc_new->task_pid = pid_key;
	}
}

static __always_inline void update_cpu_by_pid(u32 pid, s32 cpu_id)
{
	if (bpf_map_update_elem(&cpus_selected, &pid, &cpu_id, BPF_ANY) != 0) {
		bpf_printk("Warning: Failed to update cpu_id, pid %d\n", pid);
	}
}

static __always_inline bool can_fast_insert_local(struct task_struct *p, s32 cpu)
{
	u32 *cpu_load = bpf_map_lookup_elem(&cpu_load_map, &cpu);
	struct task_ctx *taskc = bpf_task_storage_get(&task_storage, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc || !cpu_load) {
		return false;
	}

	if (*cpu_load < LOAD_THRESHOLD || (taskc->runtime_ewma_sum_exec * 100) / *cpu_load > 80) {
		return true;
	}

	return false;
}

static __always_inline s32 scx_prev_select_cpu(struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	s32 cpu;

	if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		cpu = prev_cpu;
		goto insert;
	}

	if (!p || p->cpus_ptr == NULL) {
		return prev_cpu;
	}

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0) {
		goto insert;
	}

	return prev_cpu;

insert:
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	return cpu;
}

s32 BPF_STRUCT_OPS(soft_domain_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	if (!scx_bpf_check_comm(p)) {
		return scx_prev_select_cpu(p, prev_cpu, wake_flags);
	}

	s32 cpu = -1;
	u32 cpu_allowed_flag;
	u32 key = 0;
	u32 *cpu_sid;
	u32 pid_key = p->pid;
	u32 pid_parent;
	struct topo_ctx *topo;

	if (wake_flags & SCX_WAKE_FORK) {
		pid_parent = p->real_parent->pid;
		cpu_sid = bpf_map_lookup_elem(&cpus_selected, &pid_parent);
		if (cpu_sid) {
			cpu = *cpu_sid;
			update_cpu_tasks_by_pid(pid_key, cpu);
			update_cpu_by_pid(pid_key, cpu);
			goto insert_cpu;
		}

		cpu = scx_bpf_task_cpu(p->real_parent);
		if (cpu >= 0) {
			goto insert_cpu;
		}
	}

	if (wake_flags & SCX_WAKE_TTWU) {
		if (scx_bpf_check_comm(p->real_parent)) {
			pid_parent = p->real_parent->pid;
			cpu_sid = bpf_map_lookup_elem(&cpus_selected, &pid_parent);
			if (cpu_sid) {
				cpu = *cpu_sid;
				update_cpu_tasks_by_pid(pid_key, cpu);
				update_cpu_by_pid(pid_key, cpu);
				goto insert_cpu;
			}
		}
		cpu_sid = bpf_map_lookup_elem(&cpus_selected, &pid_key);
		if (cpu_sid) {
			cpu = *cpu_sid;
			goto insert_cpu;
		}
	}

	topo = bpf_map_lookup_elem(&topo_ctxs, &key);
	if (!topo) {
		goto insert_prev_cpu;
	}

	cpu_allowed_flag = get_cpu_allowed_flag(topo);
	if (cpu_allowed_flag == ALLOW_TASK_CPUS) {
		return scx_prev_select_cpu(p, prev_cpu, wake_flags);
	}

	cpu_sid = bpf_map_lookup_elem(&cpus_selected, &pid_key);
	if (cpu_sid) {
		cpu = *cpu_sid;
		goto insert_cpu;
	}

	cpu = round_robin_select_cpu(topo, allowed_node, cpu_allowed_flag);
	if (cpu >= 0) {
		update_cpu_tasks_by_pid(pid_key, cpu);
		update_cpu_by_pid(pid_key, cpu);
		goto insert_cpu;
	}

	goto insert_prev_cpu;

insert_cpu:
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
	return cpu;

insert_prev_cpu:
	return prev_cpu;
}

void BPF_STRUCT_OPS(soft_domain_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p);
	s32 cpu;
	u32 pid;
	s32 *cpu_ptr;
	struct task_ctx *taskc;
	struct cpu_ctx *cpuc;
	struct cpu_ctx *cpuc_idle_cpu;
	u64 dsq_id;
	u32 idle_cpu;
	u32 *idle_cpu_load;
	u32 pid_idle_cpu;

	if (!scx_bpf_check_comm(p)) {
		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
			return;
		}

		cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}

		cpu = scx_bpf_pick_any_cpu(p->cpus_ptr, 0);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}

		return;
	}

	pid = p->pid;
	cpu_ptr = bpf_map_lookup_elem(&cpus_selected, &pid);
	if (!cpu_ptr) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return;
	}

	if (can_fast_insert_local(p, *cpu_ptr)) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | *cpu_ptr, SCX_SLICE_DFL, 0);
		return;
	}

	taskc = bpf_task_storage_get(&task_storage, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	cpuc = lookup_cpu_ctx(*cpu_ptr);
	if (!taskc || !cpuc) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return;
	}

	dsq_id = SCX_DSQ_ID_BASE + cpuc->llc_idx;
	scx_bpf_dsq_insert(p, dsq_id, SCX_SLICE_DFL, 0);
	idle_cpu = pick_next_idle_cpu_in_llc(cpuc->llc_idx);
	idle_cpu_load = bpf_map_lookup_elem(&cpu_load_map, &idle_cpu);
	if (!idle_cpu_load || *idle_cpu_load > 307 || taskc->runtime_ewma_sum_exec + *idle_cpu_load > 900) {
		return;
	}

	cpuc_idle_cpu = lookup_cpu_ctx(idle_cpu);
	if (!cpuc_idle_cpu) {
		return;
	}

	pid_idle_cpu = cpuc_idle_cpu->task_pid;
	if (!pid_idle_cpu) {
		update_cpu_tasks_by_pid(pid, idle_cpu);
		update_cpu_by_pid(pid, idle_cpu);
		scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
		return;
	}

	scx_bpf_kick_cpu(idle_cpu, SCX_KICK_IDLE);
}

void BPF_STRUCT_OPS(soft_domain_dispatch, s32 cpu, struct task_struct *p)
{
	u64 dsq_id;

	struct cpu_ctx *cpuc = lookup_cpu_ctx(cpu);
	if (cpuc) {
		dsq_id = SCX_DSQ_ID_BASE + cpuc->llc_idx;
		scx_bpf_dsq_move_to_local(dsq_id, 0);
		return;
	}
}

static s32 create_topo_cpumask(struct bpf_cpumask **kptr)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create cpumask");
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(kptr, cpumask);
	if (cpumask) {
		scx_bpf_error("kptr already had cpumask");
		bpf_cpumask_release(cpumask);
	}

	return 0;
}

static bool check_cpu_in_mask(int cpu, const u8 *cpumask)
{
	u8 byte;
	u32 ucpu = (u32)cpu;
	u32 byte_idx = ucpu / 8;
	u32 bit_idx = ucpu % 8;

	if (cpu < 0 || cpu >= max_cpus) {
		return false;
	}

	if (byte_idx >= (max_cpus / 8)) {
		return false;
	}

	if (bpf_probe_read_kernel(&byte, sizeof(byte), &cpumask[byte_idx]) != 0) {
		return false;
	}

	return (byte & (1 << bit_idx)) != 0;
}

static s32 init_llc_bpf_mask(u32 llc)
{
	u32 cpu;
	struct bpf_cpumask *cpumask;
	struct llc_ctx *llcx;
	s32 ret;

	if (!(llcx = lookup_llc_ctx(llc))) {
		return -ENOENT;
	}

	ret = create_topo_cpumask(&llcx->bpf_cpumask);
	if (ret) {
		return ret;
	}

	bpf_rcu_read_lock();
	cpumask = llcx->bpf_cpumask;
	if (!cpumask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to lookup llc cpumask");
		return -ENOENT;
	}

	bpf_for(cpu, 0, max_cpus) {
		if (check_cpu_in_mask(cpu, llcx->cpumask)) {
			bpf_cpumask_set_cpu(cpu, cpumask);
		}
	}

	bpf_rcu_read_unlock();
	return ret;
}

static s32 init_node_bpf_mask(u32 node)
{
	u32 cpu;
	struct bpf_cpumask *cpumask;
	struct node_ctx *nodec;
	s32 ret;

	if (!(nodec = lookup_node_ctx(node))) {
		return -ENOENT;
	}

	ret = create_topo_cpumask(&nodec->bpf_cpumask);
	if (ret) {
		return ret;
	}

	bpf_rcu_read_lock();
	cpumask = nodec->bpf_cpumask;
	if (!cpumask) {
		bpf_rcu_read_unlock();
		scx_bpf_error("Failed to lookup node cpumask");
		return -ENOENT;
	}

	bpf_for(cpu, 0, max_cpus) {
		if (check_cpu_in_mask(cpu, nodec->cpumask)) {
			bpf_cpumask_set_cpu(cpu, cpumask);
		}
	}

	bpf_rcu_read_unlock();
	return ret;
}

int32_t BPF_STRUCT_OPS_SLEEPABLE(soft_domain_init)
{
	int i, ret;
	uint32_t key = 0;
	struct topo_ctx *topo;
	u64 dsq_id;

	topo = bpf_map_lookup_elem(&topo_ctxs, &key);
	if (!topo) {
		bpf_printk("topo_ctxs lookup failed\n");
		return -ENOENT;
	}

	bpf_for(i, 0, topo->nr_nodes) {
		ret = init_node_bpf_mask(i);
		if (ret) {
			return ret;
		}
	}

	bpf_for(i, 0, topo->nr_llcs) {
		ret = init_llc_bpf_mask(i);
		if (ret) {
			return ret;
		}
	}

	bpf_for(i, 0, topo->nr_llcs) {
		dsq_id = SCX_DSQ_ID_BASE + i;
		ret = scx_bpf_create_dsq(dsq_id, -1);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

void BPF_STRUCT_OPS(soft_domain_runnable, struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = bpf_task_storage_get(&task_storage, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc) {
		return;
	}

	taskc->last_runnable_ns = bpf_ktime_get_ns();
	taskc->last_sum_exec = BPF_CORE_READ(p, se.sum_exec_runtime);
}

static __always_inline u64 update_pelt_load(u64 runtime_ewma_sum_exec, u64 delta_running, u64 delta_runnable)
{
	u64 elapsed_us = delta_runnable / 1000;
	u64 decay_periods = elapsed_us / 1024;
	u64 rem_us = elapsed_us % 1024;
	u64 sub_idx = rem_us / 128;

	if (delta_runnable == 0) {
		return runtime_ewma_sum_exec;
	}

	if (decay_periods > 32) {
		decay_periods = 32;
	}

	if (sub_idx > 8) {
		sub_idx = 8;
	}
	barrier_var(sub_idx);

	if (decay_periods == 0) {
		if (sub_idx == 0) {
			sub_idx = 1;
		}

		return ((runtime_ewma_sum_exec * pelt_subperiod_q10[sub_idx]) >> 10) +
			delta_running * (1024 - pelt_subperiod_q10[sub_idx]) / delta_runnable;
	}

	return ((runtime_ewma_sum_exec * pelt_period_q10[decay_periods]) >> 10) +
		delta_running * (1024 - pelt_period_q10[decay_periods]) / delta_runnable;
}

void BPF_STRUCT_OPS(soft_domain_quiescent, struct task_struct *p)
{
	u64 now, delta_runnable, delta_running_exec;
	struct task_ctx *taskc = bpf_task_storage_get(&task_storage, p, 0, 0);
	if (!taskc || !taskc->last_runnable_ns) {
		return;
	}

	now = bpf_ktime_get_ns();
	delta_running_exec = BPF_CORE_READ(p, se.sum_exec_runtime) - taskc->last_sum_exec;
	delta_runnable = now - taskc->last_runnable_ns;
	taskc->runtime_ewma_sum_exec = update_pelt_load(taskc->runtime_ewma_sum_exec, delta_running_exec, delta_runnable);
}

void BPF_STRUCT_OPS(soft_domain_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(soft_domain_ops,
		.select_cpu		= (void *)soft_domain_select_cpu,
		.enqueue 		= (void *)soft_domain_enqueue,
		.dispatch 		= (void *)soft_domain_dispatch,
		.runnable		= (void *)soft_domain_runnable,
		.quiescent		= (void *)soft_domain_quiescent,
		.init			= (void *)soft_domain_init,
		.exit			= (void *)soft_domain_exit,
		.name			= "soft_domain");
