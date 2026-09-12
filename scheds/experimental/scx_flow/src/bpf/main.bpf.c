/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Galih Tama <galpt@v.recipes> */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
/* Per task state for the life of the task. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct flow_task_ctx);
} task_ctx_stor SEC(".maps");
/* Per CPU state with frontier plus running plus cursor. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, struct flow_cpu_state);
} cpu_state_stor SEC(".maps");
volatile u64 nr_cpu_ids;
volatile struct flow_sched_stats flow_stats;
/* Live pressure gauges for the dashboard with no task cost. */
/* Light plus hog depths sum per CPU queued counts capped at */
/* 4. Allowance holds the burst line for the light depth. */
/* Stopping refreshes all three with one pass, so snapshot */
/* reads a consistent view with no dispatch cost. */
volatile u64 flow_light_depth;
volatile u64 flow_hog_depth;
volatile u64 flow_burst_allowance_ns;
/* Per CPU group table seeded by userspace at attach. */
/* Seeded by online rank with write by id, offline stays */
/* light inert, skewed forces ready one, dense full keeps */
/* prior halves exactly. Snapshot covers online only. */
/* Ready is zero until the table holds live groups. */
/* Halves is the fallback while ready is zero. */
volatile u8 flow_group_by_cpu[1024];
volatile u8 flow_group_ready;
/* Sibling partner seeded by userspace at attach. */
/* Seeded by online rank with write by id, offline plus */
/* singleton holds 0xffff inert. Dense full matches prior. */
/* Each CPU holds the next CPU in the same core. */
/* 0xffff means singleton with no sibling. */
/* Placement only with no dispatch use. */
volatile u16 flow_sibling_by_cpu[1024];
/* Last idle kick time per CPU in nanos at 50us. */
/* Zero init, so first kick always runs with wrap. */
/* Enqueue only with no slide on skip, see enqueue. */
volatile u64 flow_kick_at[1024];
/* Governor flag for S0 plus S1 with zero init strict. */
/* Zero keeps 4.2.21 paths bit identical with group plus */
/* mask isolation. One widens placement to any allowed */
/* on in group miss with same tier order plus bypasses */
/* the kick group gate with no recount. Mask always wins */
/* in both modes with no CLI knob. Userspace writes on */
/* governor transition only. Single flag with no per CPU */
/* array. */
volatile u8 flow_perf_mode;
static __always_inline u64 flow_now(void)
{
	return bpf_ktime_get_ns();
}
static struct flow_task_ctx *flow_lookup(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0, 0);
}
static struct flow_task_ctx *flow_get(
	struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
	    (struct task_struct *)p, 0,
	    BPF_LOCAL_STORAGE_GET_F_CREATE);
}
static struct flow_cpu_state *flow_cpu(u32 cpu)
{
	u32 key = cpu;
	if (cpu >= (u32)FLOW_MAX_CPUS)
		return NULL;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}
static __always_inline bool flow_cpu_live(u32 cpu)
{
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return true;
}
static __always_inline bool flow_cpu_ok(
	const struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return false;
	if ((u64)cpu >= nr_cpu_ids)
		return false;
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return false;
	return bpf_cpumask_test_cpu((u32)cpu, p->cpus_ptr);
}
/* Nice of one task from static prio minus 120. */
/* Null maps to 0, so weight falls back to 1024. */
static __always_inline s32 flow_nice_of(
	const struct task_struct *p)
{
	s32 nice;
	if (!p)
		return 0;
	nice = (s32)p->static_prio - 120;
	return nice;
}
static __always_inline void flow_on_cpu_dec(void)
{
	s32 i;
	bpf_for(i, 0, 4) {
		u64 cur = flow_stats.on_cpu;
		u64 nxt;
		u64 old;
		if (cur == 0)
			break;
		nxt = cur - 1;
		old = __sync_val_compare_and_swap(
		    &flow_stats.on_cpu, cur, nxt);
		if (old == cur)
			break;
		if (i == 3)
			__sync_lock_test_and_set(
			    &flow_stats.on_cpu, 0);
	}
}
/* Clear rate only plus keep peer plus stand. */
/* Atomic clear, so a concurrent claim never loses. */
static __always_inline void flow_clear_running(s32 cpu)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	st->running_est = 0;
	st->running_pid = 0;
	st->running_nice = 0;
	st->running_weight = 1024;
	__sync_fetch_and_and(&st->cursor,
	    ~(u32)FLOW_CURSOR_RATE_BIT);
}
/* Clear running only when the pid owns it, so a disable */
/* plus an exit never clears a new owner after a switch. */
static __always_inline void flow_clear_running_if_owner(
	s32 cpu, u32 pid)
{
	struct flow_cpu_state *st;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	st = flow_cpu((u32)cpu);
	if (!st)
		return;
	if (st->running_pid != pid)
		return;
	st->running_est = 0;
	st->running_pid = 0;
	st->running_nice = 0;
	st->running_weight = 1024;
	__sync_fetch_and_and(&st->cursor,
	    ~(u32)FLOW_CURSOR_RATE_BIT);
}
/* Live group of one CPU from table plus halves fallback. */
/* Reads the table when ready holds groups, else halves. */
/* Table holds online rank with write by id, offline inert. */
/* Bad values fall back to halves with no trap. */
static __always_inline u8 flow_group_live(u32 cpu,
	u64 nr)
{
	u8 g;
	if (!flow_group_ready)
		return flow_group_of_cpu(cpu, nr);
	if ((u32)cpu >= (u32)FLOW_MAX_CPUS)
		return flow_group_of_cpu(cpu, nr);
	if ((u64)cpu >= nr)
		return flow_group_of_cpu(cpu, nr);
	g = flow_group_by_cpu[cpu];
	if (g == (u8)FLOW_GROUP_HOG)
		return (u8)FLOW_GROUP_HOG;
	if (g == (u8)FLOW_GROUP_LIGHT)
		return (u8)FLOW_GROUP_LIGHT;
	return flow_group_of_cpu(cpu, nr);
}
/* Least queued allowed CPU in one group. */
/* Scans 0 to 1024 with early break on nr plus */
/* max, so the bound matches the prior first. */
/* Needs live group plus mask plus queued depth. */
/* Picks the smallest queued depth with lowest id */
/* on ties by strict less only, so equal depths */
/* keep the first id with no extra pass. Missing */
/* queues read via the dsq count with no storage */
/* lookup and no new loop. Placement keeps live, */
/* dispatch keeps halves, constants frozen. */
static __always_inline s32 flow_first_in_group(
	const struct task_struct *p, u8 group)
{
	s32 best = -1;
	u64 best_q = 0;
	s32 cpu;
	bpf_for(cpu, 0, 1024) {
		u8 g;
		u64 q;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		g = flow_group_live((u32)cpu,
		    nr_cpu_ids);
		if (g != group)
			continue;
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr))
			continue;
		q = scx_bpf_dsq_nr_queued(
		    flow_dsq_for_cpu((u32)cpu));
		if (best < 0 || q < best_q) {
			best = cpu;
			best_q = q;
		}
	}
	return best;
}
/* True when one core holds no running task. */
/* Needs self plus all siblings idle by pid. */
/* Singletons read as free with no trap. */
/* Missing state fails closed with no pick. */
static __always_inline bool flow_core_free(u32 cpu)
{
	struct flow_cpu_state *st;
	u16 nxt;
	u32 cur;
	s32 i;
	if (!flow_cpu_live(cpu))
		return false;
	st = flow_cpu(cpu);
	if (!st)
		return false;
	if (st->running_pid != 0)
		return false;
	if (cpu >= 1024)
		return true;
	nxt = flow_sibling_by_cpu[cpu];
	if (nxt == (u16)0xffff)
		return true;
	if ((u32)nxt >= (u32)FLOW_MAX_CPUS)
		return true;
	if ((u64)nxt >= nr_cpu_ids)
		return true;
	if ((u32)nxt == cpu)
		return true;
	cur = (u32)nxt;
	bpf_for(i, 0, 8) {
		struct flow_cpu_state *sst;
		u16 after;
		if (!flow_cpu_live(cur))
			return true;
		sst = flow_cpu(cur);
		if (!sst)
			return false;
		if (sst->running_pid != 0)
			return false;
		if (cur >= 1024)
			return true;
		after = flow_sibling_by_cpu[cur];
		if (after == (u16)0xffff)
			return true;
		if ((u32)after >= (u32)FLOW_MAX_CPUS)
			return true;
		if ((u64)after >= nr_cpu_ids)
			return true;
		if ((u32)after == cpu)
			return true;
		if ((u32)after == cur)
			return true;
		cur = (u32)after;
		if (cur == cpu)
			return true;
	}
	return true;
}
/* First free core in one group in id order. */
/* Scans up to 1024 with early exit on match. */
/* Needs group plus mask plus free core by pid. */
/* No claim here, so a miss wastes no idle claim. */
static __always_inline s32 flow_free_in_group(
	const struct task_struct *p, u8 group)
{
	s32 cpu;
	bpf_for(cpu, 0, 1024) {
		u8 g;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		g = flow_group_live((u32)cpu,
		    nr_cpu_ids);
		if (g != group)
			continue;
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr))
			continue;
		if (!flow_core_free((u32)cpu))
			continue;
		return cpu;
	}
	return -1;
}
/* Least queued allowed CPU in any group for S0 perf. */
/* Scans 0 to 1024 with early break on nr plus max. */
/* Needs mask plus queued depth with no group check. */
/* Picks the smallest queued depth with lowest id on */
/* ties by strict less only, so equal depths keep the */
/* first id with no extra pass. Perf only on in group */
/* miss with same rule over the widened set. Mask */
/* always wins with no dispatch use. */
static __always_inline s32 flow_first_allowed(
	const struct task_struct *p)
{
	s32 best = -1;
	u64 best_q = 0;
	s32 cpu;
	bpf_for(cpu, 0, 1024) {
		u64 q;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr))
			continue;
		q = scx_bpf_dsq_nr_queued(
		    flow_dsq_for_cpu((u32)cpu));
		if (best < 0 || q < best_q) {
			best = cpu;
			best_q = q;
		}
	}
	return best;
}
/* First free core in any group for S0 perf in id order. */
/* Scans up to 1024 with early exit on match. */
/* Needs mask plus free core by pid with no group check. */
/* Perf only on in group miss with same order. Mask */
/* always wins with no claim plus no dispatch use. */
static __always_inline s32 flow_free_any(
	const struct task_struct *p)
{
	s32 cpu;
	bpf_for(cpu, 0, 1024) {
		if (cpu < 0)
			continue;
		if ((u64)cpu >= nr_cpu_ids)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		if (!bpf_cpumask_test_cpu((u32)cpu,
		    p->cpus_ptr))
			continue;
		if (!flow_core_free((u32)cpu))
			continue;
		return cpu;
	}
	return -1;
}
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "lifecycle.bpf.c"
s32 BPF_STRUCT_OPS_SLEEPABLE(flow_init)
{
	s32 ret;
	u64 n;
	s32 cpu;
	n = scx_bpf_nr_cpu_ids();
	if (n > (u64)FLOW_MAX_CPUS) {
		scx_bpf_error("CPU count over bound");
		return -E2BIG;
	}
	if (n == 0) {
		scx_bpf_error("no CPUs found");
		return -EINVAL;
	}
	nr_cpu_ids = n;
	flow_light_depth = 0;
	flow_hog_depth = 0;
	flow_burst_allowance_ns =
	    (u64)FLOW_DEMOTE_BURST_NS;
	bpf_for(cpu, 0, 1024) {
		struct flow_cpu_state *st;
		u32 key;
		u64 dsq;
		if (cpu < 0)
			continue;
		if ((u64)cpu >= n)
			break;
		if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
			break;
		dsq = flow_dsq_for_cpu((u32)cpu);
		if (dsq >= (u64)SCX_DSQ_LOCAL_ON) {
			scx_bpf_error("dsq id over bound");
			return -EINVAL;
		}
		ret = scx_bpf_create_dsq(dsq, -1);
		if (ret < 0 && ret != -EEXIST) {
			scx_bpf_error("dsq create failed");
			return ret;
		}
		key = (u32)cpu;
		st = bpf_map_lookup_elem(&cpu_state_stor, &key);
		if (!st)
			continue;
		st->frontier = 0;
		st->running_est = 0;
		st->running_pid = 0;
		st->cursor = flow_cursor_val((u32)cpu);
		st->running_nice = 0;
		st->running_weight = 1024;
		st->delay_win = 0;
		st->delay_cur = 0;
		st->delay_cnt = 0;
		/* BSS zero already covers the EMA tail, */
		/* so verify plus keep explicit zero for */
		/* the 32B to 48B growth with no trap. */
		st->cpuperf_ema = 0;
		st->cpuperf_ema_at = 0;
		if (scx_bpf_cpuperf_set)
			scx_bpf_cpuperf_set(cpu,
			    (u32)FLOW_CPUPERF_LEVEL);
	}
	if ((u64)FLOW_DSQ_PARK >= (u64)SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq((u64)FLOW_DSQ_PARK, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	if ((u64)FLOW_DSQ_PARK_HOG >=
	    (u64)SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("dsq id over bound");
		return -EINVAL;
	}
	ret = scx_bpf_create_dsq(
	    (u64)FLOW_DSQ_PARK_HOG, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("dsq create failed");
		return ret;
	}
	return 0;
}
void BPF_STRUCT_OPS(flow_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .enable			= (void *)flow_enable,
	       .disable			= (void *)flow_disable,
	       .exit_task		= (void *)flow_exit_task,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .dispatch_max_batch	= FLOW_DISPATCH_MAX_BATCH,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
