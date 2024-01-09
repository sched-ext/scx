/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * scx_rusty is a multi-domain BPF / userspace hybrid scheduler where the BPF
 * part does simple round robin in each domain and the userspace part
 * calculates the load factor of each domain and tells the BPF part how to load
 * balance the domains.
 *
 * Every task has an entry in the task_data map which lists which domain the
 * task belongs to. When a task first enters the system (rusty_prep_enable),
 * they are round-robined to a domain.
 *
 * rusty_select_cpu is the primary scheduling logic, invoked when a task
 * becomes runnable. The lb_data map is populated by userspace to inform the BPF
 * scheduler that a task should be migrated to a new domain. Otherwise, the task
 * is scheduled in priority order as follows:
 * * The current core if the task was woken up synchronously and there are idle
 *   cpus in the system
 * * The previous core, if idle
 * * The pinned-to core if the task is pinned to a specific core
 * * Any idle cpu in the domain
 *
 * If none of the above conditions are met, then the task is enqueued to a
 * dispatch queue corresponding to the domain (rusty_enqueue).
 *
 * rusty_dispatch will attempt to consume a task from its domain's
 * corresponding dispatch queue (this occurs after scheduling any tasks directly
 * assigned to it due to the logic in rusty_select_cpu). If no task is found,
 * then greedy load stealing will attempt to find a task on another dispatch
 * queue to run.
 *
 * Load balancing is almost entirely handled by userspace. BPF populates the
 * task weight, dom mask and current dom in the task_data map and executes the
 * load balance based on userspace populating the lb_data map.
 */
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include "intf.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/*
 * const volatiles are set during initialization and treated as consts by the
 * jit compiler.
 */

/*
 * Domains and cpus
 */
const volatile u32 nr_doms = 32;	/* !0 for veristat, set during init */
const volatile u32 nr_cpus = 64;	/* !0 for veristat, set during init */
const volatile u32 cpu_dom_id_map[MAX_CPUS];
const volatile u64 dom_cpumasks[MAX_DOMS][MAX_CPUS / 64];
const volatile u32 load_half_life = 1000000000	/* 1s */;

const volatile bool kthreads_local;
const volatile bool fifo_sched;
const volatile bool switch_partial;
const volatile u32 greedy_threshold;
const volatile u32 debug;

/* base slice duration */
const volatile u64 slice_ns = SCX_SLICE_DFL;

/*
 * Exit info
 */
int exit_kind = SCX_EXIT_NONE;
char exit_msg[SCX_EXIT_MSG_LEN];

/*
 * Per-CPU context
 */
struct pcpu_ctx {
	u32 dom_rr_cur; /* used when scanning other doms */

	/* libbpf-rs does not respect the alignment, so pad out the struct explicitly */
	u8 _padding[CACHELINE_SIZE - sizeof(u32)];
} __attribute__((aligned(CACHELINE_SIZE)));

struct pcpu_ctx pcpu_ctx[MAX_CPUS];

/*
 * Domain context
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct dom_ctx);
	__uint(max_entries, MAX_DOMS);
	__uint(map_flags, 0);
} dom_data SEC(".maps");

struct lock_wrapper {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct lock_wrapper);
	__uint(max_entries, MAX_DOMS);
	__uint(map_flags, 0);
} dom_load_locks SEC(".maps");

struct dom_active_pids {
	u64 gen;
	u64 read_idx;
	u64 write_idx;
	s32 pids[MAX_DOM_ACTIVE_PIDS];
};

struct dom_active_pids dom_active_pids[MAX_DOMS];

const u64 ravg_1 = 1 << RAVG_FRAC_BITS;

static void dom_load_adj(u32 dom_id, s64 adj, u64 now)
{
	struct dom_ctx *domc;
	struct lock_wrapper *lockw;

	domc = bpf_map_lookup_elem(&dom_data, &dom_id);
	lockw = bpf_map_lookup_elem(&dom_load_locks, &dom_id);

	if (!domc || !lockw) {
		scx_bpf_error("dom_ctx / lock lookup failed");
		return;
	}

	bpf_spin_lock(&lockw->lock);
	domc->load += adj;
	ravg_accumulate(&domc->load_rd, domc->load, now, load_half_life);
	bpf_spin_unlock(&lockw->lock);

	if (adj < 0 && (s64)domc->load < 0)
		scx_bpf_error("cpu%d dom%u load underflow (load=%lld adj=%lld)",
			      bpf_get_smp_processor_id(), dom_id, domc->load, adj);

	if (debug >=2 &&
	    (!domc->dbg_load_printed_at || now - domc->dbg_load_printed_at >= 1000000000)) {
		bpf_printk("LOAD ADJ dom=%u adj=%lld load=%llu",
			   dom_id,
			   adj,
			   ravg_read(&domc->load_rd, now, load_half_life) >> RAVG_FRAC_BITS);
		domc->dbg_load_printed_at = now;
	}
}

static void dom_load_xfer_task(struct task_struct *p, struct task_ctx *taskc,
			       u32 from_dom_id, u32 to_dom_id, u64 now)
{
	struct dom_ctx *from_domc, *to_domc;
	struct lock_wrapper *from_lockw, *to_lockw;
	struct ravg_data task_load_rd;
	u64 from_load[2], to_load[2], task_load;

	from_domc = bpf_map_lookup_elem(&dom_data, &from_dom_id);
	from_lockw = bpf_map_lookup_elem(&dom_load_locks, &from_dom_id);
	to_domc = bpf_map_lookup_elem(&dom_data, &to_dom_id);
	to_lockw = bpf_map_lookup_elem(&dom_load_locks, &to_dom_id);
	if (!from_domc || !from_lockw || !to_domc || !to_lockw) {
		scx_bpf_error("dom_ctx / lock lookup failed");
		return;
	}

	/*
	 * @p is moving from @from_dom_id to @to_dom_id. Its load contribution
	 * should be moved together. We only track duty cycle for tasks. Scale
	 * it by weight to get load_rd.
	 */
	ravg_accumulate(&taskc->dcyc_rd, taskc->runnable, now, load_half_life);
	task_load_rd = taskc->dcyc_rd;
	ravg_scale(&task_load_rd, p->scx.weight, 0);

	if (debug >= 2)
		task_load = ravg_read(&task_load_rd, now, load_half_life);

	/* transfer out of @from_dom_id */
	bpf_spin_lock(&from_lockw->lock);
	if (taskc->runnable)
		from_domc->load -= p->scx.weight;

	if (debug >= 2)
		from_load[0] = ravg_read(&from_domc->load_rd, now, load_half_life);

	ravg_transfer(&from_domc->load_rd, from_domc->load,
		      &task_load_rd, taskc->runnable, load_half_life, false);

	if (debug >= 2)
		from_load[1] = ravg_read(&from_domc->load_rd, now, load_half_life);

	bpf_spin_unlock(&from_lockw->lock);

	/* transfer into @to_dom_id */
	bpf_spin_lock(&to_lockw->lock);
	if (taskc->runnable)
		to_domc->load += p->scx.weight;

	if (debug >= 2)
		to_load[0] = ravg_read(&to_domc->load_rd, now, load_half_life);

	ravg_transfer(&to_domc->load_rd, to_domc->load,
		      &task_load_rd, taskc->runnable, load_half_life, true);

	if (debug >= 2)
		to_load[1] = ravg_read(&to_domc->load_rd, now, load_half_life);

	bpf_spin_unlock(&to_lockw->lock);

	if (debug >= 2)
		bpf_printk("XFER dom%u->%u task=%lu from=%lu->%lu to=%lu->%lu",
			   from_dom_id, to_dom_id,
			   task_load >> RAVG_FRAC_BITS,
			   from_load[0] >> RAVG_FRAC_BITS,
			   from_load[1] >> RAVG_FRAC_BITS,
			   to_load[0] >> RAVG_FRAC_BITS,
			   to_load[1] >> RAVG_FRAC_BITS);
}

/*
 * Statistics
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, RUSTY_NR_STATS);
} stats SEC(".maps");

static inline void stat_add(enum stat_idx idx, u64 addend)
{
	u32 idx_v = idx;

	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx_v);
	if (cnt_p)
		(*cnt_p) += addend;
}

/* Map pid -> task_ctx */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, struct task_ctx);
	__uint(max_entries, 1000000);
	__uint(map_flags, 0);
} task_data SEC(".maps");

struct task_ctx *lookup_task_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;
	s32 pid = p->pid;

	if ((taskc = bpf_map_lookup_elem(&task_data, &pid))) {
		return taskc;
	} else {
		scx_bpf_error("task_ctx lookup failed for pid %d", p->pid);
		return NULL;
	}
}

/*
 * This is populated from userspace to indicate which pids should be reassigned
 * to new doms.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, u32);
	__uint(max_entries, 1000);
	__uint(map_flags, 0);
} lb_data SEC(".maps");

/*
 * Userspace tuner will frequently update the following struct with tuning
 * parameters and bump its gen. refresh_tune_params() converts them into forms
 * that can be used directly in the scheduling paths.
 */
struct tune_input{
	u64 gen;
	u64 direct_greedy_cpumask[MAX_CPUS / 64];
	u64 kick_greedy_cpumask[MAX_CPUS / 64];
} tune_input;

u64 tune_params_gen;
private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *direct_greedy_cpumask;
private(A) struct bpf_cpumask __kptr *kick_greedy_cpumask;

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

static u32 cpu_to_dom_id(s32 cpu)
{
	const volatile u32 *dom_idp;

	if (nr_doms <= 1)
		return 0;

	dom_idp = MEMBER_VPTR(cpu_dom_id_map, [cpu]);
	if (!dom_idp)
		return MAX_DOMS;

	return *dom_idp;
}

static void refresh_tune_params(void)
{
	s32 cpu;

	if (tune_params_gen == tune_input.gen)
		return;

	tune_params_gen = tune_input.gen;

	bpf_for(cpu, 0, nr_cpus) {
		u32 dom_id = cpu_to_dom_id(cpu);
		struct dom_ctx *domc;

		if (!(domc = bpf_map_lookup_elem(&dom_data, &dom_id))) {
			scx_bpf_error("Failed to lookup dom[%u]", dom_id);
			return;
		}

		if (tune_input.direct_greedy_cpumask[cpu / 64] & (1LLU << (cpu % 64))) {
			if (direct_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, direct_greedy_cpumask);
			if (domc->direct_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, domc->direct_greedy_cpumask);
		} else {
			if (direct_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, direct_greedy_cpumask);
			if (domc->direct_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, domc->direct_greedy_cpumask);
		}

		if (tune_input.kick_greedy_cpumask[cpu / 64] & (1LLU << (cpu % 64))) {
			if (kick_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, kick_greedy_cpumask);
		} else {
			if (kick_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, kick_greedy_cpumask);
		}
	}
}

static bool task_set_domain(struct task_ctx *taskc, struct task_struct *p,
			    u32 new_dom_id, bool init_dsq_vtime)
{
	struct dom_ctx *old_domc, *new_domc;
	struct bpf_cpumask *d_cpumask, *t_cpumask;
	u32 old_dom_id = taskc->dom_id;
	s64 vtime_delta;

	old_domc = bpf_map_lookup_elem(&dom_data, &old_dom_id);
	if (!old_domc) {
		scx_bpf_error("Failed to lookup old dom%u", old_dom_id);
		return false;
	}

	if (init_dsq_vtime)
		vtime_delta = 0;
	else
		vtime_delta = p->scx.dsq_vtime - old_domc->vtime_now;

	new_domc = bpf_map_lookup_elem(&dom_data, &new_dom_id);
	if (!new_domc) {
		scx_bpf_error("Failed to lookup new dom%u", new_dom_id);
		return false;
	}

	d_cpumask = new_domc->cpumask;
	if (!d_cpumask) {
		scx_bpf_error("Failed to get dom%u cpumask kptr",
			      new_dom_id);
		return false;
	}

	t_cpumask = taskc->cpumask;
	if (!t_cpumask) {
		scx_bpf_error("Failed to look up task cpumask");
		return false;
	}

	/*
	 * set_cpumask might have happened between userspace requesting LB and
	 * here and @p might not be able to run in @dom_id anymore. Verify.
	 */
	if (bpf_cpumask_intersects((const struct cpumask *)d_cpumask,
				   p->cpus_ptr)) {
		u64 now = bpf_ktime_get_ns();

		dom_load_xfer_task(p, taskc, taskc->dom_id, new_dom_id, now);

		p->scx.dsq_vtime = new_domc->vtime_now + vtime_delta;
		taskc->dom_id = new_dom_id;
		bpf_cpumask_and(t_cpumask, (const struct cpumask *)d_cpumask,
				p->cpus_ptr);
	}

	return taskc->dom_id == new_dom_id;
}

s32 BPF_STRUCT_OPS(rusty_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	const struct cpumask *idle_smtmask = scx_bpf_get_idle_smtmask();
	struct task_ctx *taskc;
	struct bpf_cpumask *p_cpumask;
	bool prev_domestic, has_idle_cores;
	s32 cpu;

	refresh_tune_params();

	if (!(taskc = lookup_task_ctx(p)) || !(p_cpumask = taskc->cpumask))
		goto enoent;

	if (p->nr_cpus_allowed == 1) {
		cpu = prev_cpu;
		if (kthreads_local && (p->flags & PF_KTHREAD)) {
			stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		} else {
			stat_add(RUSTY_STAT_PINNED, 1);
		}
		goto direct;
	}

	/*
	 * If WAKE_SYNC and the machine isn't fully saturated, wake up @p to the
	 * local dsq of the waker.
	 */
	if (wake_flags & SCX_WAKE_SYNC) {
		struct task_struct *current = (void *)bpf_get_current_task();

		if (!(BPF_CORE_READ(current, flags) & PF_EXITING) &&
		    taskc->dom_id < MAX_DOMS) {
			struct dom_ctx *domc;
			struct bpf_cpumask *d_cpumask;
			const struct cpumask *idle_cpumask;
			bool has_idle;

			domc = bpf_map_lookup_elem(&dom_data, &taskc->dom_id);
			if (!domc) {
				scx_bpf_error("Failed to find dom%u", taskc->dom_id);
				goto enoent;
			}
			d_cpumask = domc->cpumask;
			if (!d_cpumask) {
				scx_bpf_error("Failed to acquire dom%u cpumask kptr",
					      taskc->dom_id);
				goto enoent;
			}

			idle_cpumask = scx_bpf_get_idle_cpumask();

			has_idle = bpf_cpumask_intersects((const struct cpumask *)d_cpumask,
							  idle_cpumask);

			scx_bpf_put_idle_cpumask(idle_cpumask);

			if (has_idle) {
				cpu = bpf_get_smp_processor_id();
				if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
					stat_add(RUSTY_STAT_WAKE_SYNC, 1);
					goto direct;
				}
			}
		}
	}

	has_idle_cores = !bpf_cpumask_empty(idle_smtmask);

	/* did @p get pulled out to a foreign domain by e.g. greedy execution? */
	prev_domestic = bpf_cpumask_test_cpu(prev_cpu,
					     (const struct cpumask *)p_cpumask);

	/*
	 * See if we want to keep @prev_cpu. We want to keep @prev_cpu if the
	 * whole physical core is idle. If the sibling[s] are busy, it's likely
	 * more advantageous to look for wholly idle cores first.
	 */
	if (prev_domestic) {
		if (bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			stat_add(RUSTY_STAT_PREV_IDLE, 1);
			cpu = prev_cpu;
			goto direct;
		}
	} else {
		/*
		 * @prev_cpu is foreign. Linger iff the domain isn't too busy as
		 * indicated by direct_greedy_cpumask. There may also be an idle
		 * CPU in the domestic domain
		 */
		if (direct_greedy_cpumask &&
		    bpf_cpumask_test_cpu(prev_cpu, (const struct cpumask *)
					 direct_greedy_cpumask) &&
		    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
		    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			stat_add(RUSTY_STAT_GREEDY_IDLE, 1);
			cpu = prev_cpu;
			goto direct;
		}
	}

	/*
	 * @prev_cpu didn't work out. Let's see whether there's an idle CPU @p
	 * can be directly dispatched to. We'll first try to find the best idle
	 * domestic CPU and then move onto foreign.
	 */

	/* If there is a domestic idle core, dispatch directly */
	if (has_idle_cores) {
		cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)p_cpumask,
					    SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
			goto direct;
		}
	}

	/*
	 * If @prev_cpu was domestic and is idle itself even though the core
	 * isn't, picking @prev_cpu may improve L1/2 locality.
	 */
	if (prev_domestic && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		cpu = prev_cpu;
		goto direct;
	}

	/* If there is any domestic idle CPU, dispatch directly */
	cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)p_cpumask, 0);
	if (cpu >= 0) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		goto direct;
	}

	/*
	 * Domestic domain is fully booked. If there are CPUs which are idle and
	 * under-utilized, ignore domain boundaries and push the task there. Try
	 * to find an idle core first.
	 */
	if (taskc->all_cpus && direct_greedy_cpumask &&
	    !bpf_cpumask_empty((const struct cpumask *)direct_greedy_cpumask)) {
		u32 dom_id = cpu_to_dom_id(prev_cpu);
		struct dom_ctx *domc;

		if (!(domc = bpf_map_lookup_elem(&dom_data, &dom_id))) {
			scx_bpf_error("Failed to lookup dom[%u]", dom_id);
			goto enoent;
		}

		/* Try to find an idle core in the previous and then any domain */
		if (has_idle_cores) {
			if (domc->direct_greedy_cpumask) {
				cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)
							    domc->direct_greedy_cpumask,
							    SCX_PICK_IDLE_CORE);
				if (cpu >= 0) {
					stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
					goto direct;
				}
			}

			if (direct_greedy_cpumask) {
				cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)
							    direct_greedy_cpumask,
							    SCX_PICK_IDLE_CORE);
				if (cpu >= 0) {
					stat_add(RUSTY_STAT_DIRECT_GREEDY_FAR, 1);
					goto direct;
				}
			}
		}

		/*
		 * No idle core. Is there any idle CPU?
		 */
		if (domc->direct_greedy_cpumask) {
			cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)
						    domc->direct_greedy_cpumask, 0);
			if (cpu >= 0) {
				stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
				goto direct;
			}
		}

		if (direct_greedy_cpumask) {
			cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)
						    direct_greedy_cpumask, 0);
			if (cpu >= 0) {
				stat_add(RUSTY_STAT_DIRECT_GREEDY_FAR, 1);
				goto direct;
			}
		}
	}

	/*
	 * We're going to queue on the domestic domain's DSQ. @prev_cpu may be
	 * in a different domain. Returning an out-of-domain CPU can lead to
	 * stalls as all in-domain CPUs may be idle by the time @p gets
	 * enqueued.
	 */
	if (prev_domestic)
		cpu = prev_cpu;
	else
		cpu = scx_bpf_pick_any_cpu((const struct cpumask *)p_cpumask, 0);

	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;

direct:
	taskc->dispatch_local = true;
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return cpu;

enoent:
	scx_bpf_put_idle_cpumask(idle_smtmask);
	return -ENOENT;
}

void BPF_STRUCT_OPS(rusty_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *taskc;
	struct bpf_cpumask *p_cpumask;
	pid_t pid = p->pid;
	u32 *new_dom;
	s32 cpu;

	if (!(taskc = lookup_task_ctx(p)))
		return;
	if (!(p_cpumask = taskc->cpumask)) {
		scx_bpf_error("NULL cpmask");
		return;
	}

	/*
	 * Migrate @p to a new domain if requested by userland through lb_data.
	 */
	new_dom = bpf_map_lookup_elem(&lb_data, &pid);
	if (new_dom && *new_dom != taskc->dom_id &&
	    task_set_domain(taskc, p, *new_dom, false)) {
		stat_add(RUSTY_STAT_LOAD_BALANCE, 1);
		taskc->dispatch_local = false;
		cpu = scx_bpf_pick_any_cpu((const struct cpumask *)p_cpumask, 0);
		if (cpu >= 0)
			scx_bpf_kick_cpu(cpu, 0);
		goto dom_queue;
	}

	if (taskc->dispatch_local) {
		taskc->dispatch_local = false;
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
		return;
	}

	/*
	 * @p is about to be queued on its domain's dsq. However, @p may be on a
	 * foreign CPU due to a greedy execution and not have gone through
	 * ->select_cpu() if it's being enqueued e.g. after slice exhaustion. If
	 * so, @p would be queued on its domain's dsq but none of the CPUs in
	 * the domain would be woken up which can induce temporary execution
	 * stalls. Kick a domestic CPU if @p is on a foreign domain.
	 */
	if (!bpf_cpumask_test_cpu(scx_bpf_task_cpu(p), (const struct cpumask *)p_cpumask)) {
		cpu = scx_bpf_pick_any_cpu((const struct cpumask *)p_cpumask, 0);
		scx_bpf_kick_cpu(cpu, 0);
		stat_add(RUSTY_STAT_REPATRIATE, 1);
	}

dom_queue:
	if (fifo_sched) {
		scx_bpf_dispatch(p, taskc->dom_id, slice_ns, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;
		u32 dom_id = taskc->dom_id;
		struct dom_ctx *domc;

		domc = bpf_map_lookup_elem(&dom_data, &dom_id);
		if (!domc) {
			scx_bpf_error("Failed to lookup dom[%u]", dom_id);
			return;
		}

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, domc->vtime_now - slice_ns))
			vtime = domc->vtime_now - slice_ns;

		scx_bpf_dispatch_vtime(p, taskc->dom_id, slice_ns, vtime, enq_flags);
	}

	/*
	 * If there are CPUs which are idle and not saturated, wake them up to
	 * see whether they'd be able to steal the just queued task. This path
	 * is taken only if DIRECT_GREEDY didn't trigger in select_cpu().
	 *
	 * While both mechanisms serve very similar purposes, DIRECT_GREEDY
	 * emplaces the task in a foreign CPU directly while KICK_GREEDY just
	 * wakes up a foreign CPU which will then first try to execute from its
	 * domestic domain first before snooping foreign ones.
	 *
	 * While KICK_GREEDY is a more expensive way of accelerating greedy
	 * execution, DIRECT_GREEDY shows negative performance impacts when the
	 * CPUs are highly loaded while KICK_GREEDY doesn't. Even under fairly
	 * high utilization, KICK_GREEDY can slightly improve work-conservation.
	 */
	if (taskc->all_cpus && kick_greedy_cpumask) {
		cpu = scx_bpf_pick_idle_cpu((const struct cpumask *)
					    kick_greedy_cpumask, 0);
		if (cpu >= 0) {
			stat_add(RUSTY_STAT_KICK_GREEDY, 1);
			scx_bpf_kick_cpu(cpu, 0);
		}
	}
}

static bool cpumask_intersects_domain(const struct cpumask *cpumask, u32 dom_id)
{
	s32 cpu;

	if (dom_id >= MAX_DOMS)
		return false;

	bpf_for(cpu, 0, nr_cpus) {
		if (bpf_cpumask_test_cpu(cpu, cpumask) &&
		    (dom_cpumasks[dom_id][cpu / 64] & (1LLU << (cpu % 64))))
			return true;
	}
	return false;
}

static u32 dom_rr_next(s32 cpu)
{
	struct pcpu_ctx *pcpuc;
	u32 dom_id;

	pcpuc = MEMBER_VPTR(pcpu_ctx, [cpu]);
	if (!pcpuc)
		return 0;

	dom_id = (pcpuc->dom_rr_cur + 1) % nr_doms;

	if (dom_id == cpu_to_dom_id(cpu))
		dom_id = (dom_id + 1) % nr_doms;

	pcpuc->dom_rr_cur = dom_id;
	return dom_id;
}

void BPF_STRUCT_OPS(rusty_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 dom = cpu_to_dom_id(cpu);

	if (scx_bpf_consume(dom)) {
		stat_add(RUSTY_STAT_DSQ_DISPATCH, 1);
		return;
	}

	if (!greedy_threshold)
		return;

	bpf_repeat(nr_doms - 1) {
		u32 dom_id = dom_rr_next(cpu);

		if (scx_bpf_dsq_nr_queued(dom_id) >= greedy_threshold &&
		    scx_bpf_consume(dom_id)) {
			stat_add(RUSTY_STAT_GREEDY, 1);
			break;
		}
	}
}

void BPF_STRUCT_OPS(rusty_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->runnable = true;
	taskc->is_kworker = p->flags & PF_WQ_WORKER;

	ravg_accumulate(&taskc->dcyc_rd, taskc->runnable, now, load_half_life);
	dom_load_adj(taskc->dom_id, p->scx.weight, now);
}

void BPF_STRUCT_OPS(rusty_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	struct dom_ctx *domc;
	u32 dom_id, dap_gen;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->running_at = bpf_ktime_get_ns();
	dom_id = taskc->dom_id;
	if (dom_id >= MAX_DOMS) {
		scx_bpf_error("Invalid dom ID");
		return;
	}

	/*
	 * Record that @p has been active in @domc. Load balancer will only
	 * consider recently active tasks. Access synchronization rules aren't
	 * strict. We just need to be right most of the time.
	 */
	dap_gen = dom_active_pids[dom_id].gen;
	if (taskc->dom_active_pids_gen != dap_gen) {
		u64 idx = __sync_fetch_and_add(&dom_active_pids[dom_id].write_idx, 1) %
			MAX_DOM_ACTIVE_PIDS;
		s32 *pidp;

		pidp = MEMBER_VPTR(dom_active_pids, [dom_id].pids[idx]);
		if (!pidp) {
			scx_bpf_error("dom_active_pids[%u][%llu] indexing failed",
				      dom_id, idx);
			return;
		}

		*pidp = p->pid;
		taskc->dom_active_pids_gen = dap_gen;
	}

	if (fifo_sched)
		return;

	domc = bpf_map_lookup_elem(&dom_data, &dom_id);
	if (!domc) {
		scx_bpf_error("Failed to lookup dom[%u]", dom_id);
		return;
	}

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(domc->vtime_now, p->scx.dsq_vtime))
		domc->vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(rusty_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;

	if (fifo_sched)
		return;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	/* scale the execution time by the inverse of the weight and charge */
	p->scx.dsq_vtime +=
		(bpf_ktime_get_ns() - taskc->running_at) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(rusty_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = bpf_ktime_get_ns();
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->runnable = false;

	ravg_accumulate(&taskc->dcyc_rd, taskc->runnable, now, load_half_life);
	dom_load_adj(taskc->dom_id, -(s64)p->scx.weight, now);
}

void BPF_STRUCT_OPS(rusty_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	taskc->weight = weight;
}

static u32 task_pick_domain(struct task_ctx *taskc, struct task_struct *p,
			    const struct cpumask *cpumask)
{
	s32 cpu = bpf_get_smp_processor_id();
	u32 first_dom = MAX_DOMS, dom;

	if (cpu < 0 || cpu >= MAX_CPUS)
		return MAX_DOMS;

	taskc->dom_mask = 0;

	dom = pcpu_ctx[cpu].dom_rr_cur++;
	bpf_repeat(nr_doms) {
		dom = (dom + 1) % nr_doms;
		if (cpumask_intersects_domain(cpumask, dom)) {
			taskc->dom_mask |= 1LLU << dom;
			/*
			 * AsThe starting point is round-robin'd and the first
			 * match should be spread across all the domains.
			 */
			if (first_dom == MAX_DOMS)
				first_dom = dom;
		}
	}

	return first_dom;
}

static void task_pick_and_set_domain(struct task_ctx *taskc,
				     struct task_struct *p,
				     const struct cpumask *cpumask,
				     bool init_dsq_vtime)
{
	u32 dom_id = 0;

	if (nr_doms > 1)
		dom_id = task_pick_domain(taskc, p, cpumask);

	if (!task_set_domain(taskc, p, dom_id, init_dsq_vtime))
		scx_bpf_error("Failed to set dom%d for %s[%d]",
			      dom_id, p->comm, p->pid);
}

void BPF_STRUCT_OPS(rusty_set_cpumask, struct task_struct *p,
		    const struct cpumask *cpumask)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	task_pick_and_set_domain(taskc, p, cpumask, false);
	if (all_cpumask)
		taskc->all_cpus =
			bpf_cpumask_subset((const struct cpumask *)all_cpumask, cpumask);
}

s32 BPF_STRUCT_OPS(rusty_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct bpf_cpumask *cpumask;
	struct task_ctx taskc = { .dom_active_pids_gen = -1 };
	struct task_ctx *map_value;
	long ret;
	pid_t pid;

	pid = p->pid;

	/*
	 * XXX - We want BPF_NOEXIST but bpf_map_delete_elem() in .disable() may
	 * fail spuriously due to BPF recursion protection triggering
	 * unnecessarily.
	 */
	ret = bpf_map_update_elem(&task_data, &pid, &taskc, 0 /*BPF_NOEXIST*/);
	if (ret) {
		stat_add(RUSTY_STAT_TASK_GET_ERR, 1);
		return ret;
	}

	/*
	 * Read the entry from the map immediately so we can add the cpumask
	 * with bpf_kptr_xchg().
	 */
	map_value = bpf_map_lookup_elem(&task_data, &pid);
	if (!map_value)
		/* Should never happen -- it was just inserted above. */
		return -EINVAL;

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		bpf_map_delete_elem(&task_data, &pid);
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&map_value->cpumask, cpumask);
	if (cpumask) {
		/* Should never happen as we just inserted it above. */
		bpf_cpumask_release(cpumask);
		bpf_map_delete_elem(&task_data, &pid);
		return -EINVAL;
	}

	task_pick_and_set_domain(map_value, p, p->cpus_ptr, true);

	return 0;
}

void BPF_STRUCT_OPS(rusty_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	pid_t pid = p->pid;
	long ret;

	/*
	 * XXX - There's no reason delete should fail here but BPF's recursion
	 * protection can unnecessarily fail the operation. The fact that
	 * deletions aren't reliable means that we sometimes leak task_ctx and
	 * can't use BPF_NOEXIST on allocation in .prep_enable().
	 */
	ret = bpf_map_delete_elem(&task_data, &pid);
	if (ret) {
		stat_add(RUSTY_STAT_TASK_GET_ERR, 1);
		return;
	}
}

static s32 create_dom(u32 dom_id)
{
	struct dom_ctx domc_init = {}, *domc;
	struct bpf_cpumask *cpumask;
	u32 cpu;
	s32 ret;

	ret = scx_bpf_create_dsq(dom_id, -1);
	if (ret < 0) {
		scx_bpf_error("Failed to create dsq %u (%d)", dom_id, ret);
		return ret;
	}

	ret = bpf_map_update_elem(&dom_data, &dom_id, &domc_init, 0);
	if (ret) {
		scx_bpf_error("Failed to add dom_ctx entry %u (%d)", dom_id, ret);
		return ret;
	}

	domc = bpf_map_lookup_elem(&dom_data, &dom_id);
	if (!domc) {
		/* Should never happen, we just inserted it above. */
		scx_bpf_error("No dom%u", dom_id);
		return -ENOENT;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create BPF cpumask for domain %u", dom_id);
		return -ENOMEM;
	}

	for (cpu = 0; cpu < MAX_CPUS; cpu++) {
		const volatile u64 *dmask;

		dmask = MEMBER_VPTR(dom_cpumasks, [dom_id][cpu / 64]);
		if (!dmask) {
			scx_bpf_error("array index error");
			bpf_cpumask_release(cpumask);
			return -ENOENT;
		}

		if (*dmask & (1LLU << (cpu % 64))) {
			bpf_cpumask_set_cpu(cpu, cpumask);

			bpf_rcu_read_lock();
			if (all_cpumask)
				bpf_cpumask_set_cpu(cpu, all_cpumask);
			bpf_rcu_read_unlock();
		}
	}

	cpumask = bpf_kptr_xchg(&domc->cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("Domain %u cpumask already present", dom_id);
		bpf_cpumask_release(cpumask);
		return -EEXIST;
	}

	cpumask = bpf_cpumask_create();
	if (!cpumask) {
		scx_bpf_error("Failed to create BPF cpumask for domain %u",
			      dom_id);
		return -ENOMEM;
	}

	cpumask = bpf_kptr_xchg(&domc->direct_greedy_cpumask, cpumask);
	if (cpumask) {
		scx_bpf_error("Domain %u direct_greedy_cpumask already present",
			      dom_id);
		bpf_cpumask_release(cpumask);
		return -EEXIST;
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rusty_init)
{
	struct bpf_cpumask *cpumask;
	s32 i, ret;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&all_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&direct_greedy_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return -ENOMEM;
	cpumask = bpf_kptr_xchg(&kick_greedy_cpumask, cpumask);
	if (cpumask)
		bpf_cpumask_release(cpumask);

	if (!switch_partial)
		scx_bpf_switch_all();

	bpf_for(i, 0, nr_doms) {
		ret = create_dom(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_cpus)
		pcpu_ctx[i].dom_rr_cur = i;

	return 0;
}

void BPF_STRUCT_OPS(rusty_exit, struct scx_exit_info *ei)
{
	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_kind = ei->kind;
}

SEC(".struct_ops.link")
struct sched_ext_ops rusty = {
	.select_cpu		= (void *)rusty_select_cpu,
	.enqueue		= (void *)rusty_enqueue,
	.dispatch		= (void *)rusty_dispatch,
	.runnable		= (void *)rusty_runnable,
	.running		= (void *)rusty_running,
	.stopping		= (void *)rusty_stopping,
	.quiescent		= (void *)rusty_quiescent,
	.set_weight		= (void *)rusty_set_weight,
	.set_cpumask		= (void *)rusty_set_cpumask,
	.init_task		= (void *)rusty_init_task,
	.exit_task		= (void *)rusty_exit_task,
	.init			= (void *)rusty_init,
	.exit			= (void *)rusty_exit,
	.name			= "rusty",
};
