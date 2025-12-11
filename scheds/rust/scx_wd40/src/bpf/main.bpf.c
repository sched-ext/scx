/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * The below message is as in the original scx_rusty scheduler with the name
 * updated to avoid confusion.
 *
 * scx_wd40 is a multi-domain BPF / userspace hybrid scheduler where the BPF
 * part does simple round robin in each domain and the userspace part
 * calculates the load factor of each domain and tells the BPF part how to load
 * balance the domains.
 *
 * Every task has an entry in the task_data map which lists which domain the
 * task belongs to. When a task first enters the system (wd40_prep_enable),
 * they are round-robined to a domain.
 *
 * wd40_select_cpu is the primary scheduling logic, invoked when a task
 * becomes runnable. A task's target_dom field is populated by userspace to inform
 * the BPF scheduler that a task should be migrated to a new domain. Otherwise,
 * the task is scheduled in priority order as follows:
 * * The current core if the task was woken up synchronously and there are idle
 *   cpus in the system
 * * The previous core, if idle
 * * The pinned-to core if the task is pinned to a specific core
 * * Any idle cpu in the domain
 *
 * If none of the above conditions are met, then the task is enqueued to a
 * dispatch queue corresponding to the domain (wd40_enqueue).
 *
 * wd40_dispatch will attempt to consume a task from its domain's
 * corresponding dispatch queue (this occurs after scheduling any tasks directly
 * assigned to it due to the logic in wd40_select_cpu). If no task is found,
 * then greedy load stealing will attempt to find a task on another dispatch
 * queue to run.
 *
 * Load balancing is almost entirely handled by userspace. BPF populates the
 * task weight, dom mask and current dom in the task map and executes the
 * load balance based on userspace's setting of the target_dom field.
 */

#include <scx/common.bpf.h>

#include <scx/bpf_arena_common.bpf.h>
#include <scx/bpf_arena_spin_lock.h>

#include <lib/arena.h>
#include <lib/cpumask.h>
#include <lib/percpu.h>
#include <lib/topology.h>
#include <lib/sdt_task.h>

#include "intf.h"
#include "types.h"
#include "lb_domain.h"
#include "deadline.h"

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * const volatiles are set during initialization and treated as consts by the
 * jit compiler.
 */

/*
 * Domains and cpus
 */
const volatile u32 wd40_perf_mode;

const volatile bool kthreads_local;
const volatile bool fifo_sched = false;
const volatile bool direct_greedy_numa;
const volatile u32 greedy_threshold;
const volatile u32 greedy_threshold_x_numa;

struct pcpu_ctx pcpu_ctx[MAX_CPUS];

static struct pcpu_ctx *lookup_pcpu_ctx(s32 cpu)
{
	struct pcpu_ctx *pcpuc;

	pcpuc = MEMBER_VPTR(pcpu_ctx, [cpu]);
	if (!pcpuc)
		scx_bpf_error("Failed to lookup pcpu ctx for %d", cpu);

	return pcpuc;
}

static void task_load_adj(task_ptr taskc, u64 now, bool runnable)
{
	struct ravg_data rdp;

	rdp = taskc->dcyc_rd;

	taskc->runnable = runnable;
	ravg_accumulate(&rdp, taskc->runnable, now, load_half_life);

	taskc->dcyc_rd = rdp;
}

scx_bitmap_t all_cpumask;
scx_bitmap_t direct_greedy_cpumask;
scx_bitmap_t kick_greedy_cpumask;

static inline u32 cpu_to_dom_id(u32 cpu)
{
	topo_ptr topo;
	u32 id;

	if (cpu >= NR_CPUS) {
		scx_bpf_error("invalid CPU ID");
		return MAX_DOMS;
	}

	topo = (topo_ptr)topo_nodes[TOPO_CPU][cpu];
	if (!topo) {
		scx_bpf_error("cpu %u has no topology node set", cpu);
		return MAX_DOMS;
	}

	id = topo->parent->parent->id;
	if (id >= MAX_DOMS) {
		scx_bpf_error("invalid domain id");
	}

	return id;
}

static inline bool is_offline_cpu(s32 cpu)
{
	return topo_nodes[TOPO_CPU] == NULL;
}

static s32 try_sync_wakeup(struct task_struct *p, task_ptr taskc,
			   s32 prev_cpu)
{
	struct task_struct *current = (void *)bpf_get_current_task_btf();
	s32 cpu;
	const struct cpumask *idle_cpumask;
	bool share_llc, has_idle;
	struct pcpu_ctx *pcpuc;
	dom_ptr domc;

	cpu = bpf_get_smp_processor_id();
	pcpuc = lookup_pcpu_ctx(cpu);
	if (!pcpuc)
		return -ENOENT;

	domc = pcpuc->domc;

	idle_cpumask = scx_bpf_get_idle_cpumask();

	share_llc = scx_bitmap_test_cpu(prev_cpu, domc->cpumask);
	if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_SYNC_PREV_IDLE, 1);

		cpu = prev_cpu;
		goto out;
	}

	has_idle = scx_bitmap_intersects_cpumask(domc->cpumask, idle_cpumask);

	if (has_idle && bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
	    !(current->flags & PF_EXITING) && taskc->target_dom < MAX_DOMS &&
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) == 0) {
		stat_add(RUSTY_STAT_WAKE_SYNC, 1);
		goto out;
	}

	cpu = -ENOENT;

out:
	scx_bpf_put_idle_cpumask(idle_cpumask);
	return cpu;
}

static
int select_cpu_idle_x_numa(task_ptr taskc, u32 prev_cpu, bool has_idle_cores, s32 *cpu)
{

	u32 dom_id = cpu_to_dom_id(prev_cpu);
	scx_bitmap_t tmp_direct_greedy, tmp_cpumask;
	dom_ptr domc;

	*cpu = -1;

	/*
	 * CPU may be offline e.g. CPU was removed via hotplugging and scheduler
	 * was restarted fast enough that default scheduler didn't get a chance
	 * to move the task to another CPU. In this case, we don't account for
	 * domain as we assume hotplugging is an infrequent operation. Thus,
	 * we move the task in the order of preference:
	 * 1. Move the task to idle CPU where greedy allocation is preferred
	 * 2. Move the task to any CPU where greedy allocation is preferred
	 * 3. Move the task to any CPU
	 */
	if (unlikely(is_offline_cpu(prev_cpu)))
		domc = NULL;
	else if (!(domc = lookup_dom_ctx(dom_id)))
		return -ENOENT;

	tmp_direct_greedy = direct_greedy_cpumask;
	if (!tmp_direct_greedy) {
		scx_bpf_error("Failed to lookup direct_greedy mask");
		return -ENOENT;
	}
	/*
	 * By default, only look for an idle core in the current NUMA
	 * node when looking for direct greedy CPUs outside of the
	 * current domain. Stealing work temporarily is fine when
	 * you're going across domain boundaries, but it may be less
	 * desirable when crossing NUMA boundaries as the task's
	 * working set may end up spanning multiple NUMA nodes.
	 */
	if (!direct_greedy_numa && domc) {
		tmp_cpumask = scx_percpu_scx_bitmap();
		if (!tmp_cpumask) {
			scx_bpf_error("Failed to lookup tmp cpumask");
			return -ENOENT;
		}

		scx_bitmap_and(tmp_cpumask, domc->node_cpumask, tmp_direct_greedy);
		tmp_direct_greedy = tmp_cpumask;
	}

	/* Try to find an idle core in the previous and then any domain */
	if (has_idle_cores) {
		*cpu = scx_bitmap_pick_idle_cpu(domc->direct_greedy_cpumask,
					    SCX_PICK_IDLE_CORE);
		if (*cpu >= 0) {
			stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
			return 0;
		}

		if (direct_greedy_cpumask) {
			*cpu = scx_bitmap_pick_idle_cpu(tmp_direct_greedy,
						    SCX_PICK_IDLE_CORE);
			if (*cpu >= 0) {
				stat_add(RUSTY_STAT_DIRECT_GREEDY_FAR, 1);
				return 0;
			}
		}
	}

	/*
	 * No idle core. Is there any idle CPU?
	 */
	*cpu = scx_bitmap_pick_idle_cpu(domc->direct_greedy_cpumask, 0);
	if (*cpu >= 0) {
		stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
		return 0;
	}

	if (direct_greedy_cpumask) {
		*cpu = scx_bitmap_pick_idle_cpu(tmp_direct_greedy, 0);
		if (*cpu >= 0) {
			stat_add(RUSTY_STAT_DIRECT_GREEDY_FAR, 1);
			return 0;
		}
	}

	return 0;
}

static
s32 select_cpu_retain_prev(const struct cpumask *idle_smtmask, bool prev_domestic, u32 prev_cpu)
{
	s32 cpu = -1;

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
		}

		return cpu;
	}

	/*
	 * @prev_cpu is foreign. Linger iff the domain isn't too busy as
	 * indicated by direct_greedy_cpumask. There may also be an idle
	 * CPU in the domestic domain
	 */
	if (direct_greedy_cpumask &&
	    scx_bitmap_test_cpu(prev_cpu, direct_greedy_cpumask) &&
	    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_GREEDY_IDLE, 1);
		cpu = prev_cpu;
	}

	return cpu;
}

static
s32 select_cpu_pick_local(scx_bitmap_t p_cpumask, bool prev_domestic, bool has_idle_cores, u32 prev_cpu)
{
	s32 cpu;

	/* If there is a domestic idle core, dispatch directly */
	if (has_idle_cores) {
		cpu = scx_bitmap_pick_idle_cpu(p_cpumask, SCX_PICK_IDLE_CORE);
		if (cpu >= 0) {
			stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
			return cpu;
		}
	}

	/*
	 * If @prev_cpu was domestic and is idle itself even though the core
	 * isn't, picking @prev_cpu may improve L1/2 locality.
	 */
	if (prev_domestic && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		return prev_cpu;
	}

	/* If there is any domestic idle CPU, dispatch directly */
	cpu = scx_bitmap_pick_idle_cpu(p_cpumask, 0);
	if (cpu >= 0) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		return cpu;
	}

	return -1;
}

s32 BPF_STRUCT_OPS(wd40_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	const struct cpumask *idle_smtmask = scx_bpf_get_idle_smtmask();
	task_ptr taskc;
	bool prev_domestic, has_idle_cores;
	scx_bitmap_t p_cpumask;
	s32 cpu;

	taskc = lookup_task_ctx(p);
	p_cpumask  = taskc->cpumask;

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
		cpu = try_sync_wakeup(p, taskc, prev_cpu);
		if (cpu >= 0)
			goto direct;
	}

	/* did @p get pulled out to a foreign domain by e.g. greedy execution? */
	prev_domestic = scx_bitmap_test_cpu(prev_cpu, p_cpumask);
	cpu = select_cpu_retain_prev(idle_smtmask, prev_domestic, prev_cpu);
	if (cpu >= 0)
		goto direct;

	/*
	 * @prev_cpu didn't work out. Let's see whether there's an idle CPU @p
	 * can be directly dispatched to. We'll first try to find the best idle
	 * domestic CPU and then move onto foreign.
	 */
	has_idle_cores = !bpf_cpumask_empty(idle_smtmask);

	cpu = select_cpu_pick_local(p_cpumask, prev_domestic, has_idle_cores, prev_cpu);
	if (cpu >= 0)
		goto direct;

	/*
	 * Domestic domain is fully booked. If there are CPUs which are idle and
	 * under-utilized, ignore domain boundaries (while still respecting NUMA
	 * boundaries) and push the task there. Try to find an idle core first.
	 */
	if (taskc->all_cpus && direct_greedy_cpumask &&
	    !scx_bitmap_empty(direct_greedy_cpumask)) {
		if (select_cpu_idle_x_numa(taskc, prev_cpu, has_idle_cores, &cpu))
			goto enoent;

		if (cpu >= 0)
			goto direct;
	}

	/*
	 * We're going to queue on the domestic domain's DSQ. @prev_cpu may be
	 * in a different domain. Returning an out-of-domain CPU can lead to
	 * stalls as all in-domain CPUs may be idle by the time @p gets
	 * enqueued.
	 */
	if (prev_domestic) {
		cpu = prev_cpu;
	} else {
		cpu = scx_bitmap_any_distribute(p_cpumask);
		if (cpu >= nr_cpu_ids)
			cpu = prev_cpu;
	}

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

void BPF_STRUCT_OPS(wd40_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	task_ptr taskc;
	dom_ptr domc;
	scx_bitmap_t p_cpumask;
	s32 cpu = -1;

	taskc = lookup_task_ctx(p);
	p_cpumask = taskc->cpumask;

	domc = taskc->domc;
	if (!domc)
		return;

	/*
	 * Migrate @p to a new domain if requested by userland by setting target_dom.
	 */
	if (domc->id != taskc->target_dom &&
	    task_set_domain(p, domc->id, false)) {
		stat_add(RUSTY_STAT_LOAD_BALANCE, 1);
		taskc->dispatch_local = false;
		cpu = scx_bitmap_any_distribute(p_cpumask);
		if (cpu < nr_cpu_ids)
			scx_bpf_kick_cpu(cpu, 0);
		goto dom_queue;
	}

	/*
	 * Did we decide on direct dispatch during select_cpu()?
	 */
	if (taskc->dispatch_local) {
		taskc->dispatch_local = false;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, enq_flags);
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
	if (!scx_bitmap_test_cpu(scx_bpf_task_cpu(p), p_cpumask)) {
		cpu = scx_bitmap_any_distribute(p_cpumask);
		if (cpu < nr_cpu_ids)
			scx_bpf_kick_cpu(cpu, 0);
		stat_add(RUSTY_STAT_REPATRIATE, 1);
	}

dom_queue:
	if (fifo_sched)
		scx_bpf_dsq_insert(p, taskc->target_dom, slice_ns, enq_flags);
	else
		place_task_dl(p, taskc, enq_flags);

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
	if (!taskc->all_cpus)
		return;

	const struct cpumask *idle_cpumask;

	idle_cpumask = scx_bpf_get_idle_cpumask();
	if (kick_greedy_cpumask) {
		cpu = scx_bitmap_any_and_distribute(kick_greedy_cpumask, idle_cpumask);
		if (cpu >= nr_cpu_ids)
			cpu = -EBUSY;
	}
	scx_bpf_put_cpumask(idle_cpumask);

	if (cpu >= 0) {
		stat_add(RUSTY_STAT_KICK_GREEDY, 1);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	}
}

static bool dispatch_steal_local_numa(u32 curr_dom, struct pcpu_ctx *pcpuc)
{
	u32 my_node;
	u32 dom;

	/* XXX Check if the addresses of the nodes are the same, the dom
	 * we traverse to should be in the array. */

	my_node = dom_node_id(curr_dom);

	/* try to steal a task from domains on the current NUMA node */
	bpf_repeat(nr_doms - 1) {
		dom = pcpuc->dom_rr_cur++ % nr_doms;
		if (dom == curr_dom || dom_node_id(dom) != my_node)
			continue;

		if (scx_bpf_dsq_move_to_local(dom)) {
			stat_add(RUSTY_STAT_GREEDY_LOCAL, 1);
			return true;
		}
	}

	return false;
}

static bool dispatch_steal_x_numa(u32 curr_dom, struct pcpu_ctx *pcpuc)
{
	u32 my_node;
	u32 dom;

	my_node = dom_node_id(curr_dom);

	/* try to steal a task from domains on other NUMA nodes */
	bpf_repeat(nr_doms - 1) {
		dom = pcpuc->dom_rr_cur++ % nr_doms;

		if (dom_node_id(dom) == my_node || dom == curr_dom ||
		    scx_bpf_dsq_nr_queued(dom) >= greedy_threshold_x_numa)
			continue;

		if (scx_bpf_dsq_move_to_local(dom)) {
			stat_add(RUSTY_STAT_GREEDY_XNUMA, 1);
			return true;
		}
	}

	return false;
}

void BPF_STRUCT_OPS(wd40_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 curr_dom = cpu_to_dom_id(cpu);
	struct pcpu_ctx *pcpuc;

	scx_arena_subprog_init();

	/*
	 * In older kernels, we may receive an ops.dispatch() callback when a
	 * CPU is coming online during a hotplug _before_ the hotplug callback
	 * has been invoked. We're just going to exit in that hotplug callback,
	 * so let's just defer consuming here to avoid triggering a bad DSQ
	 * error in ext.c.
	 */
	if (unlikely(is_offline_cpu(cpu)))
		return;

	if (scx_bpf_dsq_move_to_local(curr_dom)) {
		stat_add(RUSTY_STAT_DSQ_DISPATCH, 1);
		return;
	}

	if (!greedy_threshold)
		return;

	pcpuc = lookup_pcpu_ctx(cpu);
	if (!pcpuc)
		return;

	if (dispatch_steal_local_numa(curr_dom, pcpuc))
		return;

	if (!greedy_threshold_x_numa || nr_nodes == 1)
		return;

	dispatch_steal_x_numa(curr_dom, pcpuc);
}

static void update_task_wake_freq(struct task_struct *p, u64 now)
{
	task_ptr taskc;
	u64 interval;

	taskc = lookup_task_ctx(p);

	interval = now - taskc->last_woke_at;
	taskc->waker_freq = update_freq(taskc->waker_freq, interval);
	taskc->last_woke_at = now;
}

void BPF_STRUCT_OPS(wd40_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now();
	task_ptr wakee_ctx;

	wakee_ctx = lookup_task_ctx(p);
	wakee_ctx->is_kworker = p->flags & PF_WQ_WORKER;

	task_load_adj(wakee_ctx, now, true);
	dom_dcycle_adj(wakee_ctx->domc, wakee_ctx->weight, now, true);

	if (fifo_sched)
		return;

	wakee_ctx->sum_runtime = 0;

	update_task_wake_freq(bpf_get_current_task_btf(), now);
}

static void lb_record_run(task_ptr taskc)
{
	dom_ptr domc = taskc->domc;
	u32 dap_gen;

	/*
	 * Record that @p has been active in @domc. Load balancer will only
	 * consider recently active tasks. Access synchronization rules aren't
	 * strict. We just need to be right most of the time.
	 */
	dap_gen = domc->active_tasks.gen;
	if (taskc->dom_active_tasks_gen != dap_gen) {
		u64 idx = __sync_fetch_and_add(&domc->active_tasks.write_idx, 1) %
			MAX_DOM_ACTIVE_TPTRS;

		if (idx >= MAX_DOM_ACTIVE_TPTRS) {
			scx_bpf_error("dom_active_tasks[%u][%llu] out of bounds indexing",
				      domc->id, idx);
			return;
		}

		domc->active_tasks.tasks[idx] = taskc;
		taskc->dom_active_tasks_gen = dap_gen;
	}
}

void BPF_STRUCT_OPS(wd40_running, struct task_struct *p)
{
	task_ptr taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	lb_record_run(taskc);

	if (fifo_sched)
		return;

	running_update_vtime(p, taskc);
}

void BPF_STRUCT_OPS(wd40_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	stopping_update_vtime(p);
}

void BPF_STRUCT_OPS(wd40_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = scx_bpf_now(), interval;
	task_ptr taskc;
	dom_ptr domc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(domc = taskc->domc))
		return;

	task_load_adj(taskc, now, false);
	dom_dcycle_adj(domc, taskc->weight, now, false);

	if (fifo_sched)
		return;

	interval = now - taskc->last_blocked_at;
	taskc->blocked_freq = update_freq(taskc->blocked_freq, interval);
	taskc->last_blocked_at = now;
}

void BPF_STRUCT_OPS(wd40_set_weight, struct task_struct *p, u32 weight)
{
	task_ptr taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (debug >= 2)
		bpf_printk("%s[%p]: SET_WEIGHT %u -> %u", p->comm, p,
			   taskc->weight, weight);

	taskc->weight = weight;
}

void BPF_STRUCT_OPS(wd40_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
	task_ptr taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	task_pick_and_set_domain(taskc, p, cpumask, false);
	if (all_cpumask)
		taskc->all_cpus = scx_bitmap_subset_cpumask(all_cpumask, cpumask);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(wd40_init_task, struct task_struct *p __arg_trusted,
		   struct scx_init_task_args *args)
{
	u64 now = scx_bpf_now();
	task_ptr taskc;

	taskc = (task_ptr)scx_task_alloc(p);
	if (!taskc)
		return -ENOMEM;

	*(struct task_ctx *)taskc = (struct task_ctx) {
		.dom_active_tasks_gen = -1,
		.last_blocked_at = now,
		.last_woke_at = now,
		.preferred_dom_mask = 0,
		.pid = p->pid,
	};

	if (debug >= 2)
		bpf_printk("%s[%p]: INIT (weight %u))", p->comm, p, p->scx.weight);


	taskc->cpumask = scx_bitmap_alloc();
	if (!taskc->cpumask) {
		scx_task_free(p);
		return -ENOMEM;
	}

	bpf_rcu_read_lock();
	task_pick_and_set_domain(taskc, p, p->cpus_ptr, true);
	bpf_rcu_read_unlock();

	return 0;
}

void BPF_STRUCT_OPS(wd40_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	scx_task_free(p);
}

static s32 initialize_cpu(s32 cpu)
{
	struct pcpu_ctx *pcpuc = lookup_pcpu_ctx(cpu);
	dom_ptr domc;
	int perf;
	u32 i;

	scx_arena_subprog_init();

	if (!pcpuc)
		return -ENOENT;

	/*
	 * Perf has to be within [0, 1024]. Set it regardless
	 * of value to clean up any previous settings, since
	 * it persists even after removing the scheduler.
	 */
	perf = min(SCX_CPUPERF_ONE, wd40_perf_mode);
	scx_bpf_cpuperf_set(cpu, perf);

	pcpuc->dom_rr_cur = cpu;
	bpf_for(i, 0, nr_doms) {

		domc = lookup_dom_ctx(i);
		if (!domc)
			return -ENOENT;

		if (scx_bitmap_test_cpu(cpu, domc->cpumask)) {
			pcpuc->domc = domc;
			return 0;
		}
	}

	scx_bpf_error("dom%d not found for CPU %d", nr_doms, cpu);

	return -ENOENT;
}

SEC("syscall")
int wd40_setup(void)
{
	int ret, i;

	ret = create_save_scx_bitmap(&all_cpumask);
	if (ret)
		return ret;

	ret = create_save_scx_bitmap(&direct_greedy_cpumask);
	if (ret)
		return ret;

	ret = create_save_scx_bitmap(&kick_greedy_cpumask);
	if (ret)
		return ret;

	ret = lb_domain_init();
	if (ret)
		return ret;

	/* The node masks are initialized from userspace .*/

	if (nr_nodes >= MAX_NUMA_NODES) {
		scx_bpf_error("Invalid # of nodes (%d)", nr_nodes);
		return -ENOENT;
	}

	bpf_for(i, 0, nr_nodes) {
		ret = create_save_scx_bitmap((scx_bitmap_t *)&node_data[i]);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_doms) {
		ret = alloc_dom(i);
		if (ret)
			return ret;
	}

	if (debug) {
		topo_print();
		topo_print_by_level();
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(wd40_init)
{
	s32 i, ret;

	bpf_for(i, 0, nr_doms) {
		ret = create_dom(i);
		if (ret)
			return ret;

	}

	scx_bitmap_or(all_cpumask, all_cpumask, topo_all->mask);

	bpf_for(i, 0, nr_cpu_ids) {

		if (is_offline_cpu(i))
			continue;

		ret = initialize_cpu(i);
		if (ret)
			return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(wd40_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(wd40,
	       .select_cpu		= (void *)wd40_select_cpu,
	       .enqueue			= (void *)wd40_enqueue,
	       .dispatch		= (void *)wd40_dispatch,
	       .runnable		= (void *)wd40_runnable,
	       .running			= (void *)wd40_running,
	       .stopping		= (void *)wd40_stopping,
	       .quiescent		= (void *)wd40_quiescent,
	       .set_weight		= (void *)wd40_set_weight,
	       .set_cpumask		= (void *)wd40_set_cpumask,
	       .init_task		= (void *)wd40_init_task,
	       .exit_task		= (void *)wd40_exit_task,
	       .init			= (void *)wd40_init,
	       .exit			= (void *)wd40_exit,
	       .timeout_ms		= 10000,
	       .name			= "wd40");
