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
 * dispatch queue corresponding to the domain (rusty_enqueue).
 *
 * rusty_dispatch will attempt to consume a task from its domain's
 * corresponding dispatch queue (this occurs after scheduling any tasks directly
 * assigned to it due to the logic in rusty_select_cpu). If no task is found,
 * then greedy load stealing will attempt to find a task on another dispatch
 * queue to run.
 *
 * Load balancing is almost entirely handled by userspace. BPF populates the
 * task weight, dom mask and current dom in the task map and executes the
 * load balance based on userspace's setting of the target_dom field.
 */

#ifdef LSP
#define __bpf__
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/ravg_impl.bpf.h"
#else
#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include <lib/sdt_task.h>
#endif

#include "intf.h"
#include "types.h"
#include "lb_domain.h"
#include "deadline.h"

#include <scx/bpf_arena_common.h>
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
const volatile u32 nr_cpu_ids = 64;	/* !0 for veristat, set during init */
const volatile u32 cpu_dom_id_map[MAX_CPUS];
const volatile u64 numa_cpumasks[MAX_NUMA_NODES][MAX_CPUS / 64];

const volatile bool kthreads_local;
const volatile bool fifo_sched = false;
const volatile bool direct_greedy_numa;
const volatile u32 greedy_threshold;
const volatile u32 greedy_threshold_x_numa;

struct rusty_percpu_storage {
	struct bpf_cpumask __kptr *bpfmask;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct rusty_percpu_storage);
	__uint(max_entries, 1);
} scx_percpu_bpfmask_map SEC(".maps");

static int scx_rusty_percpu_storage_init(void)
{
	void *map = &scx_percpu_bpfmask_map;
	struct rusty_percpu_storage *storage;
	const u32 zero = 0;
	int ret, i;

	bpf_for (i, 0, nr_cpu_ids) {
		storage = bpf_map_lookup_percpu_elem(map, &zero, i);
		if (!storage) {
			/* Should be impossible. */
			scx_bpf_error("Did not find map entry");
			return -EINVAL;
		}

		ret = create_save_cpumask(&storage->bpfmask);
		if (ret)
			return ret;
	}

	return 0;
}

static struct bpf_cpumask *scx_percpu_bpfmask(void)
{
	struct rusty_percpu_storage *storage;
	void *map = &scx_percpu_bpfmask_map;
	const u32 zero = 0;

	storage = bpf_map_lookup_elem(map, &zero);
	if (!storage) {
		/* Should be impossible. */
		scx_bpf_error("Did not find map entry");
		return NULL;
	}

	if (!storage->bpfmask)
		scx_bpf_error("Did not properly initialize singleton");

	return storage->bpfmask;
}

struct pcpu_ctx pcpu_ctx[MAX_CPUS];

const u64 ravg_1 = 1 << RAVG_FRAC_BITS;

__hidden
struct task_ctx *lookup_task_ctx_mask(struct task_struct *p, struct bpf_cpumask **p_cpumaskp)
{
	struct task_ctx *taskc;

	if (p_cpumaskp == NULL) {
		scx_bpf_error("no mask pointer provided");
		return NULL;
	}

	taskc = lookup_task_ctx(p);
	if (!taskc)
		scx_bpf_error("task_ctx lookup failed for task %p", p);

	*p_cpumaskp = lookup_task_bpfmask(p);
	if (*p_cpumaskp == NULL)
		scx_bpf_error("task bpf_cpumask lookup failed for task %p", p);

	return taskc;
}

static struct pcpu_ctx *lookup_pcpu_ctx(s32 cpu)
{
	struct pcpu_ctx *pcpuc;

	pcpuc = MEMBER_VPTR(pcpu_ctx, [cpu]);
	if (!pcpuc)
		scx_bpf_error("Failed to lookup pcpu ctx for %d", cpu);

	return pcpuc;
}

static void task_load_adj(struct task_ctx *taskc,
			  u64 now, bool runnable)
{
	taskc->runnable = runnable;
	ravg_accumulate(&taskc->dcyc_rd, taskc->runnable, now, load_half_life);
}

/*
 * Userspace tuner will frequently update the following struct with tuning
 * parameters and bump its gen. refresh_tune_params() converts them into forms
 * that can be used directly in the scheduling paths.
 */
struct tune_input{
	u64 gen;
	u64 slice_ns;
	u64 direct_greedy_cpumask[MAX_CPUS / 64];
	u64 kick_greedy_cpumask[MAX_CPUS / 64];
} tune_input;

u64 tune_params_gen;
private(A) struct bpf_cpumask __kptr *all_cpumask;
private(A) struct bpf_cpumask __kptr *direct_greedy_cpumask;
private(A) struct bpf_cpumask __kptr *kick_greedy_cpumask;

static u32 cpu_to_dom_id(s32 cpu)
{
	const volatile u32 *dom_idp;

	dom_idp = MEMBER_VPTR(cpu_dom_id_map, [cpu]);
	if (!dom_idp)
		return MAX_DOMS;

	return *dom_idp;
}

static inline bool is_offline_cpu(s32 cpu)
{
	return cpu_to_dom_id(cpu) > MAX_DOMS;
}

static void refresh_tune_params(void)
{
	s32 cpu;

	if (tune_params_gen == tune_input.gen)
		return;

	tune_params_gen = tune_input.gen;
	slice_ns = tune_input.slice_ns;

	bpf_for(cpu, 0, nr_cpu_ids) {
		u32 dom_id = cpu_to_dom_id(cpu);
		struct lb_domain *lb_domain;

		if (is_offline_cpu(cpu))
			continue;

		if (!(lb_domain = lb_domain_get(dom_id)))
			return;

		if (tune_input.direct_greedy_cpumask[cpu / 64] & (1LLU << (cpu % 64))) {
			if (direct_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, direct_greedy_cpumask);
			if (lb_domain->direct_greedy_cpumask)
				bpf_cpumask_set_cpu(cpu, lb_domain->direct_greedy_cpumask);
		} else {
			if (direct_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, direct_greedy_cpumask);
			if (lb_domain->direct_greedy_cpumask)
				bpf_cpumask_clear_cpu(cpu, lb_domain->direct_greedy_cpumask);
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

static s32 try_sync_wakeup(struct task_struct *p, struct task_ctx *taskc,
			   s32 prev_cpu)
{
	struct task_struct *current = (void *)bpf_get_current_task_btf();
	s32 cpu;
	const struct cpumask *idle_cpumask;
	bool share_llc, has_idle;
	struct lb_domain *lb_domain;
	struct bpf_cpumask *d_cpumask;
	struct pcpu_ctx *pcpuc;

	cpu = bpf_get_smp_processor_id();
	pcpuc = lookup_pcpu_ctx(cpu);
	if (!pcpuc)
		return -ENOENT;

	lb_domain = lb_domain_get(pcpuc->dom_id);
	if (!lb_domain)
		return -ENOENT;

	d_cpumask = lb_domain->cpumask;
	if (!d_cpumask) {
		scx_bpf_error("Failed to acquire dom%u cpumask kptr",
				taskc->target_dom);
		return -ENOENT;
	}

	idle_cpumask = scx_bpf_get_idle_cpumask();

	share_llc = bpf_cpumask_test_cpu(prev_cpu, cast_mask(d_cpumask));
	if (share_llc && scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_SYNC_PREV_IDLE, 1);

		cpu = prev_cpu;
		goto out;
	}

	has_idle = bpf_cpumask_intersects(cast_mask(d_cpumask), idle_cpumask);

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
int select_cpu_idle_x_numa(struct task_ctx *taskc, u32 prev_cpu, bool has_idle_cores, s32 *cpu)
{

	u32 dom_id = cpu_to_dom_id(prev_cpu);
	struct lb_domain *lb_domain;
	struct bpf_cpumask *tmp_direct_greedy, *node_mask;
	struct bpf_cpumask *tmp_cpumask;
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

	if (!(lb_domain = lb_domain_get(domc->id))) {
		scx_bpf_error("Failed to lookup domain map value");
		return -ENOENT;
	}

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
		node_mask = lb_domain->node_cpumask;
		if (!node_mask) {
			scx_bpf_error("Failed to lookup node mask");
			return -ENOENT;
		}

		tmp_cpumask = scx_percpu_bpfmask();
		if (!tmp_cpumask) {
			scx_bpf_error("Failed to lookup tmp cpumask");
			return -ENOENT;
		}
		bpf_cpumask_and(tmp_cpumask,
				cast_mask(node_mask),
				cast_mask(tmp_direct_greedy));
		tmp_direct_greedy = tmp_cpumask;
	}

	/* Try to find an idle core in the previous and then any domain */
	if (has_idle_cores) {
		if (domc && lb_domain->direct_greedy_cpumask) {
			*cpu = scx_bpf_pick_idle_cpu(cast_mask(lb_domain->direct_greedy_cpumask),
						    SCX_PICK_IDLE_CORE);
			if (*cpu >= 0) {
				stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
				return 0;
			}
		}

		if (direct_greedy_cpumask) {
			*cpu = scx_bpf_pick_idle_cpu(cast_mask(tmp_direct_greedy),
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
	if (domc && lb_domain->direct_greedy_cpumask) {
		*cpu = scx_bpf_pick_idle_cpu(cast_mask(lb_domain->direct_greedy_cpumask), 0);
		if (*cpu >= 0) {
			stat_add(RUSTY_STAT_DIRECT_GREEDY, 1);
			return 0;
		}
	}

	if (direct_greedy_cpumask) {
		*cpu = scx_bpf_pick_idle_cpu(cast_mask(tmp_direct_greedy), 0);
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
	    bpf_cpumask_test_cpu(prev_cpu, cast_mask(direct_greedy_cpumask)) &&
	    bpf_cpumask_test_cpu(prev_cpu, idle_smtmask) &&
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
		stat_add(RUSTY_STAT_GREEDY_IDLE, 1);
		cpu = prev_cpu;
	}

	return cpu;
}

static
s32 select_cpu_pick_local(struct bpf_cpumask *p_cpumask, bool prev_domestic, bool has_idle_cores, u32 prev_cpu)
{
	s32 cpu;

	/* If there is a domestic idle core, dispatch directly */
	if (has_idle_cores) {
		cpu = scx_bpf_pick_idle_cpu(cast_mask(p_cpumask), SCX_PICK_IDLE_CORE);
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
	cpu = scx_bpf_pick_idle_cpu(cast_mask(p_cpumask), 0);
	if (cpu >= 0) {
		stat_add(RUSTY_STAT_DIRECT_DISPATCH, 1);
		return cpu;
	}

	return -1;
}

s32 BPF_STRUCT_OPS(rusty_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	const struct cpumask *idle_smtmask = scx_bpf_get_idle_smtmask();
	struct task_ctx *taskc;
	bool prev_domestic, has_idle_cores;
	struct bpf_cpumask *p_cpumask;
	s32 cpu;

	refresh_tune_params();

	if (!(taskc = lookup_task_ctx_mask(p, &p_cpumask)) || !p_cpumask)
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
		cpu = try_sync_wakeup(p, taskc, prev_cpu);
		if (cpu >= 0)
			goto direct;
	}

	/* did @p get pulled out to a foreign domain by e.g. greedy execution? */
	prev_domestic = bpf_cpumask_test_cpu(prev_cpu, cast_mask(p_cpumask));
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
	    !bpf_cpumask_empty(cast_mask(direct_greedy_cpumask))) {
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
		cpu = bpf_cpumask_any_distribute(cast_mask(p_cpumask));
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

void BPF_STRUCT_OPS(rusty_enqueue, struct task_struct *p __arg_trusted, u64 enq_flags)
{
	struct task_ctx *taskc;
	dom_ptr domc;
	struct bpf_cpumask *p_cpumask;
	s32 cpu = -1;

	if (!(taskc = lookup_task_ctx_mask(p, &p_cpumask)) || !p_cpumask)
		return;

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
		cpu = bpf_cpumask_any_distribute(cast_mask(p_cpumask));
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
	if (!bpf_cpumask_test_cpu(scx_bpf_task_cpu(p), cast_mask(p_cpumask))) {
		cpu = bpf_cpumask_any_distribute(cast_mask(p_cpumask));
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
	if (taskc->all_cpus) {
		const struct cpumask *idle_cpumask;

		idle_cpumask = scx_bpf_get_idle_cpumask();
		if (kick_greedy_cpumask) {
			cpu = bpf_cpumask_any_and_distribute(cast_mask(kick_greedy_cpumask), idle_cpumask);
			if (cpu >= nr_cpu_ids)
				cpu = -EBUSY;
		}
		scx_bpf_put_cpumask(idle_cpumask);

		if (cpu >= 0) {
			stat_add(RUSTY_STAT_KICK_GREEDY, 1);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		}
	}
}

static bool
dispatch_steal_local_numa(u32 curr_dom, struct pcpu_ctx *pcpuc)
{
	u32 my_node;
	u32 dom;

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

static bool
dispatch_steal_x_numa(u32 curr_dom, struct pcpu_ctx *pcpuc)
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

void BPF_STRUCT_OPS(rusty_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 curr_dom = cpu_to_dom_id(cpu);
	struct pcpu_ctx *pcpuc;

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

static void
update_task_wake_freq(struct task_struct *p, u64 now)
{
	struct task_ctx *taskc;
	u64 interval;

	if (!(taskc = try_lookup_task_ctx(p)))
		return;

	interval = now - taskc->last_woke_at;
	taskc->waker_freq = update_freq(taskc->waker_freq, interval);
	taskc->last_woke_at = now;
}

void BPF_STRUCT_OPS(rusty_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = scx_bpf_now();
	struct task_ctx *wakee_ctx;

	if (!(wakee_ctx = lookup_task_ctx(p)))
		return;

	wakee_ctx->is_kworker = p->flags & PF_WQ_WORKER;

	task_load_adj(wakee_ctx, now, true);
	dom_dcycle_adj(wakee_ctx->domc, wakee_ctx->weight, now, true);

	if (fifo_sched)
		return;

	wakee_ctx->sum_runtime = 0;

	update_task_wake_freq(bpf_get_current_task_btf(), now);
}

static
void lb_record_run(struct task_struct *p, dom_ptr domc, struct task_ctx *taskc)
{
	task_ptr usrptr = (task_ptr)sdt_task_data(p);
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

		usrptr = (task_ptr)sdt_task_data(p);
		cast_user(usrptr);

		domc->active_tasks.tasks[idx] = usrptr;
		taskc->dom_active_tasks_gen = dap_gen;
	}
}

void BPF_STRUCT_OPS(rusty_running, struct task_struct *p)
{
	struct task_ctx *taskc;
	dom_ptr domc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	domc = taskc->domc;
	if (!domc) {
		scx_bpf_error("Invalid dom ID");
		return;
	}

	lb_record_run(p, domc, taskc);

	if (fifo_sched)
		return;

	running_update_vtime(p, taskc, domc);
}

void BPF_STRUCT_OPS(rusty_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *taskc;
	dom_ptr domc;

	if (fifo_sched)
		return;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (!(domc = taskc->domc))
		return;

	stopping_update_vtime(p, taskc, domc);
}

void BPF_STRUCT_OPS(rusty_quiescent, struct task_struct *p, u64 deq_flags)
{
	u64 now = scx_bpf_now(), interval;
	struct task_ctx *taskc;
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

void BPF_STRUCT_OPS(rusty_set_weight, struct task_struct *p, u32 weight)
{
	struct task_ctx *taskc;

	if (!(taskc = lookup_task_ctx(p)))
		return;

	if (debug >= 2)
		bpf_printk("%s[%p]: SET_WEIGHT %u -> %u", p->comm, p,
			   taskc->weight, weight);

	taskc->weight = weight;
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
			bpf_cpumask_subset(cast_mask(all_cpumask), cpumask);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rusty_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	u64 now = scx_bpf_now();
	struct task_struct *p_map;
	struct bpfmask_wrapper wrapper;
	struct bpfmask_wrapper *mask_map_value;
	struct task_ctx *taskc;
	long ret;

	taskc = (struct task_ctx *)sdt_task_alloc(p);
	if (!taskc)
		return -ENOMEM;

	*taskc = (struct task_ctx) {
		.dom_active_tasks_gen = -1,
		.last_blocked_at = now,
		.last_woke_at = now,
		.preferred_dom_mask = 0,
		.pid = p->pid,
	};

	if (debug >= 2)
		bpf_printk("%s[%p]: INIT (weight %u))", p->comm, p, p->scx.weight);


	/*
	 * XXX Passing a trusted pointer as a key to the map turns it into a
	 * scalar for the verifier, preventing us from using it further. Make
	 * a temporary copy of our struct task_struct to pass it to the map.
	 */
	p_map = p;

	ret = bpf_map_update_elem(&task_masks, &p_map, &wrapper, 0 /*BPF NOEXIST*/);
	if (ret) {
		sdt_task_free(p);
		return ret;
	}

	mask_map_value = bpf_map_lookup_elem(&task_masks, &p_map);
	if (!mask_map_value) {
		sdt_task_free(p);
		return -EINVAL;
	}

	ret = create_save_cpumask(&mask_map_value->instance);
	if (ret) {
		bpf_map_delete_elem(&task_masks, &p_map);
		sdt_task_free(p);
		return ret;
	}

	bpf_rcu_read_lock();
	task_pick_and_set_domain(taskc, p, p->cpus_ptr, true);
	bpf_rcu_read_unlock();

	return 0;
}

void BPF_STRUCT_OPS(rusty_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	long ret;

	sdt_task_free(p);

	/*
	 * XXX - There's no reason delete should fail here but BPF's recursion
	 * protection can unnecessarily fail the operation. The fact that
	 * deletions aren't reliable means that we sometimes leak bpf_cpumask and
	 * can't use BPF_NOEXIST on allocation in .prep_enable().
	 */
	ret = bpf_map_delete_elem(&task_masks, &p);
	if (ret) {
		stat_add(RUSTY_STAT_TASK_GET_ERR, 1);
		return;
	}

}

static s32 initialize_cpu(s32 cpu)
{
	struct pcpu_ctx *pcpuc = lookup_pcpu_ctx(cpu);
	u32 i;

	if (!pcpuc)
		return -ENOENT;

	pcpuc->dom_rr_cur = cpu;
	bpf_for(i, 0, nr_doms) {
		bool in_dom;
		struct lb_domain *lb_domain;

		lb_domain = lb_domain_get(i);
		if (!lb_domain)
			return -ENOENT;

		bpf_rcu_read_lock();
		if (!lb_domain->cpumask) {
			bpf_rcu_read_unlock();
			scx_bpf_error("Failed to lookup dom node %d cpumask %p",
				i, &lb_domain->cpumask);
			return -ENOENT;
		}

		in_dom = bpf_cpumask_test_cpu(cpu, cast_mask(lb_domain->cpumask));
		bpf_rcu_read_unlock();
		if (in_dom) {
			pcpuc->dom_id = i;
			return 0;
		}
	}

	return -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rusty_init)
{
	s32 i, ret;

	ret = sdt_static_init(STATIC_ALLOC_PAGES_GRANULARITY);
	if (ret)
		return ret;

	ret = sdt_task_init(sizeof(struct task_ctx));
	if (ret)
		return ret;

	ret = lb_domain_init();
	if (ret)
		return ret;

	ret = create_save_cpumask(&all_cpumask);
	if (ret)
		return ret;

	ret = create_save_cpumask(&direct_greedy_cpumask);
	if (ret)
		return ret;

	ret = create_save_cpumask(&kick_greedy_cpumask);
	if (ret)
		return ret;

	ret = scx_rusty_percpu_storage_init();
	if (ret)
		return ret;

	bpf_for(i, 0, nr_nodes) {
		ret = create_node(i);
		if (ret)
			return ret;
	}
	bpf_for(i, 0, nr_doms) {
		ret = create_dom(i);
		if (ret)
			return ret;
	}

	bpf_for(i, 0, nr_cpu_ids) {
		if (is_offline_cpu(i))
			continue;

		ret = initialize_cpu(i);
		if (ret)
			return ret;
	}

	return 0;
}

void BPF_STRUCT_OPS(rusty_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rusty,
	       .select_cpu		= (void *)rusty_select_cpu,
	       .enqueue			= (void *)rusty_enqueue,
	       .dispatch		= (void *)rusty_dispatch,
	       .runnable		= (void *)rusty_runnable,
	       .running			= (void *)rusty_running,
	       .stopping		= (void *)rusty_stopping,
	       .quiescent		= (void *)rusty_quiescent,
	       .set_weight		= (void *)rusty_set_weight,
	       .set_cpumask		= (void *)rusty_set_cpumask,
	       .init_task		= (void *)rusty_init_task,
	       .exit_task		= (void *)rusty_exit_task,
	       .init			= (void *)rusty_init,
	       .exit			= (void *)rusty_exit,
	       .timeout_ms		= 10000,
	       .name			= "rusty");
