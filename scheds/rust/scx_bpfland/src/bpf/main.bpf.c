/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Andrea Righi <andrea.righi@linux.dev>
 *
 * scx_bpfland: one queue per CPU, in which the task that runs next is the
 * one with the earliest virtual deadline among those that are owed service,
 * as in EEVDF.
 *
 * Each CPU has a virtual clock, which advances as its tasks run, by the time
 * they run over the weight of all the tasks runnable there at the time, see
 * advance(): it is the virtual time a task would be at had it received
 * exactly its share. A task's own virtual time advances by the time it ran
 * over its weight. The difference is its lag. A task behind the clock is
 * owed service and is eligible to run, and one ahead of it has had more than
 * its share.
 *
 * A task is queued with a deadline past its virtual time by what it asks
 * for, see task_request(). A CPU runs the eligible task with the earliest
 * deadline, so a task that used little of its share runs soon, and none can
 * run ahead of its share for long. The task whose slice ends is part of that
 * pick, and keeps the CPU while it wins it, see keep_running().
 *
 * The queues are EDQs in the arena (lib/edq): they keep the tasks in
 * deadline order and find the first eligible one, which a DSQ cannot. A
 * queued task is in the scheduler's custody, with its queue node in its task
 * context, until a CPU moves it to its local DSQ or the kernel takes it back
 * in ops.dequeue().
 *
 * Tasks are placed as the kernel's fair class places them, in outline. A
 * waking task looks for an idle CPU in the LLC of its last one, where its
 * cache is: a core that is idle as a whole first, then any idle CPU, and its
 * last CPU first either way. A forked task has no cache yet, and with
 * nothing idle in the LLC it starts on an idle CPU of the node or of the
 * machine.
 *
 * Two simple load balancers move tasks after that, both toward idle CPUs. A
 * pull balancer in ops.dispatch(): a CPU whose queue is empty steals from
 * the closest queue that has a task, in its LLC, then its node, then the
 * whole machine, see steal(). And an active balancer at the tick, for a task
 * that never sleeps and so is never placed again: its CPU moves it to a
 * whole idle core while its SMT sibling is busy, or to an idle CPU of a
 * better rank, in the LLC, see balance_target(). Neither balancer compares
 * loads, so nothing moves a task between two CPUs that both stay busy.
 *
 * A task that moves keeps its lag: its virtual time is restated in the clock
 * of the CPU it moved to. A task that sleeps keeps it too: it wakes as far
 * from the clock as it was when it went to sleep, so sleeping neither earns
 * service nor pays off what the task ran beyond its share.
 *
 * A task's deadline is its virtual time plus what it asks for, which is how
 * long it runs between two sleeps. A task that works for a moment and sleeps
 * again has an early deadline and, when it wakes beside a task that asks for
 * more, takes the CPU from it.
 *
 * A waking task is also let to borrow virtual time, which puts it ahead of
 * the tasks that stayed runnable, see borrow(). --no-vtime-borrowing turns
 * that off.
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/arena_map.h>
#include <lib/edq.h>
#include <lib/sdt_alloc.h>
#include "intf.h"

#ifndef __BPF_FEATURE_ADDR_SPACE_CAST
#error "scx_bpfland requires a compiler with bpf_addr_space_cast support"
#endif

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * The verifier only associates a program with the arena if the program
 * loads the map itself. Reaching the arena through a pointer kept in a
 * global does not, so every program that touches arena memory says so.
 */
#define TOUCH_ARENA()	do { asm volatile("" :: "r"(&arena)); } while (0)

/* The weight of a task at nice 0: virtual time is real time at it. */
#define NICE_0_WEIGHT	1024ULL
#define WEIGHT_IDLEPRIO	3ULL

#define SCHED_IDLE	5
#define MAX_RT_PRIO	100
#ifndef U32_MAX
#define U32_MAX		((u32)~0U)
#endif

/*
 * The tunables, one for each option of the loader, a time in microseconds
 * as _ns.
 */
const volatile u64 slice_ns = 1600ULL * NSEC_PER_USEC;
const volatile u64 lag_bound_ns = 10ULL * NSEC_PER_MSEC;
const volatile u64 min_granularity_ns = 100ULL * NSEC_PER_USEC;
const volatile u64 vtime_borrowing_ns = 20ULL * NSEC_PER_MSEC;
/*
 * How long a task may run on CPUs of a worse tier before it swaps places
 * with one on a CPU of the best tier, see rotate_due(); 0 for never.
 */
const volatile u64 rotate_ns;
const volatile bool no_asym_packing;
const volatile bool no_preempt;
const volatile bool no_eligibility;
const volatile bool no_vlag;
const volatile bool no_vtime_borrowing;

/*
 * Whether the kernel finds a task by its scx tid, the loader set
 * SCX_OPS_TID_TO_TASK: a lookup that takes no reference. Without it a task
 * is found by its pid, which does.
 */
const volatile bool tid_lookup;

/*
 * Count for the statistics: the loader sets it with --stats or --monitor. It
 * is a constant once the scheduler is loaded, so without them the counting
 * is not in the program at all.
 */
const volatile bool stats_enabled;

/*
 * The topology, from the loader. The CPUs of each LLC, node and core are
 * listed in @llc_cpus, @node_cpus and @core_cpus, from the base of the
 * domain for its length.
 */
const volatile bool smt_enabled;
const volatile bool primary_all = true;
const volatile bool primary_cpus[MAX_CPUS];
const volatile u32 nr_cpus = 1;
const volatile s32 cpu_llc[MAX_CPUS];
const volatile s32 cpu_node[MAX_CPUS];
const volatile s32 cpu_core[MAX_CPUS];
const volatile u32 llc_base[MAX_CPUS];
const volatile u32 llc_len[MAX_CPUS];
const volatile u32 node_base[MAX_CPUS];
const volatile u32 node_len[MAX_CPUS];
const volatile u32 core_base[MAX_CPUS];
const volatile u32 core_len[MAX_CPUS];
const volatile u16 llc_cpus[MAX_CPUS];
const volatile u16 node_cpus[MAX_CPUS];
const volatile u16 core_cpus[MAX_CPUS];
/* The bit of each CPU in the queued mask, see queued_mask. */
const volatile u32 cpu_queued_bit[MAX_CPUS];

/*
 * The CPUs' ranks, as the loader set them between load and attach: the lower
 * the tier, the more a task is better off on the CPU. They come from the
 * kernel's packing priorities where it ranks the CPUs, SD_ASYM_PACKING, else
 * from the CPUs' capacities where those differ, as on a machine with big and
 * little cores. @llc_place_tier is the best tier of each LLC. @cpus_ranked
 * says whether the CPUs rank at all.
 */
u32 place_tier[MAX_CPUS];
u32 llc_place_tier[MAX_CPUS];
u32 nr_place_tiers;
bool cpus_ranked;

/* The most packing tiers the ranked pick tells apart. */
#define MAX_TIERS	8

/*
 * What the scheduler keeps per CPU, in the arena.
 */
struct cpu_ctx {
	/* The CPU's queue. */
	struct scx_edq edq;
	/*
	 * The CPU's virtual clock, on a cache line of its own: the queue's
	 * lock is written by every CPU that steals from it or queues on it.
	 */
	u64 clock __attribute__((aligned(64)));
	/*
	 * When the clock was last brought up to date, and whether a task
	 * has been running here since, see advance().
	 */
	u64 clock_at;
	/* The weights of the runnable tasks whose home this is. */
	u64 load;
	/*
	 * The request and the virtual deadline of the task running here:
	 * what a waking task has to beat to take the CPU.
	 */
	u64 running_request;
	u64 running_deadline;
	/* From when the task running here may be preempted. */
	u64 preempt_after;
	bool busy;
	/* The task running here asks for a whole slice, see long_running(). */
	bool long_run;
	/*
	 * A task is queued here to take the CPU at the end of the running
	 * task's slice, see rotation_target().
	 */
	u64 rotate_pending;
	/*
	 * Since when the task running here has run on CPUs of the best tier
	 * without sleeping, 0 for none: when it may swap places with a task
	 * on a worse CPU, see rotation_target().
	 */
	u64 running_upper_at;
	/* Where a steal of this CPU's is in the queue it scans, see steal_from(). */
	struct scx_edq_cursor cursor;
} __attribute__((aligned(64)));

typedef struct cpu_ctx __arena cpu_ctx_t;

static cpu_ctx_t *cpu_ctxs;

/*
 * Custody of a queued task: whether its node is in an EDQ, being moved to a
 * local DSQ by a CPU, or neither.
 */
enum task_state {
	TASK_NONE,
	TASK_ENQUEUED,
	TASK_DISPATCHING,
};

/*
 * What the scheduler keeps per task, in the arena. The EDQ node comes first,
 * so that a node popped from a queue is the task's context.
 */
struct task_ctx {
	struct scx_edq_task node;
	/* The task's scx tid or pid, for the CPU that pops its node. */
	u64 id;
	/* The CPU whose queue the node is in, see enum task_state. */
	s32 queued_on;
	/*
	 * The affinity of the task when it was queued: whether only its CPU
	 * can run it, or every CPU can. A steal decides on these without
	 * looking the task up.
	 */
	bool pinned;
	bool all_cpus;
	u64 state;
	/* What the task is dispatched with once popped. */
	u64 slice;
	u64 enq_flags;
	/* The task's virtual time, in the clock of its home CPU. */
	u64 vtime;
	/*
	 * The CPU whose clock @vtime is in, and whose load counts the task
	 * while it is runnable.
	 */
	s32 home;
	/*
	 * The idle CPU ops.tick() found the task better off on, plus 1, for
	 * its next enqueue to move it to; 0 for none.
	 */
	s32 target;
	/* The weight the home's load counts the task with, 0 while not runnable. */
	u64 counted;
	/*
	 * The task's lag when it stopped being runnable, how far behind its
	 * home's clock it was, negative if ahead: where it is put back when
	 * it is runnable again.
	 */
	u64 vlag;
	/* When the task last got a CPU. */
	u64 started_at;
	/*
	 * What the task has run since it last slept, and the average of that
	 * over its past sleeps: how long it runs at a time.
	 */
	u64 burst;
	u64 burst_avg;
	/*
	 * Since when the task has run on CPUs of a worse tier than the best
	 * of their LLC, 0 if it is on one of the best: when it is due to
	 * swap places with a task there, see rotate_due().
	 */
	u64 lower_at;
	/*
	 * Since when the task has run on CPUs of the best tier of their LLC
	 * without sleeping, 0 if it is on a worse one or slept since.
	 */
	u64 upper_at;
	/* The CPU of the best tier it swaps onto, plus 1; 0 for none. */
	s32 rotate_to;
	/* It is queued to swap onto a better CPU: worse ones leave it. */
	bool rotating;
};

typedef struct task_ctx __arena task_ctx_t;

static struct scx_allocator task_ctx_allocator;

struct task_ctx_ref {
	task_ctx_t *tctx;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx_ref);
} task_ctx_stor SEC(".maps");

/*
 * The cpumasks of the LLCs and nodes, for the kernel's idle CPU picks, and
 * a scratch mask per CPU for a pick restricted by a task's affinity.
 */
struct mask_slot {
	struct bpf_cpumask __kptr *mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct mask_slot);
	__uint(max_entries, 1);
} primary_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct mask_slot);
	__uint(max_entries, MAX_CPUS);
} llc_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct mask_slot);
	__uint(max_entries, MAX_CPUS);
} node_masks SEC(".maps");

/* The CPUs of each packing tier of each LLC, at LLC * MAX_TIERS + tier. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct mask_slot);
	__uint(max_entries, MAX_CPUS * MAX_TIERS);
} tier_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct mask_slot);
	__uint(max_entries, 1);
} scratch_masks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct counters);
	__uint(max_entries, 1);
} counters_stor SEC(".maps");

/*
 * One bit per CPU whose queue holds at least one task, so that a CPU looking
 * for work to steal looks at the queues worth a look only. It is a hint: a
 * bit left set is cleared by the first CPU that finds the queue empty.
 *
 * The bits change whenever a queue fills or empties, and every change costs
 * a cache miss to the CPUs that read the line. So the bits of each LLC begin
 * on a cache line of their own, which nothing else shares, where the loader
 * finds lines enough for that.
 */
static u64 queued_mask[QUEUED_WORDS] __attribute__((aligned(64)));

/*
 * Whether each LLC may have a core idle as a whole: set when a core goes
 * idle, cleared by a search that finds none, see pick_idle(). Away from the
 * read-mostly globals, as the queued mask is.
 */
static u8 llc_idle_cores[MAX_CPUS] __attribute__((aligned(64)));

/*
 * How many CPUs run a task that asks for a whole slice, one that does not
 * sleep. The search for a CPU to take has something to find only when one
 * does, and reads this first, see preempt_target(). Only a CPU that runs
 * such a task writes it, when the task starts and when it stops. It has a
 * cache line of its own, as the queued mask does.
 */
static struct {
	u64 nr;
} __attribute__((aligned(64))) long_line;
#define nr_long (long_line.nr)

/* fair.c's sched_prio_to_weight[]. */
static const u32 prio_to_weight[40] = {
	88761, 71755, 56483, 46273, 36291,
	29154, 23254, 18705, 14949, 11916,
	9548, 7620, 6100, 4904, 3906,
	3121, 2501, 1991, 1586, 1277,
	1024, 820, 655, 526, 423,
	335, 272, 215, 172, 137,
	110, 87, 70, 56, 45,
	36, 29, 23, 18, 15,
};

#define COUNT(field) do {						\
	if (stats_enabled) {						\
		u32 __key = 0;						\
		struct counters *__c =					\
			bpf_map_lookup_elem(&counters_stor, &__key);	\
		if (__c)						\
			__c->field++;					\
	}								\
} while (0)

static __always_inline bool cpu_valid(s32 cpu)
{
	return cpu >= 0 && (u32)cpu < nr_cpus;
}

/*
 * The context of @cpu. The index is masked, not only compared: the verifier
 * loses the bounds of a compared index that the compiler spills and
 * reloads.
 */
static __always_inline cpu_ctx_t *cpu_ctx(s32 cpu)
{
	TOUCH_ARENA();
	if (!cpu_valid(cpu) || !cpu_ctxs)
		return NULL;
	return &cpu_ctxs[(u32)cpu & (MAX_CPUS - 1)];
}

static __always_inline u32 idx(s32 v)
{
	return (u32)v & (MAX_CPUS - 1);
}

/*
 * The context of a task. ops.enable() caches its address in the task's
 * dsq_vtime, which no DSQ of the scheduler orders by, and the kernel clears
 * it before ops.exit_task(). Task storage covers the windows before enable
 * and after disable.
 */
static __always_inline task_ctx_t *try_lookup_task_ctx(const struct task_struct *p)
{
	struct task_ctx_ref *ref;
	u64 ptr;

	TOUCH_ARENA();
	ptr = p->scx.dsq_vtime;
	if (likely(ptr))
		return (task_ctx_t *)ptr;
	ref = bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
	return ref ? ref->tctx : NULL;
}

/*
 * The id a task is found by, see find_task(): its scx tid where the kernel
 * looks tasks up by it, its pid otherwise.
 */
static u64 task_id(const struct task_struct *p)
{
	if (tid_lookup && bpf_core_field_exists(p->scx.tid))
		return p->scx.tid;
	return p->pid;
}

/*
 * The task of @id, which put_task() lets go of. With the tid the pointer
 * holds for the RCU read section the callback runs in, and takes no
 * reference: a pid lookup takes one, two atomics on the task.
 */
static struct task_struct *find_task(u64 id)
{
	if (tid_lookup && bpf_ksym_exists(scx_bpf_tid_to_task))
		return scx_bpf_tid_to_task(id);
	return bpf_task_from_pid(id);
}

static void put_task(struct task_struct *p)
{
	if (!tid_lookup || !bpf_ksym_exists(scx_bpf_tid_to_task))
		bpf_task_release(p);
}

/* The task's weight, as fair.c's: sched_prio_to_weight[] by static priority. */
static u64 task_weight(const struct task_struct *p)
{
	s32 prio;

	if (p->policy == SCHED_IDLE)
		return WEIGHT_IDLEPRIO;
	prio = p->static_prio - MAX_RT_PRIO;
	if (prio < 0 || prio >= 40)
		return NICE_0_WEIGHT;
	return prio_to_weight[prio];
}

/* @value of service at nice 0, in the task's virtual time. */
static u64 scale_inverse(const struct task_struct *p, u64 value)
{
	u64 weight = task_weight(p);

	return weight ? value * NICE_0_WEIGHT / weight : value;
}

static bool is_pinned(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static bool is_restricted(const struct task_struct *p)
{
	return p->nr_cpus_allowed < nr_cpus;
}

static const struct cpumask *primary_mask(void)
{
	u32 key = 0;
	struct mask_slot *slot = bpf_map_lookup_elem(&primary_masks, &key);

	return slot ? (const struct cpumask *)slot->mask : NULL;
}

/* Affinity and migration constraints take precedence over the primary domain. */
static bool uses_primary(const struct task_struct *p)
{
	const struct cpumask *mask;

	if (primary_all || is_pinned(p))
		return false;
	mask = primary_mask();
	return mask && bpf_cpumask_intersects(p->cpus_ptr, mask);
}

/*
 * May @p run on @cpu, under its affinity and the primary domain? A task
 * allowed everywhere needs no look at its mask. One whose migration is
 * disabled may run on its own CPU only, whatever its mask says.
 */
static bool allowed(const struct task_struct *p, s32 cpu)
{
	if (is_migration_disabled(p))
		return cpu == scx_bpf_task_cpu(p);
	if (is_restricted(p) && !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return false;
	return primary_all || primary_cpus[idx(cpu)] || !uses_primary(p);
}

/* Pick a queue home without claiming an idle CPU: primary CPUs may be busy. */
static s32 queue_home(const struct task_struct *p, s32 prev)
{
	const struct cpumask *mask;
	s32 cpu;

	if (primary_all || allowed(p, prev))
		return prev;
	mask = primary_mask();
	if (mask && uses_primary(p)) {
		cpu = bpf_cpumask_any_and_distribute(p->cpus_ptr, mask);
		if (cpu_valid(cpu))
			return cpu;
	}
	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
	if (cpu_valid(cpu))
		return cpu;
	return prev;
}

/*
 * The shortest request a task is given: tasks that run for less at a time
 * are all served alike, and none of them preempts another.
 */
static u64 min_request(void)
{
	return slice_ns / 8;
}

/*
 * What the task asks for at a time: how long it runs between two sleeps, by
 * its average over the past ones and by what it has run since the last, no
 * less than the shortest request and no more than a slice.
 */
static u64 task_request(const task_ctx_t *tctx)
{
	u64 burst = MAX(tctx->burst, tctx->burst_avg);

	return CLAMP(burst, min_request(), slice_ns);
}

/*
 * Make @to the task's home, keeping its lag: its virtual time is as far from
 * the new clock as it was from the old, and its weight moves to the new
 * load.
 */
static void rehome(task_ctx_t *tctx, s32 to)
{
	cpu_ctx_t *old, *new;
	u64 lag, weight;

	if (tctx->home == to)
		return;
	old = cpu_ctx(tctx->home);
	new = cpu_ctx(to);
	if (!old || !new)
		return;
	lag = old->clock - tctx->vtime;
	tctx->vtime = new->clock - lag;
	weight = tctx->counted;
	if (weight) {
		__sync_fetch_and_sub(&old->load, weight);
		__sync_fetch_and_add(&new->load, weight);
	}
	tctx->home = to;
}

/*
 * Topology.
 */
static s32 llc_of(s32 cpu)
{
	return cpu_valid(cpu) ? cpu_llc[idx(cpu)] : 0;
}

static s32 node_of(s32 cpu)
{
	return cpu_valid(cpu) ? cpu_node[idx(cpu)] : 0;
}

static u32 tier_of(s32 cpu)
{
	return cpu_valid(cpu) ? place_tier[idx(cpu)] : 0;
}

static u32 llc_tier_of(s32 cpu)
{
	return llc_place_tier[idx(llc_of(cpu))];
}

/* Does the node of @cpu hold CPUs its LLC does not? */
static bool node_widens(s32 cpu)
{
	return llc_len[idx(llc_of(cpu))] != node_len[idx(node_of(cpu))];
}

/* Does the machine hold CPUs the node of @cpu does not? */
static bool all_widens(s32 cpu)
{
	return node_len[idx(node_of(cpu))] != nr_cpus;
}

static const struct cpumask *llc_mask(s32 cpu)
{
	u32 key = idx(llc_of(cpu));
	struct mask_slot *slot = bpf_map_lookup_elem(&llc_masks, &key);

	return slot ? cast_mask(slot->mask) : NULL;
}

static const struct cpumask *node_mask(s32 cpu)
{
	u32 key = idx(node_of(cpu));
	struct mask_slot *slot = bpf_map_lookup_elem(&node_masks, &key);

	return slot ? cast_mask(slot->mask) : NULL;
}

/*
 * Does placement follow a ranking of the CPUs? There is one where the kernel
 * ranks them, SD_ASYM_PACKING, as on a hybrid x86 machine with performance
 * and efficiency cores, or where their capacities differ, as on a machine
 * with big and little cores.
 */
static bool packing(void)
{
	return !no_asym_packing && cpus_ranked;
}

/*
 * Idle CPUs.
 *
 * A pick claims the CPU it returns: it clears its idle state, so that no
 * other CPU picks it too.
 */
static bool claim(s32 cpu)
{
	return scx_bpf_test_and_clear_cpu_idle(cpu);
}

/* Is the core of @cpu idle as a whole? */
static bool core_idle(s32 cpu)
{
	const struct cpumask *smt;
	bool ret;

	if (!smt_enabled)
		return true;
	smt = scx_bpf_get_idle_smtmask();
	ret = bpf_cpumask_test_cpu(cpu, smt);
	scx_bpf_put_idle_cpumask(smt);

	return ret;
}

/* Claim an idle CPU of @scope that @p may run on, of a whole idle core if @whole. */
static s32 pick_in(const struct task_struct *p, const struct cpumask *scope,
		   bool whole)
{
	u64 flags = whole ? SCX_PICK_IDLE_CORE : 0;
	struct mask_slot *slot;
	struct bpf_cpumask *tmp;
	u32 key = 0;
	bool primary = uses_primary(p);

	if (!scope)
		return -EBUSY;
	if (!is_restricted(p) && !is_pinned(p) && !primary)
		return scx_bpf_pick_idle_cpu(scope, flags);

	slot = bpf_map_lookup_elem(&scratch_masks, &key);
	if (!slot)
		return -EBUSY;
	tmp = slot->mask;
	if (!tmp)
		return -EBUSY;
	bpf_cpumask_and(tmp, scope, p->cpus_ptr);
	if (primary) {
		const struct cpumask *mask = primary_mask();

		if (!mask)
			return -EBUSY;
		bpf_cpumask_and(tmp, cast_mask(tmp), mask);
	}

	return scx_bpf_pick_idle_cpu(cast_mask(tmp), flags);
}

/*
 * Claim an idle CPU of a whole idle core if @whole, any idle CPU otherwise,
 * for @p in the LLC of @prev: @prev itself if it will do, where the task's
 * cache is, then its SMT siblings, then the rest of the LLC.
 */
static s32 pick_near(const struct task_struct *p, s32 prev, bool whole)
{
	u32 i, base, len;

	if (allowed(p, prev) && (!whole || core_idle(prev)) && claim(prev))
		return prev;

	if (!whole && smt_enabled && cpu_valid(prev)) {
		base = core_base[idx(cpu_core[idx(prev)])];
		len = core_len[idx(cpu_core[idx(prev)])];
		bpf_for(i, 0, len) {
			s32 cpu = core_cpus[idx(base + i)];

			if (cpu != prev && allowed(p, cpu) && claim(cpu))
				return cpu;
		}
	}

	return pick_in(p, llc_mask(prev), whole);
}

/*
 * Is @cpu an idle CPU that @p may run on, with its core idle as a whole if
 * @whole? @idle and @smt are the kernel's idle masks.
 */
static bool fits(const struct task_struct *p, s32 cpu, bool whole,
		 const struct cpumask *idle, const struct cpumask *smt)
{
	return bpf_cpumask_test_cpu(cpu, idle) &&
	       (!whole || bpf_cpumask_test_cpu(cpu, smt)) && allowed(p, cpu);
}

static const struct cpumask *tier_mask(s32 cpu, u32 tier)
{
	u32 key = idx(llc_of(cpu)) * MAX_TIERS + (tier & (MAX_TIERS - 1));
	struct mask_slot *slot = bpf_map_lookup_elem(&tier_masks, &key);

	return slot ? cast_mask(slot->mask) : NULL;
}

/*
 * pick_near() where the CPUs rank: claim an idle CPU of the LLC of @prev of
 * the tier the kernel prefers most, one tier at a time, @prev first within
 * its own tier, since that is where the task's cache is. A task that sleeps
 * often takes @prev before any tier when it is idle.
 */
static __noinline s32 pick_ranked(const struct task_struct *p, s32 prev, bool whole)
{
	u32 t, own = tier_of(prev), nr = CLAMP(nr_place_tiers, 1, MAX_TIERS);
	task_ctx_t *tctx = try_lookup_task_ctx(p);
	s32 cpu;

	/*
	 * A task that sleeps often fits any tier: its last CPU, if idle, has
	 * just gone idle and wakes up at once, where one idle for longer may
	 * be in a deep state.
	 */
	if (tctx && task_request(tctx) < slice_ns && allowed(p, prev) &&
	    (!whole || core_idle(prev)) && claim(prev))
		return prev;

	bpf_for(t, 0, nr) {
		if (t == own && allowed(p, prev) &&
		    (!whole || core_idle(prev)) && claim(prev))
			return prev;
		cpu = pick_in(p, tier_mask(prev, t), whole);
		if (cpu >= 0)
			return cpu;
	}

	return -EBUSY;
}

/* Is any CPU of the LLC of @cpu idle? */
static bool llc_has_idle(s32 cpu)
{
	const struct cpumask *llc = llc_mask(cpu), *idle;
	bool ret;

	if (!llc)
		return true;
	idle = scx_bpf_get_idle_cpumask();
	ret = bpf_cpumask_intersects(llc, idle);
	scx_bpf_put_idle_cpumask(idle);

	return ret;
}

static bool llc_has_idle_cores(s32 cpu)
{
	return READ_ONCE(llc_idle_cores[idx(llc_of(cpu))]);
}

static void clear_idle_cores(s32 cpu)
{
	u32 llc = idx(llc_of(cpu));

	if (READ_ONCE(llc_idle_cores[llc]))
		WRITE_ONCE(llc_idle_cores[llc], 0);
}

/*
 * Claim an idle CPU for a waking task, starting in the LLC of @prev. A core
 * whose SMT siblings are all idle comes first, since a task there shares the core
 * with nobody. Only with no such core left in the LLC does the task take any
 * idle CPU, and shares a core. Either way @prev is tried first.
 *
 * Where the CPUs rank, the same two searches take the CPU the kernel prefers
 * most rather than the nearest: work packs on the fast cores and spills to
 * the others as those fill, asymmetric packing.
 *
 * The search for a whole idle core is made only while the LLC's hint says it
 * has one, and a search that finds none clears the hint: a busy machine,
 * which has none, then makes one search per wakeup, not two.
 */
static s32 pick_idle(const struct task_struct *p, s32 prev)
{
	s32 cpu;

	/*
	 * Under load nothing is idle, and one look at the LLC says so: the
	 * ranked search would otherwise scan the idle masks once per tier.
	 */
	if (!llc_has_idle(prev))
		return -EBUSY;
	if (smt_enabled && llc_has_idle_cores(prev)) {
		cpu = packing() ? pick_ranked(p, prev, true) :
				  pick_near(p, prev, true);
		if (cpu >= 0)
			return cpu;
		clear_idle_cores(prev);
	}
	if (packing())
		return pick_ranked(p, prev, false);

	return pick_near(p, prev, false);
}

/*
 * Claim an idle CPU for @p outside the LLC of @anchor, the closest there is:
 * in its node, then anywhere. Used for forks and CPUs that are to come and
 * take a task from the queue of @anchor, which the steal reaches that far for.
 */
static s32 pick_beyond(const struct task_struct *p, s32 anchor)
{
	s32 cpu;

	if (node_widens(anchor)) {
		cpu = pick_in(p, node_mask(anchor), false);
		if (cpu >= 0)
			return cpu;
	}
	if (all_widens(anchor))
		return pick_in(p, p->cpus_ptr, false);

	return -EBUSY;
}

/*
 * Claim an idle CPU that is to come and take @p from the queue of @anchor:
 * any of the LLC, the one the kernel prefers where the CPUs rank, or the
 * closest outside it.
 */
static s32 pick_stealer(const struct task_struct *p, s32 anchor)
{
	s32 cpu = -EBUSY;

	if (packing()) {
		/*
		 * A whole idle core of a lower rank is worth more than a
		 * thread beside a busy one of a higher rank, as for a wakeup.
		 */
		if (smt_enabled && llc_has_idle_cores(anchor)) {
			cpu = pick_ranked(p, anchor, true);
			if (cpu < 0)
				clear_idle_cores(anchor);
		}
		if (cpu < 0)
			cpu = pick_ranked(p, anchor, false);
	} else {
		cpu = pick_in(p, llc_mask(anchor), false);
	}
	if (cpu >= 0)
		return cpu;

	return pick_beyond(p, anchor);
}

/*
 * Queues.
 */
static u32 queued_word(s32 cpu)
{
	return (cpu_queued_bit[idx(cpu)] / 64) & (QUEUED_WORDS - 1);
}

static u64 queued_bit(s32 cpu)
{
	return 1ULL << (cpu_queued_bit[idx(cpu)] & 63);
}

static void queued_set(s32 cpu)
{
	u64 bit = queued_bit(cpu);
	u32 word = queued_word(cpu);

	if (!(READ_ONCE(queued_mask[word]) & bit))
		__sync_fetch_and_or(&queued_mask[word], bit);
}

static bool queued_test(s32 cpu)
{
	return READ_ONCE(queued_mask[queued_word(cpu)]) & queued_bit(cpu);
}

/*
 * Clear the queued bit of @cpu if its queue is empty, looking again after
 * the clear for a task queued in the meantime.
 */
static void queued_check(s32 cpu)
{
	cpu_ctx_t *cctx = cpu_ctx(cpu);
	u64 bit = queued_bit(cpu);
	u32 word = queued_word(cpu);

	if (!cctx || scx_edq_nr_queued(&cctx->edq) || !queued_test(cpu))
		return;
	__sync_fetch_and_and(&queued_mask[word], ~bit);
	if (scx_edq_nr_queued(&cctx->edq))
		queued_set(cpu);
}

/*
 * Move the task of a popped or held node to the local DSQ of @dst, the CPU
 * ops.dispatch() runs for. False if the task is no longer the scheduler's to
 * move, because the kernel took it back with ops.dequeue() in the meantime
 * or it is gone, or if it went to the CPU it is on instead.
 *
 * A task that cannot run on @dst, one whose migration is disabled on
 * another CPU, or whose affinity changed, is still in the scheduler's
 * custody: nothing would enqueue it again if it were let go. It goes to the
 * local DSQ of the CPU it is on.
 *
 * The kernel ignores a dispatch of a task that was dequeued and queued
 * again since, so the custody state only has to keep this from dispatching
 * a task whose node is queued again.
 */
static __noinline bool dispatch_popped(task_ctx_t *tctx, s32 dst)
{
	struct task_struct *p;
	bool moved = false;

	TOUCH_ARENA();
	if (!tctx)
		return false;
	if (__sync_val_compare_and_swap(&tctx->state, TASK_ENQUEUED,
					TASK_DISPATCHING) != TASK_ENQUEUED)
		goto drop;

	p = find_task(tctx->id);
	if (!p)
		goto drop;
	if (!(p->scx.flags & SCX_TASK_QUEUED) ||
	    READ_ONCE(tctx->state) != TASK_DISPATCHING)
		goto release;
	if (!allowed(p, dst) ||
	    (is_migration_disabled(p) && scx_bpf_task_cpu(p) != dst)) {
		s32 home = queue_home(p, scx_bpf_task_cpu(p));

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | home,
				   tctx->slice, tctx->enq_flags);
		if (home != scx_bpf_task_cpu(p))
			scx_bpf_kick_cpu(home, SCX_KICK_IDLE);
		goto release;
	}

	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, tctx->slice, tctx->enq_flags);
	moved = true;
release:
	put_task(p);
drop:
	scx_edq_task_drop(&tctx->node);
	return moved;
}

/*
 * Queue @p on the queue of @cpu with @deadline, eligible from @vtime. False
 * if it went to the local DSQ of @cpu instead.
 */
static bool queue_insert(struct task_struct *p, task_ctx_t *tctx, s32 cpu,
			 u64 slice, u64 deadline, u64 vtime, u64 enq_flags)
{
	cpu_ctx_t *cctx = cpu_ctx(cpu);
	int ret;

	if (!cctx)
		goto local;
	/*
	 * A held node was popped by an older enqueue that a property change
	 * ended, and its CPU has not let go of it yet. The one node cannot
	 * stand for both: dispatch this one directly, and the stale pop fails
	 * its state check.
	 */
	if (READ_ONCE(tctx->node.holdcnt))
		goto local;

	tctx->slice = slice;
	tctx->enq_flags = enq_flags;
	tctx->queued_on = cpu;
	tctx->pinned = is_pinned(p);
	tctx->all_cpus = !is_restricted(p);
	/* Publish custody before the node becomes visible to another CPU's pop. */
	WRITE_ONCE(tctx->state, TASK_ENQUEUED);
	ret = scx_edq_insert(&cctx->edq, &tctx->node, deadline, vtime, slice);
	if (ret) {
		__sync_val_compare_and_swap(&tctx->state, TASK_ENQUEUED, TASK_NONE);
		if (ret != -ECANCELED)
			scx_bpf_error("EDQ insert failed for pid %d: %d", p->pid, ret);
		goto local;
	}
	/* Only its CPU can run a pinned task: no other needs to look. */
	if (!tctx->pinned)
		queued_set(cpu);
	return true;

local:
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice, enq_flags);
	return false;
}

/*
 * Move the eligible task with the earliest deadline from the queue of @cpu
 * to its local DSQ, or the one with the earliest deadline of all with none
 * eligible or eligibility not asked for. A pop whose task the kernel took
 * back in the meantime has still removed its node, so pop again.
 */
static __noinline bool move_own(s32 cpu, u64 clock)
{
	cpu_ctx_t *cctx = cpu_ctx(cpu);
	task_ctx_t *tctx;

	if (!cctx)
		return false;
	while (can_loop) {
		if (no_eligibility)
			tctx = (task_ctx_t *)scx_edq_pop(&cctx->edq, true);
		else
			tctx = (task_ctx_t *)scx_edq_pop_first_eligible_or_first(
					&cctx->edq, clock, true);
		if (!tctx)
			return false;
		if (dispatch_popped(tctx, cpu))
			return true;
	}
	return false;
}

/* How many queued tasks a steal looks at, from the head of the queue. */
#define STEAL_SCAN	8

/*
 * Take a task for @dst from the queue of @src: the first of the few at its
 * head that may run on @dst. A queue another CPU is working on is passed
 * over. A queue found empty has its queued bit cleared.
 */
static __noinline bool steal_from(s32 src, s32 dst)
{
	cpu_ctx_t *cctx = cpu_ctx(src), *here = cpu_ctx(dst);
	struct task_struct *p;
	task_ctx_t *tctx;
	bool busy = false;
	u64 node;
	u32 n;
	int ret;

	if (!cctx || !here)
		return false;
	if (!scx_edq_nr_queued(&cctx->edq)) {
		queued_check(src);
		return false;
	}
	scx_edq_cursor_reset(&here->cursor);
	bpf_for(n, 0, STEAL_SCAN) {
		bool ok;

		ret = scx_edq_try_peek_next_hold(&cctx->edq, &here->cursor, &node);
		if (ret) {
			busy = ret == -EBUSY;
			break;
		}
		if (!node)
			break;
		tctx = (task_ctx_t *)node;
		if (READ_ONCE(tctx->state) != TASK_ENQUEUED ||
		    (tctx->rotating && tier_of(dst) > tier_of(src))) {
			scx_edq_task_drop(&tctx->node);
			continue;
		}

		/*
		 * The task's affinity as it was queued: a change since makes
		 * the kernel dequeue it, and dispatch_popped() checks again.
		 */
		if (tctx->pinned) {
			ok = false;
		} else if (tctx->all_cpus) {
			ok = primary_all || primary_cpus[idx(dst)];
		} else {
			p = find_task(tctx->id);
			ok = p && allowed(p, dst);
			if (p)
				put_task(p);
		}
		if (!ok) {
			scx_edq_task_drop(&tctx->node);
			continue;
		}

		/* Claim the exact node the scan looked at. -EINVAL: it is gone. */
		ret = scx_edq_try_remove(&cctx->edq, &tctx->node);
		if (ret) {
			scx_edq_task_drop(&tctx->node);
			if (ret == -EINVAL)
				continue;
			busy = true;
			break;
		}
		if (dispatch_popped(tctx, dst))
			return true;
	}
	if (!busy)
		queued_check(src);

	return false;
}

/*
 * Take a task for @cpu from another queue of the domain listed in @cpus from
 * @base for @len. The queued bits name the queues worth a look.
 */
static bool steal_in(s32 cpu, const volatile u16 *cpus, u32 base, u32 len)
{
	u32 i;

	bpf_for(i, 0, len) {
		s32 peer = cpus[idx(base + i)];

		if (peer == cpu || !queued_test(peer))
			continue;
		if (steal_from(peer, cpu))
			return true;
	}
	return false;
}

/*
 * The pull balancer, from ops.dispatch() when the queue of @cpu is empty:
 * take a task for @cpu from another queue, the closest that has one it may
 * run: in its LLC, then in its node, then anywhere.
 */
static __noinline bool steal(s32 cpu)
{
	s32 llc, node;

	if (!cpu_valid(cpu))
		return false;
	llc = llc_of(cpu);
	node = node_of(cpu);

	if (steal_in(cpu, llc_cpus, llc_base[idx(llc)], llc_len[idx(llc)]))
		return true;
	if (node_widens(cpu) &&
	    steal_in(cpu, node_cpus, node_base[idx(node)], node_len[idx(node)]))
		return true;
	if (all_widens(cpu)) {
		u32 i;

		bpf_for(i, 0, nr_cpus) {
			s32 peer = (cpu + 1 + i) % nr_cpus;

			if (peer == cpu || !queued_test(peer))
				continue;
			if (steal_from(peer, cpu))
				return true;
		}
	}
	return false;
}

/*
 * The active balancer, at the tick.
 *
 * A task that does not sleep is never placed again once it runs: no wakeup
 * goes through ops.select_cpu() for it, and alone on its CPU it keeps the
 * CPU at the end of every slice, out of the reach of a steal. Started beside
 * a busy SMT sibling, or on a slow core while the fast ones were busy, it
 * would stay there with better CPUs idle.
 *
 * So the tick of the CPU it runs on looks for a better idle CPU in the LLC,
 * ends the slice when it finds one, and the enqueue that follows moves the
 * task there, as fair.c's active balance does for SMT and asymmetric
 * packing. Only the task's own CPU moves it, and the claim of the idle CPU
 * at the enqueue keeps two from going to the same one.
 */

/* Are the SMT siblings of @cpu all idle? */
static bool siblings_idle(s32 cpu, const struct cpumask *idle)
{
	u32 i, base, len;

	if (!cpu_valid(cpu))
		return true;
	base = core_base[idx(cpu_core[idx(cpu)])];
	len = core_len[idx(cpu_core[idx(cpu)])];
	bpf_for(i, 0, len) {
		s32 sib = core_cpus[idx(base + i)];

		if (sib != cpu && !bpf_cpumask_test_cpu(sib, idle))
			return false;
	}
	return true;
}

/*
 * An idle CPU of the LLC of @src that the running @p is better off on: a
 * whole idle core while a sibling of @src is busy, or one of a better packing
 * tier where the CPUs rank, a whole core on SMT, so that a move never lands
 * beside a busy sibling. The best tier there is, the first of it.
 */
static __noinline s32 balance_target(const struct task_struct *p, s32 src)
{
	const struct cpumask *idle, *smt;
	bool shared, pack = packing();
	u32 i, base, len, best, rank;
	s32 found = -1;

	if (!cpu_valid(src))
		return -1;

	idle = scx_bpf_get_idle_cpumask();
	smt = scx_bpf_get_idle_smtmask();

	shared = smt_enabled && !siblings_idle(src, idle) && llc_has_idle_cores(src);
	best = llc_tier_of(src);
	if (!shared && !(pack && tier_of(src) > best))
		goto out;

	/* Any whole idle core is better than a shared one, else only a better tier is. */
	rank = shared ? U32_MAX : tier_of(src);
	base = llc_base[idx(llc_of(src))];
	len = llc_len[idx(llc_of(src))];
	bpf_for(i, 0, len) {
		s32 cpu = llc_cpus[idx(base + i)];
		u32 tier;

		if (rank <= best)
			break;
		tier = pack ? tier_of(cpu) : best;
		if (tier < rank && fits(p, cpu, smt_enabled, idle, smt)) {
			found = cpu;
			rank = tier;
		}
	}
out:
	scx_bpf_put_idle_cpumask(smt);
	scx_bpf_put_idle_cpumask(idle);

	return found;
}

/* Is no CPU idle? Under load nothing is, and one look says so. */
static bool idle_empty(void)
{
	const struct cpumask *idle = scx_bpf_get_idle_cpumask();
	bool ret = bpf_cpumask_empty(idle);

	scx_bpf_put_idle_cpumask(idle);

	return ret;
}

/*
 * Virtual-time borrowing, which --no-vtime-borrowing turns off.
 *
 * The idea is that of the Borrowed Virtual Time scheduler of Duda and
 * Cheriton, "Borrowed-virtual-time (BVT) scheduling: supporting
 * latency-sensitive threads in a general-purpose scheduler", SOSP '99,
 * applied at wakeup only.
 *
 * A task that used up its share before it slept wakes at the clock or ahead
 * of it, and waits for the tasks that stayed runnable, although it would run
 * for a moment and sleep again. With the credit a waking task is placed at
 * least that far behind the clock instead, which makes it eligible with a
 * deadline ahead of theirs, and it preempts the task that is running. What
 * the task then runs is charged as ever.
 *
 * A waking task is also credited part of the run it interrupts, see
 * advance_wakeup(), which gives tasks that wake often more than their
 * weight's share beside tasks that never sleep, at most twice.
 *
 * And a waking task that found nothing idle is queued where it can take the
 * CPU: on a CPU whose running task asks for more than it does, which is what
 * the preemption test of ops.enqueue() wants, see preempt_target().
 */

/* A task asking for @request starts running on the CPU of @here. */
static void long_running(cpu_ctx_t *here, u64 request)
{
	if (!no_vtime_borrowing && request >= slice_ns && !here->long_run) {
		here->long_run = true;
		__sync_fetch_and_add(&nr_long, 1);
	}
}

/* The task running on the CPU of @here stops. */
static void long_stopping(cpu_ctx_t *here)
{
	if (here->long_run) {
		here->long_run = false;
		__sync_fetch_and_sub(&nr_long, 1);
	}
}

/*
 * Where a waking task goes in its CPU's virtual time, given where its lag
 * puts it and the CPU's clock: at least a credit behind the clock. A task
 * whose own lag carries it that far borrows nothing.
 */
static u64 borrow(const struct task_struct *p, u64 clock, u64 vtime)
{
	u64 borrowed;

	if (no_vtime_borrowing)
		return vtime;
	borrowed = clock - scale_inverse(p, vtime_borrowing_ns);

	return time_before(borrowed, vtime) ? borrowed : vtime;
}

/*
 * Would a task asking for @request take @cpu from what runs there: does that
 * task ask for more, is it past the time it is left alone for, and may @p
 * run there?
 */
static bool wins(const struct task_struct *p, s32 cpu, u64 request, u64 now,
		 bool restricted)
{
	cpu_ctx_t *there = cpu_ctx(cpu);

	return there && there->running_request > request &&
	       !time_before(now, there->preempt_after) &&
	       (!restricted || allowed(p, cpu));
}

/*
 * The CPU a waking task is queued on when no CPU was idle: @prev if the task
 * can take it, where its cache is, or the first CPU of the LLC of @prev that
 * it can take, or @prev after all.
 *
 * The search begins at a different CPU each time, by the clock, so that tasks
 * waking together do not all go for the same CPU. It reads the state of every
 * CPU of the LLC at worst, so it is made only while some CPU runs a task that
 * does not sleep.
 */
static __noinline s32 preempt_target(const struct task_struct *p, s32 prev)
{
	u64 request, now;
	task_ctx_t *tctx;
	u32 i, base, len, start;
	bool restricted;

	if (no_vtime_borrowing || is_pinned(p) || !cpu_valid(prev))
		return prev;
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev;

	request = task_request(tctx);
	now = scx_bpf_now();
	restricted = is_restricted(p) || uses_primary(p);
	if (wins(p, prev, request, now, restricted) || !READ_ONCE(nr_long))
		return prev;

	base = llc_base[idx(llc_of(prev))];
	len = llc_len[idx(llc_of(prev))];
	if (!len)
		return prev;
	start = (now >> 10) % len;
	bpf_for(i, 0, len) {
		u32 j = start + i;
		s32 cpu;

		if (j >= len)
			j -= len;
		cpu = llc_cpus[idx(base + j)];

		if (wins(p, cpu, request, now, restricted)) {
			COUNT(moved);
			return cpu;
		}
	}
	COUNT(missed);

	return prev;
}

/*
 * Bring the clock of the CPU of @here up to @now, with the time since the
 * last update counted at the load and @extra more weight, and return it.
 * While a task runs there the clock advances by the time over the weight of
 * every runnable task there, the running one among them.
 *
 * This is done before every change of the load, as fair.c's update_curr() is
 * before an entity is enqueued or dequeued, so that each stretch of time
 * counts at the load it ran with.
 */
static u64 advance_by(cpu_ctx_t *here, u64 now, u64 extra)
{
	u64 last = here->clock_at, load, delta;

	if (time_before(now, last))
		return here->clock;
	here->clock_at = now;
	if (!here->busy)
		return here->clock;
	load = MAX(here->load + extra, 1);
	delta = (now - last) * NICE_0_WEIGHT / load;
	here->clock += delta;

	return here->clock;
}

static u64 advance(cpu_ctx_t *here, u64 now)
{
	return advance_by(here, now, 0);
}

/*
 * Bring the clock of the CPU of @here up to @now for @p, which wakes there,
 * and return it.
 *
 * A task that wakes on a busy CPU is credited part of the run it interrupts,
 * the other half of virtual-time borrowing (see borrow()): the time since the
 * clock was last brought up to date counts as if the waking task had been
 * runnable for it too. The clock then advances less than the running task's
 * virtual time does, and a task that never sleeps falls behind the tasks that
 * wake beside it. That is what keeps a frame pipeline running beside CPU
 * hogs, whose threads barely sleep and would otherwise get no more than their
 * weight's share.
 *
 * The waking task counts for no more weight than is runnable there already,
 * so the clock advances at least half as fast as it should and every task
 * keeps at least half its share.
 */
static u64 advance_wakeup(cpu_ctx_t *here, const struct task_struct *p, u64 now)
{
	if (no_vtime_borrowing)
		return advance(here, now);

	return advance_by(here, now, MIN(task_weight(p), here->load));
}

/*
 * Charge the task of @tctx for what it ran since it last got the CPU, or
 * since the last charge: its virtual time and its burst advance as they do
 * when it stops, and its home's clock is brought up to date.
 */
static cpu_ctx_t *charge(const struct task_struct *p, task_ctx_t *tctx, u64 now)
{
	u64 ran = now - tctx->started_at;
	cpu_ctx_t *home;

	tctx->started_at = now;
	tctx->vtime += scale_inverse(p, ran);
	tctx->burst += ran;
	home = cpu_ctx(tctx->home);
	if (home)
		advance(home, now);

	return home;
}

/*
 * The deadline of the task ops.dispatch() of @cpu would pick, eligible from
 * @clock unless eligibility is not asked for. False for none.
 */
static bool head_deadline(s32 cpu, u64 clock, u64 *deadline)
{
	cpu_ctx_t *cctx = cpu_ctx(cpu);
	u64 min_slice;
	int ret;

	if (!cctx || !scx_edq_nr_queued(&cctx->edq))
		return false;
	if (!no_eligibility) {
		ret = scx_edq_try_first_eligible_deadline(&cctx->edq, clock,
							  deadline, &min_slice);
		if (ret != -EBUSY)
			return !ret;
	}
	/* Never wait for a CPU that is working on the queue: take the first. */
	return !scx_edq_first_deadline(&cctx->edq, deadline);
}

/*
 * Tier rotation, which --rotate-us enables where the CPUs rank.
 *
 * A task that never sleeps keeps its CPU slice after slice, see
 * keep_running(), and the tick moves it only to an idle CPU, see
 * balance_target(). With more CPU-bound tasks than CPUs of the best tier,
 * none of the best is ever idle: the tasks that started on worse CPUs stay
 * there, and a workload that splits its work evenly among its threads waits
 * for them.
 *
 * So a task that has run on worse CPUs for @rotate_ns swaps places with one
 * that has run on CPUs of the best tier of its LLC for as long without
 * sleeping, see rotation_target(). At the end of its slice its CPU lets it
 * go and it is queued on that CPU, see ops.enqueue(), which hands itself
 * over at the end of the slice of the task running there, see
 * ops.dispatch(). That task, put back in the queue, kicks an idle CPU to
 * come and take it, the one the rotation left: the two have swapped. A
 * rotating task is not taken by a worse CPU, which would undo the swap.
 */

/* Is @p, whose slice has ended on @cpu, due to move to a better CPU? */
static bool rotate_due(const struct task_struct *p, task_ctx_t *tctx, s32 cpu, u64 now)
{
	return rotate_ns && packing() && tctx->lower_at &&
	       tier_of(cpu) > llc_tier_of(cpu) &&
	       !time_before(now, tctx->lower_at + rotate_ns) &&
	       task_request(tctx) >= slice_ns && !is_pinned(p);
}

/*
 * Claim a CPU of the best tier of the LLC of @src that @p may run on and
 * whose task has run on the best tier for @rotate_ns without sleeping, for
 * @p to swap onto. A task that sleeps more often, such as a render thread
 * that waits for every frame, keeps its CPU, and so does one that has just
 * swapped there. The search begins at a different CPU each time, as in
 * preempt_target().
 */
static __noinline s32 rotation_target(const struct task_struct *p, s32 src, u64 now)
{
	u32 i, base, len, start, best;
	cpu_ctx_t *cctx;
	u64 upper_at;

	if (!cpu_valid(src))
		return -1;
	base = llc_base[idx(llc_of(src))];
	len = llc_len[idx(llc_of(src))];
	best = llc_tier_of(src);
	if (!len)
		return -1;
	start = (scx_bpf_now() >> 10) % len;
	bpf_for(i, 0, len) {
		u32 j = start + i;
		s32 cpu;

		if (j >= len)
			j -= len;
		cpu = llc_cpus[idx(base + j)];
		cctx = cpu_ctx(cpu);
		if (!cctx || tier_of(cpu) != best)
			continue;
		upper_at = READ_ONCE(cctx->running_upper_at);
		if (!upper_at || time_before(now, upper_at + rotate_ns) ||
		    READ_ONCE(cctx->rotate_pending) || !allowed(p, cpu))
			continue;
		if (__sync_val_compare_and_swap(&cctx->rotate_pending, 0, 1) == 0)
			return cpu;
	}

	return -1;
}

/*
 * Does @prev, whose slice has ended on @cpu and which is still runnable, keep
 * the CPU for another slice?
 *
 * The kernel calls ops.dispatch() before it puts @prev back through
 * ops.enqueue(), so @prev is in no queue when the pick is made. Taking the
 * head of the queue then hands the CPU over in strict rotation, and a nice 19
 * task got as much of it as a nice 0 one. As pick_eevdf() does with curr,
 * @prev is charged for what it ran and keeps the CPU while it is eligible and
 * nothing eligible queued has an earlier deadline. A task the tick is moving,
 * see balance_target(), goes through its enqueue instead.
 */
static bool keep_running(struct task_struct *prev, s32 cpu)
{
	u64 clock, vtime, request, deadline, head, now;
	task_ctx_t *tctx;
	cpu_ctx_t *home;
	bool keep;

	if (!(prev->scx.flags & SCX_TASK_QUEUED) ||
	    (!primary_all && !allowed(prev, cpu)))
		return false;
	tctx = try_lookup_task_ctx(prev);
	if (!tctx || tctx->target)
		return false;
	now = scx_bpf_now();
	home = charge(prev, tctx, now);
	if (!home)
		return false;

	/* Its turn on a CPU of the best tier, see rotate_due(). */
	if (rotate_due(prev, tctx, cpu, now)) {
		s32 dst = rotation_target(prev, cpu, now);

		if (dst >= 0) {
			tctx->rotate_to = dst + 1;
			return false;
		}
	}

	clock = home->clock;
	vtime = tctx->vtime;
	if (!no_eligibility && time_before(clock, vtime))
		return false;
	request = task_request(tctx);
	deadline = vtime + scale_inverse(prev, request);

	/* A tie is kept: giving the CPU up costs a switch. */
	keep = !head_deadline(cpu, clock, &head) || !time_before(head, deadline);
	if (keep) {
		/* What a waking task has to beat from now on, see ops.enqueue(). */
		home->running_request = request;
		home->running_deadline = deadline;
	}

	return keep;
}

s32 BPF_STRUCT_OPS(bpfland_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	s32 cpu;

	prev_cpu = queue_home(p, prev_cpu);
	cpu = pick_idle(p, prev_cpu);
	/*
	 * A task that has never run has no cache to stay near: with nothing
	 * idle in the LLC it starts wherever something is, which spreads the
	 * load before it has to be moved.
	 */
	if (cpu < 0 && (wake_flags & SCX_WAKE_FORK))
		cpu = pick_beyond(p, prev_cpu);
	if (cpu >= 0) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_ns, 0);
		COUNT(direct);
		return cpu;
	}

	/*
	 * Nothing idle: the task is queued, on @prev_cpu unless it borrows
	 * virtual time and can take another CPU.
	 */
	return preempt_target(p, prev_cpu);
}

void BPF_STRUCT_OPS(bpfland_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p), idle;
	u64 bound, clock, floor, ceiling, vtime, request, deadline, now;
	bool wakeup = enq_flags & SCX_ENQ_WAKEUP, rotating = false;
	task_ctx_t *tctx;
	cpu_ctx_t *here;

	tctx = try_lookup_task_ctx(p);
	cpu = queue_home(p, cpu);

	/*
	 * A task whose slice ops.tick() ended to move it: it goes to the CPU
	 * found then if that is still idle, and the claim keeps another CPU
	 * from sending a task there too. A task that slept in between is
	 * placed by its wakeup instead.
	 */
	if (tctx && tctx->target) {
		s32 dst = tctx->target - 1;

		tctx->target = 0;
		if (!wakeup && !is_pinned(p) && cpu_valid(dst) &&
		    allowed(p, dst) && claim(dst)) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | dst, slice_ns, enq_flags);
			scx_bpf_kick_cpu(dst, SCX_KICK_IDLE);
			COUNT(balanced);
			return;
		}
	}

	/*
	 * A task that is to swap onto a better CPU is queued there, see
	 * rotate_due(), and none of the placements below apply to it.
	 */
	if (tctx && tctx->rotate_to) {
		s32 dst = tctx->rotate_to - 1;
		cpu_ctx_t *dctx = cpu_ctx(dst);

		tctx->rotate_to = 0;
		if (!wakeup && dctx && allowed(p, dst)) {
			cpu = dst;
			rotating = true;
		} else if (dctx) {
			WRITE_ONCE(dctx->rotate_pending, 0);
		}
	}

	/*
	 * With ENQ_LAST the kernel hands over the last task of a CPU that
	 * found nothing else to run, instead of keeping it running. The task
	 * keeps its queue home: on a queue, the first CPU to run out of work would
	 * take it, and a task alone on its CPU would move at every slice. The
	 * CPU has made its pick by now and may be going idle, so it is told
	 * to look again.
	 */
	if ((enq_flags & SCX_ENQ_LAST) && !rotating) {
		u64 dsq = cpu == scx_bpf_task_cpu(p) ? SCX_DSQ_LOCAL : SCX_DSQ_LOCAL_ON | cpu;

		scx_bpf_dsq_insert(p, dsq, slice_ns, enq_flags);
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

	here = cpu_ctx(cpu);
	if (!tctx || !here) {
		if (!primary_all) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice_ns, enq_flags);
			scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		} else {
			scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
		}
		return;
	}

	/*
	 * A wakeup the kernel queued to the task's CPU did not go through
	 * ops.select_cpu(). Give the task the same chance of an idle CPU
	 * here, and of running there at once.
	 */
	if (!__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p) &&
	    !rotating && !is_pinned(p)) {
		idle = pick_idle(p, cpu);
		if (idle >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | idle, slice_ns, enq_flags);
			scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
			COUNT(direct);
			return;
		}
		/*
		 * Nothing idle: it may take another CPU, as from
		 * ops.select_cpu(), unless its own is about to go idle. The
		 * kernel queues a wakeup in the LLC only to a CPU left with
		 * nothing to run, which the idle search cannot see yet.
		 */
		if (wakeup && (READ_ONCE(here->busy) || scx_edq_nr_queued(&here->edq))) {
			cpu = preempt_target(p, cpu);
			here = cpu_ctx(cpu);
			if (!here) {
				scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, slice_ns, enq_flags);
				return;
			}
		}
	}

	rehome(tctx, cpu);

	/*
	 * The lag bound: a task is at most this far behind the clock, however
	 * long it slept, and at most this far ahead of it. It is less virtual
	 * time for a heavier task, as a slice is.
	 */
	now = scx_bpf_now();
	bound = scale_inverse(p, lag_bound_ns);
	clock = advance(here, now);
	floor = clock - bound;
	ceiling = clock + bound;
	vtime = tctx->vtime;
	if (time_before(vtime, floor))
		vtime = floor;
	else if (time_before(ceiling, vtime))
		vtime = ceiling;

	/* A waking task may borrow virtual time, see borrow(). */
	if (wakeup) {
		u64 placed = borrow(p, clock, vtime);

		if (placed != vtime)
			COUNT(borrowed);
		vtime = placed;
	}
	tctx->vtime = vtime;

	/*
	 * The deadline is where the task's virtual time is after what it asks
	 * for, see task_request().
	 */
	request = task_request(tctx);
	deadline = vtime + scale_inverse(p, request);
	/* Set before the node is visible: worse CPUs leave it, see steal_from(). */
	tctx->rotating = rotating;
	if (rotating)
		COUNT(rotated);
	queue_insert(p, tctx, cpu, slice_ns, deadline, vtime, enq_flags);

	/*
	 * Wakeup preemption. The task running here was the eligible one with
	 * the earliest deadline when it was picked, and keeps the CPU for its
	 * slice. A task that wakes eligible, if eligibility is asked for,
	 * asking for less than the running one and with an earlier deadline,
	 * takes the CPU now: the running task goes back in the queue, charged
	 * for what it ran. Two tasks that ask for the same do not preempt
	 * each other, which keeps a load of tasks that all sleep from
	 * switching at every wakeup.
	 *
	 * A CPU is also left alone for a while after a task starts running on
	 * it, and after it is preempted. A task that takes the CPU gets to do
	 * some work before the next one takes it, however many wake up in a
	 * row, and the one waking waits for that long at most.
	 */
	if (!no_preempt && wakeup && request < here->running_request &&
	    (no_eligibility || !time_before(clock, vtime)) &&
	    time_before(deadline, here->running_deadline) &&
	    !time_before(now, here->preempt_after)) {
		here->preempt_after = now + min_granularity_ns;
		COUNT(preempts);
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
		return;
	}

	/*
	 * An idle CPU can take it from here. Not for a wakeup: the idle search
	 * of ops.select_cpu(), or the one above for a wakeup that skipped it,
	 * has just found nothing idle. A task put back at the end of its slice
	 * or after a preemption had no search, and a CPU left idle in the
	 * meantime would sleep through it: that is what the kick is for, as
	 * nothing balances otherwise.
	 */
	if (!wakeup && !rotating) {
		idle = pick_stealer(p, cpu);
		if (idle >= 0)
			scx_bpf_kick_cpu(idle, SCX_KICK_IDLE);
	}
}

void BPF_STRUCT_OPS(bpfland_dispatch, s32 cpu, struct task_struct *prev)
{
	cpu_ctx_t *here = cpu_ctx(cpu);
	bool handover = false;

	/*
	 * A task is queued here to swap places with the one whose slice has
	 * ended, see rotation_target(): that one does not keep the CPU.
	 */
	if (here && READ_ONCE(here->rotate_pending)) {
		WRITE_ONCE(here->rotate_pending, 0);
		handover = true;
	}

	if (prev && !handover && keep_running(prev, cpu)) {
		scx_bpf_task_set_slice(prev, slice_ns);
		return;
	}

	/*
	 * The eligible task with the earliest deadline, or the one with the
	 * earliest deadline of all if eligibility is not asked for.
	 */
	if (move_own(cpu, here ? here->clock : 0))
		return;
	/*
	 * The queue is empty. The task that ran here, if still runnable, is
	 * queued back as soon as this returns: clearing the queued bit now
	 * and setting it again then is two atomic writes per switch to a word
	 * other CPUs share. Leave the bit to the next CPU that finds the queue
	 * empty.
	 */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		queued_check(cpu);

	if (steal(cpu)) {
		COUNT(steals);
		return;
	}
	/* With no alternative, keep runnable work even if it is ahead of the clock. */
	if (prev && !handover && (prev->scx.flags & SCX_TASK_QUEUED) &&
	    (primary_all || allowed(prev, cpu))) {
		task_ctx_t *tctx = try_lookup_task_ctx(prev);

		if (tctx && !tctx->target && !tctx->rotate_to)
			scx_bpf_task_set_slice(prev, slice_ns);
	}
}

void BPF_STRUCT_OPS(bpfland_tick, struct task_struct *p)
{
	task_ctx_t *tctx;
	s32 dst;

	/* Move existing CPU-bound work into the primary domain even when it is full. */
	if (!primary_all && !primary_cpus[idx(scx_bpf_task_cpu(p))] && uses_primary(p)) {
		scx_bpf_task_set_slice(p, 0);
		return;
	}
	if (idle_empty())
		return;
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	/*
	 * Only a task that does not sleep is moved: one that does is placed
	 * again at its next wakeup, and chasing it would cost its cache for
	 * nothing.
	 */
	if (task_request(tctx) < slice_ns || is_pinned(p))
		return;
	dst = balance_target(p, scx_bpf_task_cpu(p));
	if (dst >= 0) {
		tctx->target = dst + 1;
		scx_bpf_task_set_slice(p, 0);
	}
}

void BPF_STRUCT_OPS(bpfland_runnable, struct task_struct *p, u64 enq_flags)
{
	s32 cpu = scx_bpf_task_cpu(p);
	task_ctx_t *tctx;
	cpu_ctx_t *home;
	u64 now, clock, weight;

	tctx = try_lookup_task_ctx(p);
	home = cpu_ctx(cpu);
	if (!tctx || !home)
		return;

	/*
	 * The time run here so far counts at the load without this task, or,
	 * for a wakeup, with it, see advance_wakeup().
	 */
	now = scx_bpf_now();
	if (enq_flags & SCX_ENQ_WAKEUP)
		clock = advance_wakeup(home, p, now);
	else
		clock = advance(home, now);

	if (!no_vlag) {
		/*
		 * The task comes back with the lag it left with, against the
		 * clock of the CPU it comes back on: what the clock did in the
		 * meantime is neither owed to the task nor forgiven.
		 */
		tctx->vtime = clock - tctx->vlag;
		tctx->home = cpu;
	} else {
		rehome(tctx, cpu);
	}
	weight = task_weight(p);
	tctx->counted = weight;
	__sync_fetch_and_add(&home->load, weight);
}

void BPF_STRUCT_OPS(bpfland_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	u64 now, request;
	task_ctx_t *tctx;
	cpu_ctx_t *here;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	WRITE_ONCE(tctx->state, TASK_NONE);

	/* The CPU the task runs on is not always the one it was queued on. */
	rehome(tctx, cpu);
	now = scx_bpf_now();
	tctx->started_at = now;

	/* How long it has run on worse CPUs, see rotate_due(). */
	tctx->rotating = false;
	if (rotate_ns) {
		if (tier_of(cpu) <= llc_tier_of(cpu)) {
			tctx->lower_at = 0;
			if (!tctx->upper_at)
				tctx->upper_at = now;
		} else {
			tctx->upper_at = 0;
			if (!tctx->lower_at)
				tctx->lower_at = now;
		}
	}

	/* What a waking task has to beat to take the CPU, see ops.enqueue(). */
	here = cpu_ctx(cpu);
	if (here) {
		/* The clock runs from here on, see advance(). */
		advance(here, now);
		here->busy = true;
		request = task_request(tctx);
		here->preempt_after = now + min_granularity_ns;
		here->running_request = request;
		here->running_deadline = tctx->vtime + scale_inverse(p, request);
		if (rotate_ns)
			WRITE_ONCE(here->running_upper_at, tctx->upper_at);
		long_running(here, request);
	}
}

void BPF_STRUCT_OPS(bpfland_stopping, struct task_struct *p, bool runnable)
{
	task_ctx_t *tctx;
	cpu_ctx_t *home;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	home = charge(p, tctx, scx_bpf_now());
	if (home) {
		home->busy = false;
		if (rotate_ns)
			WRITE_ONCE(home->running_upper_at, 0);
		long_stopping(home);
	}
}

void BPF_STRUCT_OPS(bpfland_quiescent, struct task_struct *p, u64 deq_flags)
{
	task_ctx_t *tctx;
	cpu_ctx_t *home;
	u64 clock, weight;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * The task sleeps: what it ran since the last sleep goes into its
	 * average, a quarter of it at a time, and a new burst begins.
	 */
	if (deq_flags & SCX_DEQ_SLEEP) {
		u64 burst = MIN(tctx->burst, slice_ns);

		tctx->burst_avg = (tctx->burst_avg * 3 + burst) / 4;
		tctx->burst = 0;
		if (rotate_ns)
			tctx->upper_at = 0;
	}

	home = cpu_ctx(tctx->home);
	if (!home)
		return;
	/* The time run here so far counts at the load with this task. */
	clock = advance(home, scx_bpf_now());
	tctx->vlag = clock - tctx->vtime;
	weight = tctx->counted;
	if (weight) {
		__sync_fetch_and_sub(&home->load, weight);
		tctx->counted = 0;
	}
}

/*
 * The kernel takes a task the scheduler holds back: out of the queue it waits
 * in, or away from the CPU that is moving it to its local DSQ, which then
 * finds the state changed and lets go.
 */
void BPF_STRUCT_OPS(bpfland_dequeue, struct task_struct *p, u64 deq_flags)
{
	task_ctx_t *tctx;
	cpu_ctx_t *cctx;
	u64 state;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	state = __sync_lock_test_and_set(&tctx->state, TASK_NONE);
	if (state != TASK_ENQUEUED)
		return;
	cctx = cpu_ctx(tctx->queued_on);
	if (!cctx)
		return;
	/* -EINVAL: a CPU popped the node first, and will find the state changed. */
	scx_edq_remove(&cctx->edq, &tctx->node);
}

void BPF_STRUCT_OPS(bpfland_set_weight, struct task_struct *p, u32 weight)
{
	u64 old, new, clock, lag, size;
	task_ctx_t *tctx;
	cpu_ctx_t *home;
	bool ahead;

	/*
	 * A runnable task whose weight changes: the load follows it at once,
	 * and the task keeps its lag in real time, as fair.c's
	 * reweight_entity() keeps it.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	old = tctx->counted;
	new = task_weight(p);
	if (!old || !new || old == new)
		return;
	home = cpu_ctx(tctx->home);
	if (!home)
		return;

	clock = advance(home, scx_bpf_now());
	__sync_fetch_and_add(&home->load, new - old);
	tctx->counted = new;

	/* The lag is signed, and BPF divides only unsigned: scale its magnitude. */
	lag = clock - tctx->vtime;
	ahead = (s64)lag < 0;
	size = ahead ? -lag : lag;
	size = size * old / new;
	lag = ahead ? -size : size;
	tctx->vtime = clock - lag;
}

void BPF_STRUCT_OPS(bpfland_update_idle, s32 cpu, bool idle)
{
	u32 llc;

	/* A core that goes idle as a whole sets the hint of its LLC. */
	if (!idle || !smt_enabled || !cpu_valid(cpu))
		return;
	llc = idx(llc_of(cpu));
	if (READ_ONCE(llc_idle_cores[llc]) || !core_idle(cpu))
		return;
	WRITE_ONCE(llc_idle_cores[llc], 1);
}

void BPF_STRUCT_OPS(bpfland_dump_cpu, struct scx_dump_ctx *dctx, s32 cpu, bool idle)
{
	cpu_ctx_t *cctx = cpu_ctx(cpu);

	if (!cctx)
		return;
	scx_bpf_dump("bpfland queued=%llu clock=%llu load=%llu running_request=%llu queued_bit=%d",
		     scx_edq_nr_queued(&cctx->edq), cctx->clock, cctx->load,
		     cctx->running_request, queued_test(cpu));
}

void BPF_STRUCT_OPS(bpfland_dump_task, struct scx_dump_ctx *dctx, struct task_struct *p)
{
	task_ctx_t *tctx = try_lookup_task_ctx(p);

	if (!tctx)
		return;
	scx_bpf_dump("bpfland state=%llu queued_on=%d hold=%d vtime=%llu home=%d request=%llu",
		     tctx->state, tctx->queued_on, tctx->node.holdcnt, tctx->vtime,
		     tctx->home, task_request(tctx));
}

void BPF_STRUCT_OPS(bpfland_enable, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);
	task_ctx_t *tctx;
	cpu_ctx_t *here;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;
	/*
	 * A new task starts on the clock, owed nothing and owing nothing, and
	 * asking for a whole slice until it has shown that it sleeps.
	 */
	tctx->burst_avg = slice_ns;
	tctx->vlag = 0;
	tctx->home = cpu;
	here = cpu_ctx(cpu);
	if (here)
		tctx->vtime = here->clock;
	scx_bpf_task_set_dsq_vtime(p, (u64)tctx);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct task_ctx_ref *ref;
	task_ctx_t *tctx;

	ref = bpf_task_storage_get(&task_ctx_stor, p, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ref)
		return -ENOMEM;
	tctx = scx_alloc(&task_ctx_allocator);
	if (!tctx)
		return -ENOMEM;
	/*
	 * No memset: LLVM 19 expands one on arena memory through the uncast
	 * pointer and the verifier rejects the program, see
	 * scx_edq_task_init(). Adjacent zero stores can be folded into the
	 * same thing, hence WRITE_ONCE for those.
	 */
	scx_edq_task_init(&tctx->node);
	tctx->id = task_id(p);
	tctx->queued_on = -1;
	WRITE_ONCE(tctx->state, TASK_NONE);
	WRITE_ONCE(tctx->slice, 0);
	WRITE_ONCE(tctx->enq_flags, 0);
	WRITE_ONCE(tctx->vtime, 0);
	tctx->home = scx_bpf_task_cpu(p);
	tctx->target = 0;
	tctx->rotate_to = 0;
	tctx->rotating = false;
	WRITE_ONCE(tctx->lower_at, 0);
	WRITE_ONCE(tctx->upper_at, 0);
	WRITE_ONCE(tctx->counted, 0);
	WRITE_ONCE(tctx->vlag, 0);
	WRITE_ONCE(tctx->started_at, 0);
	WRITE_ONCE(tctx->burst, 0);
	WRITE_ONCE(tctx->burst_avg, slice_ns);
	ref->tctx = tctx;

	return 0;
}

void BPF_STRUCT_OPS(bpfland_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx_ref *ref;
	task_ctx_t *tctx;
	int ret;

	TOUCH_ARENA();
	ref = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!ref || !ref->tctx)
		return;
	tctx = ref->tctx;
	ref->tctx = NULL;
	ret = scx_edq_task_detach(&tctx->node);
	if (ret) {
		scx_bpf_error("EDQ detach failed for pid %d: %d", p->pid, ret);
		return;
	}
	scx_free(&task_ctx_allocator, tctx);
}

/*
 * Return one CPU's SD_ASYM_PACKING state and arch_asym_cpu_priority(), for
 * the loader to rank the CPUs with, between load and attach.
 */
SEC("syscall")
int bpfland_cpu_priority(struct cpu_priority_args *args)
{
	u64 cpu = args->cpu;
	int priority;

	args->priority = 0;
	args->asym_packing = 0;
	if (cpu > INT_MAX || !&sched_core_priority || !&sd_asym_packing)
		return 0;
	priority = cpu_priority(cpu);
	if (priority < 0 || !cpu_asym_packing_dom(cpu))
		return 0;
	args->priority = priority;
	args->asym_packing = 1;

	return 0;
}

/* A cpumask of the @len CPUs listed in @cpus from @base. */
static struct bpf_cpumask *domain_mask(const volatile u16 *cpus, u32 base, u32 len)
{
	struct bpf_cpumask *mask;
	u32 k;

	mask = bpf_cpumask_create();
	if (!mask)
		return NULL;
	bpf_for(k, 0, len)
		bpf_cpumask_set_cpu(cpus[idx(base + k)], mask);

	return mask;
}

static void install_mask(struct mask_slot *slot, struct bpf_cpumask *mask)
{
	mask = bpf_kptr_xchg(&slot->mask, mask);
	if (mask)
		bpf_cpumask_release(mask);
}

/* Fill the cpumask of every LLC and node, and the scratch mask of every CPU. */
static int init_masks(void)
{
	struct bpf_cpumask *mask;
	struct mask_slot *slot;
	u32 i, dom, key, zero = 0;

	if (!primary_all) {
		slot = bpf_map_lookup_elem(&primary_masks, &zero);
		if (!slot)
			return -ENOMEM;
		mask = bpf_cpumask_create();
		if (!mask)
			return -ENOMEM;
		bpf_for(i, 0, nr_cpus) {
			if (primary_cpus[idx(i)])
				bpf_cpumask_set_cpu(i, mask);
		}
		install_mask(slot, mask);
	}

	bpf_for(i, 0, nr_cpus) {
		/*
		 * Every LLC and node with a CPU is the domain of one. The key
		 * is a copy: a variable whose address the lookup takes is
		 * reloaded without its bounds.
		 */
		dom = idx(llc_of(i));
		key = dom;
		slot = bpf_map_lookup_elem(&llc_masks, &key);
		if (slot && !slot->mask) {
			mask = domain_mask(llc_cpus, llc_base[idx(dom)], llc_len[idx(dom)]);
			if (!mask)
				return -ENOMEM;
			install_mask(slot, mask);
		}

		dom = idx(node_of(i));
		key = dom;
		slot = bpf_map_lookup_elem(&node_masks, &key);
		if (slot && !slot->mask) {
			mask = domain_mask(node_cpus, node_base[idx(dom)], node_len[idx(dom)]);
			if (!mask)
				return -ENOMEM;
			install_mask(slot, mask);
		}

		/* The tier masks, filled a CPU at a time. */
		key = idx(llc_of(i)) * MAX_TIERS + (tier_of(i) & (MAX_TIERS - 1));
		slot = bpf_map_lookup_elem(&tier_masks, &key);
		if (slot) {
			if (!slot->mask) {
				mask = bpf_cpumask_create();
				if (!mask)
					return -ENOMEM;
				install_mask(slot, mask);
			}
			bpf_rcu_read_lock();
			mask = slot->mask;
			if (mask)
				bpf_cpumask_set_cpu(i, mask);
			bpf_rcu_read_unlock();
		}

		slot = bpf_map_lookup_percpu_elem(&scratch_masks, &zero, i);
		if (!slot)
			continue;
		mask = bpf_cpumask_create();
		if (!mask)
			return -ENOMEM;
		install_mask(slot, mask);
	}

	return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(bpfland_init)
{
	u64 bytes, pages;
	int ret;

	if (nr_cpus > MAX_CPUS || nr_cpus != scx_bpf_nr_cpu_ids())
		return -EINVAL;

	/* The CPU contexts, zeroed, which is an empty queue and a clock at 0. */
	bytes = (u64)nr_cpus * sizeof(struct cpu_ctx);
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
	cpu_ctxs = bpf_arena_alloc_pages(&arena, NULL, pages, NUMA_NO_NODE, 0);
	if (!cpu_ctxs)
		return -ENOMEM;

	ret = scx_alloc_init(&task_ctx_allocator, sizeof(struct task_ctx),
			     __alignof__(struct task_ctx));
	if (ret)
		return ret;

	return init_masks();
}

void BPF_STRUCT_OPS(bpfland_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bpfland_ops,
	       .select_cpu		= (void *)bpfland_select_cpu,
	       .enqueue			= (void *)bpfland_enqueue,
	       .dequeue			= (void *)bpfland_dequeue,
	       .dispatch		= (void *)bpfland_dispatch,
	       .tick			= (void *)bpfland_tick,
	       .runnable		= (void *)bpfland_runnable,
	       .running			= (void *)bpfland_running,
	       .stopping		= (void *)bpfland_stopping,
	       .quiescent		= (void *)bpfland_quiescent,
	       .set_weight		= (void *)bpfland_set_weight,
	       .update_idle		= (void *)bpfland_update_idle,
	       .dump_cpu		= (void *)bpfland_dump_cpu,
	       .dump_task		= (void *)bpfland_dump_task,
	       .enable			= (void *)bpfland_enable,
	       .init_task		= (void *)bpfland_init_task,
	       .exit_task		= (void *)bpfland_exit_task,
	       .init			= (void *)bpfland_init,
	       .exit			= (void *)bpfland_exit,
	       .timeout_ms		= 5000,
	       .name			= "bpfland");
