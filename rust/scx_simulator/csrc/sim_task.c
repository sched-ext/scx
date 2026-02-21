/*
 * sim_task.c - task_struct accessor implementations
 *
 * These functions provide safe field access to the kernel's task_struct
 * from Rust code, avoiding the need to replicate the full struct layout
 * in Rust or use bindgen on the massive vmlinux.h.
 *
 * NOTE: We cannot include <stdlib.h> or <string.h> here because they
 * conflict with vmlinux.h type definitions. Instead, we forward-declare
 * the few libc functions we need.
 */
#include "sim_wrapper.h"

/* Forward declarations for libc functions to avoid stdlib.h/vmlinux.h conflicts */
extern void *calloc(unsigned long nmemb, unsigned long size);
extern void free(void *ptr);
extern void *memcpy(void *dst, const void *src, unsigned long n);
extern void *memset(void *s, int c, unsigned long n);

/* Provide the LINUX_KERNEL_VERSION symbol that common.bpf.h declares as extern */
int LINUX_KERNEL_VERSION = 0;

/*
 * Global root cgroup structures for simulator cgroup modeling.
 *
 * Every task starts with cgroups pointing to this default css_set,
 * which in turn points at a root cgroup.  Schedulers that use cgroups
 * (e.g., mitosis) access p->cgroups->dfl_cgrp->kn->id and expect
 * consistent pointers.
 */
static struct kernfs_node sim_root_kn;
static struct cgroup sim_root_cgroup;
static struct css_set sim_root_css_set;
static int sim_root_cgroup_initialized;

static void sim_init_root_cgroup(void)
{
	if (sim_root_cgroup_initialized)
		return;

	memset(&sim_root_kn, 0, sizeof(sim_root_kn));
	sim_root_kn.id = 1; /* matches default root_cgid */

	memset(&sim_root_cgroup, 0, sizeof(sim_root_cgroup));
	sim_root_cgroup.kn = &sim_root_kn;
	sim_root_cgroup.self.cgroup = &sim_root_cgroup;
	sim_root_cgroup.level = 0;
	/* subsys[] is zeroed (no cpuset), percpu_count_ptr is 0 (not dying) */

	memset(&sim_root_css_set, 0, sizeof(sim_root_css_set));
	sim_root_css_set.dfl_cgrp = &sim_root_cgroup;

	sim_root_cgroup_initialized = 1;
}

void *sim_get_root_cgroup(void)
{
	sim_init_root_cgroup();
	return &sim_root_cgroup;
}

struct task_struct *sim_task_alloc(void)
{
	struct task_struct *p = calloc(1, sizeof(struct task_struct));
	if (p) {
		sim_init_root_cgroup();
		p->cgroups = &sim_root_css_set;
		p->real_parent = p; /* self-referencing; simulates init as parent */
	}
	return p;
}

void sim_task_free(struct task_struct *p)
{
	free(p);
}

unsigned long sim_task_struct_size(void)
{
	return sizeof(struct task_struct);
}

/* Identity */
void sim_task_set_pid(struct task_struct *p, int pid)
{
	p->pid = pid;
}

int sim_task_get_pid(struct task_struct *p)
{
	return p->pid;
}

void sim_task_set_comm(struct task_struct *p, const char *comm)
{
	int i;
	for (i = 0; i < (int)sizeof(p->comm) - 1 && comm[i]; i++)
		p->comm[i] = comm[i];
	p->comm[i] = '\0';
}

/* Scheduling parameters */
void sim_task_set_weight(struct task_struct *p, u32 weight)
{
	p->scx.weight = weight;
}

u32 sim_task_get_weight(struct task_struct *p)
{
	return p->scx.weight;
}

void sim_task_set_static_prio(struct task_struct *p, int prio)
{
	p->static_prio = prio;
	/* For normal (non-RT/DL) tasks, prio == static_prio.
	 * Setting prio ensures rt_or_dl_task() returns false
	 * (prio >= MAX_RT_PRIO == 100, since static_prio is 100..139). */
	p->prio = prio;
}

void sim_task_set_flags(struct task_struct *p, unsigned int flags)
{
	p->flags = flags;
}

void sim_task_set_nr_cpus_allowed(struct task_struct *p, int nr)
{
	p->nr_cpus_allowed = nr;
}

int sim_task_get_nr_cpus_allowed(struct task_struct *p)
{
	return p->nr_cpus_allowed;
}

/* SCX entity fields */
u64 sim_task_get_dsq_vtime(struct task_struct *p)
{
	return p->scx.dsq_vtime;
}

void sim_task_set_dsq_vtime(struct task_struct *p, u64 vtime)
{
	p->scx.dsq_vtime = vtime;
}

u64 sim_task_get_slice(struct task_struct *p)
{
	return p->scx.slice;
}

void sim_task_set_slice(struct task_struct *p, u64 slice)
{
	p->scx.slice = slice;
}

u32 sim_task_get_scx_weight(struct task_struct *p)
{
	return p->scx.weight;
}

void sim_task_set_scx_weight(struct task_struct *p, u32 weight)
{
	p->scx.weight = weight;
}

/* cpus_ptr and scx.flags */
void sim_task_setup_cpus_ptr(struct task_struct *p)
{
	/* Point cpus_ptr at the embedded cpus_mask and fill with all-1s
	 * so the task is allowed to run on every CPU. */
	memset(&p->cpus_mask, 0xFF, sizeof(p->cpus_mask));
	p->cpus_ptr = &p->cpus_mask;
}

void sim_task_clear_cpumask(struct task_struct *p)
{
	memset(&p->cpus_mask, 0, sizeof(p->cpus_mask));
	p->cpus_ptr = &p->cpus_mask;
}

void sim_task_set_cpumask_cpu(struct task_struct *p, int cpu)
{
	/* Set one bit in cpus_mask. cpumask uses unsigned long array,
	 * with BITS_PER_LONG bits per element. */
	unsigned long *bits = (unsigned long *)&p->cpus_mask;
	int word = cpu / (sizeof(unsigned long) * 8);
	int bit = cpu % (sizeof(unsigned long) * 8);
	bits[word] |= (1UL << bit);
}

void *sim_task_get_cpus_ptr(struct task_struct *p)
{
	return (void *)p->cpus_ptr;
}

u32 sim_task_get_scx_flags(struct task_struct *p)
{
	return p->scx.flags;
}

void sim_task_set_scx_flags(struct task_struct *p, u32 flags)
{
	p->scx.flags = flags;
}

/* Execution time accounting (sum_exec_runtime) */
u64 sim_task_get_sum_exec_runtime(struct task_struct *p)
{
	return p->se.sum_exec_runtime;
}

void sim_task_set_sum_exec_runtime(struct task_struct *p, u64 ns)
{
	p->se.sum_exec_runtime = ns;
}

/* Address space (mm_struct pointer) */
void sim_task_set_mm(struct task_struct *p, void *mm)
{
	p->mm = (struct mm_struct *)mm;
}

void *sim_task_get_mm(struct task_struct *p)
{
	return (void *)p->mm;
}

/* Dummy exit_info for the exit callback */
static struct scx_exit_info sim_exit_info;

/* Set a task's real_parent to another task.
 * Used to create parent-child relationships so scheduler code
 * (e.g. LAVD's waker-wakee tracking) can see related tasks. */
void sim_task_set_real_parent(struct task_struct *child,
			      struct task_struct *parent)
{
	child->real_parent = parent;
}

struct scx_exit_info *sim_get_exit_info(void)
{
	return &sim_exit_info;
}

/* Init task args for the init_task callback */
static struct scx_init_task_args sim_init_task_args;

struct scx_init_task_args *sim_get_init_task_args(void)
{
	sim_init_root_cgroup();
	sim_init_task_args.fork = false;
	/* Default to root cgroup; engine overrides via sim_set_init_task_cgroup() */
	sim_init_task_args.cgroup = &sim_root_cgroup;
	return &sim_init_task_args;
}

void sim_set_init_task_cgroup(void *cgrp)
{
	sim_init_task_args.cgroup = (struct cgroup *)cgrp;
}

/* Exit task args for the exit_task callback */
static struct scx_exit_task_args sim_exit_task_args;

struct scx_exit_task_args *sim_get_exit_task_args(void)
{
	sim_exit_task_args.cancelled = false;
	return &sim_exit_task_args;
}

/* ---------------------------------------------------------------------------
 * Cgroup allocation for non-root cgroups
 *
 * Each cgroup needs:
 * - struct cgroup (main structure)
 * - struct kernfs_node (for kn->id)
 * - struct css_set (for task->cgroups)
 * - struct cpuset + cpumask (for cpuset modeling)
 *
 * We allocate these together and wire up the pointers.
 * ---------------------------------------------------------------------------*/

/* Maximum depth of cgroup hierarchy (from kernel/cgroup/cgroup.c) */
#ifndef CGROUP_ANCESTOR_MAX
#define CGROUP_ANCESTOR_MAX 32
#endif

/*
 * Allocate a new cgroup with the given ID and level.
 * parent is the parent cgroup's struct cgroup pointer (or NULL for root).
 */
void *sim_cgroup_alloc(u64 cgid, u32 level, void *parent)
{
	struct cgroup *cgrp;
	struct kernfs_node *kn;
	struct css_set *css_set;

	cgrp = calloc(1, sizeof(struct cgroup));
	if (!cgrp)
		return NULL;

	kn = calloc(1, sizeof(struct kernfs_node));
	if (!kn) {
		free(cgrp);
		return NULL;
	}

	css_set = calloc(1, sizeof(struct css_set));
	if (!css_set) {
		free(kn);
		free(cgrp);
		return NULL;
	}

	/* Set up kernfs_node */
	kn->id = cgid;

	/* Set up cgroup */
	cgrp->kn = kn;
	cgrp->self.cgroup = cgrp;
	cgrp->level = level;
	/* percpu_count_ptr = 0 means not dying */

	/* Set up css_set to point at this cgroup */
	css_set->dfl_cgrp = cgrp;

	/* Store parent pointer in ancestors array if parent is valid */
	if (parent) {
		struct cgroup *pcgrp = (struct cgroup *)parent;
		/* Copy parent's ancestors and add parent */
		u32 i;
		u32 plevel = pcgrp->level;
		for (i = 0; i < plevel && i < (u32)(CGROUP_ANCESTOR_MAX - 1); i++)
			cgrp->ancestors[i] = pcgrp->ancestors[i];
		if (plevel < (u32)CGROUP_ANCESTOR_MAX)
			cgrp->ancestors[plevel] = pcgrp;
	}
	/* Self is at our own level */
	if (level < CGROUP_ANCESTOR_MAX)
		cgrp->ancestors[level] = cgrp;

	return cgrp;
}

/*
 * Free a cgroup allocated by sim_cgroup_alloc.
 */
void sim_cgroup_free(void *cgrp_ptr)
{
	struct cgroup *cgrp = (struct cgroup *)cgrp_ptr;
	if (!cgrp)
		return;

	/* Free the kernfs_node */
	if (cgrp->kn)
		free(cgrp->kn);

	/* Free the cpuset if allocated (cpuset_cgrp_id == 0) */
	if (cgrp->subsys[cpuset_cgrp_id]) {
		struct cpuset *cs = container_of(
			cgrp->subsys[cpuset_cgrp_id], struct cpuset, css);
		if (cs) {
			/* cpus_allowed is an embedded array, no separate free needed */
			free(cs);
		}
	}

	free(cgrp);
}

/*
 * Set a cgroup's cpuset.cpus allowed mask.
 *
 * This allocates a struct cpuset and wires it into cgrp->subsys[0]
 * (cpuset_cgrp_id == 0). The cpuset's cpus_allowed field is set to
 * contain the specified CPU IDs.
 *
 * cpus is an array of CPU IDs, nr_cpus is the count.
 */
void sim_cgroup_set_cpuset(void *cgrp_ptr, const u32 *cpus, u32 nr_cpus)
{
	struct cgroup *cgrp = (struct cgroup *)cgrp_ptr;
	struct cpuset *cs;
	u32 i;

	if (!cgrp || !cpus || nr_cpus == 0)
		return;

	/* Free any existing cpuset */
	if (cgrp->subsys[cpuset_cgrp_id]) {
		struct cpuset *old_cs = container_of(
			cgrp->subsys[cpuset_cgrp_id], struct cpuset, css);
		free(old_cs);
		cgrp->subsys[cpuset_cgrp_id] = NULL;
	}

	/* Allocate a new cpuset */
	cs = calloc(1, sizeof(struct cpuset));
	if (!cs)
		return;

	/* Wire up the CSS <-> cgroup relationship */
	cs->css.cgroup = cgrp;
	cgrp->subsys[cpuset_cgrp_id] = &cs->css;

	/*
	 * Set cpus_allowed bitmask.
	 *
	 * cpumask_var_t is defined as `struct cpumask[1]` when
	 * CONFIG_CPUMASK_OFFSTACK is disabled (the common case).
	 * This means cpus_allowed is an embedded array, not a pointer.
	 * We can directly access cs->cpus_allowed[0] as the cpumask.
	 */
	memset(&cs->cpus_allowed[0], 0, sizeof(struct cpumask));

	/* Set the specified CPU bits */
	for (i = 0; i < nr_cpus; i++) {
		u32 cpu = cpus[i];
		/* Set bit in cpumask (assuming __bits_per_long = 64) */
		unsigned long *bits = (unsigned long *)&cs->cpus_allowed[0];
		u32 word = cpu / (sizeof(unsigned long) * 8);
		u32 bit = cpu % (sizeof(unsigned long) * 8);
		bits[word] |= (1UL << bit);
	}
}

/*
 * Assign a task to a cgroup (update task->cgroups to point to the cgroup's css_set).
 */
void sim_task_set_cgroup(struct task_struct *p, void *cgrp_ptr)
{
	struct cgroup *cgrp = (struct cgroup *)cgrp_ptr;
	struct css_set *css;

	if (!cgrp) {
		/* Fall back to root */
		sim_init_root_cgroup();
		p->cgroups = &sim_root_css_set;
		return;
	}

	/* We need a css_set for this cgroup. For dynamically allocated cgroups,
	 * we allocated one in sim_cgroup_alloc. We need to find or create it.
	 * For simplicity, allocate a new css_set per task assignment. */
	css = calloc(1, sizeof(struct css_set));
	if (!css) {
		/* Fall back to root on allocation failure */
		sim_init_root_cgroup();
		p->cgroups = &sim_root_css_set;
		return;
	}
	css->dfl_cgrp = cgrp;
	p->cgroups = css;
}

/*
 * Get the cgroup a task belongs to.
 */
void *sim_task_get_cgroup(struct task_struct *p)
{
	if (!p || !p->cgroups)
		return sim_get_root_cgroup();
	return p->cgroups->dfl_cgrp;
}

/* Migration disabled counter */
void sim_task_set_migration_disabled(struct task_struct *p, unsigned short val)
{
	p->migration_disabled = val;
}

unsigned short sim_task_get_migration_disabled(struct task_struct *p)
{
	return p->migration_disabled;
}
