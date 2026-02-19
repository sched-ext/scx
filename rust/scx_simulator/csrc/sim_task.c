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
	sim_init_task_args.cgroup = &sim_root_cgroup;
	return &sim_init_task_args;
}

/* Exit task args for the exit_task callback */
static struct scx_exit_task_args sim_exit_task_args;

struct scx_exit_task_args *sim_get_exit_task_args(void)
{
	sim_exit_task_args.cancelled = false;
	return &sim_exit_task_args;
}
