/*
 * sim_task.h - task_struct accessor declarations for the simulator
 *
 * These use C-compatible types that work with both vmlinux.h and Rust FFI.
 * We avoid stdint.h to prevent conflicts with vmlinux.h type definitions.
 */
#pragma once

struct task_struct;

/* Allocation */
struct task_struct *sim_task_alloc(void);
void sim_task_free(struct task_struct *p);
unsigned long sim_task_struct_size(void);

/* Identity */
void sim_task_set_pid(struct task_struct *p, int pid);
int sim_task_get_pid(struct task_struct *p);
void sim_task_set_comm(struct task_struct *p, const char *comm);

/* Scheduling parameters -- use unsigned int / unsigned long long
 * to avoid type conflicts between vmlinux.h and stdint.h */
void sim_task_set_weight(struct task_struct *p, unsigned int weight);
unsigned int sim_task_get_weight(struct task_struct *p);
void sim_task_set_static_prio(struct task_struct *p, int prio);
void sim_task_set_flags(struct task_struct *p, unsigned int flags);
void sim_task_set_nr_cpus_allowed(struct task_struct *p, int nr);
int sim_task_get_nr_cpus_allowed(struct task_struct *p);

/* SCX entity fields */
unsigned long long sim_task_get_dsq_vtime(struct task_struct *p);
void sim_task_set_dsq_vtime(struct task_struct *p, unsigned long long vtime);
unsigned long long sim_task_get_slice(struct task_struct *p);
void sim_task_set_slice(struct task_struct *p, unsigned long long slice);
unsigned int sim_task_get_scx_weight(struct task_struct *p);
void sim_task_set_scx_weight(struct task_struct *p, unsigned int weight);

/* cpus_ptr and scx.flags accessors */
void sim_task_setup_cpus_ptr(struct task_struct *p);
void sim_task_clear_cpumask(struct task_struct *p);
void sim_task_set_cpumask_cpu(struct task_struct *p, int cpu);
void *sim_task_get_cpus_ptr(struct task_struct *p);
unsigned int sim_task_get_scx_flags(struct task_struct *p);
void sim_task_set_scx_flags(struct task_struct *p, unsigned int flags);

/* Root cgroup for simulator cgroup modeling.
 * Returns a pointer to the global root cgroup (struct cgroup *). */
void *sim_get_root_cgroup(void);

/* Address space (mm_struct pointer) */
void sim_task_set_mm(struct task_struct *p, void *mm);
void *sim_task_get_mm(struct task_struct *p);

/* Cgroup allocation and management */
void *sim_cgroup_alloc(unsigned long long cgid, unsigned int level, void *parent);
void sim_cgroup_free(void *cgrp);
void sim_cgroup_set_cpuset(void *cgrp, const unsigned int *cpus, unsigned int nr_cpus);
void sim_task_set_cgroup(struct task_struct *p, void *cgrp);
void *sim_task_get_cgroup(struct task_struct *p);

/* Override the cgroup in init_task_args before calling init_task */
void sim_set_init_task_cgroup(void *cgrp);

/* Migration disabled counter
 * When migration_disabled > 0, the task cannot migrate even if nr_cpus_allowed > 1.
 * This models the kernel's migration_disabled field which is incremented when
 * tasks enter BPF code or explicitly disable migration. */
void sim_task_set_migration_disabled(struct task_struct *p, unsigned short val);
unsigned short sim_task_get_migration_disabled(struct task_struct *p);
