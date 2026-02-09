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

/* SCX entity fields */
unsigned long long sim_task_get_dsq_vtime(struct task_struct *p);
void sim_task_set_dsq_vtime(struct task_struct *p, unsigned long long vtime);
unsigned long long sim_task_get_slice(struct task_struct *p);
void sim_task_set_slice(struct task_struct *p, unsigned long long slice);
unsigned int sim_task_get_scx_weight(struct task_struct *p);
void sim_task_set_scx_weight(struct task_struct *p, unsigned int weight);
