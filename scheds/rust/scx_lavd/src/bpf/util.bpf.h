/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UTIL_H
#define __UTIL_H

extern struct bpf_cpumask __kptr *turbo_cpumask; /* CPU mask for turbo CPUs */
extern struct bpf_cpumask __kptr *big_cpumask; /* CPU mask for big CPUs */
extern struct bpf_cpumask __kptr *active_cpumask; /* CPU mask for active CPUs */
extern struct bpf_cpumask __kptr *ovrflw_cpumask; /* CPU mask for overflow CPUs */

extern const volatile u64	nr_llcs;	/* number of LLC domains */
extern const volatile u64	__nr_cpu_ids;	/* maximum CPU IDs */
extern volatile u64		nr_cpus_onln;	/* current number of online CPUs */

extern const volatile u32	cpu_sibling[LAVD_CPU_ID_MAX]; /* siblings for CPUs when SMT is active */

/*
 * Scheduler parameters
 */
extern volatile bool		reinit_cpumask_for_performance;
extern volatile bool		no_preemption;
extern volatile bool		no_core_compaction;
extern volatile bool		no_freq_scaling;

extern const volatile bool	no_wake_sync;
extern const volatile bool	no_slice_boost;
extern const volatile bool	per_cpu_dsq;
extern const volatile bool	enable_cpu_bw;
extern const volatile bool	is_autopilot_on;
extern const volatile u8	verbose;

/*
 * Exit information (from UEI_DEFINE)
 */
extern struct user_exit_info uei;
extern char uei_dump[];
extern const volatile u32 uei_dump_len;

u64 calc_avg_freq(u64 old_freq, u64 interval);
bool is_kernel_task(struct task_struct *p);
bool is_kernel_worker(struct task_struct *p);
bool is_ksoftirqd(struct task_struct *p);
bool is_pinned(const struct task_struct *p);
bool use_full_cpus(void);
void set_on_core_type(task_ctx __arg_arena *taskc, const struct cpumask *cpumask);
bool prob_x_out_of_y(u32 x, u32 y);
u32 get_primary_cpu(u32 cpu);
u64 task_exec_time(struct task_struct __arg_trusted *p);

#endif /* __UTIL_H */
