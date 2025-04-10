/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMMON_BPF_H
#define __SCX_COMMON_BPF_H

/*
 * The generated kfunc prototypes in vmlinux.h are missing address space
 * attributes which cause build failures. For now, suppress the generated
 * prototypes. See https://github.com/sched-ext/scx/issues/1111.
 */
#define BPF_NO_KFUNC_PROTOTYPES

#ifdef LSP
#define __bpf__
#include "../vmlinux.h"
#else
#include "vmlinux.h"
#endif

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>
#include "user_exit_info.h"
#include "enum_defs.autogen.h"

#define PF_IO_WORKER			0x00000010	/* Task is an IO worker */
#define PF_WQ_WORKER			0x00000020	/* I'm a workqueue worker */
#define PF_KTHREAD			0x00200000	/* I am a kernel thread */
#define PF_EXITING			0x00000004
#define CLOCK_MONOTONIC			1

extern int LINUX_KERNEL_VERSION __kconfig;
extern const char CONFIG_CC_VERSION_TEXT[64] __kconfig __weak;
extern const char CONFIG_LOCALVERSION[64] __kconfig __weak;

/*
 * Earlier versions of clang/pahole lost upper 32bits in 64bit enums which can
 * lead to really confusing misbehaviors. Let's trigger a build failure.
 */
static inline void ___vmlinux_h_sanity_check___(void)
{
	_Static_assert(SCX_DSQ_FLAG_BUILTIN,
		       "bpftool generated vmlinux.h is missing high bits for 64bit enums, upgrade clang and pahole");
}

/**
 * scx_bpf_create_dsq - Create a custom DSQ
 * @dsq_id: DSQ to create
 * @node: NUMA node to allocate from
 *
 * Create a custom DSQ identified by @dsq_id. Can be called from any sleepable
 * scx callback, and any BPF_PROG_TYPE_SYSCALL prog.
 */
s32 scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;

/**
 * scx_bpf_select_cpu_dfl - The default implementation of ops.select_cpu()
 * @p: task_struct to select a CPU for
 * @prev_cpu: CPU @p was on previously
 * @wake_flags: %SCX_WAKE_* flags
 * @is_idle: out parameter indicating whether the returned CPU is idle
 *
 * Can only be called from ops.select_cpu() if the built-in CPU selection is
 * enabled - ops.update_idle() is missing or %SCX_OPS_KEEP_BUILTIN_IDLE is set.
 * @p, @prev_cpu and @wake_flags match ops.select_cpu().
 *
 * Returns the picked CPU with *@is_idle indicating whether the picked CPU is
 * currently idle and thus a good candidate for direct dispatching.
 */
s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool *is_idle) __ksym;

/**
 * scx_bpf_dsq_insert - Insert a task into the FIFO queue of a DSQ
 * @p: task_struct to insert
 * @dsq_id: DSQ to insert into
 * @slice: duration @p can run for in nsecs, 0 to keep the current value
 * @enq_flags: SCX_ENQ_*
 *
 * Insert @p into the FIFO queue of the DSQ identified by @dsq_id. It is safe to
 * call this function spuriously. Can be called from ops.enqueue(),
 * ops.select_cpu(), and ops.dispatch().
 *
 * When called from ops.select_cpu() or ops.enqueue(), it's for direct dispatch
 * and @p must match the task being enqueued.
 *
 * When called from ops.select_cpu(), @enq_flags and @dsp_id are stored, and @p
 * will be directly inserted into the corresponding dispatch queue after
 * ops.select_cpu() returns. If @p is inserted into SCX_DSQ_LOCAL, it will be
 * inserted into the local DSQ of the CPU returned by ops.select_cpu().
 * @enq_flags are OR'd with the enqueue flags on the enqueue path before the
 * task is inserted.
 *
 * When called from ops.dispatch(), there are no restrictions on @p or @dsq_id
 * and this function can be called upto ops.dispatch_max_batch times to insert
 * multiple tasks. scx_bpf_dispatch_nr_slots() returns the number of the
 * remaining slots. scx_bpf_consume() flushes the batch and resets the counter.
 *
 * This function doesn't have any locking restrictions and may be called under
 * BPF locks (in the future when BPF introduces more flexible locking).
 *
 * @p is allowed to run for @slice. The scheduling path is triggered on slice
 * exhaustion. If zero, the current residual slice is maintained. If
 * %SCX_SLICE_INF, @p never expires and the BPF scheduler must kick the CPU with
 * scx_bpf_kick_cpu() to trigger scheduling.
 */
void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) __ksym __weak;

/**
 * scx_bpf_dsq_insert_vtime - Insert a task into the vtime priority queue of a DSQ
 * @p: task_struct to insert
 * @dsq_id: DSQ to insert into
 * @slice: duration @p can run for in nsecs, 0 to keep the current value
 * @vtime: @p's ordering inside the vtime-sorted queue of the target DSQ
 * @enq_flags: SCX_ENQ_*
 *
 * Insert @p into the vtime priority queue of the DSQ identified by @dsq_id.
 * Tasks queued into the priority queue are ordered by @vtime. All other aspects
 * are identical to scx_bpf_dsq_insert().
 *
 * @vtime ordering is according to time_before64() which considers wrapping. A
 * numerically larger vtime may indicate an earlier position in the ordering and
 * vice-versa.
 *
 * A DSQ can only be used as a FIFO or priority queue at any given time and this
 * function must not be called on a DSQ which already has one or more FIFO tasks
 * queued and vice-versa. Also, the built-in DSQs (SCX_DSQ_LOCAL and
 * SCX_DSQ_GLOBAL) cannot be used as priority queues.
 */
void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq_id, u64 slice, u64 vtime, u64 enq_flags) __ksym __weak;

/**
 * scx_bpf_dispatch_nr_slots - Return the number of remaining dispatch slots
 *
 * Can only be called from ops.dispatch().
 */
u32 scx_bpf_dispatch_nr_slots(void) __ksym;

/**
 * scx_bpf_dispatch_cancel - Cancel the latest dispatch
 *
 * Cancel the latest dispatch. Can be called multiple times to cancel further
 * dispatches. Can only be called from ops.dispatch().
 */
void scx_bpf_dispatch_cancel(void) __ksym;

/**
 * scx_bpf_dsq_move_to_local - move a task from a DSQ to the current CPU's local DSQ
 * @dsq_id: DSQ to move task from
 *
 * Move a task from the non-local DSQ identified by @dsq_id to the current CPU's
 * local DSQ for execution. Can only be called from ops.dispatch().
 *
 * This function flushes the in-flight dispatches from scx_bpf_dsq_insert()
 * before trying to move from the specified DSQ. It may also grab rq locks and
 * thus can't be called under any BPF locks.
 *
 * Returns %true if a task has been moved, %false if there isn't any task to
 * move.
 */
bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym __weak;

/**
 * scx_bpf_dsq_move_set_slice - Override slice when moving between DSQs
 * @it__iter: DSQ iterator in progress
 * @slice: duration the moved task can run for in nsecs
 *
 * Override the slice of the next task that will be moved from @it__iter using
 * scx_bpf_dsq_move[_vtime](). If this function is not called, the previous
 * slice duration is kept.
 */
void scx_bpf_dsq_move_set_slice(struct bpf_iter_scx_dsq *it__iter, u64 slice) __ksym __weak;

/**
 * scx_bpf_dsq_move_set_vtime - Override vtime when moving between DSQs
 * @it__iter: DSQ iterator in progress
 * @vtime: task's ordering inside the vtime-sorted queue of the target DSQ
 *
 * Override the vtime of the next task that will be moved from @it__iter using
 * scx_bpf_dsq_move_vtime(). If this function is not called, the previous slice
 * vtime is kept. If scx_bpf_dsq_move() is used to dispatch the next task, the
 * override is ignored and cleared.
 */
void scx_bpf_dsq_move_set_vtime(struct bpf_iter_scx_dsq *it__iter, u64 vtime) __ksym __weak;

/**
 * scx_bpf_dsq_move - Move a task from DSQ iteration to a DSQ
 * @it__iter: DSQ iterator in progress
 * @p: task to transfer
 * @dsq_id: DSQ to move @p to
 * @enq_flags: SCX_ENQ_*
 *
 * Transfer @p which is on the DSQ currently iterated by @it__iter to the DSQ
 * specified by @dsq_id. All DSQs - local DSQs, global DSQ and user DSQs - can
 * be the destination.
 *
 * For the transfer to be successful, @p must still be on the DSQ and have been
 * queued before the DSQ iteration started. This function doesn't care whether
 * @p was obtained from the DSQ iteration. @p just has to be on the DSQ and have
 * been queued before the iteration started.
 *
 * @p's slice is kept by default. Use scx_bpf_dsq_move_set_slice() to update.
 *
 * Can be called from ops.dispatch() or any BPF context which doesn't hold a rq
 * lock (e.g. BPF timers or SYSCALL programs).
 *
 * Returns %true if @p has been consumed, %false if @p had already been consumed
 * or dequeued.
 */
bool scx_bpf_dsq_move(struct bpf_iter_scx_dsq *it__iter, struct task_struct *p, u64 dsq_id, u64 enq_flags) __ksym __weak;

/**
 * scx_bpf_dsq_move_vtime - Move a task from DSQ iteration to a PRIQ DSQ
 * @it__iter: DSQ iterator in progress
 * @p: task to transfer
 * @dsq_id: DSQ to move @p to
 * @enq_flags: SCX_ENQ_*
 *
 * Transfer @p which is on the DSQ currently iterated by @it__iter to the
 * priority queue of the DSQ specified by @dsq_id. The destination must be a
 * user DSQ as only user DSQs support priority queue.
 *
 * @p's slice and vtime are kept by default. Use scx_bpf_dsq_move_set_slice()
 * and scx_bpf_dsq_move_set_vtime() to update.
 *
 * All other aspects are identical to scx_bpf_dsq_move(). See
 * scx_bpf_dsq_insert_vtime() for more information on @vtime.
 */
bool scx_bpf_dsq_move_vtime(struct bpf_iter_scx_dsq *it__iter, struct task_struct *p, u64 dsq_id, u64 enq_flags) __ksym __weak;

/**
 * scx_bpf_reenqueue_local - Re-enqueue tasks on a local DSQ
 *
 * Iterate over all of the tasks currently enqueued on the local DSQ of the
 * caller's CPU, and re-enqueue them in the BPF scheduler. Returns the number of
 * processed tasks. Can only be called from ops.cpu_release().
 */
u32 scx_bpf_reenqueue_local(void) __ksym;

/**
 * scx_bpf_kick_cpu - Trigger reschedule on a CPU
 * @cpu: cpu to kick
 * @flags: %SCX_KICK_* flags
 *
 * Kick @cpu into rescheduling. This can be used to wake up an idle CPU or
 * trigger rescheduling on a busy CPU. This can be called from any online
 * scx_ops operation and the actual kicking is performed asynchronously through
 * an irq work.
 */
void scx_bpf_kick_cpu(s32 cpu, u64 flags) __ksym;

/**
 * scx_bpf_dsq_nr_queued - Return the number of queued tasks
 * @dsq_id: id of the DSQ
 *
 * Return the number of tasks in the DSQ matching @dsq_id. If not found,
 * -%ENOENT is returned.
 */
s32 scx_bpf_dsq_nr_queued(u64 dsq_id) __ksym;

/**
 * scx_bpf_destroy_dsq - Destroy a custom DSQ
 * @dsq_id: DSQ to destroy
 *
 * Destroy the custom DSQ identified by @dsq_id. Only DSQs created with
 * scx_bpf_create_dsq() can be destroyed. The caller must ensure that the DSQ is
 * empty and no further tasks are dispatched to it. Ignored if called on a DSQ
 * which doesn't exist. Can be called from any online scx_ops operations.
 */
void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;

/**
 * bpf_iter_scx_dsq_new - Create a DSQ iterator
 * @it: iterator to initialize
 * @dsq_id: DSQ to iterate
 * @flags: %SCX_DSQ_ITER_*
 *
 * Initialize BPF iterator @it which can be used with bpf_for_each() to walk
 * tasks in the DSQ specified by @dsq_id. Iteration using @it only includes
 * tasks which are already queued when this function is invoked.
 */
int bpf_iter_scx_dsq_new(struct bpf_iter_scx_dsq *it, u64 dsq_id, u64 flags) __ksym __weak;

/**
 * bpf_iter_scx_dsq_next - Progress a DSQ iterator
 * @it: iterator to progress
 *
 * Return the next task. See bpf_iter_scx_dsq_new().
 */
struct task_struct *bpf_iter_scx_dsq_next(struct bpf_iter_scx_dsq *it) __ksym __weak;

/**
 * bpf_iter_scx_dsq_destroy - Destroy a DSQ iterator
 * @it: iterator to destroy
 *
 * Undo scx_iter_scx_dsq_new().
 */
void bpf_iter_scx_dsq_destroy(struct bpf_iter_scx_dsq *it) __ksym __weak;

/**
 * scx_bpf_exit_bstr - Gracefully exit the BPF scheduler.
 * @exit_code: Exit value to pass to user space via struct scx_exit_info.
 * @fmt: error message format string
 * @data: format string parameters packaged using ___bpf_fill() macro
 * @data__sz: @data len, must end in '__sz' for the verifier
 *
 * Indicate that the BPF scheduler wants to exit gracefully, and initiate ops
 * disabling.
 */
void scx_bpf_exit_bstr(s64 exit_code, char *fmt, unsigned long long *data, u32 data__sz) __ksym __weak;

/**
 * scx_bpf_error_bstr - Indicate fatal error
 * @fmt: error message format string
 * @data: format string parameters packaged using ___bpf_fill() macro
 * @data__sz: @data len, must end in '__sz' for the verifier
 *
 * Indicate that the BPF scheduler encountered a fatal error and initiate ops
 * disabling.
 */
void scx_bpf_error_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym;

/**
 * scx_bpf_dump_bstr - Generate extra debug dump specific to the BPF scheduler
 * @fmt: format string
 * @data: format string parameters packaged using ___bpf_fill() macro
 * @data__sz: @data len, must end in '__sz' for the verifier
 *
 * To be called through scx_bpf_dump() helper from ops.dump(), dump_cpu() and
 * dump_task() to generate extra debug dump specific to the BPF scheduler.
 *
 * The extra dump may be multiple lines. A single line may be split over
 * multiple calls. The last line is automatically terminated.
 */
void scx_bpf_dump_bstr(char *fmt, unsigned long long *data, u32 data_len) __ksym __weak;

/**
 * scx_bpf_cpuperf_cap - Query the maximum relative capacity of a CPU
 * @cpu: CPU of interest
 *
 * Return the maximum relative capacity of @cpu in relation to the most
 * performant CPU in the system. The return value is in the range [1,
 * %SCX_CPUPERF_ONE]. See scx_bpf_cpuperf_cur().
 */
u32 scx_bpf_cpuperf_cap(s32 cpu) __ksym __weak;

/**
 * scx_bpf_cpuperf_cur - Query the current relative performance of a CPU
 * @cpu: CPU of interest
 *
 * Return the current relative performance of @cpu in relation to its maximum.
 * The return value is in the range [1, %SCX_CPUPERF_ONE].
 *
 * The current performance level of a CPU in relation to the maximum performance
 * available in the system can be calculated as follows:
 *
 *   scx_bpf_cpuperf_cap() * scx_bpf_cpuperf_cur() / %SCX_CPUPERF_ONE
 *
 * The result is in the range [1, %SCX_CPUPERF_ONE].
 */
u32 scx_bpf_cpuperf_cur(s32 cpu) __ksym __weak;

/**
 * scx_bpf_cpuperf_set - Set the relative performance target of a CPU
 * @cpu: CPU of interest
 * @perf: target performance level [0, %SCX_CPUPERF_ONE]
 *
 * Set the target performance level of @cpu to @perf. @perf is in linear
 * relative scale between 0 and %SCX_CPUPERF_ONE. This determines how the
 * schedutil cpufreq governor chooses the target frequency.
 *
 * The actual performance level chosen, CPU grouping, and the overhead and
 * latency of the operations are dependent on the hardware and cpufreq driver in
 * use. Consult hardware and cpufreq documentation for more information. The
 * current performance level can be monitored using scx_bpf_cpuperf_cur().
 */
void scx_bpf_cpuperf_set(s32 cpu, u32 perf) __ksym __weak;

/**
 * scx_bpf_nr_node_ids - Return the number of possible node IDs
 *
 * All valid node IDs in the system are smaller than the returned value.
 */
u32 scx_bpf_nr_node_ids(void) __ksym __weak;

/**
 * scx_bpf_nr_cpu_ids - Return the number of possible CPU IDs
 *
 * All valid CPU IDs in the system are smaller than the returned value.
 */
u32 scx_bpf_nr_cpu_ids(void) __ksym __weak;

/**
 * scx_bpf_cpu_node - Return the NUMA node the given @cpu belongs to, or
 *		      trigger an error if @cpu is invalid
 * @cpu: target CPU
 */
int scx_bpf_cpu_node(s32 cpu) __ksym __weak;

/**
 * scx_bpf_get_possible_cpumask - Get a referenced kptr to cpu_possible_mask
 */
const struct cpumask *scx_bpf_get_possible_cpumask(void) __ksym __weak;

/**
 * scx_bpf_get_online_cpumask - Get a referenced kptr to cpu_online_mask
 */
const struct cpumask *scx_bpf_get_online_cpumask(void) __ksym __weak;

/**
 * scx_bpf_put_cpumask - Release a possible/online cpumask
 * @cpumask: cpumask to release
 */
void scx_bpf_put_cpumask(const struct cpumask *cpumask) __ksym __weak;

/**
 * scx_bpf_get_idle_cpumask_node - Get a referenced kptr to the
 * idle-tracking per-CPU cpumask of a target NUMA node.
 * @node: target NUMA node
 *
 * Returns an empty cpumask if idle tracking is not enabled, if @node is
 * not valid, or running on a UP kernel. In this case the actual error will
 * be reported to the BPF scheduler via scx_ops_error().
 */
const struct cpumask *scx_bpf_get_idle_cpumask_node(int node) __ksym __weak;

/**
 * scx_bpf_get_idle_cpumask - Get a referenced kptr to the idle-tracking
 * per-CPU cpumask.
 *
 * Returns an empty mask if idle tracking is not enabled, or running on a
 * UP kernel.
 */
const struct cpumask *scx_bpf_get_idle_cpumask(void) __ksym;

/**
 * scx_bpf_get_idle_smtmask_node - Get a referenced kptr to the
 * idle-tracking, per-physical-core cpumask of a target NUMA node. Can be
 * used to determine if an entire physical core is free.
 * @node: target NUMA node
 *
 * Returns an empty cpumask if idle tracking is not enabled, if @node is
 * not valid, or running on a UP kernel. In this case the actual error will
 * be reported to the BPF scheduler via scx_ops_error().
 */
const struct cpumask *scx_bpf_get_idle_smtmask_node(int node) __ksym __weak;

/**
 * scx_bpf_get_idle_smtmask_node - Get a referenced kptr to the
 * idle-tracking, per-physical-core cpumask of a target NUMA node. Can be
 * used to determine if an entire physical core is free.
 * @node: target NUMA node
 *
 * Returns an empty cpumask if idle tracking is not enabled, if @node is
 * not valid, or running on a UP kernel. In this case the actual error will
 * be reported to the BPF scheduler via scx_ops_error().
 */
const struct cpumask *scx_bpf_get_idle_smtmask(void) __ksym;

/**
 * scx_bpf_put_idle_cpumask - Release a previously acquired referenced kptr to
 * either the percpu, or SMT idle-tracking cpumask.
 * @idle_mask: &cpumask to use
 */
void scx_bpf_put_idle_cpumask(const struct cpumask *cpumask) __ksym;

/**
 * scx_bpf_test_and_clear_cpu_idle - Test and clear @cpu's idle state
 * @cpu: cpu to test and clear idle for
 *
 * Returns %true if @cpu was idle and its idle state was successfully cleared.
 * %false otherwise.
 *
 * Unavailable if ops.update_idle() is implemented and
 * %SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 */
bool scx_bpf_test_and_clear_cpu_idle(s32 cpu) __ksym;

/**
 * scx_bpf_pick_idle_cpu_node - Pick and claim an idle cpu from @node
 * @cpus_allowed: Allowed cpumask
 * @node: target NUMA node
 * @flags: %SCX_PICK_IDLE_* flags
 *
 * Pick and claim an idle cpu in @cpus_allowed from the NUMA node @node.
 *
 * Returns the picked idle cpu number on success, or -%EBUSY if no matching
 * cpu was found.
 *
 * The search starts from @node and proceeds to other online NUMA nodes in
 * order of increasing distance (unless SCX_PICK_IDLE_IN_NODE is specified,
 * in which case the search is limited to the target @node).
 *
 * Always returns an error if ops.update_idle() is implemented and
 * %SCX_OPS_KEEP_BUILTIN_IDLE is not set, or if
 * %SCX_OPS_BUILTIN_IDLE_PER_NODE is not set.
 */
s32 scx_bpf_pick_idle_cpu_node(const cpumask_t *cpus_allowed, int node, u64 flags) __ksym __weak;

/**
 * scx_bpf_pick_idle_cpu - Pick and claim an idle cpu
 * @cpus_allowed: Allowed cpumask
 * @flags: %SCX_PICK_IDLE_CPU_* flags
 *
 * Pick and claim an idle cpu in @cpus_allowed. Returns the picked idle cpu
 * number on success. -%EBUSY if no matching cpu was found.
 *
 * Idle CPU tracking may race against CPU scheduling state transitions. For
 * example, this function may return -%EBUSY as CPUs are transitioning into the
 * idle state. If the caller then assumes that there will be dispatch events on
 * the CPUs as they were all busy, the scheduler may end up stalling with CPUs
 * idling while there are pending tasks. Use scx_bpf_pick_any_cpu() and
 * scx_bpf_kick_cpu() to guarantee that there will be at least one dispatch
 * event in the near future.
 *
 * Unavailable if ops.update_idle() is implemented and
 * %SCX_OPS_KEEP_BUILTIN_IDLE is not set.
 *
 * Always returns an error if %SCX_OPS_BUILTIN_IDLE_PER_NODE is set, use
 * scx_bpf_pick_idle_cpu_node() instead.
 */
s32 scx_bpf_pick_idle_cpu(const cpumask_t *cpus_allowed, u64 flags) __ksym;

/**
 * scx_bpf_pick_any_cpu_node - Pick and claim an idle cpu if available
 *			       or pick any CPU from @node
 * @cpus_allowed: Allowed cpumask
 * @node: target NUMA node
 * @flags: %SCX_PICK_IDLE_CPU_* flags
 *
 * Pick and claim an idle cpu in @cpus_allowed. If none is available, pick any
 * CPU in @cpus_allowed. Guaranteed to succeed and returns the picked idle cpu
 * number if @cpus_allowed is not empty. -%EBUSY is returned if @cpus_allowed is
 * empty.
 *
 * The search starts from @node and proceeds to other online NUMA nodes in
 * order of increasing distance (unless %SCX_PICK_IDLE_IN_NODE is specified,
 * in which case the search is limited to the target @node, regardless of
 * the CPU idle state).
 *
 * If ops.update_idle() is implemented and %SCX_OPS_KEEP_BUILTIN_IDLE is not
 * set, this function can't tell which CPUs are idle and will always pick any
 * CPU.
 */
s32 scx_bpf_pick_any_cpu_node(const cpumask_t *cpus_allowed, int node, u64 flags) __ksym __weak;

/**
 * scx_bpf_pick_any_cpu - Pick and claim an idle cpu if available or pick any CPU
 * @cpus_allowed: Allowed cpumask
 * @flags: %SCX_PICK_IDLE_CPU_* flags
 *
 * Pick and claim an idle cpu in @cpus_allowed. If none is available, pick any
 * CPU in @cpus_allowed. Guaranteed to succeed and returns the picked idle cpu
 * number if @cpus_allowed is not empty. -%EBUSY is returned if @cpus_allowed is
 * empty.
 *
 * If ops.update_idle() is implemented and %SCX_OPS_KEEP_BUILTIN_IDLE is not
 * set, this function can't tell which CPUs are idle and will always pick any
 * CPU.
 *
 * Always returns an error if %SCX_OPS_BUILTIN_IDLE_PER_NODE is set, use
 * scx_bpf_pick_any_cpu_node() instead.
 */
s32 scx_bpf_pick_any_cpu(const cpumask_t *cpus_allowed, u64 flags) __ksym;

/**
 * scx_bpf_task_running - Is task currently running?
 * @p: task of interest
 */
bool scx_bpf_task_running(const struct task_struct *p) __ksym;

/**
 * scx_bpf_task_cpu - CPU a task is currently associated with
 * @p: task of interest
 */
s32 scx_bpf_task_cpu(const struct task_struct *p) __ksym;

/**
 * scx_bpf_cpu_rq - Fetch the rq of a CPU
 * @cpu: CPU of the rq
 */
struct rq *scx_bpf_cpu_rq(s32 cpu) __ksym;

/**
 * scx_bpf_task_cgroup - Return the sched cgroup of a task
 * @p: task of interest
 *
 * @p->sched_task_group->css.cgroup represents the cgroup @p is associated with
 * from the scheduler's POV. SCX operations should use this function to
 * determine @p's current cgroup as, unlike following @p->cgroups,
 * @p->sched_task_group is protected by @p's rq lock and thus atomic w.r.t. all
 * rq-locked operations. Can be called on the parameter tasks of rq-locked
 * operations. The restriction guarantees that @p's rq is locked by the caller.
 */
struct cgroup *scx_bpf_task_cgroup(struct task_struct *p) __ksym __weak;

/**
 * scx_bpf_now - Returns a high-performance monotonically non-decreasing
 * clock for the current CPU. The clock returned is in nanoseconds.
 *
 * It provides the following properties:
 *
 * 1) High performance: Many BPF schedulers call bpf_ktime_get_ns() frequently
 *  to account for execution time and track tasks' runtime properties.
 *  Unfortunately, in some hardware platforms, bpf_ktime_get_ns() -- which
 *  eventually reads a hardware timestamp counter -- is neither performant nor
 *  scalable. scx_bpf_now() aims to provide a high-performance clock by
 *  using the rq clock in the scheduler core whenever possible.
 *
 * 2) High enough resolution for the BPF scheduler use cases: In most BPF
 *  scheduler use cases, the required clock resolution is lower than the most
 *  accurate hardware clock (e.g., rdtsc in x86). scx_bpf_now() basically
 *  uses the rq clock in the scheduler core whenever it is valid. It considers
 *  that the rq clock is valid from the time the rq clock is updated
 *  (update_rq_clock) until the rq is unlocked (rq_unpin_lock).
 *
 * 3) Monotonically non-decreasing clock for the same CPU: scx_bpf_now()
 *  guarantees the clock never goes backward when comparing them in the same
 *  CPU. On the other hand, when comparing clocks in different CPUs, there
 *  is no such guarantee -- the clock can go backward. It provides a
 *  monotonically *non-decreasing* clock so that it would provide the same
 *  clock values in two different scx_bpf_now() calls in the same CPU
 *  during the same period of when the rq clock is valid.
 */
u64 scx_bpf_now(void) __ksym __weak;

/*
 * scx_bpf_events - Get a system-wide event counter to
 * @events: output buffer from a BPF program
 * @events__sz: @events len, must end in '__sz'' for the verifier
 */
void scx_bpf_events(struct scx_event_stats *events, size_t events__sz) __ksym __weak;

/*
 * Use the following as @it__iter when calling scx_bpf_dsq_move[_vtime]() from
 * within bpf_for_each() loops.
 */
#define BPF_FOR_EACH_ITER	(&___it)

#define scx_read_event(e, name)							\
	(bpf_core_field_exists((e)->name) ? (e)->name : 0)

static inline __attribute__((format(printf, 1, 2)))
void ___scx_bpf_bstr_format_checker(const char *fmt, ...) {}

#define SCX_STRINGIFY(x) #x
#define SCX_TOSTRING(x) SCX_STRINGIFY(x)

/*
 * Helper macro for initializing the fmt and variadic argument inputs to both
 * bstr exit kfuncs. Callers to this function should use ___fmt and ___param to
 * refer to the initialized list of inputs to the bstr kfunc.
 */
#define scx_bpf_bstr_preamble(fmt, args...)					\
	static char ___fmt[] = fmt;						\
	/*									\
	 * Note that __param[] must have at least one				\
	 * element to keep the verifier happy.					\
	 */									\
	unsigned long long ___param[___bpf_narg(args) ?: 1] = {};		\
										\
	_Pragma("GCC diagnostic push")						\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")			\
	___bpf_fill(___param, args);						\
	_Pragma("GCC diagnostic pop")

/*
 * scx_bpf_exit() wraps the scx_bpf_exit_bstr() kfunc with variadic arguments
 * instead of an array of u64. Using this macro will cause the scheduler to
 * exit cleanly with the specified exit code being passed to user space.
 */
#define scx_bpf_exit(code, fmt, args...)					\
({										\
	scx_bpf_bstr_preamble(fmt, args)					\
	scx_bpf_exit_bstr(code, ___fmt, ___param, sizeof(___param));		\
	___scx_bpf_bstr_format_checker(fmt, ##args);				\
})

/*
 * scx_bpf_error() wraps the scx_bpf_error_bstr() kfunc with variadic arguments
 * instead of an array of u64. Invoking this macro will cause the scheduler to
 * exit in an erroneous state, with diagnostic information being passed to the
 * user. It appends the file and line number to aid debugging.
 */
#define scx_bpf_error(fmt, args...)						\
({										\
	scx_bpf_bstr_preamble(							\
		__FILE__ ":" SCX_TOSTRING(__LINE__) ": " fmt, ##args)		\
	scx_bpf_error_bstr(___fmt, ___param, sizeof(___param));			\
	___scx_bpf_bstr_format_checker(						\
		__FILE__ ":" SCX_TOSTRING(__LINE__) ": " fmt, ##args);		\
})

/*
 * scx_bpf_dump() wraps the scx_bpf_dump_bstr() kfunc with variadic arguments
 * instead of an array of u64. To be used from ops.dump() and friends.
 */
#define scx_bpf_dump(fmt, args...)						\
({										\
	scx_bpf_bstr_preamble(fmt, args)					\
	scx_bpf_dump_bstr(___fmt, ___param, sizeof(___param));			\
	___scx_bpf_bstr_format_checker(fmt, ##args);				\
})

/*
 * scx_bpf_dump_header() is a wrapper around scx_bpf_dump that adds a header
 * of system information for debugging.
 */
#define scx_bpf_dump_header()							\
({										\
	scx_bpf_dump("kernel: %d.%d.%d %s\ncc: %s\n",				\
		     LINUX_KERNEL_VERSION >> 16,				\
		     LINUX_KERNEL_VERSION >> 8 & 0xFF,				\
		     LINUX_KERNEL_VERSION & 0xFF,				\
		     CONFIG_LOCALVERSION,					\
		     CONFIG_CC_VERSION_TEXT);					\
})

#define BPF_STRUCT_OPS(name, args...)						\
SEC("struct_ops/"#name)								\
BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...)					\
SEC("struct_ops.s/"#name)							\
BPF_PROG(name, ##args)

/**
 * RESIZABLE_ARRAY - Generates annotations for an array that may be resized
 * @elfsec: the data section of the BPF program in which to place the array
 * @arr: the name of the array
 *
 * libbpf has an API for setting map value sizes. Since data sections (i.e.
 * bss, data, rodata) themselves are maps, a data section can be resized. If
 * a data section has an array as its last element, the BTF info for that
 * array will be adjusted so that length of the array is extended to meet the
 * new length of the data section. This macro annotates an array to have an
 * element count of one with the assumption that this array can be resized
 * within the userspace program. It also annotates the section specifier so
 * this array exists in a custom sub data section which can be resized
 * independently.
 *
 * See RESIZE_ARRAY() for the userspace convenience macro for resizing an
 * array declared with RESIZABLE_ARRAY().
 */
#define RESIZABLE_ARRAY(elfsec, arr) arr[1] SEC("."#elfsec"."#arr)

/**
 * MEMBER_VPTR - Obtain the verified pointer to a struct or array member
 * @base: struct or array to index
 * @member: dereferenced member (e.g. .field, [idx0][idx1], .field[idx0] ...)
 *
 * The verifier often gets confused by the instruction sequence the compiler
 * generates for indexing struct fields or arrays. This macro forces the
 * compiler to generate a code sequence which first calculates the byte offset,
 * checks it against the struct or array size and add that byte offset to
 * generate the pointer to the member to help the verifier.
 *
 * Ideally, we want to abort if the calculated offset is out-of-bounds. However,
 * BPF currently doesn't support abort, so evaluate to %NULL instead. The caller
 * must check for %NULL and take appropriate action to appease the verifier. To
 * avoid confusing the verifier, it's best to check for %NULL and dereference
 * immediately.
 *
 *	vptr = MEMBER_VPTR(my_array, [i][j]);
 *	if (!vptr)
 *		return error;
 *	*vptr = new_value;
 *
 * sizeof(@base) should encompass the memory area to be accessed and thus can't
 * be a pointer to the area. Use `MEMBER_VPTR(*ptr, .member)` instead of
 * `MEMBER_VPTR(ptr, ->member)`.
 */
#define MEMBER_VPTR(base, member) (typeof((base) member) *)			\
({										\
	u64 __base = (u64)&(base);						\
	u64 __addr = (u64)&((base) member) - __base;				\
	_Static_assert(sizeof(base) >= sizeof((base) member),			\
		       "@base is smaller than @member, is @base a pointer?");	\
	asm volatile (								\
		"if %0 <= %[max] goto +2\n"					\
		"%0 = 0\n"							\
		"goto +1\n"							\
		"%0 += %1\n"							\
		: "+r"(__addr)							\
		: "r"(__base),							\
		  [max]"i"(sizeof(base) - sizeof((base) member)));		\
	__addr;									\
})

/**
 * ARRAY_ELEM_PTR - Obtain the verified pointer to an array element
 * @arr: array to index into
 * @i: array index
 * @n: number of elements in array
 *
 * Similar to MEMBER_VPTR() but is intended for use with arrays where the
 * element count needs to be explicit.
 * It can be used in cases where a global array is defined with an initial
 * size but is intended to be be resized before loading the BPF program.
 * Without this version of the macro, MEMBER_VPTR() will use the compile time
 * size of the array to compute the max, which will result in rejection by
 * the verifier.
 */
#define ARRAY_ELEM_PTR(arr, i, n) (typeof(arr[i]) *)				\
({										\
	u64 __base = (u64)arr;							\
	u64 __addr = (u64)&(arr[i]) - __base;					\
	asm volatile (								\
		"if %0 <= %[max] goto +2\n"					\
		"%0 = 0\n"							\
		"goto +1\n"							\
		"%0 += %1\n"							\
		: "+r"(__addr)							\
		: "r"(__base),							\
		  [max]"r"(sizeof(arr[0]) * ((n) - 1)));			\
	__addr;									\
})


/*
 * BPF declarations and helpers
 */

/* list and rbtree */
#define __contains(name, node) __attribute__((btf_decl_tag("contains:" #name ":" #node)))
#define private(name) SEC(".data." #name) __hidden __attribute__((aligned(8)))

void *bpf_obj_new_impl(__u64 local_type_id, void *meta) __ksym;
void bpf_obj_drop_impl(void *kptr, void *meta) __ksym;

#define bpf_obj_new(type) ((type *)bpf_obj_new_impl(bpf_core_type_id_local(type), NULL))
#define bpf_obj_drop(kptr) bpf_obj_drop_impl(kptr, NULL)

int bpf_list_push_front_impl(struct bpf_list_head *head,
				    struct bpf_list_node *node,
				    void *meta, __u64 off) __ksym;
#define bpf_list_push_front(head, node) bpf_list_push_front_impl(head, node, NULL, 0)

int bpf_list_push_back_impl(struct bpf_list_head *head,
				   struct bpf_list_node *node,
				   void *meta, __u64 off) __ksym;
#define bpf_list_push_back(head, node) bpf_list_push_back_impl(head, node, NULL, 0)

struct bpf_list_node *bpf_list_pop_front(struct bpf_list_head *head) __ksym;
struct bpf_list_node *bpf_list_pop_back(struct bpf_list_head *head) __ksym;
struct bpf_rb_node *bpf_rbtree_remove(struct bpf_rb_root *root,
				      struct bpf_rb_node *node) __ksym;
int bpf_rbtree_add_impl(struct bpf_rb_root *root, struct bpf_rb_node *node,
			bool (less)(struct bpf_rb_node *a, const struct bpf_rb_node *b),
			void *meta, __u64 off) __ksym;
#define bpf_rbtree_add(head, node, less) bpf_rbtree_add_impl(head, node, less, NULL, 0)

struct bpf_rb_node *bpf_rbtree_first(struct bpf_rb_root *root) __ksym;

void *bpf_refcount_acquire_impl(void *kptr, void *meta) __ksym;
#define bpf_refcount_acquire(kptr) bpf_refcount_acquire_impl(kptr, NULL)

/* task */

/**
 * bpf_task_from_pid - Find a struct task_struct from its pid by looking it up
 * in the root pid namespace idr. If a task is returned, it must either be
 * stored in a map, or released with bpf_task_release().
 * @pid: The pid of the task being looked up.
 */
struct task_struct *bpf_task_from_pid(s32 pid) __ksym;

/**
 * bpf_task_acquire - Acquire a reference to a task. A task acquired by this
 * kfunc which is not stored in a map as a kptr, must be released by calling
 * bpf_task_release().
 * @p: The task on which a reference is being acquired.
 */
struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;

/**
 * bpf_task_release - Release the reference acquired on a task.
 * @p: The task on which a reference is being released.
 */
void bpf_task_release(struct task_struct *p) __ksym;

/* cgroup */

/**
 * bpf_cgroup_ancestor - Perform a lookup on an entry in a cgroup's ancestor
 * array. A cgroup returned by this kfunc which is not subsequently stored in a
 * map, must be released by calling bpf_cgroup_release().
 * @cgrp: The cgroup for which we're performing a lookup.
 * @level: The level of ancestor to look up.
 */
struct cgroup *bpf_cgroup_ancestor(struct cgroup *cgrp, int level) __ksym;

/**
 * bpf_cgroup_release - Release the reference acquired on a cgroup.
 * If this kfunc is invoked in an RCU read region, the cgroup is guaranteed to
 * not be freed until the current grace period has ended, even if its refcount
 * drops to 0.
 * @cgrp: The cgroup on which a reference is being released.
 */
void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

/**
 * bpf_cgroup_from_id - Find a cgroup from its ID. A cgroup returned by this
 * kfunc which is not subsequently stored in a map, must be released by calling
 * bpf_cgroup_release().
 * @cgid: cgroup id.
 */
struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;

/* css iteration */
struct bpf_iter_css;
struct cgroup_subsys_state;
extern int bpf_iter_css_new(struct bpf_iter_css *it,
			    struct cgroup_subsys_state *start,
			    unsigned int flags) __weak __ksym;
extern struct cgroup_subsys_state *
bpf_iter_css_next(struct bpf_iter_css *it) __weak __ksym;
extern void bpf_iter_css_destroy(struct bpf_iter_css *it) __weak __ksym;

/* cpumask */

/**
 * bpf_cpumask_create() - Create a mutable BPF cpumask.
 *
 * Allocates a cpumask that can be queried, mutated, acquired, and released by
 * a BPF program. The cpumask returned by this function must either be embedded
 * in a map as a kptr, or freed with bpf_cpumask_release().
 *
 * bpf_cpumask_create() allocates memory using the BPF memory allocator, and
 * will not block. It may return NULL if no memory is available.
 *
 * Return:
 * * A pointer to a new struct bpf_cpumask instance on success.
 * * NULL if the BPF memory allocator is out of memory.
 */
struct bpf_cpumask *bpf_cpumask_create(void) __ksym;

/**
 * bpf_cpumask_acquire() - Acquire a reference to a BPF cpumask.
 * @cpumask: The BPF cpumask being acquired. The cpumask must be a trusted
 *	     pointer.
 *
 * Acquires a reference to a BPF cpumask. The cpumask returned by this function
 * must either be embedded in a map as a kptr, or freed with
 * bpf_cpumask_release().
 *
 * Return:
 * * The struct bpf_cpumask pointer passed to the function.
 *
 */
struct bpf_cpumask *bpf_cpumask_acquire(struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_release() - Release a previously acquired BPF cpumask.
 * @cpumask: The cpumask being released.
 *
 * Releases a previously acquired reference to a BPF cpumask. When the final
 * reference of the BPF cpumask has been released, it is subsequently freed in
 * an RCU callback in the BPF memory allocator.
 */
void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_first() - Get the index of the first nonzero bit in the cpumask.
 * @cpumask: The cpumask being queried.
 *
 * Find the index of the first nonzero bit of the cpumask. A struct bpf_cpumask
 * pointer may be safely passed to this function.
 *
 * Return:
 * * The index of the first nonzero bit in the struct cpumask.
 */
u32 bpf_cpumask_first(const struct cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_first_zero() - Get the index of the first unset bit in the
 *			      cpumask.
 * @cpumask: The cpumask being queried.
 *
 * Find the index of the first unset bit of the cpumask. A struct bpf_cpumask
 * pointer may be safely passed to this function.
 *
 * Return:
 * * The index of the first zero bit in the struct cpumask.
 */
u32 bpf_cpumask_first_zero(const struct cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_set_cpu() - Set a bit for a CPU in a BPF cpumask.
 * @cpu: The CPU to be set in the cpumask.
 * @cpumask: The BPF cpumask in which a bit is being set.
 */
void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_clear_cpu() - Clear a bit for a CPU in a BPF cpumask.
 * @cpu: The CPU to be cleared from the cpumask.
 * @cpumask: The BPF cpumask in which a bit is being cleared.
 */
void bpf_cpumask_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_test_cpu() - Test whether a CPU is set in a cpumask.
 * @cpu: The CPU being queried for.
 * @cpumask: The cpumask being queried for containing a CPU.
 *
 * Return:
 * * true  - @cpu is set in the cpumask
 * * false - @cpu was not set in the cpumask, or @cpu is an invalid cpu.
 */
bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_test_and_set_cpu() - Atomically test and set a CPU in a BPF cpumask.
 * @cpu: The CPU being set and queried for.
 * @cpumask: The BPF cpumask being set and queried for containing a CPU.
 *
 * Return:
 * * true  - @cpu is set in the cpumask
 * * false - @cpu was not set in the cpumask, or @cpu is invalid.
 */
bool bpf_cpumask_test_and_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_test_and_clear_cpu() - Atomically test and clear a CPU in a BPF
 *				      cpumask.
 * @cpu: The CPU being cleared and queried for.
 * @cpumask: The BPF cpumask being cleared and queried for containing a CPU.
 *
 * Return:
 * * true  - @cpu is set in the cpumask
 * * false - @cpu was not set in the cpumask, or @cpu is invalid.
 */
bool bpf_cpumask_test_and_clear_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_setall() - Set all of the bits in a BPF cpumask.
 * @cpumask: The BPF cpumask having all of its bits set.
 */
void bpf_cpumask_setall(struct bpf_cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_clear() - Clear all of the bits in a BPF cpumask.
 * @cpumask: The BPF cpumask being cleared.
 */
void bpf_cpumask_clear(struct bpf_cpumask *cpumask) __ksym;
/**
 * bpf_cpumask_and() - AND two cpumasks and store the result.
 * @dst: The BPF cpumask where the result is being stored.
 * @src1: The first input.
 * @src2: The second input.
 *
 * Return:
 * * true  - @dst has at least one bit set following the operation
 * * false - @dst is empty following the operation
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
bool bpf_cpumask_and(struct bpf_cpumask *dst, const struct cpumask *src1,
		     const struct cpumask *src2) __ksym;
/**
 * bpf_cpumask_or() - OR two cpumasks and store the result.
 * @dst: The BPF cpumask where the result is being stored.
 * @src1: The first input.
 * @src2: The second input.
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
void bpf_cpumask_or(struct bpf_cpumask *dst, const struct cpumask *src1,
		    const struct cpumask *src2) __ksym;

/**
 * bpf_cpumask_xor() - XOR two cpumasks and store the result.
 * @dst: The BPF cpumask where the result is being stored.
 * @src1: The first input.
 * @src2: The second input.
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
void bpf_cpumask_xor(struct bpf_cpumask *dst, const struct cpumask *src1,
		     const struct cpumask *src2) __ksym;

/**
 * bpf_cpumask_equal() - Check two cpumasks for equality.
 * @src1: The first input.
 * @src2: The second input.
 *
 * Return:
 * * true   - @src1 and @src2 have the same bits set.
 * * false  - @src1 and @src2 differ in at least one bit.
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
bool bpf_cpumask_equal(const struct cpumask *src1, const struct cpumask *src2) __ksym;

/**
 * bpf_cpumask_intersects() - Check two cpumasks for overlap.
 * @src1: The first input.
 * @src2: The second input.
 *
 * Return:
 * * true   - @src1 and @src2 have at least one of the same bits set.
 * * false  - @src1 and @src2 don't have any of the same bits set.
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
bool bpf_cpumask_intersects(const struct cpumask *src1, const struct cpumask *src2) __ksym;

/**
 * bpf_cpumask_subset() - Check if a cpumask is a subset of another.
 * @src1: The first cpumask being checked as a subset.
 * @src2: The second cpumask being checked as a superset.
 *
 * Return:
 * * true   - All of the bits of @src1 are set in @src2.
 * * false  - At least one bit in @src1 is not set in @src2.
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
bool bpf_cpumask_subset(const struct cpumask *src1, const struct cpumask *src2) __ksym;

/**
 * bpf_cpumask_empty() - Check if a cpumask is empty.
 * @cpumask: The cpumask being checked.
 *
 * Return:
 * * true   - None of the bits in @cpumask are set.
 * * false  - At least one bit in @cpumask is set.
 *
 * A struct bpf_cpumask pointer may be safely passed to @cpumask.
 */
bool bpf_cpumask_empty(const struct cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_full() - Check if a cpumask has all bits set.
 * @cpumask: The cpumask being checked.
 *
 * Return:
 * * true   - All of the bits in @cpumask are set.
 * * false  - At least one bit in @cpumask is cleared.
 *
 * A struct bpf_cpumask pointer may be safely passed to @cpumask.
 */
bool bpf_cpumask_full(const struct cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_copy() - Copy the contents of a cpumask into a BPF cpumask.
 * @dst: The BPF cpumask being copied into.
 * @src: The cpumask being copied.
 *
 * A struct bpf_cpumask pointer may be safely passed to @src.
 */
void bpf_cpumask_copy(struct bpf_cpumask *dst, const struct cpumask *src) __ksym;

/**
 * bpf_cpumask_any_distribute() - Return a random set CPU from a cpumask.
 * @cpumask: The cpumask being queried.
 *
 * Return:
 * * A random set bit within [0, num_cpus) if at least one bit is set.
 * * >= num_cpus if no bit is set.
 *
 * A struct bpf_cpumask pointer may be safely passed to @src.
 */
u32 bpf_cpumask_any_distribute(const struct cpumask *cpumask) __ksym;

/**
 * bpf_cpumask_any_and_distribute() - Return a random set CPU from the AND of
 *				      two cpumasks.
 * @src1: The first cpumask.
 * @src2: The second cpumask.
 *
 * Return:
 * * A random set bit within [0, num_cpus) from the AND of two cpumasks, if at
 *   least one bit is set.
 * * >= num_cpus if no bit is set.
 *
 * struct bpf_cpumask pointers may be safely passed to @src1 and @src2.
 */
u32 bpf_cpumask_any_and_distribute(const struct cpumask *src1,
				   const struct cpumask *src2) __ksym;

/**
 * bpf_cpumask_weight() - Return the number of bits in @cpumask.
 * @cpumask: The cpumask being queried.
 *
 * Count the number of set bits in the given cpumask.
 *
 * Return:
 * * The number of bits set in the mask.
 */
u32 bpf_cpumask_weight(const struct cpumask *cpumask) __ksym;

/**
 * bpf_iter_bits_new() - Initialize a new bits iterator for a given memory area
 * @it: The new bpf_iter_bits to be created
 * @unsafe_ptr__ign: A pointer pointing to a memory area to be iterated over
 * @nr_words: The size of the specified memory area, measured in 8-byte units.
 * The maximum value of @nr_words is @BITS_ITER_NR_WORDS_MAX. This limit may be
 * further reduced by the BPF memory allocator implementation.
 *
 * This function initializes a new bpf_iter_bits structure for iterating over
 * a memory area which is specified by the @unsafe_ptr__ign and @nr_words. It
 * copies the data of the memory area to the newly created bpf_iter_bits @it for
 * subsequent iteration operations.
 *
 * On success, 0 is returned. On failure, ERR is returned.
 */
int bpf_iter_bits_new(struct bpf_iter_bits *it, const u64 *unsafe_ptr__ign, u32 nr_words) __ksym;

/**
 * bpf_iter_bits_next() - Get the next bit in a bpf_iter_bits
 * @it: The bpf_iter_bits to be checked
 *
 * This function returns a pointer to a number representing the value of the
 * next bit in the bits.
 *
 * If there are no further bits available, it returns NULL.
 */
int *bpf_iter_bits_next(struct bpf_iter_bits *it) __ksym;

/**
 * bpf_iter_bits_destroy() - Destroy a bpf_iter_bits
 * @it: The bpf_iter_bits to be destroyed
 *
 * Destroy the resource associated with the bpf_iter_bits.
 */
void bpf_iter_bits_destroy(struct bpf_iter_bits *it) __ksym;

#define def_iter_struct(name)							\
struct bpf_iter_##name {							\
    struct bpf_iter_bits it;							\
    const struct cpumask *bitmap;						\
};

#define def_iter_new(name)							\
static inline int bpf_iter_##name##_new(					\
	struct bpf_iter_##name *it, const u64 *unsafe_ptr__ign, u32 nr_words)	\
{										\
	it->bitmap = scx_bpf_get_##name##_cpumask();				\
	return bpf_iter_bits_new(&it->it, (const u64 *)it->bitmap,		\
				 sizeof(struct cpumask) / 8);			\
}

#define def_iter_next(name)							\
static inline int *bpf_iter_##name##_next(struct bpf_iter_##name *it) {		\
	return bpf_iter_bits_next(&it->it);					\
}

#define def_iter_destroy(name)							\
static inline void bpf_iter_##name##_destroy(struct bpf_iter_##name *it) {	\
	scx_bpf_put_cpumask(it->bitmap);					\
	bpf_iter_bits_destroy(&it->it);						\
}
#define def_for_each_cpu(cpu, name) for_each_##name##_cpu(cpu)

/// Provides iterator for possible and online cpus.
///
/// # Example
///
/// ```
/// static inline void example_use() {
///     int *cpu;
///
///     for_each_possible_cpu(cpu){
///         bpf_printk("CPU %d is possible", *cpu);
///     }
///
///     for_each_online_cpu(cpu){
///         bpf_printk("CPU %d is online", *cpu);
///     }
/// }
/// ```
def_iter_struct(possible);
def_iter_new(possible);
def_iter_next(possible);
def_iter_destroy(possible);
#define for_each_possible_cpu(cpu) bpf_for_each(possible, cpu, NULL, 0)

def_iter_struct(online);
def_iter_new(online);
def_iter_next(online);
def_iter_destroy(online);
#define for_each_online_cpu(cpu) bpf_for_each(online, cpu, NULL, 0)

/*
 * Access a cpumask in read-only mode (typically to check bits).
 */
static __always_inline const struct cpumask *cast_mask(struct bpf_cpumask *mask)
{
	return (const struct cpumask *)mask;
}

/*
 * Return true if task @p cannot migrate to a different CPU, false
 * otherwise.
 */
static inline bool is_migration_disabled(const struct task_struct *p)
{
	if (bpf_core_field_exists(p->migration_disabled))
		return p->migration_disabled;
	return false;
}

/* rcu */
void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

/*
 * Time helpers, most of which are from jiffies.h.
 */

/**
 * time_delta - Calculate the delta between new and old time stamp
 * @after: first comparable as u64
 * @before: second comparable as u64
 *
 * Return: the time difference, which is >= 0
 */
static inline s64 time_delta(u64 after, u64 before)
{
	return (s64)(after - before) > 0 ? (s64)(after - before) : 0;
}

/**
 * time_after - returns true if the time a is after time b.
 * @a: first comparable as u64
 * @b: second comparable as u64
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 *
 * Return: %true is time a is after time b, otherwise %false.
 */
static inline bool time_after(u64 a, u64 b)
{
	 return (s64)(b - a) < 0;
}

/**
 * time_before - returns true if the time a is before time b.
 * @a: first comparable as u64
 * @b: second comparable as u64
 *
 * Return: %true is time a is before time b, otherwise %false.
 */
static inline bool time_before(u64 a, u64 b)
{
	return time_after(b, a);
}

/**
 * time_after_eq - returns true if the time a is after or the same as time b.
 * @a: first comparable as u64
 * @b: second comparable as u64
 *
 * Return: %true is time a is after or the same as time b, otherwise %false.
 */
static inline bool time_after_eq(u64 a, u64 b)
{
	 return (s64)(a - b) >= 0;
}

/**
 * time_before_eq - returns true if the time a is before or the same as time b.
 * @a: first comparable as u64
 * @b: second comparable as u64
 *
 * Return: %true is time a is before or the same as time b, otherwise %false.
 */
static inline bool time_before_eq(u64 a, u64 b)
{
	return time_after_eq(b, a);
}

/**
 * time_in_range - Calculate whether a is in the range of [b, c].
 * @a: time to test
 * @b: beginning of the range
 * @c: end of the range
 *
 * Return: %true is time a is in the range [b, c], otherwise %false.
 */
static inline bool time_in_range(u64 a, u64 b, u64 c)
{
	return time_after_eq(a, b) && time_before_eq(a, c);
}

/**
 * time_in_range_open - Calculate whether a is in the range of [b, c).
 * @a: time to test
 * @b: beginning of the range
 * @c: end of the range
 *
 * Return: %true is time a is in the range [b, c), otherwise %false.
 */
static inline bool time_in_range_open(u64 a, u64 b, u64 c)
{
	return time_after_eq(a, b) && time_before(a, c);
}


/*
 * Other helpers
 */

/* useful compiler attributes */
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __maybe_unused __attribute__((__unused__))

/*
 * READ/WRITE_ONCE() are from kernel (include/asm-generic/rwonce.h). They
 * prevent compiler from caching, redoing or reordering reads or writes.
 */
typedef __u8  __attribute__((__may_alias__))  __u8_alias_t;
typedef __u16 __attribute__((__may_alias__)) __u16_alias_t;
typedef __u32 __attribute__((__may_alias__)) __u32_alias_t;
typedef __u64 __attribute__((__may_alias__)) __u64_alias_t;

static __always_inline void __read_once_size(const volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(__u8_alias_t  *) res = *(volatile __u8_alias_t  *) p; break;
	case 2: *(__u16_alias_t *) res = *(volatile __u16_alias_t *) p; break;
	case 4: *(__u32_alias_t *) res = *(volatile __u32_alias_t *) p; break;
	case 8: *(__u64_alias_t *) res = *(volatile __u64_alias_t *) p; break;
	default:
		barrier();
		__builtin_memcpy((void *)res, (const void *)p, size);
		barrier();
	}
}

static __always_inline void __write_once_size(volatile void *p, void *res, int size)
{
	switch (size) {
	case 1: *(volatile  __u8_alias_t *) p = *(__u8_alias_t  *) res; break;
	case 2: *(volatile __u16_alias_t *) p = *(__u16_alias_t *) res; break;
	case 4: *(volatile __u32_alias_t *) p = *(__u32_alias_t *) res; break;
	case 8: *(volatile __u64_alias_t *) p = *(__u64_alias_t *) res; break;
	default:
		barrier();
		__builtin_memcpy((void *)p, (const void *)res, size);
		barrier();
	}
}

/*
 * __unqual_typeof(x) - Declare an unqualified scalar type, leaving
 *			non-scalar types unchanged,
 *
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 *
 * This is copied verbatim from kernel's include/linux/compiler_types.h, but
 * with default expression (for pointers) changed from (x) to (typeof(x)0).
 *
 * This is because LLVM has a bug where for lvalue (x), it does not get rid of
 * an extra address_space qualifier, but does in case of rvalue (typeof(x)0).
 * Hence, for pointers, we need to create an rvalue expression to get the
 * desired type. See https://github.com/llvm/llvm-project/issues/53400.
 */
#define __scalar_type_to_expr_cases(type) \
	unsigned type : (unsigned type)0, signed type : (signed type)0

#define __unqual_typeof(x)                              \
	typeof(_Generic((x),                            \
		char: (char)0,                          \
		__scalar_type_to_expr_cases(char),      \
		__scalar_type_to_expr_cases(short),     \
		__scalar_type_to_expr_cases(int),       \
		__scalar_type_to_expr_cases(long),      \
		__scalar_type_to_expr_cases(long long), \
		default: (typeof(x))0))

#define READ_ONCE(x)								\
({										\
	union { __unqual_typeof(x) __val; char __c[1]; } __u =			\
		{ .__c = { 0 } };						\
	__read_once_size((__unqual_typeof(x) *)&(x), __u.__c, sizeof(x));	\
	__u.__val;								\
})

#define WRITE_ONCE(x, val)							\
({										\
	union { __unqual_typeof(x) __val; char __c[1]; } __u =			\
		{ .__val = (val) }; 						\
	__write_once_size((__unqual_typeof(x) *)&(x), __u.__c, sizeof(x));	\
	__u.__val;								\
})

/*
 * log2_u32 - Compute the base 2 logarithm of a 32-bit exponential value.
 * @v: The value for which we're computing the base 2 logarithm.
 */
static inline u32 log2_u32(u32 v)
{
        u32 r;
        u32 shift;

        r = (v > 0xFFFF) << 4; v >>= r;
        shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
        shift = (v > 0xF) << 2; v >>= shift; r |= shift;
        shift = (v > 0x3) << 1; v >>= shift; r |= shift;
        r |= (v >> 1);
        return r;
}

/*
 * log2_u64 - Compute the base 2 logarithm of a 64-bit exponential value.
 * @v: The value for which we're computing the base 2 logarithm.
 */
static inline u32 log2_u64(u64 v)
{
        u32 hi = v >> 32;
        if (hi)
                return log2_u32(hi) + 32 + 1;
        else
                return log2_u32(v) + 1;
}

/*
 * Return a value proportionally scaled to the task's weight.
 */
static inline u64 scale_by_task_weight(const struct task_struct *p, u64 value)
{
	return (value * p->scx.weight) / 100;
}

/*
 * Return a value inversely proportional to the task's weight.
 */
static inline u64 scale_by_task_weight_inverse(const struct task_struct *p, u64 value)
{
	return value * 100 / p->scx.weight;
}


#include "compat.bpf.h"
#include "enums.bpf.h"

#endif	/* __SCX_COMMON_BPF_H */
