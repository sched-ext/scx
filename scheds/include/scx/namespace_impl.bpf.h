/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 */
#include "namespace.bpf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>


__hidden struct pid* get_task_pid_ptr(const struct task_struct* task,
				      enum pid_type type)
{
	// Returns the pid pointer of the given task. See get_task_pid_ptr for
	// the kernel implementation.
	return (type == PIDTYPE_PID) ? BPF_CORE_READ(task, thread_pid) :
		BPF_CORE_READ(task, signal, pids[type]);
}

__hidden struct pid_namespace* get_task_pid_ns(const struct task_struct* task,
					       enum pid_type type)
{
	struct pid_namespace* ns;
	struct pid* p;
	int level;

	// See kernel function task_active_pid_ns in pid.c which calls into
	// ns_of_pid. Returns the pid namespace of the given task.
	if (!task)
		task = (struct task_struct*)bpf_get_current_task();

	if (!task)
		return NULL;

	p = get_task_pid_ptr(task, type);
	if (!p)
		return NULL;

	level = BPF_CORE_READ(p, level);
	ns = BPF_CORE_READ(p, numbers[level].ns);
	return ns;
}

__hidden pid_t get_pid_nr_ns(struct pid* pid, struct pid_namespace* ns)
{
	int level, ns_level;
	pid_t nr = 0;

	/* This function implements the kernel equivalent pid_nr_ns in linux/pid.h */
	if (!pid || !ns)
		return nr;

	level = BPF_CORE_READ(pid, level);
	ns_level = BPF_CORE_READ(ns, level);
	if (ns_level <= level) {
		struct upid upid;

		upid = BPF_CORE_READ(pid, numbers[ns_level]);
		if (upid.ns == ns)
			nr = upid.nr;
	}
	return nr;
}

__hidden pid_t get_task_ns_pid(const struct task_struct* task)
{
	struct pid_namespace* ns;
	struct pid* p;

	if (!task)
		task = (struct task_struct*)bpf_get_current_task();

	ns = get_task_pid_ns(task, PIDTYPE_TGID);
	p = get_task_pid_ptr(task, PIDTYPE_PID);
	return get_pid_nr_ns(p, ns);
}

__hidden pid_t get_ns_pid(void)
{
	return get_task_ns_pid(NULL);
}
