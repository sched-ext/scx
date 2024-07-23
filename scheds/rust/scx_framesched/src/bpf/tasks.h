/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __TASKS_H
#define __TASKS_H

#ifndef SCX_MAIN_SCHED
#error "Should only be included from the main sched BPF C file"
#endif

#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

#include "intf.h"

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctxs SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 8192 * sizeof(struct task_notif_msg));
} task_notifier SEC(".maps");

/* Payload for notifying user space about updated task context. */
struct task_notif_reply {
	int pid;
	u64 token;
	enum fs_dl_qos qos;
};

static struct task_ctx *tasks_try_lookup_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctxs, p, 0, 0);
}

static struct task_ctx *tasks_lookup_ctx(struct task_struct *p)
{
	struct task_ctx *taskc;

	taskc = tasks_try_lookup_ctx(p);
	if (!taskc)
		scx_bpf_error("Failed to lookup task ctx for %s[%d]", p->comm, p->pid);

	return taskc;
}

static int tasks_init_task(struct task_struct *p, __maybe_unused struct scx_init_task_args *args)
{
	struct task_ctx *taskc;
	int err;

	taskc = bpf_task_storage_get(&task_ctxs, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!taskc)
		return -ENOMEM;

	err = create_assign_cpumask(&taskc->cpumask);
	if (err)
		return err;

	taskc->runtime.qos = weight_to_qos(p->scx.weight);

	return 0;
}

static void tasks_publish_notif(struct task_struct *p, struct task_ctx *tctx)
{
	struct task_notif_msg *notif;
	static u64 token = 0;

	/*
	 * Let user space know that the task needs to have its QoS reset.
	 */
	notif = bpf_ringbuf_reserve(&task_notifier, sizeof(*notif), 0);
	if (!notif) {
		scx_bpf_error("Failed to reserve task notif");
		return;
	}

	__sync_fetch_and_add(&token, 1);

	tctx->token = token;
	notif->token = token;
	notif->pid = p->pid;

	bpf_ringbuf_submit(notif, 0);
}

SEC("syscall")
int update_task_qos(struct task_notif_reply *input)
{
	int pid = input->pid;
	u64 token = input->token;
	struct task_ctx *tctx;
	struct task_struct *p = bpf_task_from_pid(pid);
	int err = -ENOENT;

	if (!p)
		return -ENOENT;

	bpf_rcu_read_lock();
	tctx = tasks_lookup_ctx(p);
	if (!tctx)
		goto unlock_out;

	if (token != tctx->token) {
		err = -ECANCELED;
		goto unlock_out;
	}

	tctx->token = -1;
	tctx->runtime.qos = input->qos;
	err = 0;

unlock_out:
	bpf_task_release(p);
	bpf_rcu_read_unlock();
	return err;
}

#endif // __TASKS_H
