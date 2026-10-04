// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";
s32 scx_bpf_create_dsq(u64 id, s32 node) __ksym;
void scx_bpf_destroy_dsq(u64 id) __ksym;
s32 scx_bpf_dsq_nr_queued(u64 id) __ksym;
struct task_struct *scx_bpf_dsq_peek(u64 id) __ksym;
void scx_bpf_dsq_insert(struct task_struct *p, u64 id, u64 slice, u64 flags) __ksym;
bool scx_bpf_dsq_move_to_local(u64 id) __ksym;

struct results {
	u64 checks, errors, creates, duplicates, misses, race_ops;
	u64 small_inserts, large_inserts, small_moves, large_moves, peeks;
	u64 exit_kind;
};
struct results result;
static const u64 ids[] = {0, 1, 1026, 2047, 2048, 65536, 1ULL << 32,
			 (1ULL << 63) - 1};

static __always_inline void check(bool ok)
{
	__sync_fetch_and_add(&result.checks, 1);
	if (!ok)
		__sync_fetch_and_add(&result.errors, 1);
}

SEC("struct_ops.s/dsq_test_init")
s32 BPF_PROG(dsq_test_init)
{
	int i, r, err;

	check(scx_bpf_create_dsq(1ULL << 63, -1) == -22);
	for (r = 0; r < 16; r++) {
		for (i = 0; i < 8; i++) {
			u64 id = ids[i];

			check(scx_bpf_dsq_nr_queued(id) == -2);
			err = scx_bpf_create_dsq(id, -1);
			check(!err);
			if (err)
				return err;
			check(scx_bpf_dsq_nr_queued(id) == 0);
			check(scx_bpf_create_dsq(id, -1) == -17);
			scx_bpf_destroy_dsq(id);
			check(scx_bpf_dsq_nr_queued(id) == -2);
			scx_bpf_destroy_dsq(id);
			err = scx_bpf_create_dsq(id, -1);
			check(!err);
			if (err)
				return err;
			check(scx_bpf_dsq_nr_queued(id) == 0);
			scx_bpf_destroy_dsq(id);
			check(scx_bpf_dsq_nr_queued(id) == -2);
		}
	}
	if (result.errors)
		return -22;
	err = scx_bpf_create_dsq(7, -1);
	if (err)
		return err;
	return scx_bpf_create_dsq(4096, -1);
}

SEC("syscall")
int BPF_PROG(dsq_test_race)
{
	int i;

	for (i = 0; i < 32; i++) {
		s32 err = scx_bpf_create_dsq(2047, -1);
		s32 nr;

		check(err == 0 || err == -17);
		if (!err)
			__sync_fetch_and_add(&result.creates, 1);
		else if (err == -17)
			__sync_fetch_and_add(&result.duplicates, 1);
		nr = scx_bpf_dsq_nr_queued(2047);
		check(nr == 0 || nr == -2);
		if (nr == -2)
			__sync_fetch_and_add(&result.misses, 1);
		scx_bpf_destroy_dsq(2047);
		__sync_fetch_and_add(&result.race_ops, 1);
	}
	return 0;
}

SEC("struct_ops/dsq_test_enqueue")
void BPF_PROG(dsq_test_enqueue, struct task_struct *p, u64 flags)
{
	bool large = p->pid & 1;

	if (large)
		__sync_fetch_and_add(&result.large_inserts, 1);
	else
		__sync_fetch_and_add(&result.small_inserts, 1);
	scx_bpf_dsq_insert(p, large ? 4096 : 7, 1000000, flags);
}

SEC("struct_ops/dsq_test_dispatch")
void BPF_PROG(dsq_test_dispatch, s32 cpu, struct task_struct *prev)
{
	u64 first = cpu & 1 ? 4096 : 7;
	u64 second = cpu & 1 ? 7 : 4096;

	check(scx_bpf_dsq_nr_queued(first) >= 0);
	check(scx_bpf_dsq_nr_queued(second) >= 0);
	if (scx_bpf_dsq_peek(first))
		__sync_fetch_and_add(&result.peeks, 1);
	if (scx_bpf_dsq_move_to_local(first)) {
		if (first == 7)
			__sync_fetch_and_add(&result.small_moves, 1);
		else
			__sync_fetch_and_add(&result.large_moves, 1);
	} else if (scx_bpf_dsq_move_to_local(second)) {
		if (second == 7)
			__sync_fetch_and_add(&result.small_moves, 1);
		else
			__sync_fetch_and_add(&result.large_moves, 1);
	}
}

SEC("struct_ops/dsq_test_exit")
void BPF_PROG(dsq_test_exit, struct scx_exit_info *ei)
{
	result.exit_kind = ei->kind;
}

SEC(".struct_ops.link")
struct sched_ext_ops dsq_test_ops = {
	.init = (void *)dsq_test_init,
	.enqueue = (void *)dsq_test_enqueue,
	.dispatch = (void *)dsq_test_dispatch,
	.exit = (void *)dsq_test_exit,
	.timeout_ms = 5000,
	.name = "dsq_index_test",
};
