// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

/*
 * Test program to verify if kfuncs are supported in syscall programs.
 * This program tries to call bpf_cpumask_create() and bpf_cpumask_release()
 * which are kfuncs that should be available if the kernel supports
 * calling kfuncs from syscall programs (commit a8e03b6bbb2c).
 */
SEC("syscall")
int BPF_PROG(kfuncs_test_syscall)
{
	struct bpf_cpumask *mask;

	mask = bpf_cpumask_create();
	if (!mask)
		return -1;
	bpf_cpumask_release(mask);

	return 0;
}
