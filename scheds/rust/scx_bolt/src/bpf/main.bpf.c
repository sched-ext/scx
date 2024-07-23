/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include <scx/user_exit_info.h>

char _license[] SEC("license") = "GPL";

const volatile u8 debug;

UEI_DEFINE(uei);

s32 BPF_STRUCT_OPS_SLEEPABLE(bolt_init)
{
	return 0;
}

void BPF_STRUCT_OPS(bolt_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(bolt,
	       .init			= (void *)bolt_init,
	       .exit			= (void *)bolt_exit,
	       .timeout_ms		= 10000,
	       .name			= "bolt");
