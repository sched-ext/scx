/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_tiny.bpf.skel.h"

static volatile int exit_req;

static void sigint_handler(int sig)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_tiny *skel;
	struct bpf_link *link;
	__u64 ecode;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(tiny_ops, scx_tiny);

	SCX_OPS_LOAD(skel, tiny_ops, scx_tiny, uei);
	link = SCX_OPS_ATTACH(skel, tiny_ops, scx_tiny);

	fprintf(stdout, "tiny is running\n");
	fflush(stdout);

	while (!exit_req && !UEI_EXITED(skel, uei))
		sleep(1);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_tiny__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
