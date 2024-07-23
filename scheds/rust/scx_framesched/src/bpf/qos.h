/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __QOS_H
#define __QOS_H

#ifndef SCX_MAIN_SCHED
#error "Should only be included from the main sched BPF C file"
#endif

#include <scx/common.bpf.h>

#include "intf.h"

static enum fs_dl_qos weight_to_qos(u64 weight)
{
	if (weight < DEFAULT_WEIGHT)
		return FS_DL_QOS_LOW;
	else if (weight == DEFAULT_WEIGHT)
		return FS_DL_QOS_NORMAL;
	else if (weight < MAX_WEIGHT)
		return FS_DL_QOS_HIGH;
	else
		return FS_DL_QOS_MAX;
}

#endif /* __QOS_H */
