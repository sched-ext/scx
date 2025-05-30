/* Copyright (c) Meta Platforms, Inc. and affiliates. */
#ifndef __LAYERED_UTIL_H
#define __LAYERED_UTIL_H

#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

extern const volatile u32 debug;

#define dbg(fmt, args...)	do { if (debug) bpf_printk(fmt, ##args); } while (0)
#define trace(fmt, args...)	do { if (debug > 1) bpf_printk(fmt, ##args); } while (0)

enum MatchType {
    STR_PREFIX = 0,
    STR_SUFFIX = 1,
    STR_SUBSTR = 2
};

bool match_str(const char *prefix, const char *str, enum MatchType match_type);
char *format_cgrp_path(struct cgroup *cgrp);

#endif /* __LAYERED_UTIL_H */
