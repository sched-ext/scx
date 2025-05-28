
#ifdef LSP
#ifndef __bpf__
#define __bpf__
#endif
#include "../../../../include/scx/common.bpf.h"
#else
#include <scx/common.bpf.h>
#endif

#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "intf.h"
#include "timer.bpf.h"
#include "util.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	/* double size because verifier can't follow length calculation */
	__uint(value_size, 2 * MAX_PATH);
	__uint(max_entries, 1);
} cgrp_path_bufs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_PATH);
	__uint(max_entries, 1);
} match_bufs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_PATH);
	__uint(max_entries, 1);
} str_bufs SEC(".maps");

__hidden char *format_cgrp_path(struct cgroup *cgrp)
{
	u32 zero = 0;
	char *path = bpf_map_lookup_elem(&cgrp_path_bufs, &zero);
	u32 len = 0, level, max_level;

	if (!path) {
		scx_bpf_error("cgrp_path_buf lookup failed");
		return NULL;
	}

	max_level = cgrp->level;
	if (max_level > 127)
		max_level = 127;

	bpf_for(level, 1, max_level + 1) {
		int ret;

		if (level > 1 && len < MAX_PATH - 1)
			path[len++] = '/';

		if (len >= MAX_PATH - 1) {
			scx_bpf_error("cgrp_path_buf overflow");
			return NULL;
		}

		ret = bpf_probe_read_kernel_str(path + len, MAX_PATH - len - 1,
						BPF_CORE_READ(cgrp, ancestors[level], kn, name));
		if (ret < 0) {
			scx_bpf_error("bpf_probe_read_kernel_str failed");
			return NULL;
		}

		len += ret - 1;
	}

	if (len >= MAX_PATH - 2) {
		scx_bpf_error("cgrp_path_buf overflow");
		return NULL;
	}
	path[len] = '/';
	path[len + 1] = '\0';

	return path;
}

__hidden __noinline int clamp_pathind(int i)
{
	return i > 0 ? i % MAX_PATH : 0;
}

bool __noinline match_prefix_suffix(const char *prefix, const char *str, bool match_suffix)
{
	u32 c, zero = 0;
	int str_len, match_str_len, offset, i;

	if (!prefix || !str) {
		scx_bpf_error("invalid args: %s %s",
			      prefix, str);
		return false;
	}

	char *match_buf = bpf_map_lookup_elem(&match_bufs, &zero);
	char *str_buf = bpf_map_lookup_elem(&str_bufs, &zero);
	if (!match_buf || !str_buf) {
		scx_bpf_error("failed to look up buf");
		return false;
	}

	match_str_len = bpf_probe_read_kernel_str(match_buf, MAX_PATH, prefix);
	if (match_str_len < 0) {
		scx_bpf_error("failed to read prefix");
		return false;
	}

	str_len = bpf_probe_read_kernel_str(str_buf, MAX_PATH, str);
	if (str_len < 0) {
		scx_bpf_error("failed to read str");
		return false;
	}

	if (match_str_len > str_len)
		return false;

	offset = 0;

	if (match_suffix)
		offset = str_len - match_str_len;

	// use MAX_PATH instead of str_len for when
	// prefix/suffix == string.
	bpf_for(c, offset, MAX_PATH) {
		i = c - offset;

		if (match_buf[clamp_pathind(i)] == '\0')
			return true;

		if (str_buf[clamp_pathind(c)] != match_buf[clamp_pathind(i)])
			return false;
	}
	return false;
}

// Copied from above for verifier.
bool __noinline match_substr(const char *prefix, const char *str)
{
	u32 zero = 0;
	int str_len, match_str_len, x, y;

	if (!prefix || !str) {
		scx_bpf_error("invalid args: %s %s",
			      prefix, str);
		return false;
	}

	char *match_buf = bpf_map_lookup_elem(&match_bufs, &zero);
	char *str_buf = bpf_map_lookup_elem(&str_bufs, &zero);
	if (!match_buf || !str_buf) {
		scx_bpf_error("failed to look up buf");
		return false;
	}

	match_str_len = bpf_probe_read_kernel_str(match_buf, MAX_PATH, prefix);
	if (match_str_len < 0) {
		scx_bpf_error("failed to read prefix");
		return false;
	}

	str_len = bpf_probe_read_kernel_str(str_buf, MAX_PATH, str);
	if (str_len < 0) {
		scx_bpf_error("failed to read str");
		return false;
	}

	if (match_str_len > str_len)
		return false;

	bpf_for(x, 0, MAX_PATH) {
		if (str_len - x < y)
			break;

		bpf_for(y, 0, MAX_PATH) {
			if (match_buf[clamp_pathind(y)] == '\0')
				return true;
			if (str_buf[clamp_pathind(x+y)] != match_buf[clamp_pathind(y)])
				break;
		}
	}
	return false;
}

bool __noinline match_str(const char *prefix, const char *str, enum MatchType match_type)
{

	switch (match_type) {
		case STR_PREFIX:
			return match_prefix_suffix(prefix, str, false);
			break;
		case STR_SUFFIX:
			return match_prefix_suffix(prefix, str, true);
			break;
		case STR_SUBSTR:
			return match_substr(prefix, str);
			break;
		default:
			scx_bpf_error("match_str w/o match type specified");
			return false;
	}

	return false;
}
