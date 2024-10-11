/* to be included in the main bpf.c file */

#ifdef LSP
#define __bpf__
#ifndef LSP_INC
#include "../../../../include/scx/common.bpf.h"
#include "../../../../include/scx/ravg_impl.bpf.h"
#endif

#include "intf.h"

#include <stdbool.h>
#include <string.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#endif



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
} prefix_bufs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_PATH);
	__uint(max_entries, 1);
} str_bufs SEC(".maps");

static char *format_cgrp_path(struct cgroup *cgrp)
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

bool __noinline match_prefix(const char *prefix, const char *str, u32 max_len)
{
	u32 c, zero = 0;
	int len;

	if (!prefix || !str || max_len > MAX_PATH) {
		scx_bpf_error("invalid args: %s %s %u",
			      prefix, str, max_len);
		return false;
	}

	char *pre_buf = bpf_map_lookup_elem(&prefix_bufs, &zero);
	char *str_buf = bpf_map_lookup_elem(&str_bufs, &zero);
	if (!pre_buf || !str_buf) {
		scx_bpf_error("failed to look up buf");
		return false;
	}

	len = bpf_probe_read_kernel_str(pre_buf, MAX_PATH, prefix);
	if (len < 0) {
		scx_bpf_error("failed to read prefix");
		return false;
	}

	len = bpf_probe_read_kernel_str(str_buf, MAX_PATH, str);
	if (len < 0) {
		scx_bpf_error("failed to read str");
		return false;
	}

	bpf_for(c, 0, max_len) {
		c &= 0xfff;
		if (c > len) {
			scx_bpf_error("invalid length");
			return false; /* appease the verifier */
		}
		if (pre_buf[c] == '\0')
			return true;
		if (str_buf[c] != pre_buf[c])
			return false;
	}
	return false;
}
