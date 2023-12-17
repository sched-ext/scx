/* to be included in the main bpf.c file */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	/* double size because verifier can't follow length calculation */
	__uint(value_size, 2 * MAX_PATH);
	__uint(max_entries, 1);
} cgrp_path_bufs SEC(".maps");

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

static inline bool match_prefix(const char *prefix, const char *str, u32 max_len)
{
	int c;

	bpf_for(c, 0, max_len) {
		if (prefix[c] == '\0')
			return true;
		if (str[c] != prefix[c])
			return false;
	}
	return false;
}
