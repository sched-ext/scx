/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#pragma once

/*
 * This header provides additional BPF helpers not in the standard bpf_helpers.h.
 * It assumes the standard <bpf/bpf_helpers.h> has already been included.
 */

extern int bpf_stream_vprintk(int stream_id, const char *fmt__str, const void *args,
			      __u32 len__sz) __weak __ksym;

#ifdef bpf_stream_printk
#undef bpf_stream_printk
#endif

#define bpf_stream_printk(stream_id, fmt, args...)					\
({											\
	int ___ret = 0;									\
											\
	if (bpf_ksym_exists(bpf_stream_vprintk)) {				\
		static const char ___fmt[] = fmt;					\
		unsigned long long ___param[___bpf_narg(args)];				\
											\
		_Pragma("GCC diagnostic push")						\
		_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")			\
		___bpf_fill(___param, args);						\
		_Pragma("GCC diagnostic pop")						\
											\
		___ret = bpf_stream_vprintk(stream_id, ___fmt, ___param,		\
					    sizeof(___param));				\
	}										\
											\
	___ret;										\
})

/*
 * Stream elements are concatenated without separators and the stream watcher
 * consumes them line-wise, so an unterminated print glues onto whatever
 * follows, a kernel error report included. The wrappers below terminate every
 * print. Use them instead of raw bpf_stream_printk().
 */
#define scx_out(fmt, ...) bpf_stream_printk(1, fmt "\n", ##__VA_ARGS__)
#define scx_err(fmt, ...) bpf_stream_printk(2, fmt "\n", ##__VA_ARGS__)

#define scx_out_loc(fmt, ...) \
	bpf_stream_printk(1, "%s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
#define scx_err_loc(fmt, ...) \
	bpf_stream_printk(2, "%s:%d " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
