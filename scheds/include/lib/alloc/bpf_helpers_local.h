/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#pragma once

/*
 * This header provides additional BPF helpers not in the standard bpf_helpers.h.
 * It assumes the standard <bpf/bpf_helpers.h> has already been included.
 */

extern int bpf_stream_vprintk_impl(int stream_id, const char *fmt__str, const void *args,
				   __u32 len__sz, void *aux__prog) __weak __ksym;

#ifdef bpf_stream_printk
#undef bpf_stream_printk
#endif

#define bpf_stream_printk(stream_id, fmt, args...)					\
({											\
	int ___ret = 0;									\
											\
	if (bpf_ksym_exists(bpf_stream_vprintk_impl)) {				\
		static const char ___fmt[] = fmt;					\
		unsigned long long ___param[___bpf_narg(args)];				\
											\
		_Pragma("GCC diagnostic push")						\
		_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")			\
		___bpf_fill(___param, args);						\
		_Pragma("GCC diagnostic pop")						\
											\
		___ret = bpf_stream_vprintk_impl(stream_id, ___fmt, ___param,		\
						 sizeof(___param), NULL);		\
	}										\
											\
	___ret;										\
})

#define scx_out(fmt, ...) bpf_stream_printk(1, (fmt), ##__VA_ARGS__)
#define scx_err(fmt, ...) bpf_stream_printk(2, (fmt), ##__VA_ARGS__)

#define scx_out_loc(fmt, ...) bpf_stream_printk(1, "%s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)
#define scx_err_loc(fmt, ...) bpf_stream_printk(2, "%s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)
