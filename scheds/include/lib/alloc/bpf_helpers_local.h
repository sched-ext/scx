/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPF_HELPERS_LOCAL__
#define __BPF_HELPERS_LOCAL__

/*
 * This header provides additional BPF helpers not in the standard bpf_helpers.h.
 * It assumes the standard <bpf/bpf_helpers.h> has already been included.
 */

extern int bpf_stream_vprintk_impl(int stream_id, const char *fmt__str, const void *args,
				   __u32 len__sz, void *aux__prog) __weak __ksym;

#define bpf_stream_printk(stream_id, fmt, args...)					\
({											\
	static const char ___fmt[] = fmt;						\
	unsigned long long ___param[___bpf_narg(args)];					\
											\
	_Pragma("GCC diagnostic push")							\
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")				\
	___bpf_fill(___param, args);							\
	_Pragma("GCC diagnostic pop")							\
											\
	bpf_stream_vprintk_impl(stream_id, ___fmt, ___param, sizeof(___param), NULL);	\
})

#endif /* __BPF_HELPERS_LOCAL__ */
