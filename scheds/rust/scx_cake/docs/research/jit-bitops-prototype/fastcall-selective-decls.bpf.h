/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CAKE_FASTCALL_SELECTIVE_DECLS_BPF_H
#define CAKE_FASTCALL_SELECTIVE_DECLS_BPF_H

#if !__has_attribute(bpf_fastcall)
#error "This experiment requires Clang bpf_fastcall support"
#endif

extern unsigned long long bpf_ctz64(unsigned long long x)
	__attribute__((bpf_fastcall, weak, section(".ksyms")));
extern unsigned long long bpf_popcnt64(unsigned long long x)
	__attribute__((bpf_fastcall, weak, section(".ksyms")));

#endif
