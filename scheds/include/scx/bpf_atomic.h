// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#ifndef BPF_ATOMIC_H
#define BPF_ATOMIC_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern bool CONFIG_X86_64 __kconfig __weak;

/* No-op for BPF */
#define cpu_relax() ({})

#define cmpxchg(p, old, new) __sync_val_compare_and_swap((p), old, new)

#define try_cmpxchg(p, pold, new)                                 \
	({                                                        \
		__unqual_typeof(*(pold)) __o = *(pold);           \
		__unqual_typeof(*(p)) __r = cmpxchg(p, __o, new); \
		if (__r != __o)                                   \
			*(pold) = __r;                            \
		__r == __o;                                       \
	})

#define try_cmpxchg_relaxed(p, pold, new) try_cmpxchg(p, pold, new)

#define try_cmpxchg_acquire(p, pold, new) try_cmpxchg(p, pold, new)

#define smp_mb()                                 \
	({                                       \
		unsigned long __val;             \
		__sync_fetch_and_add(&__val, 0); \
	})

#define smp_rmb()                   \
	({                          \
		if (!CONFIG_X86_64) \
			smp_mb();   \
		else                \
			barrier();  \
	})

#define smp_wmb()                   \
	({                          \
		if (!CONFIG_X86_64) \
			smp_mb();   \
		else                \
			barrier();  \
	})

/* Control dependency provides LOAD->STORE, provide LOAD->LOAD */
#define smp_acquire__after_ctrl_dep() ({ smp_rmb(); })

#define smp_load_acquire(p)                                  \
	({                                                   \
		__unqual_typeof(*(p)) __v = READ_ONCE(*(p)); \
		if (!CONFIG_X86_64)                          \
			smp_mb();                            \
		barrier();                                   \
		__v;                                         \
	})

#define smp_store_release(p, val)      \
	({                             \
		if (!CONFIG_X86_64)    \
			smp_mb();      \
		barrier();             \
		WRITE_ONCE(*(p), val); \
	})

#define smp_cond_load_relaxed_label(p, cond_expr, label)                \
	({                                                              \
		typeof(p) __ptr = (p);                                  \
		__unqual_typeof(*(p)) VAL;                              \
		for (;;) {                                              \
			VAL = (__unqual_typeof(*(p)))READ_ONCE(*__ptr); \
			if (cond_expr)                                  \
				break;                                  \
			cond_break_label(label);                        \
			cpu_relax();                                    \
		}                                                       \
		(typeof(*(p)))VAL;                                      \
	})

#define smp_cond_load_acquire_label(p, cond_expr, label)                  \
	({                                                                \
		__unqual_typeof(*p) __val =                               \
			smp_cond_load_relaxed_label(p, cond_expr, label); \
		smp_acquire__after_ctrl_dep();                            \
		(typeof(*(p)))__val;                                      \
	})

#define atomic_read(p) READ_ONCE((p)->counter)

#define atomic_cond_read_relaxed_label(p, cond_expr, label) \
	smp_cond_load_relaxed_label(&(p)->counter, cond_expr, label)

#define atomic_cond_read_acquire_label(p, cond_expr, label) \
	smp_cond_load_acquire_label(&(p)->counter, cond_expr, label)

#define atomic_try_cmpxchg_relaxed(p, pold, new) \
	try_cmpxchg_relaxed(&(p)->counter, pold, new)

#define atomic_try_cmpxchg_acquire(p, pold, new) \
	try_cmpxchg_acquire(&(p)->counter, pold, new)

#endif /* BPF_ATOMIC_H */
