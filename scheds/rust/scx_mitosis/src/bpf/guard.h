/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Scope-based cleanup helpers for BPF code.
 *
 * These macros provide RAII-style automatic cleanup using GCC's cleanup
 * attribute, following the Linux kernel's pattern from include/linux/cleanup.h.
 *
 * Usage:
 *   guard(rcu)();                                      // RCU read lock for scope
 *   struct cgroup *cgrp __free(bpf_cgroup) = ...;     // Auto-release cgroup
 *   struct bpf_cpumask *mask __free(bpf_cpumask) = ...; // Auto-release cpumask
 */

#ifndef __GUARD_H
#define __GUARD_H

/*
 * __cleanup - Attribute for automatic cleanup on scope exit
 *
 * This mirrors the kernel's linux/compiler.h definition.
 */
#ifndef __cleanup
#define __cleanup(func) __attribute__((__cleanup__(func)))
#endif

/*
 * DEFINE_FREE - Define a cleanup function for use with __free()
 *
 * @_name: name for the cleanup (used as __free(_name))
 * @_type: the type of the variable
 * @_free: cleanup expression using _T as the variable
 *
 * Example:
 *   DEFINE_FREE(kfree, void *, if (_T) kfree(_T))
 *   void *p __free(kfree) = kmalloc(...);
 */
#define DEFINE_FREE(_name, _type, _free)           \
	static inline void __free_##_name(void *p) \
	{                                          \
		_type _T = *(_type *)p;            \
		_free;                             \
	}

#define __free(_name) __cleanup(__free_##_name)

/*
 * Free functions for BPF resources
 */
DEFINE_FREE(bpf_cgroup, struct cgroup *, if (_T) bpf_cgroup_release(_T))
DEFINE_FREE(bpf_cpumask, struct bpf_cpumask *, if (_T) bpf_cpumask_release(_T))
DEFINE_FREE(scx_idle_cpumask, const struct cpumask *,
	    if (_T) scx_bpf_put_idle_cpumask(_T))

/*
 * Helper to generate unique variable names
 */
#define __GUARD_CONCAT(a, b) a##b
#define __GUARD_UNIQUE(prefix) __GUARD_CONCAT(prefix, __COUNTER__)

/*
 * RCU read lock guard
 *
 * Usage:
 *   guard(rcu)();
 *   // RCU read lock held until end of scope
 */
typedef struct {
	char _dummy;
} __bpf_rcu_guard_t;

static inline __bpf_rcu_guard_t __bpf_rcu_constructor(void)
{
	__bpf_rcu_guard_t ret = {};
	bpf_rcu_read_lock();
	return ret;
}

static inline void __bpf_rcu_destructor(__bpf_rcu_guard_t *t)
{
	bpf_rcu_read_unlock();
}

#define __guard_rcu()                                                \
	__bpf_rcu_guard_t __GUARD_UNIQUE(__rcu_guard)                \
		__attribute__((__unused__,                           \
			       __cleanup__(__bpf_rcu_destructor))) = \
			__bpf_rcu_constructor()

/*
 * Generic guard() macro similar to Linux kernel's guard()
 *
 * Usage:
 *   guard(rcu)();  // RCU lock for remainder of scope
 */
#define guard(name) __guard_##name

#endif /* __GUARD_H */
