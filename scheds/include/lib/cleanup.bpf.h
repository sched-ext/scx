/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * RAII guard framework — subset of the kernel's cleanup.h for BPF.
 *
 * Naming and structure follow the kernel's include/linux/cleanup.h.
 */

#pragma once

/* DEFINE_FREE — scoped cleanup for owned resources (refcounts, allocations) */
#define DEFINE_FREE(_name, _type, _free)           \
	static inline void __free_##_name(void *p) \
	{                                          \
		_type _T = *(_type *)p;            \
		_free;                             \
	}

#define __free(_name) __attribute__((__cleanup__(__free_##_name)))

/*
 * Wrapper that enforces __must_check semantics so callers cannot
 * accidentally discard the returned pointer and leak the resource.
 */
static inline __attribute__((__warn_unused_result__)) const volatile void *
__must_check_fn(const volatile void *val)
{
	return val;
}

/* Like a non-atomic xchg(var, NULL), returns the old value. */
#define __get_and_null(p)                  \
	({                                 \
		typeof(p) *__ptr = &(p);   \
		typeof(p)  __val = *__ptr; \
		*__ptr		 = NULL;   \
		__val;                     \
	})

/*
 * Transfer ownership out, preventing cleanup.
 *
 * Sets the variable to NULL (so the cleanup is a no-op, assuming
 * the DEFINE_FREE expression includes a NULL check) and returns the
 * original value.
 */
#define no_free_ptr(p) \
	((typeof(p))__must_check_fn((const volatile void *)__get_and_null(p)))

#define return_ptr(p) return no_free_ptr(p)

/*
 * DEFINE_GUARD — scoped cleanup for lock-like resources.
 * Built on DEFINE_CLASS, matching the kernel's naming convention.
 *
 * _type is the lock pointer type, _lock/_unlock use _T as the pointer.
 */
#define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)     \
	typedef _type	   class_##_name##_t;                       \
	static inline void class_##_name##_destructor(_type *p)     \
	{                                                           \
		_type _T = *p;                                      \
		_exit;                                              \
	}                                                           \
	static inline _type class_##_name##_constructor(_init_args) \
	{                                                           \
		_type t = _init;                                    \
		return t;                                           \
	}

#define CLASS(_name, var)                                                  \
	class_##_name##_t var                                              \
		__attribute__((__cleanup__(class_##_name##_destructor))) = \
			class_##_name##_constructor

#define DEFINE_GUARD(_name, _type, _lock, _unlock)     \
	DEFINE_CLASS(                                  \
		_name, _type, if (_T) { _unlock; }, ({ \
			_lock;                         \
			_T;                            \
		}),                                    \
		_type _T)

#define guard(_name) CLASS(_name, ___bpf_apply(__guard_, __COUNTER__))

#define __scoped_guard(_name, _label, args...)                    \
	for (CLASS(_name, scope)(args); true; ({ goto _label; })) \
		if (0) {                                          \
_label:                                                           \
			break;                                    \
		} else

#define scoped_guard(_name, args...) \
	__scoped_guard(_name, ___bpf_apply(__label_, __COUNTER__), args)

/*
 * Resource type definitions
 */

/* Cgroup reference */
DEFINE_FREE(cgroup, struct cgroup *, if (_T) bpf_cgroup_release(_T))

/* BPF cpumask */
DEFINE_FREE(bpf_cpumask, struct bpf_cpumask *, if (_T) bpf_cpumask_release(_T))

/* Idle cpumask from scx_bpf_get_idle_smtmask */
DEFINE_FREE(idle_cpumask, const struct cpumask *,
	    if (_T) scx_bpf_put_idle_cpumask(_T))

/*
 * RCU read lock — vmlinux.h already exports class_rcu_t from the
 * kernel's own guard. Reuse that type and just define the
 * constructor/destructor.
 */
static inline void class_rcu_destructor(class_rcu_t *_T)
{
	if (_T->lock)
		bpf_rcu_read_unlock();
}

static inline class_rcu_t class_rcu_constructor(void)
{
	class_rcu_t _t = { .lock = (void *)1 };
	bpf_rcu_read_lock();
	return _t;
}

/* BPF spin lock */
DEFINE_GUARD(spin_lock, struct bpf_spin_lock *, bpf_spin_lock(_T),
	     bpf_spin_unlock(_T))

/* Task reference from bpf_task_from_pid / bpf_task_acquire */
DEFINE_FREE(task, struct task_struct *, if (_T) bpf_task_release(_T))
