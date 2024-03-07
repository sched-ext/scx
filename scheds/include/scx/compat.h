/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */
#ifndef __SCX_COMPAT_H
#define __SCX_COMPAT_H

#include <bpf/btf.h>

struct btf *__COMPAT_vmlinux_btf __attribute__((weak));

static inline void __COMPAT_load_vmlinux_btf(void)
{
	if (!__COMPAT_vmlinux_btf) {
		__COMPAT_vmlinux_btf = btf__load_vmlinux_btf();
		SCX_BUG_ON(!__COMPAT_vmlinux_btf, "btf__load_vmlinux_btf()");
	}
}

static inline bool __COMPAT_read_enum(const char *type, const char *name, u64 *v)
{
	const struct btf_type *t;
	const char *n;
	s32 tid;
	int i;

	__COMPAT_load_vmlinux_btf();

	tid = btf__find_by_name_kind(__COMPAT_vmlinux_btf, type, BTF_KIND_ENUM);
	if (tid < 0)
		return false;

	t = btf__type_by_id(__COMPAT_vmlinux_btf, tid);
	SCX_BUG_ON(!t, "btf__type_by_id(%d)", tid);

	if (btf_is_enum(t)) {
		struct btf_enum *e = btf_enum(t);

		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			n = btf__name_by_offset(__COMPAT_vmlinux_btf, e[i].name_off);
			SCX_BUG_ON(!n, "btf__name_by_offset()");
			if (!strcmp(n, name)) {
				*v = e[i].val;
				return true;
			}
		}
	} else if (btf_is_enum64(t)) {
		struct btf_enum64 *e = btf_enum64(t);

		for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
			n = btf__name_by_offset(__COMPAT_vmlinux_btf, e[i].name_off);
			SCX_BUG_ON(!n, "btf__name_by_offset()");
			if (!strcmp(n, name)) {
				*v = btf_enum64_value(&e[i]);
				return true;
			}
		}
	}

	return false;
}

#define __COMPAT_ENUM_OR_ZERO(__type, __ent)					\
({										\
	u64 __val = 0;								\
	__COMPAT_read_enum(__type, __ent, &__val);				\
	__val;									\
})

static inline bool __COMPAT_struct_has_field(const char *type, const char *field)
{
	const struct btf_type *t;
	const struct btf_member *m;
	const char *n;
	s32 tid;
	int i;

	__COMPAT_load_vmlinux_btf();
	tid = btf__find_by_name_kind(__COMPAT_vmlinux_btf, type, BTF_KIND_STRUCT);
	if (tid < 0)
		return false;

	t = btf__type_by_id(__COMPAT_vmlinux_btf, tid);
	SCX_BUG_ON(!t, "btf__type_by_id(%d)", tid);

	m = btf_members(t);

	for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
		n = btf__name_by_offset(__COMPAT_vmlinux_btf, m[i].name_off);
		SCX_BUG_ON(!n, "btf__name_by_offset()");
			if (!strcmp(n, field))
				return true;
	}

	return false;
}

/*
 * An ops flag, %SCX_OPS_SWITCH_PARTIAL, replaced scx_bpf_switch_all() which had
 * to be called from ops.init(). To support both before and after, use both
 * %__COMPAT_SCX_OPS_SWITCH_PARTIAL and %__COMPAT_scx_bpf_switch_all() defined
 * in compat.bpf.h.
 */
#define __COMPAT_SCX_OPS_SWITCH_PARTIAL						\
	__COMPAT_ENUM_OR_ZERO("scx_ops_flags", "SCX_OPS_SWITCH_PARTIAL")

/*
 * struct sched_ext_ops can change over time. If compat.bpf.h::SCX_OPS_DEFINE()
 * is used to define ops and compat.h::SCX_OPS_LOAD/ATTACH() are used to load
 * and attach it, backward compatibility is automatically maintained where
 * reasonable.
 *
 * - sched_ext_ops.exit_dump_len was added later. On kernels which don't support
 *   it, the value is ignored and a warning is triggered if the value is
 *   requested to be non-zero.
 */
#define SCX_OPS_LOAD(__skel, __ops_name, __scx_name, __uei_name) ({		\
	UEI_SET_SIZE(__skel, __ops_name, __uei_name);				\
	if (__COMPAT_struct_has_field("sched_ext_ops", "exit_dump_len") &&	\
	    (__skel)->struct_ops.__ops_name->exit_dump_len) {			\
		fprintf(stderr, "WARNING: kernel doesn't support setting exit dump len\n"); \
		(__skel)->struct_ops.__ops_name->exit_dump_len = 0;	\
	}									\
	SCX_BUG_ON(__scx_name##__load((__skel)), "Failed to load skel");	\
})

#define SCX_OPS_ATTACH(__skel, __ops_name) ({					\
	struct bpf_link *__link;						\
	__link = bpf_map__attach_struct_ops((__skel)->maps.__ops_name);		\
	SCX_BUG_ON(!__link, "Failed to attach struct_ops");			\
	__link;									\
})

#endif	/* __SCX_COMPAT_H */
