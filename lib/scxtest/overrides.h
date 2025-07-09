#pragma once

/*
 * This is meant to override certain things we don't need to have for our tests.
 *
 * Stub structs should all go into scheds/include/arch/test/vmlinux.h.
 *
 * This is only meant for things/functionality that we are explicitly disabling,
 * basically if it's a
 *
 * #define some_special_macro(x) do_some_stuff
 *
 * that we want to get rid of that belongs here.
 */
#define __builtin_preserve_field_info(x,y) 1
#define __builtin_preserve_enum_value(x,y) 1

#define bpf_addr_space_cast(var, dst_as, src_as)

#define MEMBER_VPTR(base, member) \
	(typeof((base) member) *)(&((base)member))

#define ARRAY_ELEM_PTR(arr, i, n) \
	(typeof(arr[i]) *)((char *)(arr) + (i) * sizeof(typeof(*(arr))))

/* This is a static helper for some reason, so we have to define it here. */
#define bpf_get_prandom_u32() 0
