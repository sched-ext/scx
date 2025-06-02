/* Copyright (c) David Vernet <void@manifault.com> */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#ifndef __HELPERS_H
#define __HELPERS_H

static inline u64 scale_up_fair(u64 value, u64 weight)
{
	return value * weight / 100;
}

static inline u64 scale_inverse_fair(u64 value, u64 weight)
{
	return value * 100 / weight;
}

static inline int create_assign_cpumask(struct bpf_cpumask **out)
{
	struct bpf_cpumask *mask;

	mask = bpf_cpumask_create();
	if (!mask) {
		scx_bpf_error("Failed to create mask");
		return -ENOMEM;
	}

	mask = bpf_kptr_xchg(out, mask);
	if (mask) {
		scx_bpf_error("Mask was already stored in map");
		bpf_cpumask_release(mask);
		return -EEXIST;
	}

	return 0;
}

static inline u64 calc_avg(u64 curr_avg, u64 latest)
{
	return (curr_avg - (curr_avg >> 2)) + (latest >> 2);
}

#endif // __HELPERS_H
