// SPDX-License-Identifier: GPL-2.0
/*
 * Performance level helper for the dispatch pass.
 *
 * Holds the per CPU depth check plus the transition only set with
 * no knob and no extra walk. Any own plus local plus running picks
 * max else half, and a steady level makes no call. Runs with the
 * dispatch CPU only and no remote use, so
 * the same CPU proof holds with no extra guard. Old kernels skip
 * with no call, and unknown CPUs skip with no call. The choice
 * stays in the allowlist before the cap, the cap may step outside
 * it within range, so no trap fires. Shared backlog never boosts
 * an idle CPU, so only the dealing CPU takes max.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Last level per CPU with no call on steady. */
/* Holds one level per CPU, so a repeat level skips the set. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FLOW_MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_perf_last SEC(".maps");
/* Update one CPU level from per CPU depth with no call on steady. */
/* Any own plus local plus running picks max else half with no shared */
/* use, so an idle CPU stays at half while a dealing CPU takes max. */
/* The kfunc check runs first, so old kernels skip with no call. The */
/* live check runs next, so unknown CPUs skip with no call. The */
/* allowlist guards the pre cap choice only, the cap may step outside */
/* it within range, so no trap fires. The last level check holds, so */
/* a steady level makes no call. Runs with the dispatch CPU only and */
/* no remote use. */
static __noinline void flow_perf_update(s32 cpu)
{
	s32 own;
	s32 local;
	u64 depth = 0;
	u32 want;
	u32 cap;
	u32 key;
	u32 *last;
	struct flow_cpu_state *st;
	/* Old kernels hold no set, so skip with no call. */
	if (!bpf_ksym_exists(scx_bpf_cpuperf_set))
		return;
	/* Unknown CPUs hold no level, so skip with no call. */
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu))
		return;
	/* Own plus local shape the depth with two polls only and no tier */
	/* pre scan, so the pass pays no shared walk. A bad read drops */
	/* with no boost, so a missing queue stays idle. */
	own = scx_bpf_dsq_nr_queued(flow_local_dsq((u32)cpu));
	if (own > 0)
		depth += (u64)own;
	local = scx_bpf_dsq_nr_queued((u64)SCX_DSQ_LOCAL_ON |
	    (u64)(u32)cpu);
	if (local > 0)
		depth += (u64)local;
	/* The running view adds one, so a busy CPU counts its task. */
	st = flow_cpu((u32)cpu);
	if (st && READ_ONCE(st->running_pid) != 0)
		depth += 1;
	/* Any depth picks max else half with no knob. */
	if (depth > 0)
		want = (u32)FLOW_CPU_PERF_MAX;
	else
		want = (u32)FLOW_CPU_PERF_HALF;
	/* The allowlist guards the pre cap choice with half plus max. */
	/* Dead by build here with no other level, kept fail closed. */
	if (want != (u32)FLOW_CPU_PERF_HALF &&
	    want != (u32)FLOW_CPU_PERF_MAX)
		return;
	/* The cap clamps the want within range, so want stays at or */
	/* below cap. A zero cap skips with no call as a guard. */
	/* Past the clamp the want may sit outside the allowlist, still */
	/* in range, so the set stays safe. */
	if (bpf_ksym_exists(scx_bpf_cpuperf_cap)) {
		cap = scx_bpf_cpuperf_cap(cpu);
		if (cap == 0)
			return;
		if (want > cap)
			want = cap;
	}
	/* Past bound CPUs hold no row, so skip with no call. Live */
	/* already covers this bound, the check keeps the helper safe */
	/* apart with no caller trust. */
	if ((u64)cpu >= (u64)FLOW_MAX_CPUS)
		return;
	key = (u32)cpu;
	last = bpf_map_lookup_elem(&cpu_perf_last, &key);
	if (!last)
		return;
	/* A steady level holds, so skip the set with no call. The store */
	/* uses the atomic to match the pid plus cursor rows with no torn */
	/* write, the load pairs relaxed with no order need. */
	if (READ_ONCE(*last) == want)
		return;
	__sync_lock_test_and_set(last, want);
	scx_bpf_cpuperf_set(cpu, want);
}
