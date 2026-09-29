// SPDX-License-Identifier: GPL-2.0
/*
 * Flat hint helpers for the core.
 *
 * Holds the id plus level plus ancestor helpers for the flat hint
 * view. The flat view tunes the period only, and no group or pool
 * shapes order. Runs inline with no walk past one ancestor step, so
 * the verifier stays small.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Id of one hierarchy with root at one on missing. */
/* Runs on an acquired or ops trusted pointer with a held view, */
/* so the node read stays valid. A missing pointer means the root, */
/* so the id stays one. */
static __always_inline u64 flow_cgrp_id(
	struct cgroup *cgrp)
{
	struct kernfs_node *kn;
	u64 id;
	if (!cgrp)
		return 1;
	kn = BPF_CORE_READ(cgrp, kn);
	if (!kn)
		return 1;
	id = BPF_CORE_READ(kn, id);
	if (!id)
		return 1;
	return id;
}
/* Hint of one task from its hierarchy with paired release. */
/* Reads the flat row for the task id only with no ancestor walk, so */
/* the hot path pays one lookup. A null hierarchy means the root, so */
/* the default period applies with no hint use. */
static __always_inline u32 flow_task_hint(
	struct task_struct *p)
{
	struct cgroup *cgrp = flow_task_cgrp(p);
	u64 id;
	u32 hint;
	if (!cgrp)
		return 0;
	id = flow_cgrp_id(cgrp);
	flow_cgrp_put(cgrp);
	hint = flow_hint_us(id);
	return hint;
}
