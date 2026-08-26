/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Tejun Heo <tj@kernel.org>
 */
#pragma once

#ifdef __BPF__

struct cgroup;

void __arena *scx_cgrp_data(struct cgroup *cgrp);
int scx_cgrp_init(__u64 data_size);
void __arena *scx_cgrp_alloc(struct cgroup *cgrp);
void scx_cgrp_free(struct cgroup *cgrp);
void scx_cgrp_free_rcu(struct cgroup *cgrp);

#endif	/* __BPF__ */
