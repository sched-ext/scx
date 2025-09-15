#pragma once

int scx_pmu_install(u64 event);
int scx_pmu_uninstall(u64 event);

int scx_pmu_task_init(struct task_struct *p);
int scx_pmu_task_fini(struct task_struct *p);

int scx_pmu_read(struct task_struct *p, u64 event, u64 *value, bool clear);
