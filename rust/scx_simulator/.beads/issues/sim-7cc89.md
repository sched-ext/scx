---
title: Model migration_disabled for LAVD SCX_DSQ_LOCAL_ON validation
status: closed
priority: 1
issue_type: task
created_at: 2026-02-20T00:01:02.108082806+00:00
updated_at: 2026-02-20T01:35:48.457250852+00:00
closed_at: 2026-02-20T01:35:48.457250622+00:00
---

# Description

Production LAVD bug: migration-disabled kworker dispatched to wrong CPU via SCX_DSQ_LOCAL_ON. The simulator stubs is_migration_disabled() to false. Need to: add migration_disabled accessors to sim_task.c, remove stubs from wrapper.c, add dispatch validation. Test cases added: test_lavd_migration_disabled_kworker_scenario, test_lavd_pinned_task_cpumask_respected.
