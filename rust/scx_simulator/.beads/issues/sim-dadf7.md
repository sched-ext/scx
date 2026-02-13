---
title: Add exit callback to Scheduler trait and engine
status: closed
priority: 3
issue_type: feature
created_at: 2026-02-13T13:04:17.951027614+00:00
updated_at: 2026-02-13T13:19:35.222932285+00:00
closed_at: 2026-02-13T13:19:35.222932225+00:00
---

# Description

COSMOS defines cosmos_exit (line 1182) for cleanup. The engine never calls an
exit callback, and the Scheduler trait has no exit method.

Work needed:
- Add exit to SchedOps struct in ffi.rs
- Add exit method to Scheduler trait with default no-op
- Call exit from the engine during SimulatorEngine::drop or an explicit shutdown method
- Low priority since exit is cleanup-only and doesn't affect scheduling behavior
