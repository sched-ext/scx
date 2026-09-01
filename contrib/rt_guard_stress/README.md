# rt_guard_stress — kernel selftest sources (sched-ext/scx#1202)

Copy these files into the Linux kernel tree:

```
tools/testing/selftests/sched_ext/rt_guard_stress.c
tools/testing/selftests/sched_ext/rt_guard_stress.bpf.c
```

Add `rt_guard_stress` to `tools/testing/selftests/sched_ext/Makefile` after `rt_stall`.

Requires `tools/sched_ext/include/scx/scx_rt_guard.bpf.h` (or `scheds/include/scx/scx_rt_guard.bpf.h` from this repo).

## Verified on Contabo VPS

- Kernel: `6.19.0-rc7` + `CONFIG_SCHED_CLASS_EXT=y`
- `RT_GUARD_PASS fail=0`
- `HOLY_GRAIL_1202_SOLVED=YES` (12/12)

Evidence: https://github.com/abdullahhanif-001/elite-ebpf-telemetry/tree/main/docs/evidence/scx-1202
