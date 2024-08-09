# Developer Guide
## eBPF
The scheduling logic for sched_ext schedulers is written in eBPF (BPF). For
high level documentation the kernel docs should be referenced.

- [kernel documentation](https://docs.kernel.org/bpf/index.html)
- [eBPF docs](https://ebpf-docs.dylanreimerink.nl/)

When working on schedulers the following documentation is rather useful as
schedulers will use a combination of BPF cpumasks, helper functions, kfuncs and
maps for scheduling logic.

- [BPF maps](https://docs.kernel.org/bpf/maps.html)
- [bpf helper functions](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
- [kfuncs](https://docs.kernel.org/bpf/kfuncs.html)
- [BPF cpumasks](https://docs.kernel.org/bpf/cpumasks.html)

The [kernel BPF tests](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf)
are also a useful source of examples of BPF functionality.

## Scheduling
The [kernel scheduling docs](https://docs.kernel.org/scheduler/index.html)
provide a high level overview of the existing scheduler subsystem. The kernel
docs cover various topics such as deadline scheduling, realtime scheduling and
the interaction of schedulers with other system resources.

When schedulers are written to scale beyond more than a single core eventually
the scheduler needs to implement a load balancing algorithm. Calculating the
load between scheduling domains becomes a difficult problem. sched_ext has a
common crate for calculating weights between scheduling domains. See the
`infeasible` crate in `rust/scx_utils/src` for the implementation.

## Useful Tools
### `bpftool`
[`bpftool`](https://github.com/libbpf/bpftool) contains many utilities for
interacting with the BPF subsystem and BPF programs. If you need to know
what BPF programs, maps, iterators are loaded on a system `bpftool` will
provide all this information.

Listing BPF maps:
```
$ sudo bpftool map list
11: hash_of_maps  name cgroup_hash  flags 0x0
        key 8B  value 4B  max_entries 2048  memlock 172992B
        pids systemd(1)
```
Listing `struct_ops`:
```
$ sudo bpftool struct_ops list 
21381: layered         sched_ext_ops                   
```

### `retsnoop`
[`retsnoop`](https://github.com/anakryiko/retsnoop) is a BPF tool for tracing
linux. It is very useful if you are trying to understand the flow of kernel
functions. This can be useful when BPF verification issues are encountered. The
following example shows how the verifier `do_check_common` function can be
traced.

```
$ sudo retsnoop -e 'do_check*' -a ':kernel/bpf/*.c' -T
07:55:28.049718 -> 07:55:28.049797 TID/PID 270611/270611 (bpftool/bpftool):

FUNCTION CALL TRACE                 RESULT     DURATION
---------------------------------   ---------  --------
→ do_check_common                                      
    → init_func_state                                  
        ↔ tnum_const                [0]         2.084us
    ← init_func_state               [void]      6.648us
    ↔ tnum_const                    [0]         2.662us
    → do_check                                         
        ↔ mark_reg_unknown          [void]      2.251us
        ↔ tnum_const                [0]         2.421us
        ↔ reg_bounds_sanity_check   [0]         2.049us
        ↔ check_reference_leak      [0]         2.014us
        → check_return_code                            
            ↔ mark_reg_read         [0]         2.212us
        ← check_return_code         [0]         6.531us
        ↔ pop_stack                 [-ENOENT]   2.099us
    ← do_check                      [0]        34.822us
    ↔ pop_stack                     [-ENOENT]   2.167us
← do_check_common                   [0]        76.413us

                    entry_SYSCALL_64_after_hwframe+0x4b  (entry_SYSCALL_64 @ arch/x86/entry/entry_64.S:130:0)
                    do_syscall_64+0x6a                   (arch/x86/entry/common.c:0:0)                       
                    __x64_sys_bpf+0x18                   (kernel/bpf/syscall.c:5792:1)                       
                    . __se_sys_bpf                       (kernel/bpf/syscall.c:5792:1)                       
                    . __do_sys_bpf                       (kernel/bpf/syscall.c:5794:9)                       
                    __sys_bpf+0x27e                      (kernel/bpf/syscall.c:0:9)                          
                    bpf_prog_load+0x593                  (kernel/bpf/syscall.c:2908:6)                       
                    bpf_check+0x1066                     (kernel/bpf/verifier.c:21608:8)                     
                    . do_check_main                      (kernel/bpf/verifier.c:20938:8)                     
    76us [0]        do_check_common+0x552                (kernel/bpf/verifier.c:20856:9)                     
!    2us [-ENOENT]  pop_stack                                                                                
```

### `bpftrace`
[`bpftrace`](https://github.com/bpftrace/bpftrace) is a high level tracing
language for BPF. When working with sched_ext `bpftrace` programs can be used
for understanding scheduler run queue latency as other scheduler internals. See
the `scripts` dir for examples.

### `stress-ng`
For generating synthetic load on a system
[`stress-ng`](https://github.com/ColinIanKing/stress-ng) can be used.
`stress-ng` can generate different types of load on the system including cpu
bound, fork heavy, NUMA, cache heavy and more.

### `veristat`
[`veristat`](https://github.com/libbpf/veristat) is a tool to provide statics
from the BPF verifier for BPF programs. It can also be used to compare
verification stats across runs. This is useful when trying to optimize BPF
programs for their instruction count.

### `turbostat`
[`turbostat`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/power/x86/turbostat)
is a tool for inspecting CPU frequency as well as power utilization. When
optimizing schedulers for energy performance `turbostat` can be used to
understand the energy required per operation.
