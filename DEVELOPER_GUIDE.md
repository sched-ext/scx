# Developer Guide
## eBPF
The scheduling logic for sched_ext schedulers is written in eBPF (BPF). For
high level documentation the kernel docs should be referenced.

- [kernel documentation](https://docs.kernel.org/bpf/index.html)
- [eBPF docs](https://ebpf-docs.dylanreimerink.nl/)
- [rustdocs and sched_ext for-next docs](https://sched-ext.github.io/scx/)

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

## Development kernels
This repository has a kernel lock file at `./kernel-versions.json` where we track
several kernels important to development.

If your change requires a new commit from a branch, you can update this file with:
    nix run ./.github/workflows#update-kernels
or with:
    python3 ./.github/workflows/update-kernels.py

Otherwise new changes will be picked up automatically. If the changes that are
picked up automatically fail CI, you can fix this in a PR separately - the automatic
updater will kick back in once things are green. Create a branch and PR as normal
both updating the kernel lock and making necessary fixes to the codebase.

We use `virtme-ng` for testing in the CI environment, and it should be possible
to reproduce this locally with the same pinned kernels. Currently the most effective
documentation for this will be to read the CI workflows. If this improves in the
future we'll endeavour to update this documentation.

## Rust
We use `cargo fmt` to ensure consistency in our Rust code. This runs on PRs in
the CI and will fail with a patch if your code doesn't match. We currently need
a nightly version of Rust to format so have pinned this for consistency. If you
have rustup installed this will use the version in `rust-toolchain.toml`.

    $ cargo fmt

## Useful Tools

## [scxtop](https://github.com/sched-ext/scx/blob/main/tools/scxtop/README.md)
`scxtop` is a top like tool that collects and aggregates various perf and
sched_ext events. See the
[README](https://github.com/sched-ext/scx/blob/main/tools/scxtop/README.md) for
more details.

### [Perfetto](https://perfetto.dev/)
[Perfetto](https://perfetto.dev/) is a profiling and trace visualization
platform. It can be used to view scheduling data, which is useful for
understanding scheduling decisions. The [`sched_ftrace.py`](scripts/sched_ftrace.py)
script can be used to generate a ftrace compatible with Perfetto.

```
$ sudo ./scripts/sched_ftrace.py > sched.ftrace
```
The output of the script can then be loaded into the perfetto UI:
![perfetto](https://github.com/user-attachments/assets/23e18bd4-8016-40e7-8b49-d2be8ef62f1b)

### perf

The linux `perf` tool has a subcommand for profiling scheduling `perf sched`.
The interface is text driven, but is able to provide various timeline views and
aggregations of scheduler events. The following is an example of using `perf
sched` to get a timeline histogram with additional scheduling metrics.

```
$ perf sched record
$ perf sched timehist -Vw --state
           time    cpu  0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0  task name                       wait time  sch delay   run time  state
                                                                                                           [tid/pid]                          (msec)     (msec)     (msec)       
--------------- ------  ---------------------------------------------------------------------------------  ------------------------------  ---------  ---------  ---------  -----
  960264.500659 [0000]                                                                                     perf[1635250]                                                    awakened: migration/0[19]
  960264.500680 [0000]  s                                                                                  perf[1635250]                       0.000      0.000      0.000      D                                 
  960264.500683 [0000]                                                                                     migration/0[19]                                                  awakened: perf[1635250]
  960264.500809 [0001]                                                                                     perf[1635250]                                                    awakened: migration/1[24]
  960264.500814 [0001]   s                                                                                 perf[1635250]                       0.000      0.000      0.000      D                                 
  960264.500816 [0001]                                                                                     migration/1[24]                                                  awakened: perf[1635250]
  960264.500824 [0001]   s                                                                                 migration/1[24]                     0.000      0.005      0.009      S                                 
  960264.502403 [0001]   i                                                                                 <idle>                              0.000      0.000      1.579      I                                 
  960264.502418 [0001]   s                                                                                 HTTPSrvExec39[3403538/3403436]      0.000      0.000      0.014      S                                 
  960264.506002 [0001]   i                                                                                 <idle>                              0.014      0.000      3.583      I                                 
  960264.506045 [0001]   s                                                                                 CfgrIO0[13302/13094]                0.000      0.000      0.043      S                                 
  960264.506763 [0001]                                                                                     swapper                                                          awakened: chef-client[1629157]
  960264.506767 [0001]   i                                                                                 <idle>                              0.043      0.000      0.721      I                                 
  960264.506784 [0001]   s                                                                                 chef-client[1629157]                0.000      0.003      0.017      S                                 
  960264.507622 [0001]   i                                                                                 <idle>                              0.017      0.000      0.837      I                                 
  960264.507806 [0001]                                                                                     mcrcfg-fci[1635235/1635080]                                      awakened: GlobalCPUThread[1635186/1635080
  960264.507937 [0001]                                                                                     mcrcfg-fci[1635235/1635080]                                       awakened: FalconClientThr[1635187/1635080
  960264.507996 [0001]                                                                                     mcrcfg-fci[1635235/1635080]                                       awakened: CfgrIO0[1635185/1635080]
  960264.508007 [0001]   s                                                                                 mcrcfg-fci[1635235/1635080]          0.000      0.000      0.384      S                                  
  960264.508079 [0001]   i                                                                                 <idle>                               0.384      0.000      0.071      I                                  
  960264.508100 [0001]                                                                                     ThriftSrv.N2104[1635036/2683498                                   awakened: IOThreadPool0[2685229/2683498]
  960264.508108 [0001]   s                                                                                 ThriftSrv.N2104[1635036/2683498      0.000      0.000      0.029      S                                  
  960264.508638 [0001]   i                                                                                 <idle>                               0.029      0.000      0.529      I                                  
  960264.508655 [0001]                                                                                     ThriftSrv.N2104[1635036/2683498                                   awakened: ThriftIO70[2683693/2683498]

```

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

### `bpftop`
[`bpftop`](https://github.com/Netflix/bpftop) is a top/htop like program that
provides an overview of bpf program usage. It shows period and total average
runtime for each eBPF program, which is useful in understanding each scheduler
subprogram.

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
