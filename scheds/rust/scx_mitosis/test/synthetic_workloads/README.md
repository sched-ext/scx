# Synthetic Workloads for scx_mitosis Testing

This directory contains tools and experiments for testing the scx_mitosis scheduler with synthetic workloads.

### `cgroup_cli.sh`
A utility script that creates transient systemd services running busy loops on specified CPU sets.

**Usage:**
```bash
./cgroup_cli.sh start <unit_name> <cpuspec> <nthreads>  # Start workload
./cgroup_cli.sh stop [unit_name|all]                    # Stop workload(s)
./cgroup_cli.sh status [unit_name|all]                  # Check status
./cgroup_cli.sh list                                    # List active services
./cgroup_cli.sh monitor                                 # Monitor CPU usage
```

### How I've used cgroup_cli.sh to test scx_mitosis
It's easy to make different numbers of cgroups, with different cpusets, and with different numbers of threads.
This can be useful for testing hypotheses about why scx_mitosis barfed on a macrobenchmark.

One time this was useful was showing that (before adding work stealing), scx_mitosis could get into states where it was not doing a good job with work conservation. It's easier to demonstrate this and narrow in on the simplest reproducible experiment. In this case I started by launching 80 threads on 80 cpus and saw that many were idle. Then I simplified it to launching 2 threads on 2 cpus that were members of different L3s. I could show that 50% of the time, a CPU would sit idle while the remaining one ran both threads. After adding work stealing, both experiments showed ideal work conservation.

### Future use
This may prove useful for developing and testing dynamic cell creation and destruction.
