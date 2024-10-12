#!/usr/bin/env bash
duration=${1:-5}
out=${2:-"$(pwd)/sched.ftrace"}
cd /sys/kernel/debug/tracing
echo 1 > tracing_on
echo 1 > events/sched/sched_switch/enable
timeout "${duration}" cat trace_pipe > "${out}.tmp"
echo 0 > events/sched/sched_switch/enable
echo 0 > tracing_on
cd -
./ftrace_trim "${out}.tmp" `nproc` > "${out}"
rm "${out}.tmp"
