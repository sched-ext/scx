#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Piotr Gorski <lucjan.lucjanov@gmail.com>
#
# Load scx_ravd, run some work under it, and stop it, on a kernel with the
# cid form of sched_ext: in a VM, as root.
#
#   bash tests/smoke.sh target/release/scx_ravd

set -euo pipefail

scheduler=${1:?usage: bash tests/smoke.sh /path/to/scx_ravd}
scheduler_pid=
workers=()
log=$(mktemp)

cleanup() {
    if [[ -n "$scheduler_pid" ]]; then
        kill "$scheduler_pid" 2>/dev/null || true
        wait "$scheduler_pid" 2>/dev/null || true
    fi
    for worker in "${workers[@]}"; do
        kill "$worker" 2>/dev/null || true
        wait "$worker" 2>/dev/null || true
    done
    rm -f -- "$log"
}
trap cleanup EXIT

wait_enabled() {
    for ((attempt = 0; attempt < 100; attempt++)); do
        kill -0 "$scheduler_pid"
        if [[ $(cat /sys/kernel/sched_ext/state) == enabled ]]; then
            [[ $(cat /sys/kernel/sched_ext/root/ops) == ravd ]]
            return
        fi
        sleep 0.1
    done
    echo 'scheduler failed to enable' >&2
    return 1
}

[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]
"$scheduler" --verify
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]

"$scheduler" >"$log" 2>&1 &
scheduler_pid=$!
wait_enabled

# CPU-bound work, a pipeline of producers and consumers, which is what
# latency criticality is measured from, and pinned tasks.
for ((worker = 0; worker < 4; worker++)); do
    (dd if=/dev/zero bs=1M count=256 status=none | sha256sum >/dev/null) &
    workers+=("$!")
done
for ((worker = 0; worker < 2; worker++)); do
    (for ((i = 0; i < 2000; i++)); do echo "$i"; done | while read -r _; do :; done) &
    workers+=("$!")
done
for cpu in 0 1; do
    (taskset -c "$cpu" dd if=/dev/zero bs=1M count=64 status=none | md5sum >/dev/null) &
    workers+=("$!")
done
for worker in "${workers[@]}"; do
    wait "$worker"
done
workers=()
[[ $(cat /sys/kernel/sched_ext/state) == enabled ]]

kill -TERM "$scheduler_pid"
# The loader fails the run when the arena or idle-state counters are not
# clean at exit, and prints them.
status=0
wait "$scheduler_pid" || status=$?
scheduler_pid=
cat "$log"
[[ $status == 0 ]]
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]

"$scheduler" --duration 2 &
scheduler_pid=$!
wait_enabled
wait "$scheduler_pid"
scheduler_pid=
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]
echo 'scx_ravd smoke test passed'
