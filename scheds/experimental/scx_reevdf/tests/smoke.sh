#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

set -euo pipefail

scheduler=${1:?usage: bash tests/smoke.sh /path/to/scx_reevdf}
test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
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
            [[ $(cat /sys/kernel/sched_ext/root/ops) == reevdf ]]
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
for ((worker = 0; worker < 4; worker++)); do
    (dd if=/dev/zero bs=1M count=128 status=none | sha256sum >/dev/null) &
    workers+=("$!")
done
for worker in "${workers[@]}"; do
    wait "$worker"
done
workers=()
[[ $(cat /sys/kernel/sched_ext/state) == enabled ]]
python3 "$test_dir/fairness.py"
# One task queued behind the running one: only keeping the running task
# when it wins the pick honors the weights here. fair.c gives 3.77.
python3 "$test_dir/fairness.py" --nice 0 6 --workers 1 --min-ratio 2.5 --max-ratio 5.0
python3 "$test_dir/yield.py"
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

"$scheduler" &
scheduler_pid=$!
wait_enabled
echo S > /proc/sysrq-trigger
for ((attempt = 0; attempt < 100; attempt++)); do
    if ! kill -0 "$scheduler_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if kill -0 "$scheduler_pid" 2>/dev/null; then
    echo 'loader did not notice kernel exit' >&2
    exit 1
fi
if wait "$scheduler_pid"; then
    echo 'kernel exit was not reported as an error' >&2
    exit 1
fi
scheduler_pid=
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]
echo 'Rust BPF scheduler smoke test passed'
