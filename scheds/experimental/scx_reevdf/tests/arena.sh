#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

set -euo pipefail

scheduler=${1:?usage: bash tests/arena.sh /path/to/scx_reevdf}
logs=$(mktemp -d)
scheduler_pid=

cleanup() {
    if [[ -n "$scheduler_pid" ]]; then
        kill "$scheduler_pid" 2>/dev/null || true
        wait "$scheduler_pid" 2>/dev/null || true
    fi
    rm -rf -- "$logs"
}
trap cleanup EXIT

[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]
"$scheduler" >"$logs/churn" 2>&1 &
scheduler_pid=$!
for ((attempt = 0; attempt < 100; attempt++)); do
    if ! kill -0 "$scheduler_pid" 2>/dev/null; then
        cat "$logs/churn"
        exit 1
    fi
    if [[ $(cat /sys/kernel/sched_ext/state) == enabled ]]; then
        break
    fi
    sleep 0.1
done
[[ $(cat /sys/kernel/sched_ext/state) == enabled ]]
[[ $(cat /sys/kernel/sched_ext/root/ops) == reevdf ]]

python3 - <<'PY'
import os
import time

for batch in range(64):
    children = []
    try:
        for child in range(8):
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            children.append(pid)
    finally:
        for pid in children:
            _, status = os.waitpid(pid, 0)
            assert os.waitstatus_to_exitcode(status) == 0
    time.sleep(0.01)
PY

kill -TERM "$scheduler_pid"
wait "$scheduler_pid"
scheduler_pid=
cat "$logs/churn"
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]

# The pool starts with 512 pages of 8 contexts each: attaching beside 4200
# more tasks has to grow it.
python3 - "$scheduler" >"$logs/growth" 2>&1 <<'PY'
import subprocess
import sys

children = []
try:
    for child in range(4200):
        children.append(subprocess.Popen(["sleep", "30"]))
    result = subprocess.run([sys.argv[1], "--duration", "1"])
finally:
    for child in children:
        child.terminate()
    for child in children:
        child.wait()
sys.exit(result.returncode)
PY
cat "$logs/growth"
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]

python3 - "$logs/churn" "$logs/growth" <<'PY'
import pathlib
import re
import sys

pattern = r"arena: allocated=(\d+) freed=(\d+) errors=(\d+) failures=(\d+) pages=(\d+)"
for path in sys.argv[1:]:
    match = re.search(pattern, pathlib.Path(path).read_text())
    assert match is not None, f"missing arena counters in {path}"
    allocated, freed, errors, failures, pages = map(int, match.groups())
    assert allocated == freed and errors == 0 and failures == 0, match.group()
    if path.endswith("churn"):
        assert allocated > 512, match.group()
    else:
        assert allocated > 4200 and pages > 512, match.group()
PY

"$scheduler" --duration 1
[[ $(cat /sys/kernel/sched_ext/state) == disabled ]]
echo 'Rust arena lifecycle test passed'
