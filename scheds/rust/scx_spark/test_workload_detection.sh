#!/bin/bash

# Test script for workload detection features in scx_spark
# This script demonstrates how the scheduler can detect and optimize for different ML workload types

set -e

echo "=== SCX Spark Workload Detection Test ==="
echo

LHOME=localhome/local-emilys
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

cleanup() {
    echo "Cleaning up..."
    if [ -n "$SCHED_PID" ]; then
        kill $SCHED_PID 2>/dev/null || true
    fi
    echo 0 > /sys/sched_ext/current_sched_ext 2>/dev/null || true
}

trap cleanup EXIT

meson compile -C ../../../build scx_spark
sudo meson install -C ../../../build

echo "Starting scx_spark with workload detection..."
/${LHOME}/bin/scx_spark \
    --enable-gpu-support \
    --enable-workload-detection \
    --workload-aware-scheduling \
    --debug \
    --verbose \
    & SCHED_PID=$!

# Wait for scheduler to start
sleep 3

echo "Scheduler started with PID: $SCHED_PID"
/${LHOME}/llama.cpp/build/bin/llama-bench -m /${LHOME}/llama.cpp/models/Llama-3.2-1B-Instruct-Q6_K.gguf & LLAMA_PID=$!
echo "Llama started with PID: $LLAMA_PID"
wait $LLAMA_PID

echo
echo "=== Test Completed ==="
echo "The scheduler should have detected and classified the different workload types."
echo "Check the monitoring output for workload-specific dispatch statistics." 