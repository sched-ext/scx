#!/bin/bash

# Benchmark Script for the CURRENTLY RUNNING scheduler
# This script does NOT switch schedulers. It just runs tests on the active one.
# Required: sudo permissions, sysbench, perf, build-essential, bc

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)"
   exit 1
fi

BASE_DIR=$(pwd)
TEST_DIR="$BASE_DIR/sch_tests"
LINUX_DIR="$TEST_DIR/linux"
NORMAL_USER="rishi"

# Detect current scheduler name
CURRENT_SCHED=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo "Default/Unknown")

echo "=========================================================="
echo "RUNNING BENCHMARKS ON CURRENT SCHEDULER: $CURRENT_SCHED"
echo "=========================================================="

# 1. Sysbench (Throughput)
echo "--> [1/4] Running Sysbench (CPU Throughput)..."
SYS_OUT=$(sysbench cpu --cpu-max-prime=20000 --threads=$(nproc) run)
EPS=$(echo "$SYS_OUT" | grep "events per second:" | awk '{print $4}')
echo "    RESULT: $EPS events/s"
echo ""

# 2. Schbench (Tail Latency)
echo "--> [2/4] Running Schbench (Wakeup Latency)..."
if [ -f "$TEST_DIR/schbench/schbench" ]; then
    SCH_OUT=$($TEST_DIR/schbench/schbench -m 8 -t 4 -r 10 2>&1)
    echo "$SCH_OUT" | grep -A 7 "Wakeup Latencies"
    
    P50=$(echo "$SCH_OUT" | grep -A 5 "Wakeup Latencies" | grep "50.0th:" | sed 's/.*50.0th:[[:space:]]*//' | awk '{print $1}')
    P99=$(echo "$SCH_OUT" | grep -A 5 "Wakeup Latencies" | grep "99.0th:" | sed 's/.*99.0th:[[:space:]]*//' | awk '{print $1}')
    echo "    RESULT: Median=${P50}us, 99th=${P99}us"
else
    echo "    [ERROR] schbench binary not found in $TEST_DIR/schbench/"
fi
echo ""

# 3. Perf (Cache Efficiency under load)
echo "--> [3/4] Running Perf (Cache Misses)..."
PERF_OUT=$(perf stat -e cache-misses,cache-references -- sysbench cpu --cpu-max-prime=10000 --threads=$(nproc) run 2>&1)
CACHE_PCT=$(echo "$PERF_OUT" | grep "cache-misses" | awk '{print $4}' | tr -d '%')
echo "    RESULT: ${CACHE_PCT:-N/A}% misses"
echo ""

# 4. Linux Kernel Compilation
echo "--> [4/4] Running Kernel Compilation (Real-world stress)..."
if [ -d "$LINUX_DIR" ]; then
    cd "$LINUX_DIR"
    sudo -u $NORMAL_USER make mrproper > /dev/null 2>&1
    sudo -u $NORMAL_USER make defconfig > /dev/null 2>&1
    
    echo "    Starting parallel build (-j$(nproc))..."
    START_TIME=$(date +%s.%N)
    sudo -u $NORMAL_USER make -j$(nproc) > /dev/null 2>&1
    EXIT_VAL=$?
    END_TIME=$(date +%s.%N)
    
    if [ $EXIT_VAL -ne 0 ]; then
        echo "    RESULT: FAILED"
    else
        COMPILE_TIME=$(echo "$END_TIME - $START_TIME" | bc | awk '{printf "%.2f", $0}')
        echo "    RESULT: $COMPILE_TIME seconds"
    fi
    cd "$BASE_DIR"
else
    echo "    [SKIP] Linux source not found in $LINUX_DIR"
fi

echo "=========================================================="
echo "BENCHMARK COMPLETE FOR: $CURRENT_SCHED"
echo "=========================================================="
