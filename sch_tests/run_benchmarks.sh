#!/bin/bash

# Benchmark Script for scx_rdtai and other scx schedulers
# Required: sudo permissions, sysbench, perf, build-essential, bc

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)"
   exit 1
fi

BASE_DIR=$(pwd)
SCH_DIR="$BASE_DIR/target/release"
TEST_DIR="$BASE_DIR/sch_tests"
LINUX_DIR="$TEST_DIR/linux"
RESULT_FILE="$TEST_DIR/benchmark_report.md"
LOG_FILE="$TEST_DIR/benchmark_details.log"

# Define the non-root user for kernel compilation
NORMAL_USER="rishi"

SCHEDULERS=("scx_rlfifo" "scx_rusty" "scx_rustland" "scx_rdtai")

# 0. Setup Kernel Repo (Run as normal user)
if [ ! -d "$LINUX_DIR" ]; then
    echo "Cloning shallow Linux kernel for compilation test as $NORMAL_USER..." | tee -a "$LOG_FILE"
    sudo -u $NORMAL_USER git clone --depth 1 https://github.com/torvalds/linux.git "$LINUX_DIR"
fi

# Setup Report Header (Overwrites old report)
cat <<EOF > "$RESULT_FILE"
# Scheduler Benchmark Report
Generated on: $(date)

| Scheduler | Sysbench (Events/s) | Schbench Median (us) | Schbench 99th (us) | Cache Misses (%) | Kernel Compile (s) |
|-----------|----------------------|----------------------|--------------------|------------------|-------------------|
EOF

echo "Starting Benchmarking Suite..." | tee -a "$LOG_FILE"
echo "--------------------------------" | tee -a "$LOG_FILE"

for SCHED in "${SCHEDULERS[@]}"; do
    echo "Testing Scheduler: $SCHED" | tee -a "$LOG_FILE"
    
    # 1. Start Scheduler
    $SCH_DIR/$SCHED > "$TEST_DIR/${SCHED}_output.log" 2>&1 &
    SCHED_PID=$!
    sleep 5
    
    if ! ps -p $SCHED_PID > /dev/null; then
        echo "  [ERROR] $SCHED failed to start." | tee -a "$LOG_FILE"
        echo "| $SCHED | FAILED | FAILED | FAILED | FAILED | FAILED |" >> "$RESULT_FILE"
        continue
    fi

    # 2. Sysbench
    echo "  -> Running Sysbench..." | tee -a "$LOG_FILE"
    SYS_OUT=$(sysbench cpu --cpu-max-prime=20000 --threads=$(nproc) run)
    EPS=$(echo "$SYS_OUT" | grep "events per second:" | awk '{print $4}')
    echo "     Result: $EPS events/s" | tee -a "$LOG_FILE"

    # 3. Schbench
    echo "  -> Running Schbench..." | tee -a "$LOG_FILE"
    SCH_OUT=$($TEST_DIR/schbench/schbench -m 8 -t 4 -r 10 2>&1)
    
    # RESTORED: Print the full detailed schbench output to the screen and log
    echo "$SCH_OUT" | tee -a "$LOG_FILE"
    
    P50=$(echo "$SCH_OUT" | grep -A 5 "Wakeup Latencies" | grep "50.0th:" | sed 's/.*50.0th:[[:space:]]*//' | awk '{print $1}')
    P99=$(echo "$SCH_OUT" | grep -A 5 "Wakeup Latencies" | grep "99.0th:" | sed 's/.*99.0th:[[:space:]]*//' | awk '{print $1}')
    echo "     Parsed Result: Median=${P50}us, P99=${P99}us" | tee -a "$LOG_FILE"

    # 4. Perf (Under Load)
    echo "  -> Running Perf..." | tee -a "$LOG_FILE"
    PERF_OUT=$(perf stat -e cache-misses,cache-references -- sysbench cpu --cpu-max-prime=10000 --threads=$(nproc) run 2>&1)
    CACHE_PCT=$(echo "$PERF_OUT" | grep "cache-misses" | awk '{print $4}' | tr -d '%')
    echo "     Result: ${CACHE_PCT:-N/A}% misses" | tee -a "$LOG_FILE"

    # 5. Kernel Compilation (Run as normal user)
    echo "  -> Running Kernel Compile as $NORMAL_USER..." | tee -a "$LOG_FILE"
    cd "$LINUX_DIR"
    sudo -u $NORMAL_USER make mrproper > /dev/null 2>&1
    sudo -u $NORMAL_USER make defconfig > /dev/null 2>&1
    
    START_TIME=$(date +%s.%N)
    sudo -u $NORMAL_USER make -j$(nproc) > "$TEST_DIR/last_kernel_build.log" 2>&1
    EXIT_VAL=$?
    END_TIME=$(date +%s.%N)
    
    if [ $EXIT_VAL -ne 0 ]; then
        COMPILE_TIME="FAILED"
        echo "     [ERROR] Kernel compile failed! Check last_kernel_build.log" | tee -a "$LOG_FILE"
    else
        COMPILE_TIME=$(echo "$END_TIME - $START_TIME" | bc | awk '{printf "%.2f", $0}')
        echo "     Result: $COMPILE_TIME seconds" | tee -a "$LOG_FILE"
    fi
    cd "$BASE_DIR"

    # 6. Stop Scheduler
    kill -SIGINT $SCHED_PID
    wait $SCHED_PID 2>/dev/null
    
    # 7. Record Results
    echo "| $SCHED | ${EPS:-N/A} | ${P50:-N/A} | ${P99:-N/A} | ${CACHE_PCT:-N/A} | $COMPILE_TIME |" >> "$RESULT_FILE"
    echo "--------------------------------" | tee -a "$LOG_FILE"
    sleep 2
done

echo "Benchmarking Complete!" | tee -a "$LOG_FILE"
cat "$RESULT_FILE"