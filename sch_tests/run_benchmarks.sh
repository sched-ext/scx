#!/bin/bash

# Enhanced Benchmark Script for scx_rdtai and other scx schedulers
# Required: sudo permissions, sysbench, perf, build-essential, bc, rt-tests

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

# 0. Setup Kernel Repo
if [ ! -d "$LINUX_DIR" ]; then
    echo "Cloning shallow Linux kernel for compilation test..." | tee -a "$LOG_FILE"
    sudo -u $NORMAL_USER git clone --depth 1 https://github.com/torvalds/linux.git "$LINUX_DIR"
fi

# Setup Report Header
cat <<EOF > "$RESULT_FILE"
# Scheduler Benchmark Report (Deep Analysis)
Generated on: $(date)

## 1. Throughput & Execution Efficiency
*Higher Events/s and IPC is better. Lower Cache Misses and Compile Time is better.*

| Scheduler | Sysbench (Events/s) | IPC (instr/cycle) | Cache Misses (%) | Kernel Compile (s) | Hackbench (s) |
|-----------|----------------------|-------------------|------------------|--------------------|---------------|
EOF

# Temporary files for latency tables
WAKEUP_TABLE=$(mktemp)
REQ_TABLE=$(mktemp)

cat <<EOF > "$WAKEUP_TABLE"
## 2. Wakeup Latencies (Schbench)
*Time from thread wake to execution. Lower is better (microseconds).*

| Scheduler | 50.0th (us) | 90.0th (us) | 99.0th (us) | 99.9th (us) |
|-----------|-------------|-------------|-------------|-------------|
EOF

cat <<EOF > "$REQ_TABLE"
## 3. Request Latencies (Schbench)
*Time from request start to completion. Lower is better (microseconds).*

| Scheduler | 50.0th (us) | 90.0th (us) | 99.0th (us) | 99.9th (us) |
|-----------|-------------|-------------|-------------|-------------|
EOF

echo "Starting Benchmarking Suite (Warmup + Recording Runs)..." | tee -a "$LOG_FILE"
echo "--------------------------------------------------------" | tee -a "$LOG_FILE"

for SCHED in "${SCHEDULERS[@]}"; do
    echo "Testing Scheduler: $SCHED" | tee -a "$LOG_FILE"
    
    # 1. Start Scheduler
    $SCH_DIR/$SCHED > "$TEST_DIR/${SCHED}_output.log" 2>&1 &
    SCHED_PID=$!
    sleep 5
    
    if ! ps -p $SCHED_PID > /dev/null; then
        echo "  [ERROR] $SCHED failed to start." | tee -a "$LOG_FILE"
        echo "| $SCHED | FAILED | FAILED | FAILED | FAILED | FAILED |" >> "$RESULT_FILE"
        echo "| $SCHED | FAILED | FAILED | FAILED | FAILED |" >> "$WAKEUP_TABLE"
        echo "| $SCHED | FAILED | FAILED | FAILED | FAILED |" >> "$REQ_TABLE"
        continue
    fi

    # 2. Sysbench + IPC/Cache (Warmup + Record)
    for RUN in 1 2; do
        echo "  -> Running Sysbench & Perf (Run $RUN/2)..." | tee -a "$LOG_FILE"
        if [ $RUN -eq 2 ]; then
            # Record detailed perf metrics during the second run
            PERF_OUT=$(perf stat -e instructions,cycles,cache-misses,cache-references -- sysbench cpu --cpu-max-prime=30000 --time=20 --threads=$(nproc) run 2>&1)
            EPS=$(echo "$PERF_OUT" | grep "events per second:" | awk '{print $4}')
            IPC=$(echo "$PERF_OUT" | grep "insn per cycle" | awk '{print $4}')
            CACHE_PCT=$(echo "$PERF_OUT" | grep "cache-misses" | awk '{print $4}' | tr -d '%')
            echo "     Result: $EPS events/s, IPC: $IPC, Cache Misses: ${CACHE_PCT:-N/A}%" | tee -a "$LOG_FILE"
        else
            sysbench cpu --cpu-max-prime=30000 --time=10 --threads=$(nproc) run > /dev/null
        fi
    done

    # 3. Schbench (Warmup + Record)
    for RUN in 1 2; do
        echo "  -> Running Schbench (Run $RUN/2)..." | tee -a "$LOG_FILE"
        SCH_OUT=$($TEST_DIR/schbench/schbench -m 8 -t 4 -r 30 2>&1)
        if [ $RUN -eq 2 ]; then
            echo "$SCH_OUT" | tee -a "$LOG_FILE"
            W_P50=$(echo "$SCH_OUT" | grep -A 6 "Wakeup Latencies" | grep "50.0th:" | tail -1 | sed 's/.*50.0th:[[:space:]]*//' | awk '{print $1}')
            W_P90=$(echo "$SCH_OUT" | grep -A 6 "Wakeup Latencies" | grep "90.0th:" | tail -1 | sed 's/.*90.0th:[[:space:]]*//' | awk '{print $1}')
            W_P99=$(echo "$SCH_OUT" | grep -A 6 "Wakeup Latencies" | grep "99.0th:" | tail -1 | sed 's/.*99.0th:[[:space:]]*//' | awk '{print $1}')
            W_P999=$(echo "$SCH_OUT" | grep -A 6 "Wakeup Latencies" | grep "99.9th:" | tail -1 | sed 's/.*99.9th:[[:space:]]*//' | awk '{print $1}')

            R_P50=$(echo "$SCH_OUT" | grep -A 6 "Request Latencies" | grep "50.0th:" | tail -1 | sed 's/.*50.0th:[[:space:]]*//' | awk '{print $1}')
            R_P90=$(echo "$SCH_OUT" | grep -A 6 "Request Latencies" | grep "90.0th:" | tail -1 | sed 's/.*90.0th:[[:space:]]*//' | awk '{print $1}')
            R_P99=$(echo "$SCH_OUT" | grep -A 6 "Request Latencies" | grep "99.0th:" | tail -1 | sed 's/.*99.0th:[[:space:]]*//' | awk '{print $1}')
            R_P999=$(echo "$SCH_OUT" | grep -A 6 "Request Latencies" | grep "99.9th:" | tail -1 | sed 's/.*99.9th:[[:space:]]*//' | awk '{print $1}')
            
            echo "     Parsed Wakeup Latencies: Median=${W_P50}us, P99=${W_P99}us" | tee -a "$LOG_FILE"
            echo "     Parsed Request Latencies: Median=${R_P50}us, P99=${R_P99}us" | tee -a "$LOG_FILE"
        fi
    done

    # 4. Hackbench (Warmup + Record)
    for RUN in 1 2; do
        echo "  -> Running Hackbench (Run $RUN/2)..." | tee -a "$LOG_FILE"
        H_OUT=$(hackbench -g 20 -l 1000 2>&1)
        if [ $RUN -eq 2 ]; then
            echo "$H_OUT" | tee -a "$LOG_FILE"
            H_TIME=$(echo "$H_OUT" | grep "Time:" | awk '{print $2}')
            echo "     Result: $H_TIME seconds" | tee -a "$LOG_FILE"
        fi
    done

    # 5. Kernel Compilation (Warmup + Record)
    for RUN in 1 2; do
        echo "  -> Running Kernel Compile (Run $RUN/2)..." | tee -a "$LOG_FILE"
        cd "$LINUX_DIR"
        sudo -u $NORMAL_USER make mrproper > /dev/null 2>&1
        sudo -u $NORMAL_USER make defconfig > /dev/null 2>&1
        START_TIME=$(date +%s.%N)
        # Using -j$(nproc) as requested
        sudo -u $NORMAL_USER make -j$(nproc) > "$TEST_DIR/last_kernel_build.log" 2>&1
        EXIT_VAL=$?
        END_TIME=$(date +%s.%N)
        cd "$BASE_DIR"
        if [ $RUN -eq 2 ]; then
            if [ $EXIT_VAL -ne 0 ]; then
                COMPILE_TIME="FAILED"
                echo "     [ERROR] Kernel compile failed! Check last_kernel_build.log" | tee -a "$LOG_FILE"
            else
                COMPILE_TIME=$(echo "$END_TIME - $START_TIME" | bc | awk '{printf "%.2f", $0}')
                echo "     Result: $COMPILE_TIME seconds" | tee -a "$LOG_FILE"
            fi
        fi
    done

    # 6. Stop Scheduler
    kill -SIGINT $SCHED_PID
    wait $SCHED_PID 2>/dev/null
    
    # 7. Record Results
    echo "| $SCHED | ${EPS:-N/A} | ${IPC:-N/A} | ${CACHE_PCT:-N/A} | $COMPILE_TIME | ${H_TIME:-N/A} |" >> "$RESULT_FILE"
    echo "| $SCHED | ${W_P50:-N/A} | ${W_P90:-N/A} | ${W_P99:-N/A} | ${W_P999:-N/A} |" >> "$WAKEUP_TABLE"
    echo "| $SCHED | ${R_P50:-N/A} | ${R_P90:-N/A} | ${R_P99:-N/A} | ${R_P999:-N/A} |" >> "$REQ_TABLE"
    echo "--------------------------------------------------------" | tee -a "$LOG_FILE"
    sleep 2
done

# Assemble Final Report
echo "" >> "$RESULT_FILE"
cat "$WAKEUP_TABLE" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"
cat "$REQ_TABLE" >> "$RESULT_FILE"

rm "$WAKEUP_TABLE" "$REQ_TABLE"

echo "Benchmarking Complete!" | tee -a "$LOG_FILE"
cat "$RESULT_FILE"
