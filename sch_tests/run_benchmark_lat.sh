#!/bin/bash

# Latency and Complex Workload Benchmark Script for scx_rdtai
# Measures IPC, Database, Network, and Real-time Jitter (HFT)
# Required: sudo, hackbench, iperf3, redis-server, pgbench, cyclictest

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)"
   exit 1
fi

BASE_DIR=$(pwd)
SCH_DIR="$BASE_DIR/target/release"
TEST_DIR="$BASE_DIR/sch_tests"
RESULT_FILE="$TEST_DIR/latency_report.md"
LOG_FILE="$TEST_DIR/latency_details.log"

SCHEDULERS=("scx_rlfifo" "scx_rusty" "scx_rustland" "scx_rdtai")

# Ensure dependencies
if ! command -v jq &> /dev/null; then apt-get install -y jq; fi

# Function to calculate percentiles from cyclictest histogram
# Usage: get_cyclictest_percentile <percentile> <histogram_file>
get_cyclictest_percentile() {
    local p=$1
    local file=$2
    local total=$(awk '{sum+=$2} END {print sum}' "$file")
    if [ "$total" -eq 0 ]; then echo "0"; return; fi
    local target=$(echo "$p * $total / 100" | bc)
    awk -v target="$target" '{count+=$2; if (count >= target) {print $1; exit}}' "$file"
}

# Setup Report Header
cat <<EOF > "$RESULT_FILE"
# Latency & Complex Workload Benchmark Report
Generated on: $(date)

## 1. IPC & Messaging (Hackbench)
*Lower is better (seconds)*

| Scheduler | Run 1 (s) | Run 2 (Recorded) (s) |
|-----------|-----------|----------------------|
EOF

echo "Starting Latency Benchmarking Suite..." | tee -a "$LOG_FILE"

for SCHED in "${SCHEDULERS[@]}"; do
    echo "Testing Scheduler: $SCHED" | tee -a "$LOG_FILE"
    
    # Start Scheduler
    $SCH_DIR/$SCHED > /dev/null 2>&1 &
    SCHED_PID=$!
    sleep 5
    
    if ! ps -p $SCHED_PID > /dev/null; then
        echo "  [ERROR] $SCHED failed to start." | tee -a "$LOG_FILE"
        echo "| $SCHED | FAILED | FAILED |" >> "$RESULT_FILE"
        continue
    fi

    # --- 1. Hackbench (IPC) ---
    echo "  -> Running Hackbench..." | tee -a "$LOG_FILE"
    H1=$(hackbench -g 20 -l 1000 | grep "Time:" | awk '{print $2}')
    H2=$(hackbench -g 20 -l 1000 | grep "Time:" | awk '{print $2}')
    echo "| $SCHED | $H1 | $H2 |" >> "$RESULT_FILE"

    kill -SIGINT $SCHED_PID
    wait $SCHED_PID 2>/dev/null
    sleep 2
done

# --- 2. Redis Latency ---
echo "" >> "$RESULT_FILE"
echo "## 2. Key-Value Store Latency (Redis)" >> "$RESULT_FILE"
echo "*Lower is better (milliseconds at percentiles)*" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"
echo "| Scheduler | GET P50 | GET P95 | GET P99 | SET P50 | SET P95 | SET P99 |" >> "$RESULT_FILE"
echo "|-----------|---------|---------|---------|---------|---------|---------|" >> "$RESULT_FILE"

# Start Redis manually to ensure it's up
killall redis-server 2>/dev/null
redis-server --daemonize yes
sleep 2

for SCHED in "${SCHEDULERS[@]}"; do
    echo "Testing Redis under $SCHED..." | tee -a "$LOG_FILE"
    $SCH_DIR/$SCHED > /dev/null 2>&1 &
    SCHED_PID=$!
    sleep 3

    # Warmup
    redis-benchmark -t set,get -n 50000 -q > /dev/null 2>&1
    # Record CSV
    REDIS_OUT=$(redis-benchmark -t set,get -n 100000 --csv)
    
    # Header: "test","rps","avg","min","p50","p95","p99","max"
    G_P50=$(echo "$REDIS_OUT" | grep "GET" | awk -F',' '{print $5}' | tr -d '"')
    G_P95=$(echo "$REDIS_OUT" | grep "GET" | awk -F',' '{print $6}' | tr -d '"')
    G_P99=$(echo "$REDIS_OUT" | grep "GET" | awk -F',' '{print $7}' | tr -d '"')
    
    S_P50=$(echo "$REDIS_OUT" | grep "SET" | awk -F',' '{print $5}' | tr -d '"')
    S_P95=$(echo "$REDIS_OUT" | grep "SET" | awk -F',' '{print $6}' | tr -d '"')
    S_P99=$(echo "$REDIS_OUT" | grep "SET" | awk -F',' '{print $7}' | tr -d '"')
    
    echo "| $SCHED | $G_P50 | $G_P95 | $G_P99 | $S_P50 | $S_P95 | $S_P99 |" >> "$RESULT_FILE"

    kill -SIGINT $SCHED_PID
    wait $SCHED_PID 2>/dev/null
    sleep 2
done

killall redis-server 2>/dev/null

# --- 3. HFT Simulation (Jitter/Wakeup Latency) ---
echo "" >> "$RESULT_FILE"
echo "## 3. HFT Real-Time Jitter (Cyclictest)" >> "$RESULT_FILE"
echo "*Wakeup latency under stress (microseconds). Lower is better.*" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"
echo "| Scheduler | Avg | P50 | P90 | P99 | Max |" >> "$RESULT_FILE"
echo "|-----------|-----|-----|-----|-----|-----|" >> "$RESULT_FILE"

for SCHED in "${SCHEDULERS[@]}"; do
    echo "Testing Jitter under $SCHED..." | tee -a "$LOG_FILE"
    $SCH_DIR/$SCHED > /dev/null 2>&1 &
    SCHED_PID=$!
    sleep 3

    # Run cyclictest with histogram
    HIST_FILE=$(mktemp)
    CYC_OUT=$(cyclictest --smp -p 95 -m -l 100000 -q --duration=15s --histogram=5000 > "$HIST_FILE")
    
    # Parse Max and Avg
    MAX_VAL=$(grep -o "Max:.*" "$HIST_FILE" | awk '{print $2}' | sort -rn | head -1)
    AVG_VAL=$(grep -o "Avg:.*" "$HIST_FILE" | awk '{print $2}' | awk '{sum+=$1} END {print sum/NR}')
    
    # Clean histogram for parsing (keep only the data lines)
    CLEAN_HIST=$(mktemp)
    grep "^[0-9]" "$HIST_FILE" | awk '{sum=0; for(i=2;i<=NF;i++) sum+=$i; print $1, sum}' > "$CLEAN_HIST"
    
    P50=$(get_cyclictest_percentile 50 "$CLEAN_HIST")
    P90=$(get_cyclictest_percentile 90 "$CLEAN_HIST")
    P99=$(get_cyclictest_percentile 99 "$CLEAN_HIST")

    echo "| $SCHED | $AVG_VAL | $P50 | $P90 | $P99 | $MAX_VAL |" >> "$RESULT_FILE"

    rm "$HIST_FILE" "$CLEAN_HIST"
    kill -SIGINT $SCHED_PID
    wait $SCHED_PID 2>/dev/null
    sleep 2
done

# --- 4. Network Throughput (iperf3 local) ---
echo "" >> "$RESULT_FILE"
echo "## 4. Local Network Throughput (iperf3)" >> "$RESULT_FILE"
echo "*Higher is better (Gbps)*" >> "$RESULT_FILE"
echo "" >> "$RESULT_FILE"
echo "| Scheduler | Throughput (Gbps) |" >> "$RESULT_FILE"
echo "|-----------|-------------------| " >> "$RESULT_FILE"

for SCHED in "${SCHEDULERS[@]}"; do
    echo "Testing Network under $SCHED..." | tee -a "$LOG_FILE"
    $SCH_DIR/$SCHED > /dev/null 2>&1 &
    SCHED_PID=$!
    sleep 3

    # Start iperf3 server
    iperf3 -s -D > /dev/null 2>&1
    sleep 1
    # Warmup
    iperf3 -c 127.0.0.1 -t 3 > /dev/null 2>&1
    # Record
    NET_OUT=$(iperf3 -c 127.0.0.1 -t 10 --json)
    GBPS=$(echo "$NET_OUT" | jq '.end.sum_received.bits_per_second / 1000000000' 2>/dev/null || echo "N/A")
    
    echo "| $SCHED | $GBPS |" >> "$RESULT_FILE"

    killall iperf3 2>/dev/null
    kill -SIGINT $SCHED_PID
    wait $SCHED_PID 2>/dev/null
    sleep 2
done

echo "Benchmarking Complete!" | tee -a "$LOG_FILE"
cat "$RESULT_FILE"
