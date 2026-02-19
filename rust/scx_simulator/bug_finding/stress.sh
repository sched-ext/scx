#!/bin/bash
# stress.sh - Bug finding through randomized stress testing
#
# Runs parallel stress tests with random seeds to find scheduler bugs.
# Keeps all CPU cores busy until Ctrl-C or a bug is found.
#
# Usage:
#   ./bug_finding/stress.sh              # Run until Ctrl-C or bug
#   ./bug_finding/stress.sh --jobs 4     # Use 4 parallel jobs
#   ./bug_finding/stress.sh --once       # Single iteration
#   ./bug_finding/stress.sh --verbose    # Show all output

set -euo pipefail

cd "$(dirname "$0")/.."

# Configuration
JOBS=${JOBS:-$(nproc)}
ONCE=false
VERBOSE=false
SCHEDULER=${SCHEDULER:-all}  # lavd, mitosis, simple, or all

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --jobs|-j)
            JOBS="$2"
            shift 2
            ;;
        --once)
            ONCE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --scheduler|-s)
            SCHEDULER="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --jobs, -j N      Number of parallel jobs (default: nproc)"
            echo "  --once            Run single iteration then exit"
            echo "  --verbose, -v     Show all test output"
            echo "  --scheduler, -s   Scheduler to test: lavd, mitosis, simple, all (default: all)"
            echo "  --help, -h        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Ensure the project is built
echo "Building scx_simulator..."
cargo build -p scx_simulator --release 2>&1 | tail -5

# Check for GNU parallel
if ! command -v parallel &> /dev/null; then
    echo "Warning: GNU parallel not found, falling back to sequential execution"
    JOBS=1
fi

# Track statistics
ITERATIONS=0
START_TIME=$(date +%s)
BUG_FOUND=false
BUG_SEED=0
BUG_SCHEDULER=""
BUG_EXIT=""

# Cleanup on exit
cleanup() {
    local elapsed=$(($(date +%s) - START_TIME))
    echo ""
    echo "=== Stress Test Summary ==="
    echo "Iterations: $ITERATIONS"
    echo "Elapsed: ${elapsed}s"
    if [[ "$BUG_FOUND" == "true" ]]; then
        echo ""
        echo "!!! BUG FOUND !!!"
        echo "Scheduler: $BUG_SCHEDULER"
        echo "Seed: $BUG_SEED"
        echo "Exit: $BUG_EXIT"
        echo ""
        echo "Reproduce with:"
        echo "  STRESS_SEED=$BUG_SEED cargo test -p scx_simulator stress_random_${BUG_SCHEDULER} -- --nocapture"
    else
        echo "No bugs found."
    fi
}
trap cleanup EXIT

# Run a single stress test with given seed and scheduler
run_stress_test() {
    local seed=$1
    local sched=$2

    # Run the stress test (--ignored because stress tests are marked #[ignore])
    local output
    local result=0
    output=$(STRESS_SEED=$seed STRESS_SCHEDULER=$sched \
        cargo test -p scx_simulator --release "stress_random_${sched}" -- --ignored --nocapture 2>&1) || result=$?

    if [[ $result -ne 0 ]]; then
        # Extract error info from output
        local exit_info
        exit_info=$(echo "$output" | grep -E "(ErrorStall|ErrorBpf|ErrorDispatch|panicked)" | head -1 || echo "unknown error")
        echo "FOUND:$seed:$sched:$exit_info"
        return 1
    fi

    return 0
}
export -f run_stress_test

# Main loop
echo "Starting stress testing with $JOBS parallel jobs..."
echo "Testing scheduler(s): $SCHEDULER"
echo "Press Ctrl-C to stop"
echo ""

SEED=$$  # Start with PID as seed

run_batch() {
    local batch_seed=$1
    local schedulers

    if [[ "$SCHEDULER" == "all" ]]; then
        schedulers="lavd mitosis simple"
    else
        schedulers="$SCHEDULER"
    fi

    for sched in $schedulers; do
        for i in $(seq 1 "$JOBS"); do
            local test_seed=$((batch_seed + i))
            echo "$test_seed $sched"
        done
    done
}

if [[ "$ONCE" == "true" ]]; then
    # Single iteration mode
    echo "Running single iteration with seed $SEED..."

    if [[ "$SCHEDULER" == "all" ]]; then
        for sched in lavd mitosis simple; do
            echo "Testing $sched..."
            if ! run_stress_test "$SEED" "$sched"; then
                BUG_FOUND=true
                BUG_SEED=$SEED
                BUG_SCHEDULER=$sched
                exit 1
            fi
        done
    else
        if ! run_stress_test "$SEED" "$SCHEDULER"; then
            BUG_FOUND=true
            BUG_SEED=$SEED
            BUG_SCHEDULER=$SCHEDULER
            exit 1
        fi
    fi
    ITERATIONS=1
    exit 0
fi

# Continuous mode
while true; do
    # Generate batch of test configurations
    batch_file=$(mktemp)
    run_batch "$SEED" > "$batch_file"

    # Count tests in batch
    batch_size=$(wc -l < "$batch_file")

    if command -v parallel &> /dev/null && [[ "$JOBS" -gt 1 ]]; then
        # Run batch in parallel
        if $VERBOSE; then
            result_file=$(mktemp)
            parallel --colsep ' ' -j "$JOBS" --halt soon,fail=1 \
                run_stress_test {1} {2} < "$batch_file" 2>&1 | tee "$result_file" || true

            # Check for bugs
            if grep -q "^FOUND:" "$result_file"; then
                bug_line=$(grep "^FOUND:" "$result_file" | head -1)
                BUG_FOUND=true
                BUG_SEED=$(echo "$bug_line" | cut -d: -f2)
                BUG_SCHEDULER=$(echo "$bug_line" | cut -d: -f3)
                BUG_EXIT=$(echo "$bug_line" | cut -d: -f4-)
                rm -f "$batch_file" "$result_file"
                exit 1
            fi
            rm -f "$result_file"
        else
            result_file=$(mktemp)
            parallel --colsep ' ' -j "$JOBS" --halt soon,fail=1 \
                run_stress_test {1} {2} < "$batch_file" > "$result_file" 2>&1 || true

            # Check for bugs
            if grep -q "^FOUND:" "$result_file"; then
                bug_line=$(grep "^FOUND:" "$result_file" | head -1)
                BUG_FOUND=true
                BUG_SEED=$(echo "$bug_line" | cut -d: -f2)
                BUG_SCHEDULER=$(echo "$bug_line" | cut -d: -f3)
                BUG_EXIT=$(echo "$bug_line" | cut -d: -f4-)
                rm -f "$batch_file" "$result_file"
                exit 1
            fi
            rm -f "$result_file"
        fi
    else
        # Sequential fallback
        while read -r test_seed sched; do
            if $VERBOSE; then
                echo "Testing $sched with seed $test_seed..."
            fi
            if ! run_stress_test "$test_seed" "$sched" 2>&1; then
                BUG_FOUND=true
                BUG_SEED=$test_seed
                BUG_SCHEDULER=$sched
                rm -f "$batch_file"
                exit 1
            fi
        done < "$batch_file"
    fi

    rm -f "$batch_file"

    ITERATIONS=$((ITERATIONS + batch_size))
    SEED=$((SEED + batch_size))

    # Progress update
    elapsed=$(($(date +%s) - START_TIME))
    rate=$((ITERATIONS / (elapsed + 1)))
    printf "\rIterations: %d | Elapsed: %ds | Rate: %d/s   " "$ITERATIONS" "$elapsed" "$rate"
done
