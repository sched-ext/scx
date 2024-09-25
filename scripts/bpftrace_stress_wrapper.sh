#!/bin/bash

STRESS_CMD="$1"
SCHED_CMD="$2"
TIMEOUT_SEC="$3"
BPFTRACE_SCRIPTS="$4"

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

for a in $(echo "$BPFTRACE_SCRIPTS" | tr ',' ' '); do
  bpftrace "$SCRIPT_DIR/$a" > "$(basename a).txt" 2>&1 &
done

$STRESS_CMD > stress_cmd.txt 2>&1 &

STRESS_PID=$!

timeout --foreground --preserve-status $TIMEOUT_SEC $SCHED_CMD > sched_output.txt 2>&1 &

STATUS_PID=$!

tail --pid=$STATUS_PID -f sched_output.txt

for a in $(echo "$BPFTRACE_SCRIPTS" | tr ',' ' '); do
  echo "$a OUTPUT"
  cat "$(basename a).txt"
  echo "$a OUTPUT DONE"
done

echo "STRESS OUTPUT"
cat stress_cmd.txt
echo "STRESS OUTPUT DONE"

# if anything isn't right, exit non 0 so we know.
wait $STRESS_PID
wait $STATUS_PID
