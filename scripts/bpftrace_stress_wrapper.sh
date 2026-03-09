#!/bin/bash

set +x

STRESS_CMD="$1"
SCHED_CMD="$2"
TIMEOUT_SEC="$3"
BPFTRACE_SCRIPTS="$4"
KERNEL_HEADERS="$5"

echo $PWD

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

for a in $(echo "$BPFTRACE_SCRIPTS" | tr ',' ' '); do
   BPFTRACE_KERNEL_SOURCE=${KERNEL_HEADERS} bpftrace -o "$a.ci.log" $SCRIPT_DIR/$a &
done

$STRESS_CMD > stress_cmd.ci.log 2>&1 &

STRESS_PID=$!

timeout --foreground --preserve-status $TIMEOUT_SEC $SCHED_CMD > sched_output.ci.log 2>&1 &

STATUS_PID=$!

# wait for scheduler to exit
tail --pid=$STATUS_PID -f sched_output.ci.log

# wait for stress to exit, ignore err
wait $STRESS_PID || true

sleep 10

killall -w 10s $(jobs -p)

for a in $(echo "$BPFTRACE_SCRIPTS" | tr ',' ' '); do
  echo "$a OUTPUT"
  cat "$a.ci.log"
  echo "$a OUTPUT DONE"
done

echo "STRESS OUTPUT"
cat stress_cmd.ci.log
echo "STRESS OUTPUT DONE"

# if anything isn't right, exit non 0 so we know.
wait $STRESS_PID
wait $STATUS_PID