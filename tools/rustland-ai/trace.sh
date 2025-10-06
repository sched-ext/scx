#!/bin/bash

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

echo "prev_comm,prio,timeslice" > .trace.csv
sudo "$SCRIPT_DIR/trace-sched" >> .trace.csv
grep -v "^Attaching" < .trace.csv | grep -v "^swapper" | grep -v "^@start_ts_ns" | grep -v "^$" > trace.csv
rm -f .trace.csv
