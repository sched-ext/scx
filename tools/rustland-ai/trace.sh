#!/bin/bash
echo "prev_comm,prio,timeslice" > .trace.csv
sudo ./trace-sched >> .trace.csv
grep -v "^Attaching" < .trace.csv | grep -v "^swapper" | grep -v "^@start_ts_ns" | grep -v "^$" > trace.csv
rm -f .trace.csv
