#!/usr/bin/env python3

import os
import sys
import time

HEADER = "TASK-PID"
BUFF_STARTED = "buffer started ###"
TRACING_PATH = "/sys/kernel/tracing"
TRACE_PIPE_PATH = os.path.join(TRACING_PATH, "trace_pipe")


def ftrace_trim(stream, duration, nproc):
    nproc = nproc - 1
    seen_header = False
    proc_buffer_started = 0
    start_time = time.time()

    for line in stream:
        if time.time() - start_time >= duration:
            break
        l = line.replace("\n", "")
        if HEADER in l:
            seen_header = True
            print(l)
        if BUFF_STARTED in line:
            proc_buffer_started += 1
            continue
        if proc_buffer_started == nproc or not seen_header:
            print(l)


def run_trace(duration):
    tracing_on_path = os.path.join(TRACING_PATH, "tracing_on")
    sched_switch_enable_path = os.path.join(
        TRACING_PATH, "events/sched/sched_switch/enable"
    )

    # Enable tracing and sched_switch event
    with open(tracing_on_path, "w") as f:
        f.write("1")
    with open(sched_switch_enable_path, "w") as f:
        f.write("1")

    # Process the sched_switch events from the trace file
    try:
        with open(TRACE_PIPE_PATH, "r") as trace_pipe:
            ftrace_trim(trace_pipe, duration, os.cpu_count())

    except KeyboardInterrupt:
        pass  # Allow clean termination with Ctrl+C

    # Disable tracing and sched_switch event after the duration
    with open(sched_switch_enable_path, "w") as f:
        f.write("0")
    with open(tracing_on_path, "w") as f:
        f.write("0")


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    run_trace(duration)


if __name__ == "__main__":
    main()
