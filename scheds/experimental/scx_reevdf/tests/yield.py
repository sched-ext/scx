# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

import multiprocessing
import os
import time


def worker(cpu, yields, barrier, result):
    os.sched_setaffinity(0, {cpu})
    barrier.wait(timeout=10)
    start = time.process_time()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if yields:
            os.sched_yield()
    result.send(time.process_time() - start)
    result.close()


def main():
    # A task that yields in a loop forfeits the rest of its request every
    # time, so beside a CPU hog on one CPU it gets almost nothing, as under
    # fair.c. Charged only for the time it ran, it would get half.
    cpu = min(os.sched_getaffinity(0))
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(3)
    processes = []
    readers = []
    try:
        for yields in (False, True):
            reader, writer = context.Pipe(duplex=False)
            process = context.Process(target=worker, args=(cpu, yields, barrier, writer))
            process.start()
            writer.close()
            processes.append(process)
            readers.append(reader)
        barrier.wait(timeout=10)
        for process in processes:
            process.join(timeout=15)
            assert process.exitcode == 0, "worker failed or stalled"
        hog, yielder = (reader.recv() for reader in readers)
        print(f"hog/yield CPU time: {hog:.2f}/{yielder:.2f} s")
        assert yielder < 0.1 * hog, f"yielder got too much CPU: {hog:.2f}/{yielder:.2f}"
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join()
        for reader in readers:
            reader.close()


if __name__ == "__main__":
    main()
