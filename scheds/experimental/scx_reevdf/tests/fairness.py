# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

import argparse
import multiprocessing
import os
import time


def worker(cpu, nice, barrier, result):
    os.sched_setaffinity(0, {cpu})
    os.setpriority(os.PRIO_PROCESS, 0, nice)
    barrier.wait(timeout=10)
    start = time.process_time()
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        for iteration in range(10000):
            pass
    result.send(time.process_time() - start)
    result.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nice", type=int, nargs=2, default=(0, 5))
    parser.add_argument("--workers", type=int, default=2, help="workers per nice value")
    parser.add_argument("--min-ratio", type=float, default=2.0)
    parser.add_argument("--max-ratio", type=float, default=4.5)
    args = parser.parse_args()
    nices = [args.nice[0]] * args.workers + [args.nice[1]] * args.workers
    cpu = min(os.sched_getaffinity(0))
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(len(nices) + 1)
    processes = []
    readers = []
    try:
        for nice in nices:
            reader, writer = context.Pipe(duplex=False)
            process = context.Process(target=worker, args=(cpu, nice, barrier, writer))
            process.start()
            writer.close()
            processes.append(process)
            readers.append(reader)
        barrier.wait(timeout=10)
        for process in processes:
            process.join(timeout=15)
            assert process.exitcode == 0, "CPU worker failed or stalled"
        runtimes = [reader.recv() for reader in readers]
        assert min(runtimes) > 0.2, f"insufficient CPU time: {runtimes}"
        ratio = sum(runtimes[: args.workers]) / sum(runtimes[args.workers :])
        print(f"nice {args.nice[0]}/nice {args.nice[1]} CPU ratio: {ratio:.2f} (deadline)")
        assert args.min_ratio <= ratio <= args.max_ratio, f"unexpected CPU ratio: {ratio:.2f}"
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join()
        for reader in readers:
            reader.close()


if __name__ == "__main__":
    main()
