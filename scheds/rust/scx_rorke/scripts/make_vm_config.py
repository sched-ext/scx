#!/usr/bin/env python3

import subprocess
import sys
import json
import re


def get_vm_pid(vm_name):
    try:
        # Use 'ps' to find the VM PID
        cmd = ["ps", "-C", "qemu-system-x86_64", "-o", "pid=", "-o", "cmd="]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        for line in result.stdout.strip().split("\n"):
            if vm_name in line:
                pid = int(line.strip().split()[0])
                return pid
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    return None


def get_vcpu_pids(vm_name, vm_pid):
    # First, try using 'virsh qemu-monitor-command'
    try:
        cmd = ["virsh", "qemu-monitor-command", vm_name, "--hmp", "info cpus"]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        vcpu_pids = []
        for line in result.stdout.strip().split("\n"):
            match = re.search(r"thread_id=(\d+)", line)
            if match:
                vcpu_pids.append(int(match.group(1)))
        if vcpu_pids:
            return vcpu_pids
    except subprocess.CalledProcessError:
        pass  # Proceed to alternative method

    # Alternative method: list threads of the VM process
    try:
        cmd = ["ps", "-T", "-p", str(vm_pid), "-o", "tid=", "-o", "comm="]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        vcpu_pids = []
        for line in result.stdout.strip().split("\n"):
            tid_str, comm = line.strip().split(None, 1)
            if "CPU" in comm or "vcpu" in comm:
                vcpu_pids.append(int(tid_str))
        return vcpu_pids
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
    return []


def main():
    if len(sys.argv) < 2:
        print("Usage: get_vm_pids.py <vm_name1> [<vm_name2> ...]")
        sys.exit(1)

    vm_names = sys.argv[1:]
    output = []

    # Check if VM is running
    for vm_name in vm_names:
        try:
            cmd = ["sudo", "virsh", "domstate", vm_name]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            state = result.stdout.strip()
            if state != "running":
                print(f"Error: VM '{vm_name}' is not running.")
                sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.stderr.strip()}")
            sys.exit(1)

        vm_pid = get_vm_pid(vm_name)
        if vm_pid is None:
            print(f"Error: Could not find PID for VM '{vm_name}'.")
            sys.exit(1)

        vcpu_pids = get_vcpu_pids(vm_name, vm_pid)

        output.append({"vm_id": vm_pid, "vcpus": vcpu_pids})

    print(json.dumps(output, indent=4))


if __name__ == "__main__":
    main()
