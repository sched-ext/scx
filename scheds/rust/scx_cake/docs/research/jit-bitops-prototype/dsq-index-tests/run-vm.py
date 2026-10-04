from pathlib import Path
import argparse, hashlib, json, re, subprocess, time

parser = argparse.ArgumentParser()
parser.add_argument('name')
parser.add_argument('--hash-only', action='store_true')
parser.add_argument('--baseline', action='store_true')
parser.add_argument('--cpus', type=int, default=2)
parser.add_argument('--sim', action='store_true')
parser.add_argument('--no-bitops', action='store_true')
parser.add_argument('--sockets', type=int, default=1)
parser.add_argument('--debug-kernel', action='store_true')
parser.add_argument('--poc-off', action='store_true')
a = parser.parse_args()
p = Path(__file__).resolve().parent
out = p.parent.parent.parent / 'scx_cake_bench/runs' / p.name / a.name
out.mkdir(parents=True, exist_ok=False)
kernel = (p.parent / 'cake_deep_research_20261002T101516Z' if a.baseline else p) / 'build/arch/x86/boot/bzImage'
if a.debug_kernel:
    kernel = p / 'kernels' / ('baseline-debug.bzImage' if a.baseline else 'candidate-debug.bzImage')
append = 'console=ttyS0 rdinit=/init panic=-1 oops=panic nokaslr quiet'
if a.hash_only: append += ' sched_ext.dsq_direct=0'
if a.baseline: append += ' cake_baseline=1'
if a.sim: append += ' cake_sim=1'
if a.poc_off: append += ' cake_poc_off=1'
cpu = 'qemu64,-bmi1,-popcnt,-abm' if a.no_bitops else 'max'
topology = f'{a.cpus},sockets=1,cores={a.cpus // 2},threads=2' if a.cpus > 2 else str(a.cpus)
if a.sockets > 1:
    topology = f'{a.cpus},sockets={a.sockets},cores={a.cpus // (2 * a.sockets)},threads=2'
cmd = ['qemu-system-x86_64', '-accel', 'tcg,thread=multi', '-cpu', cpu,
       '-smp', topology, '-m', '2048', '-kernel', str(kernel), '-initrd', str(p/'validation.cpio'),
       '-append', append, '-nographic', '-no-reboot', '-nic', 'none']
(out/'command.json').write_text(json.dumps(cmd, indent=2)+'\n')
kernel_hash = hashlib.sha256(kernel.read_bytes()).hexdigest()
initramfs_hash = hashlib.sha256((p/'validation.cpio').read_bytes()).hexdigest()
started = time.time()
try:
    with (out/'serial.log').open('wb') as log:
        rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=240).returncode
except subprocess.TimeoutExpired:
    rc = 124
log = (out/'serial.log').read_text(errors='replace')
passed = rc == 0 and 'VM_COMPLETE failed=0 final=disabled' in log
passed &= not any(x in log for x in ['BUG:', 'Oops:', 'WARNING:', 'Kernel panic'])
passed &= kernel_hash == hashlib.sha256(kernel.read_bytes()).hexdigest()
passed &= initramfs_hash == hashlib.sha256((p/'validation.cpio').read_bytes()).hexdigest()
tests = [dict((k, int(v)) for k, v in re.findall(r'(\w+)=(\d+)', line))
         for line in log.splitlines() if line.startswith(('DSQ_TEST ', 'WORKLOAD '))]
result = dict(name=a.name, returncode=rc, passed=bool(passed), elapsed_seconds=time.time()-started,
              kernel_sha256=kernel_hash, initramfs_sha256=initramfs_hash,
              config=vars(a), tests=tests)
(out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result), flush=True)
raise SystemExit(0 if passed else 1)
