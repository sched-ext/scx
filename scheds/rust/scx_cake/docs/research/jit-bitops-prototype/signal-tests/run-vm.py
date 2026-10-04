from pathlib import Path
import argparse, hashlib, json, subprocess, time
ap = argparse.ArgumentParser()
ap.add_argument("workspace", type=Path)
ap.add_argument("name")
ap.add_argument("--kernel", type=Path)
ap.add_argument("--production", action="store_true")
ap.add_argument("--cpus", type=int, default=2)
ap.add_argument("--no-bitops", action="store_true")
ap.add_argument("--no-irq", action="store_true")
ap.add_argument("--debug", action="store_true")
ap.add_argument("--verbose-boot", action="store_true")
a = ap.parse_args()
p = a.workspace.resolve()
repo = Path(__file__).resolve().parents[7]
out = repo.parent / "scx_cake_bench/runs" / p.name / a.name
out.mkdir(parents=True, exist_ok=False)
kernel = a.kernel.resolve() if a.kernel else p/"build/arch/x86/boot/bzImage"
initrd = p/"validation.cpio"
append = "console=ttyS0 rdinit=/init panic=-1 oops=panic nokaslr quiet"
if a.production: append += " cake_production=1"
if a.no_irq: append += " tsc=noirqtime"
if a.debug: append += " no5lvl cake_poc_off=1"
if a.verbose_boot: append += " loglevel=7"
cmd = ["qemu-system-x86_64", "-accel", "tcg,thread=multi", "-cpu",
       "qemu64,-bmi1,-popcnt,-abm" if a.no_bitops else "max",
       "-smp", str(a.cpus), "-m", "2048", "-kernel", str(kernel), "-initrd", str(initrd),
       "-append", append, "-nographic", "-no-reboot", "-nic", "none"]
(out/"command.json").write_text(json.dumps(cmd, indent=2)+"\n")
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
try:
    before = {str(path): digest(path) for path in [kernel, initrd]}
except OSError as error:
    result = dict(name=a.name, passed=False, errors=[str(error)], phase="artifact_preflight")
    (out/"result.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result), flush=True)
    raise SystemExit(1)
started = time.time()
try:
    with (out/"serial.log").open("wb") as log:
        rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=300).returncode
except subprocess.TimeoutExpired:
    rc = 124
except OSError as error:
    with (out/"serial.log").open("ab") as log:
        log.write((str(error)+"\n").encode())
    rc = 127
log = (out/"serial.log").read_text(errors="replace")
errors = [line for line in log.splitlines() if any(x in line for x in ["BUG:", "Oops:", "WARNING:", "Kernel panic"])]
passed = rc == 0 and "VM_COMPLETE failed=0 final=disabled" in log and not errors
for path, sha in before.items():
    try:
        if digest(Path(path)) != sha:
            errors.append("Artifact changed during run: " + path)
    except OSError as error:
        errors.append(str(error))
passed &= not errors
result = dict(name=a.name, passed=bool(passed), returncode=rc, seconds=time.time()-started,
              hashes=before, errors=errors, serial_log=str(out/"serial.log"))
(out/"result.json").write_text(json.dumps(result, indent=2)+"\n")
print(json.dumps(result), flush=True)
raise SystemExit(0 if passed else 1)
