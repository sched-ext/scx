from pathlib import Path
import argparse, hashlib, json, shutil, subprocess
parser = argparse.ArgumentParser()
parser.add_argument("workspace", type=Path)
parser.add_argument("--runtime-root", type=Path, required=True,
                    help="Root containing usr/lib and lib64; must support the guest CPU")
args = parser.parse_args()
p = args.workspace.resolve()
repo = Path(__file__).resolve().parents[7]
source = Path(__file__).resolve().parent
base = args.runtime_root.resolve()
root = p / "vm-root"
for name in ["lib64", "usr/lib", "proc", "sys", "dev", "work", "results"]:
    (root / name).mkdir(parents=True, exist_ok=True)
for name in ["libc.so.6", "libelf.so.1", "libz.so.1", "libzstd.so.1", "libgcc_s.so.1", "libm.so.6", "libbpf.so.1"]:
    shutil.copy2(base / "usr/lib" / name, root / "usr/lib" / name)
shutil.copy2(base / "lib64/ld-linux-x86-64.so.2", root / "lib64/ld-linux-x86-64.so.2")
lib = base / "usr/lib"
for file, output, extra in [("init.c", root/"init", []), ("signals.c", root/"work/signals-test", ["-lbpf", "-lelf", "-lz"])]:
    cmd = ["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-march=x86-64", "-nostartfiles",
           str(lib/"Scrt1.o"), str(lib/"crti.o"), str(source/file), "-L"+str(lib),
           "-Wl,-rpath-link,"+str(lib), *extra, "-lc", str(lib/"crtn.o"), "-o", str(output)]
    subprocess.run(cmd, check=True)
subprocess.run(["clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86",
                "-Wno-missing-declarations", "-I", str(p), "-c", str(source/"signals.bpf.c"),
                "-o", str(root/"work/signals.bpf.o")], check=True)
shutil.copy2(repo/"target/release/scx_cake", root/"work/scx_cake")
files = ["."] + [str(f.relative_to(root)) for f in sorted(root.rglob("*"))]
with (p/"validation.cpio").open("wb") as output:
    subprocess.run(["cpio", "--null", "-o", "-H", "newc", "--owner=0:0"],
                   input=("\0".join(files)+"\0").encode(), cwd=root, stdout=output, check=True)
(p/"vm-files.json").write_text(json.dumps({str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
    for f in root.rglob("*") if f.is_file()}, indent=2)+"\n")
