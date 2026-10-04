from pathlib import Path
import hashlib, json, shutil, subprocess

p = Path(__file__).resolve().parent
repo = p.parent.parent
base = repo / 'target/cake_scalar_bounds_20261002T082205Z/vm-root'
root = p / 'vm-root'
for directory in ['lib64', 'usr/lib', 'proc', 'sys', 'dev', 'work', 'results']:
    (root / directory).mkdir(parents=True, exist_ok=True)
for name in ['libc.so.6', 'libelf.so.1', 'libz.so.1', 'libzstd.so.1', 'libgcc_s.so.1', 'libm.so.6', 'libbpf.so.1']:
    shutil.copy2(base / 'usr/lib' / name, root / 'usr/lib' / name)
shutil.copy2(base / 'lib64/ld-linux-x86-64.so.2', root / 'lib64/ld-linux-x86-64.so.2')
shutil.copy2(repo / 'target/release/scx_cake', root / 'work/scx_cake')
for name in ['dsq-test', 'dsq-test.bpf.o']:
    shutil.copy2(p / name, root / 'work' / name)
lib = base / 'usr/lib'
subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-march=x86-64', '-nostartfiles', str(lib/'Scrt1.o'),
                str(lib/'crti.o'), str(p/'vm-init.c'), '-L'+str(lib),
                '-Wl,-rpath-link,'+str(lib), '-lc', str(lib/'crtn.o'),
                '-o', str(root/'init')], check=True)
files = ['.'] + [str(f.relative_to(root)) for f in sorted(root.rglob('*'))]
with (p / 'validation.cpio').open('wb') as output:
    subprocess.run(['cpio', '--null', '-o', '-H', 'newc', '--owner=0:0'],
                   input=('\0'.join(files)+'\0').encode(), cwd=root, stdout=output, check=True)
(p / 'vm-files.json').write_text(json.dumps({str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest()
    for f in root.rglob('*') if f.is_file()}, indent=2)+'\n')
