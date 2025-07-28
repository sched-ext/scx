# vmlinux_docify

A simple tool for annotating vmlinux.h with documentation from kernel sources.

To help bridge the tooling gap between writing `C` code for the bpf vm vs `C` code for err, everything else.

```bash
Usage: vmlinux_docify [OPTIONS] --kernel-dir <KERNEL_DIR> --vmlinux-h <VMLINUX_H>

Options:
  -k, --kernel-dir <KERNEL_DIR>
          Path to the kernel source directory

  -v, --vmlinux-h <VMLINUX_H>
          Path to the vmlinux.h file to annotate

  -o, --output <OUTPUT>
          Path to the output file (default: vmlinux_annotated.h)
          
          [default: vmlinux_annotated.h]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```
