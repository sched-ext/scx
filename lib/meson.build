libs = ['sdt_task']

objs = []

foreach lib : libs
  bpf_o = gen_bpf_o.process(lib + '.bpf.c', extra_args: bpf_includes)
  tgt = custom_target(lib,
    output: lib + '.bpf.o',
    input: lib + '.bpf.c',
    command: [bpf_clang, bpf_base_cflags, bpf_includes, '-target', 'bpf',
        libbpf_c_headers, '-c', '@INPUT@', '-o', '@OUTPUT@'],
    depends: [libbpf],
    build_by_default: true,
    build_always_stale: true,
  )

  objs += [tgt]
endforeach

custom_target(scx_lib_name,
  output: scx_lib_name + '.bpf.o',
  command: [compile_scx_lib, bpftool_exe_path, '@OUTPUT@', scx_lib_name],
  depends: objs,
  build_by_default: true,
  build_always_stale: true,
)

# Install include/lib as a lib/ subdir of our headers
install_subdir(join_paths(meson.current_source_dir(), 'include/scx'), install_dir: 'include', install_tag: 'devel')
