subdir('scxtest')

libs = ['sdt_alloc', 'sdt_task']

objs = []

foreach src: libs
  # Copy of gen_bpf_o(), because custom targets and generators don't mix
  bpf_o = custom_target(src,
            output: src + '.bpf.o',
            input: src + '.bpf.c',
            command: [bpf_clang, bpf_base_cflags, '-target', 'bpf', libbpf_c_headers, bpf_includes,
                        '-c', '@INPUT@', '-o', '@OUTPUT@'],
            depends: [libbpf, bpftool_target]
            )

  objs += [bpf_o]
endforeach

scx_lib = custom_target(scx_lib_name,
  output: scx_lib_name + '.bpf.o',
  command: [compile_scx_lib, bpftool_exe_path, '@OUTPUT@', scx_lib_name, objs],
  depends: objs,
)

test_sources = ['arena.bpf.c', 'bitmap.bpf.c', 'cpumask.bpf.c', 'sdt_alloc.bpf.c', 'sdt_task.bpf.c', 'topology.bpf.c']

scx_lib_test_obj = static_library('scxlib_test',
  test_sources,
  include_directories: include_directories(['.', 'scxtest']),
  c_args: scx_test_c_args,
  dependencies: [kernel_dep, libbpf_dep, user_c_dep, scxtest_dep],
)

scx_lib_test_dep = declare_dependency(
  link_with: scx_lib_test_obj,
  include_directories: include_directories(['.']),

)
