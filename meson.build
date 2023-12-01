project('sched_ext schedulers', 'c',
        version: '0.0.1',
        license: 'GPL2')

cc = meson.get_compiler('c')

bpf_clang = find_program(get_option('bpf_clang'))
bpftool = find_program(get_option('bpftool'))
cargo = find_program(get_option('cargo'))

get_clang_ver = find_program(join_paths(meson.current_source_dir(),
                                        'meson-scripts/get_clang_ver'))
bpftool_build_skel = find_program(join_paths(meson.current_source_dir(),
                                             'meson-scripts/bpftool_build_skel'))
get_sys_incls = find_program(join_paths(meson.current_source_dir(),
                                        'meson-scripts/get_sys_incls'))

bpf_clang_ver = run_command(get_clang_ver, bpf_clang, check: true).stdout().strip()
bpf_clang_maj = bpf_clang_ver.split('.')[0].to_int()

if bpf_clang_maj < 16
  error('clang < 16 loses high 32 bits of 64 bit enums when compiling BPF (@0@ ver=@1@)'
        .format(bpf_clang.full_path(), bpf_clang_ver))
elif bpf_clang_maj < 17
  warning('clang >= 17 recommended (@0@ ver=@1@)'
          .format(bpf_clang.full_path(), bpf_clang_ver))
endif

if get_option('libbpf_a') != ''
  libbpf_dep = [declare_dependency(
    link_args: get_option('libbpf_a'),
    include_directories: get_option('libbpf_h')),
    cc.find_library('elf'),
    cc.find_library('z')]
else
  libbpf_dep = dependency('libbpf', version: '>=1.2.2')
  if libbpf_dep.version().version_compare('<1.3')
    warning('libbpf <1.3 does not support RESIZE_ARRAY(), expect breakages in schedulers that use them')
  endif
endif

#
# Determine bpf_common_cflags which will be used to compile all .bpf.o
# files. Note that "-target bpf" is not included to accommodate
# libbpf_cargo::SkeletonBuilder.
#
# Map https://mesonbuild.com/Reference-tables.html#cpu-families to the
# __TARGET_ARCH list in tools/lib/bpf/bpf_tracing.h in the kernel tree.
#
arch_dict = {
  'x86': 'x86',
  'x86_64': 'x86',
  's390': 's390',
  'arm': 'arm',
  'aarch64': 'arm64',
  'mips': 'mips',
  'mips64': 'mips',
  'ppc': 'powerpc',
  'ppc64': 'powerpc',
  'sparc': 'sparc',
  'sparc64': 'sparc',
  'riscv32': 'riscv',
  'riscv64': 'riscv',
  'arc': 'arc',
  'loongarch64': 'loongarch'
}

cpu = host_machine.cpu_family()
if cpu not in arch_dict
  error('CPU family "@0@" is not in known arch dict'.format(cpu))
endif

sys_incls = run_command(get_sys_incls, bpf_clang, check: true).stdout().splitlines()

bpf_common_cflags = ['-g', '-O2', '-Wall', '-Wno-compare-distinct-pointer-types',
                     '-D__TARGET_ARCH_' + arch_dict[cpu], '-mcpu=v3',
                     '-m@0@-endian'.format(host_machine.endian())] + sys_incls

message('cpu=@0@ bpf_common_cflags=@1@'.format(cpu, bpf_common_cflags))

#
# Generators to build BPF skel file
#
gen_bpf_o = generator(bpf_clang,
                      output: '@BASENAME@.o',
                      arguments: [bpf_common_cflags, '-target', 'bpf',
                                  '@EXTRA_ARGS@', '-c', '@INPUT@', '-o', '@OUTPUT@'])
gen_bpf_skel = generator(bpftool_build_skel,
                         output: ['@BASENAME@.skel.h', '@BASENAME@.subskel.h' ],
                         arguments: [bpftool.full_path(), '@INPUT@', '@OUTPUT0@', '@OUTPUT1@'])

cargo_extra_args = ['--quiet']

subdir('rust')
subdir('scheds')
