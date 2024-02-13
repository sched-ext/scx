project('sched_ext schedulers', 'c',
        version: '0.1.7',
        license: 'GPL-2.0')

if meson.version().version_compare('<1.2')
  error('meson >= 1.2 required')
endif

fs = import('fs')

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
cargo_fetch = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/cargo_fetch'))
test_sched  = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/test_sched'))

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
    cc.find_library('z'),
    cc.find_library('zstd')]
else
  libbpf_dep = dependency('libbpf', version: '>=1.2.2')
  if libbpf_dep.version().version_compare('<1.3')
    warning('libbpf <1.3 does not support RESIZE_ARRAY(), expect breakages in schedulers that use them')
  endif
endif

#
# Determine bpf_base_cflags which will be used to compile all .bpf.o files.
# Note that "-target bpf" is not included to accommodate
# libbpf_cargo::SkeletonBuilder.
#
# Map https://mesonbuild.com/Reference-tables.html#cpu-families to the
# __TARGET_ARCH list in tools/lib/bpf/bpf_tracing.h in the kernel tree.
#
arch_dict = {
  'x86': 'x86',
  'x86_64': 'x86',
  's390x': 's390',
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
bpf_base_cflags = ['-g', '-O2', '-Wall', '-Wno-compare-distinct-pointer-types',
                   '-D__TARGET_ARCH_' + arch_dict[cpu], '-mcpu=v3',
                   '-m@0@-endian'.format(host_machine.endian())] + sys_incls

message('cpu=@0@ bpf_base_cflags=@1@'.format(cpu, bpf_base_cflags))

libbpf_c_headers = []

if get_option('libbpf_a') != ''
  foreach header: get_option('libbpf_h')
    libbpf_c_headers += ['-I', header]
  endforeach
endif

#
# Generators to build BPF skel file for C schedulers.
#
gen_bpf_o = generator(bpf_clang,
                      output: '@BASENAME@.o',
                      arguments: [bpf_base_cflags, '-target', 'bpf', libbpf_c_headers, '@EXTRA_ARGS@',
                                  '-c', '@INPUT@', '-o', '@OUTPUT@'])
gen_bpf_skel = generator(bpftool_build_skel,
                         output: ['@BASENAME@.skel.h', '@BASENAME@.subskel.h' ],
                         arguments: [bpftool.full_path(), '@INPUT@', '@OUTPUT0@', '@OUTPUT1@'])

#
# For rust sub-projects.
#
cargo_build_args = ['--quiet']
if get_option('buildtype') == 'release'
  cargo_build_args += '--release'
endif

if get_option('offline')
  cargo_build_args += '--offline'
endif

cargo_env = environment()
cargo_env.set('BPF_CLANG', bpf_clang.full_path())

foreach flag: bpf_base_cflags
  cargo_env.append('BPF_BASE_CFLAGS', flag, separator: ' ')
endforeach

if get_option('libbpf_a') != ''
  foreach header: get_option('libbpf_h')
    cargo_env.append('BPF_EXTRA_CFLAGS_PRE_INCL', '-I' + header, separator: ' ')
  endforeach

  cargo_env.append('RUSTFLAGS',
                   '-C link-args=-lelf -C link-args=-lz -C link-args=-lzstd -L '
                   + fs.parent(get_option('libbpf_a')))

  #
  # XXX - scx_rusty's original Cargo.toml contained a dependency matching
  # the following. However, it doesn't seem necessary to enable linking to
  # libbpf.a. Ask Dan Schatzberg about the role the dependency line plays.
  #
  #cargo_build_args += ['--config',
  #                     'dependencies.libbpf-sys.version="1.2"',
  #                     '--config',
  #                     'dependencies.libbpf-sys.features=["novendor", "static"]']
endif

if get_option('cargo_home') != ''
  cargo_env.set('CARGO_HOME', get_option('cargo_home'))
endif

if get_option('enable_rust')
  meson.add_install_script('meson-scripts/install_rust_user_scheds')
endif

run_target('fetch', command: [cargo_fetch, cargo], env: cargo_env)

if get_option('kernel') != ''
  kernel = get_option('kernel')
endif

run_target('test_sched', command: [test_sched, kernel])

if get_option('enable_rust')
  subdir('rust')
endif
subdir('scheds')

systemd = dependency('systemd', required: get_option('systemd'))

if systemd.found()
  subdir('services')
endif
