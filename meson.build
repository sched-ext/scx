project('sched_ext schedulers', 'c',
        version: '0.1.10',
        license: 'GPL-2.0',)

if meson.version().version_compare('<1.2')
  error('meson >= 1.2 required')
endif

fs = import('fs')

cc = meson.get_compiler('c')

enable_rust = get_option('enable_rust')

bpf_clang = find_program(get_option('bpf_clang'))

enable_stress = get_option('enable_stress')

if enable_rust
  cargo = find_program(get_option('cargo'))
endif

if enable_stress
  run_stress_tests = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/run_stress_tests'))
endif

get_clang_ver = find_program(join_paths(meson.current_source_dir(),
                                        'meson-scripts/get_clang_ver'))
get_bpftool_ver = find_program(join_paths(meson.current_source_dir(),
                                          'meson-scripts/get_bpftool_ver'))
bpftool_build_skel = find_program(join_paths(meson.current_source_dir(),
                                             'meson-scripts/bpftool_build_skel'))
get_sys_incls = find_program(join_paths(meson.current_source_dir(),
                                        'meson-scripts/get_sys_incls'))
test_sched  = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/test_sched'))
fetch_libbpf = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/fetch_libbpf'))
build_libbpf = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/build_libbpf'))
fetch_bpftool = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/fetch_bpftool'))
build_bpftool = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/build_bpftool'))
if enable_rust
  cargo_fetch = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/cargo_fetch'))
endif

bpf_clang_ver = run_command(get_clang_ver, bpf_clang, check: true).stdout().strip()
if bpf_clang_ver == ''
  error('Unable to find clang version')
endif

bpf_clang_maj = bpf_clang_ver.split('.')[0].to_int()

if bpf_clang_maj < 16
  error('clang < 16 loses high 32 bits of 64 bit enums when compiling BPF (@0@ ver=@1@)'
        .format(bpf_clang.full_path(), bpf_clang_ver))
elif bpf_clang_maj < 17
  warning('clang >= 17 recommended (@0@ ver=@1@)'
          .format(bpf_clang.full_path(), bpf_clang_ver))
endif

# These are for building libbpf and/or bpftool

if meson.get_compiler('c').get_id() == 'gcc'
  extra_args = ['-Wno-sign-compare', '-Wno-maybe-uninitialized', '-Wno-calloc-transposed-args']
else
  extra_args = []
endif

executable('cc_cflags_probe', 'meson-scripts/cc_cflags_probe.c', install: false, pie: true, c_args : extra_args)

jq = find_program('jq')
make = find_program('make')
nproc = find_program('nproc')

make_jobs = 1
if nproc.found()
  make_jobs = run_command(nproc, check: true).stdout().to_int()
endif

libbpf_path = '@0@/libbpf'.format(meson.current_build_dir())
libbpf_src_path = '@0@/src'.format(libbpf_path)
libbpf_a = '@0@/libbpf.a'.format(libbpf_src_path)
should_build_libbpf = true
libbpf_h = get_option('libbpf_h')
libbpf_local_h = get_option('libbpf_h')

if get_option('libbpf_a') == 'disabled'
  libbpf_a = ''
  should_build_libbpf = false
elif get_option('libbpf_a') != ''
  libbpf_a = get_option('libbpf_a')
  if not fs.exists(libbpf_a)
    error('@0@ does not exist.'.format(libbpf_a))
  endif
  should_build_libbpf = false
endif

# WARNING! To build libbpf with the same compiler(CC) and CFLAGS
# as the schedulers we need to do this hack whereby we create a dummy exe
# then read the compiler and args from meson's compile_commands.json
# and re-set them when we build libbpf with make
if should_build_libbpf
  if not jq.found() or not make.found()
    error('To build the libbpf library "make" and "jq" are required')
  endif

  libbpf_header_paths = ['/src/usr/include', '/include/uapi']

  libbpf_h = []

  # This exists because meson doesn't like absolute paths for include_directories
  # if they are found within the same directory as the source
  libbpf_local_h = []
  local_build_path = meson.current_build_dir().replace(meson.current_source_dir(), '')

  foreach path : libbpf_header_paths
    libbpf_h += ['@0@'.format(libbpf_path) + path]
    libbpf_local_h += ['.@0@/libbpf'.format(local_build_path) +  path]
  endforeach

  message('Fetching libbpf repo')
  libbpf_commit = '42065ea6627ff6e1ab4c65e51042a70fbf30ff7c'
  run_command(fetch_libbpf, meson.current_build_dir(), libbpf_commit, check: true)

  make_jobs = 1
  if nproc.found()
    make_jobs = run_command(nproc, check: true).stdout().to_int()
  endif

  libbpf = custom_target('libbpf',
              output: '@PLAINNAME@.__PHONY__',
              input: 'meson-scripts/cc_cflags_probe.c',
              command: [build_libbpf, jq, make, libbpf_src_path, '@0@'.format(make_jobs)],
              build_by_default: true)
else
  # this is a noop when we're not building libbpf ourselves
  libbpf = custom_target('libbpf',
              output: '@PLAINNAME@.__PHONY__',
              input: 'meson-scripts/cc_cflags_probe.c',
              command: ['echo'],
              build_by_default: true)
endif

if libbpf_a != ''
  libbpf_dep = [declare_dependency(
    link_args: libbpf_a,
    include_directories: libbpf_local_h),
    cc.find_library('elf'),
    cc.find_library('z'),
    cc.find_library('zstd')]
else
  libbpf_dep = dependency('libbpf', version: '>=1.4')
endif

if get_option('kernel_headers') != ''
  kernel_headers = get_option('kernel_headers')
  kernel_dep = [declare_dependency(include_directories: kernel_headers)]
else
  kernel_dep = []
endif

bpftool_path = '@0@/bpftool/src'.format(meson.current_build_dir())
should_build_bpftool = true
bpftool_exe_path = '@0@/bpftool'.format(bpftool_path)

if get_option('bpftool') == 'disabled'
  bpftool = find_program('bpftool')
  should_build_bpftool = false
  bpftool_exe_path = bpftool.full_path()
elif get_option('bpftool') != ''
  bpftool = find_program(get_option('bpftool'))
  should_build_bpftool = false
  bpftool_exe_path = bpftool.full_path()
endif

if should_build_bpftool
  message('Fetching bpftool repo')
  bpftool_commit = '42065ea6627ff6e1ab4c65e51042a70fbf30ff7c'
  run_command(fetch_bpftool, meson.current_build_dir(), bpftool_commit, check: true)

  bpftool_target = custom_target('bpftool_target',
              output: '@PLAINNAME@.__PHONY__',
              input: 'meson-scripts/bpftool_dummy.c',
              command: [build_bpftool, jq, make, bpftool_path, '@0@'.format(make_jobs)],
              build_by_default: true)
else
  bpftool_ver = run_command(get_bpftool_ver, bpftool_exe_path, check: true).stdout().strip()
  bpftool_maj = bpftool_ver.split('.')[0].to_int()
  bpftool_min = bpftool_ver.split('.')[1].to_int()
  if bpftool_maj < 7 or (bpftool_maj == 7 and bpftool_min < 4)
    error('bpftool >= 7.4 required (@0@ ver=@1@)'.format(bpftool_exe_path, bpftool_ver))
  endif
  # this is a noop when we're not building bpftool ourselves
  bpftool_target = custom_target('bpftool_target',
              output: '@PLAINNAME@.__PHONY__',
              input: 'meson-scripts/bpftool_dummy.c',
              command: ['echo'],
              build_by_default: true)
endif
# end libbpf/bpftool stuff

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

if get_option('werror')
  bpf_base_cflags += '-Werror'
endif

message('cpu=@0@ bpf_base_cflags=@1@'.format(cpu, bpf_base_cflags))

libbpf_c_headers = []

if libbpf_a != ''
  foreach header: libbpf_h
    libbpf_c_headers += ['-I', header]
  endforeach
endif

#
# Generators to build BPF skel file for C schedulers.
#
gen_bpf_o = generator(bpf_clang,
                      output: '@BASENAME@.o',
                      depends: [libbpf],
                      arguments: [bpf_base_cflags, '-target', 'bpf', libbpf_c_headers, '@EXTRA_ARGS@',
                                  '-c', '@INPUT@', '-o', '@OUTPUT@'])
gen_bpf_skel = generator(bpftool_build_skel,
                         output: ['@BASENAME@.skel.h','@BASENAME@.subskel.h' ],
                         depends: [libbpf, bpftool_target],
                         arguments: [bpftool_exe_path, '@INPUT@', '@OUTPUT0@', '@OUTPUT1@'])

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

if libbpf_a != ''
  foreach header: libbpf_h
    cargo_env.append('BPF_EXTRA_CFLAGS_PRE_INCL', '-I' + header, separator: ' ')
  endforeach

  cargo_env.append('RUSTFLAGS',
                   '-C relocation-model=pic -C link-args=-lelf -C link-args=-lz -C link-args=-lzstd -L '
                   + fs.parent(libbpf_a))

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

if enable_rust
  meson.add_install_script('meson-scripts/install_rust_user_scheds')
  run_target('fetch', command: [cargo_fetch, cargo], env: cargo_env)
endif

if get_option('kernel') != ''
  kernel = get_option('kernel')
endif

run_target('test_sched', command: [test_sched, kernel])

if enable_rust
  subdir('rust')
endif
subdir('scheds')

if enable_stress
  run_target('stress_tests', command: [run_stress_tests, '-k', kernel, '-b',
    meson.current_build_dir()])
endif

systemd = dependency('systemd', required: get_option('systemd'))

if systemd.found()
  subdir('services/systemd')
endif

openrc = dependency('openrc', required: get_option('openrc'))

if openrc.found()
  subdir('services/openrc')
endif

libalpm = dependency('libalpm', required: get_option('libalpm'))

if libalpm.found() and systemd.found()
  subdir('libalpm/systemd')
endif

if libalpm.found() and openrc.found()
  subdir('libalpm/openrc')
endif
