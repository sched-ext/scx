project('sched_ext schedulers', 'c',
        default_options : ['c_std=gnu11'], # Use gnu11 as the C standard to compile vmlinux.h without errors.
        version: '1.0.18',
        license: 'GPL-2.0',
        meson_version : '>= 1.2.0',)

force_meson = get_option('force_meson')
if not force_meson
  error('Meson builds are deprecated. Please switch to `cargo build` for Rust'
          + ' schedulers and `make` for C schedulers. Meson will be removed in an'
          + ' upcoming release. Please report any issues packaging for distributions'
          + ' at https://github.com/sched-ext/scx/discussions/2731. If you need'
          + ' Meson to unblock yourself temporarily, add `-Dforce_meson=true` when'
          + ' configuring.')
endif

fs = import('fs')

cc = meson.get_compiler('c')

enable_rust = get_option('enable_rust')

bpf_clang = find_program(get_option('bpf_clang'))

run_veristat = find_program(join_paths(meson.current_source_dir(),
                                       'meson-scripts/veristat'))
run_veristat_diff = find_program(join_paths(meson.current_source_dir(),
                                       'meson-scripts/veristat_diff'))

enable_stress = get_option('enable_stress')

veristat_scheduler = get_option('veristat_scheduler')

veristat_diff_dir = get_option('veristat_diff_dir')

build_outside_src = get_option('build_outside_src')

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
bpftool_build_skel_lib = find_program(join_paths(meson.current_source_dir(),
                                             'meson-scripts/bpftool_build_skel_lib'))
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
scx_lib_name = 'lib'
scx_lib_path = join_paths(meson.current_build_dir(), 'lib/', scx_lib_name)
compile_scx_lib = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/compile_scx_lib'))

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
protoc = find_program('protoc', required: true)
llvm_strip = find_program('llvm-strip', required: true)
seccomp = dependency('libseccomp', required: true)

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
    if not build_outside_src
      libbpf_local_h += ['.@0@/libbpf'.format(local_build_path) +  path]
    else
      libbpf_local_h += ['@0@/libbpf'.format(local_build_path) +  path]
    endif
  endforeach

  message('Fetching libbpf repo')
  libbpf_commit = 'b4fa3e39a77fd65574fb5f899486795fc3d89bd9'
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
  bpftool_commit = '183e7010387d1fc9f08051426e9a9fbd5f8d409e'
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
  if bpftool_maj < 7 or (bpftool_maj == 7 and bpftool_min < 5)
    error('bpftool >= 7.5 required (@0@ ver=@1@)'.format(bpftool_exe_path, bpftool_ver))
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
  'riscv64gc': 'riscv',
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

# BPF compilation uses the gen_bpf_o generator. The following should be
# passed in as extra_args.
bpf_includes = ['-I', join_paths(meson.current_source_dir(), 'scheds/include'),
                '-I', join_paths(meson.current_source_dir(), 'scheds/include/bpf-compat'),
                '-I', join_paths(meson.current_source_dir(), 'scheds/include/lib'),
                '-I', join_paths(meson.current_source_dir(), 'scheds/vmlinux'),
                '-I', join_paths(meson.current_source_dir(), 'scheds/vmlinux/arch/' + arch_dict[cpu]),]

user_c_dep = [declare_dependency(
  include_directories: [include_directories('scheds/include'), include_directories('scheds/vmlinux')],
)]

lib_objs = []
subdir('lib')

#
# Generators to build BPF skel file for C schedulers.
#
gen_bpf_o = generator(bpf_clang,
                      output: '@BASENAME@.o',
                      depends: [libbpf],
                      arguments: [bpf_base_cflags, '-target', 'bpf', libbpf_c_headers, bpf_includes,
                                  '-c', '@INPUT@', '-o', '@OUTPUT@'])

gen_bpf_skel = generator(bpftool_build_skel,
                         output: ['@BASENAME@.skel.h','@BASENAME@.subskel.h' ],
                         depends: [libbpf, bpftool_target],
                         arguments: [bpftool_exe_path, '@INPUT@', '@OUTPUT0@', '@OUTPUT1@'])

gen_bpf_skel_lib = generator(bpftool_build_skel_lib,
                         output: ['@BASENAME@.skel.h','@BASENAME@.subskel.h' ],
                         depends: [libbpf, bpftool_target, scx_lib],
                         arguments: [bpftool_exe_path, '@INPUT@', '@OUTPUT0@', '@OUTPUT1@', scx_lib_path])

#
# For rust sub-projects.
#
cargo_build_args = ['--quiet']
if get_option('buildtype') == 'release' or get_option('buildtype') == 'plain'
  cargo_build_args += '--release'
endif

if get_option('offline')
  cargo_build_args += '--offline'
endif

if get_option('kernel') != ''
  kernel = get_option('kernel')
endif

if meson.is_cross_build()
  cargo_target = host_machine.cpu_family() + '-unknown-' + host_machine.kernel() + '-gnu'
  cargo_build_args += ['--target', cargo_target]
endif

if enable_rust
  cargo = find_program(get_option('cargo'))
  cargo_fetch = find_program(join_paths(meson.current_source_dir(),
                                      'meson-scripts/cargo_fetch'))
  cargo_env = environment()
  cargo_env.set('BPF_CLANG', bpf_clang.full_path())

  meson.add_install_script('meson-scripts/install_rust_user_scheds')

  foreach flag: bpf_base_cflags
    cargo_env.append('BPF_BASE_CFLAGS', flag, separator: ' ')
  endforeach

  # Cargo already uses a vendored and locked libbpf in the form of libbpf-sys.
  # Don't attempt to further complicate things by building one for them if we
  # built it, but do still provide it if it was supplied by the user.
  if libbpf_a != '' and not should_build_libbpf
    foreach header: libbpf_h
      cargo_env.append('BPF_EXTRA_CFLAGS_PRE_INCL', '-I' + header, separator: ' ')
    endforeach

    cargo_env.append('RUSTFLAGS',
                     '-C relocation-model=pic -C link-args=-lelf -C link-args=-lz -C link-args=-lzstd -L '
                     + fs.parent(libbpf_a), separator: ' ')

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

  run_target('fetch', command: [cargo_fetch, cargo], env: cargo_env)

  rust_scheds = ['scx_lavd', 'scx_bpfland', 'scx_rustland', 'scx_rlfifo',
                 'scx_flash', 'scx_cosmos', 'scx_rusty', 'scx_p2dq',
                 'scx_layered', 'scx_mitosis', 'scx_tickless', 'scx_chaos', 'scx_beerland']
  rust_misc = ['scx_stats', 'scx_stats_derive', 'scx_utils',
               'scx_rustland_core']

  sched_deps = [libbpf, bpftool_target]
  cargo_cmd = [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
               cargo_build_args]

  # target to compile all rust subprojects
  custom_target('rust_all',
                output: '@PLAINNAME@.__PHONY__',
                input: 'Cargo.toml',
                command: cargo_cmd,
                env: cargo_env,
                depends: sched_deps,
                build_by_default: true,
                build_always_stale: true)

  # targets to build individual rust subprojects
  foreach p : rust_scheds + rust_misc
    custom_target(p,
                  output: p + '@PLAINNAME@.__PHONY__',
                  input: 'Cargo.toml',
                  command: cargo_cmd + ['-p', p],
                  env: cargo_env,
                  depends: sched_deps,
                  build_by_default: false,
                  build_always_stale: true)
  endforeach
else
  rust_scheds = []
endif

run_target('test_sched', command: [test_sched, kernel])
run_target('veristat', command: [run_veristat, meson.current_build_dir(),
                                 get_option('veristat_scheduler'), get_option('kernel')])

if get_option('vng_rw_mount') == true
  foreach s : rust_scheds
    run_target('test_sched_'+s, command: [test_sched, kernel, s, 'VNG_RW=true'])
    run_target('veristat_'+s, command: [run_veristat, meson.current_build_dir(),
                                   get_option('veristat_scheduler'), get_option('kernel'), s, 'VNG_RW=true'])
  endforeach
else
  foreach s : rust_scheds
    run_target('test_sched_'+s, command: [test_sched, kernel, s])
    run_target('veristat_'+s, command: [run_veristat, meson.current_build_dir(),
                                   get_option('veristat_scheduler'), get_option('kernel'), s])
  endforeach
endif

run_target('veristat_diff', command: [run_veristat_diff, meson.current_build_dir(),
                                 get_option('veristat_scheduler'), get_option('kernel'),
                                 get_option('veristat_diff_dir')])

if enable_stress
  # not sure there's a better way
  # only different...
  copys = [
    custom_target('copy stress wrapper',
      input : 'scripts/bpftrace_stress_wrapper.sh',
      output :  'bpftrace_stress_wrapper.sh',
      command : ['cp', '-a', '@INPUT@', '@OUTPUT@'],
      install : false,
      build_by_default : true),
     custom_target('copy dsq_lat',
      input : 'scripts/dsq_lat.bt',
      output :  'dsq_lat.bt',
      command : ['cp', '-a', '@INPUT@', '@OUTPUT@'],
      install : false,
      build_by_default : true),
      custom_target('copy runq_lat',
        input : 'scripts/process_runqlat.bt',
        output :  'process_runqlat.bt',
        command : ['cp', '-a', '@INPUT@', '@OUTPUT@'],
        install : false,
        build_by_default : true)
    ]
  run_target('stress_tests', command: [run_stress_tests, '-k', kernel, '-b',
                                       meson.current_build_dir()], depends: [copys])

  if get_option('vng_rw_mount') == true
      foreach s : rust_scheds
      if get_option('kernel_headers') == ''
        run_target('stress_tests_'+s, command: [run_stress_tests, '-k', kernel,
                                                '-b', meson.current_build_dir(), '--sched', s,
                                                '--rw', 'true',
                                                '--extra-scheduler-args', get_option('extra_sched_args')],
                                                depends: [copys])
      else
        run_target('stress_tests_'+s, command: [run_stress_tests, '-k', kernel,
                                                '-b', meson.current_build_dir(), '--sched', s,
                                                '--rw', 'true', 
                                                '--headers', get_option('kernel_headers'),
                                                '--extra-scheduler-args', get_option('extra_sched_args')],
                                                depends: [copys])
      endif
      endforeach
  else
      foreach s : rust_scheds
        if get_option('kernel_headers') == ''
          run_target('stress_tests_'+s, command: [run_stress_tests, '-k', kernel, 
                                              '-b', meson.current_build_dir(), '--sched', s,
                                              '--extra-scheduler-args', get_option('extra_sched_args')],
                                              depends: [copys])
        else
          run_target('stress_tests_'+s, command: [run_stress_tests, '-k', kernel, 
                                              '-b', meson.current_build_dir(), '--sched', s,
                                              '--headers', get_option('kernel_headers'),
                                              '--extra-scheduler-args', get_option('extra_sched_args')],
                                              depends: [copys])
        endif
      endforeach
  endif
endif

thread_dep = dependency('threads')

subdir('scheds')

openrc = dependency('openrc', required: get_option('openrc'))

if openrc.found()
  subdir('services/openrc')
endif
