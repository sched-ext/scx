if serialize
  sched_deps = [libbpf, bpftool_target, sched]
else
  sched_deps = [libbpf, bpftool_target]
endif

sched = custom_target('scx_asdf',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
                        cargo_build_args],
              env: cargo_env,
              depends: sched_deps,
              build_always_stale: true)
