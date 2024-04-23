sched = custom_target('scx_rustland',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
                        cargo_build_args],
              env: cargo_env,
              depends: [libbpf, bpftool_target, sched],
              build_always_stale: true)
