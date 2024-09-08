sched_deps = [libbpf, bpftool_target]
cargo_cmd = [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
             cargo_build_args]

# the target to compile all rust schedulers
custom_target('rust_scheds',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: cargo_cmd,
              env: cargo_env,
              depends: sched_deps,
              build_by_default: true,
              build_always_stale: true)

foreach sched: SCHEDULERS
  custom_target(sched,
                output: sched + '@PLAINNAME@.__PHONY__',
                input: 'Cargo.toml',
                command: cargo_cmd + ['-p', sched],
                env: cargo_env,
                depends: sched_deps,
                build_by_default: false,
                build_always_stale: true)
endforeach
