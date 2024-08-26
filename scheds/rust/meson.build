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

# per-scheduler targets
rust_scheds = ['scx_lavd', 'scx_bpfland', 'scx_rustland', 'scx_rlfifo',
               'scx_edfgpt', 'scx_rusty',
               'scx_layered'] # scx_mitosis temporarily excluded

foreach sched: rust_scheds
  custom_target(sched,
                output: sched + '@PLAINNAME@.__PHONY__',
                input: 'Cargo.toml',
                command: cargo_cmd + ['-p', sched],
                env: cargo_env,
                depends: sched_deps,
                build_by_default: false,
                build_always_stale: true)
endforeach
