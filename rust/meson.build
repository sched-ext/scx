cargo_cmd = [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
             cargo_build_args]

# the target to compile all rust binaries
custom_target('rust_binaries',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: cargo_cmd,
              env: cargo_env,
              depends: sched_deps,
              build_by_default: true,
              build_always_stale: true)

# the target to compile loader binary
rust_binaries = ['scx_loader']

foreach binary: rust_binaries
  custom_target(binary,
                output: binary + '@PLAINNAME@.__PHONY__',
                input: 'Cargo.toml',
                command: cargo_cmd + ['-p', binary],
                env: cargo_env,
                build_by_default: false,
                build_always_stale: true)
endforeach
