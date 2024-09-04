cargo_cmd = [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
             cargo_build_args]

rust_libs = ['scx_utils', 'scx_stats', 'scx_rustland_core']
rust_bins = ['scx_loader']

cargo_bins_args = []

foreach bin : rust_bins
  cargo_bins_args += ['-p', bin]
endforeach

# the default target to compile all rust binaries (but no libraries)
custom_target('rust_bins',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: cargo_cmd + cargo_bins_args,
              env: cargo_env,
              depends: sched_deps,
              build_by_default: true,
              build_always_stale: true)

# the target to compile individual packages
foreach binary: rust_libs + rust_bins
  custom_target(binary,
                output: binary + '@PLAINNAME@.__PHONY__',
                input: 'Cargo.toml',
                command: cargo_cmd + ['-p', binary],
                env: cargo_env,
                build_by_default: false,
                build_always_stale: true)
endforeach
