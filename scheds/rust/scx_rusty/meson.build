custom_target('scx_rusty',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
                        cargo_build_args],
              env: cargo_env,
              depends: [libbpf],
              build_by_default: true)
