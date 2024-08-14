custom_target('scx_stat',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
                        '--all', cargo_build_args],
              env: cargo_env,
              build_by_default: true)
