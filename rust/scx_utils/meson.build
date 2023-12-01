custom_target('scx_utils',
              output: '@PLAINNAME@.__PHONY__',
              input: 'Cargo.toml',
              command: [cargo, 'build', '--manifest-path=@INPUT@', '--target-dir=@OUTDIR@',
                        cargo_extra_args],
              build_by_default: true)
