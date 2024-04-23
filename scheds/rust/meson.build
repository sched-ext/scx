# the previous scheduler in the compile sequence
sched = []

# to add a new scheduler, assign the output of your custom_target to sched
# and add sched as a dependency to your custom_target. For example:
#
# sched = custom_target('scx_mysched',
#                       ...
#                       depends: [mydep, sched],
#                       build_always_stale: true)
subdir('scx_layered')
subdir('scx_rusty')
subdir('scx_rustland')
subdir('scx_rlfifo')
subdir('scx_lavd')

# the target to compile all rust schedulers
custom_target('rust_scheds',
              input: 'meson.build',
              output: '@PLAINNAME@.__PHONY__',
              command: ['touch', '@PLAINNAME@.__PHONY__'],
              depends: sched,
              build_by_default: true)
