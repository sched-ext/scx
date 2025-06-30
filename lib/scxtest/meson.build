scxtest_lib = static_library(
  'scxtest',
  'scx_test.c',
  'overrides.c',
  'scx_test_map.c',
  'scx_test_cpumask.c',
  c_args: ['-DTEST'],
)

scxtest_dep = declare_dependency(
  link_with: scxtest_lib,
  include_directories: include_directories(['.']),
)
