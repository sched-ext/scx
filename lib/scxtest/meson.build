scxtest_lib = static_library(
  'scxtest',
  'scx_test.c',
  'overrides.c',
  c_args: ['-DTEST'],
)

scxtest_dep = declare_dependency(
  link_with: scxtest_lib,
  include_directories: include_directories(['.']),
)
