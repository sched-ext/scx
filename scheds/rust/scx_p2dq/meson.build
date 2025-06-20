e = executable('scx_p2dq_test',
  ['src/bpf/main.bpf.c'],
  dependencies: [scx_test_dep],
  c_args: scx_test_c_args,
  install: false,
  build_by_default: false)
test('scx_p2dq_test', e)
