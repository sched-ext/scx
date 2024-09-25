c_scheds = ['scx_simple', 'scx_qmap', 'scx_central', 'scx_userland', 'scx_nest',
            'scx_flatcg', 'scx_pair']

foreach sched: c_scheds
  thread_dep = dependency('threads')
  bpf_o = gen_bpf_o.process(sched + '.bpf.c', extra_args: bpf_includes)
  bpf_skel = gen_bpf_skel.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             include_directories: [user_c_includes],
             dependencies: [kernel_dep, libbpf_dep, thread_dep],
             install: true)
endforeach
