c_scheds = ['scx_simple', 'scx_qmap', 'scx_central', 'scx_userland', 'scx_nest',
            'scx_flatcg', 'scx_pair', 'scx_prev', 'scx_cosmos']

c_scheds_lib = ['scx_sdt']

thread_dep = dependency('threads')

foreach sched: c_scheds
  bpf_o = gen_bpf_o.process(sched + '.bpf.c')
  bpf_skel = gen_bpf_skel.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             dependencies: [kernel_dep, libbpf_dep, thread_dep, user_c_dep],
             install: true)
endforeach

foreach sched: c_scheds_lib
  bpf_o = gen_bpf_o.process(sched + '.bpf.c')
  bpf_skel = gen_bpf_skel_lib.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             dependencies: [kernel_dep, libbpf_dep, thread_dep, user_c_dep],
             install: true)
endforeach
