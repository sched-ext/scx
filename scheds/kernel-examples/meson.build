c_scheds = ['scx_simple', 'scx_qmap', 'scx_central', 'scx_pair', 'scx_flatcg', 'scx_userland']

foreach sched: c_scheds
  bpf_o = gen_bpf_o.process(sched + '.bpf.c', extra_args: bpf_includes)
  bpf_skel = gen_bpf_skel.process(bpf_o)
  executable(sched, [bpf_skel, sched + '.c'],
             include_directories: [user_c_includes],
             dependencies: libbpf_dep)
endforeach
