# BPF compilation uses the gen_bpf_o generator. The following should be
# passed in as extra_args.
bpf_includes = ['-I', join_paths(meson.current_source_dir(), 'include/common'),
                '-I', join_paths(meson.current_source_dir(), 'include/vmlinux')]

# Common include paths for user C compilation. The following should be
# passed in as executable::include_directories.
user_c_includes = include_directories('include/common')

subdir('kernel-examples')
