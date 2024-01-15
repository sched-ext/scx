systemd_system_unit_dir = systemd.get_variable(pkgconfig : 'systemdsystemunitdir')

  install_data(
    [
      'sched-ext-central.service',  'sched-ext-flatcg.service',  'sched-ext-nest.service',  'sched-ext-pair.service', 'sched-ext-qmap.service', 'sched-ext-rustland.service',  'sched-ext-rusty.service',  'sched-ext-simple.service',  'sched-ext-userland.service',
    ],
    install_dir: systemd_system_unit_dir
  )
