systemd_system_unit_dir = systemd.get_variable(pkgconfig : 'systemdsystemunitdir')

  install_data(
    [
      'scx_central.service',  'scx_flatcg.service',  'scx_nest.service',  'scx_pair.service', 'scx_qmap.service', 'scx_rustland.service',  'scx_rusty.service',  'scx_simple.service',  'scx_userland.service',
    ],
    install_dir: systemd_system_unit_dir
  )
