systemd_system_unit_dir = systemd.get_variable(pkgconfig : 'systemdsystemunitdir')

  install_data(
    [
      'scx.service',
    ],
    install_dir: systemd_system_unit_dir
  )

  install_data(
    [
      'journald@sched-ext.conf',
    ],
    install_dir: '/etc/systemd'
  )

  install_data(
    [
      'scx',
    ],
    install_dir: '/etc/default'
  )
