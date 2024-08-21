# Install the 'scx.initrd' file to /etc/init.d/scx
install_data('scx.initrd', install_dir: '/etc/init.d', rename: 'scx')

# Install the 'scx' file to the '/etc/default' directory
install_data('../scx', install_dir: '/etc/default')

# Install the 'scx.logrotate' file to /etc/logrotate.d/scx
install_data('scx.logrotate', install_dir: '/etc/logrotate.d', rename: 'scx')

# Symlinking /etc/default/scx to /etc/conf.d/scx
install_symlink(
      'scx',
      pointing_to: '/etc/default/scx',
      install_dir: '/etc/conf.d'
)
# meson.add_install_script(
    # 'sh', '-c',
    # 'mkdir -p $(dirname $DESTDIR/@0@/@1@)'.format(systemd_system_unit_dir,
    #     'multi-user.target.wants/phosphor-certificate-manager@nslcd.service'),
# )
# meson.add_install_script(
    # 'sh', '-c',
    # 'ln -s @0@ $DESTDIR/@1@/@2@'.format('../phosphor-certificate-manager@.service',
    #     systemd_system_unit_dir,
    #     'multi-user.target.wants/phosphor-certificate-manager@nslcd.service'),
# )
