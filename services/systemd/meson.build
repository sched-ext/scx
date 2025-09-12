# Get the directory for systemd system unit files
systemd_system_unit_dir = systemd.get_variable(pkgconfig : 'systemdsystemunitdir')

# Install the 'scx_loader.service' file to the systemd system unit directory
install_data('scx_loader.service', install_dir: systemd_system_unit_dir)

# Install the 'org.scx.Loader.service' file to the dbus system services directory
install_data('org.scx.Loader.service', install_dir: '/usr/share/dbus-1/system-services')

# Install the default 'scx_loader' config file to the '$VENDORDIR/scx_loader' directory
install_data('../scx_loader.toml', rename: 'config.toml', install_dir: get_option('vendordir') + '/scx_loader')
