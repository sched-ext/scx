# Get the directory for systemd system unit files
systemd_system_unit_dir = systemd.get_variable(pkgconfig : 'systemdsystemunitdir')

# Install the 'scx.service' file to the systemd system unit directory
install_data('scx.service', install_dir: systemd_system_unit_dir)

# Install the 'journald@sched-ext.conf' file to the '/etc/systemd' directory
install_data('journald@sched-ext.conf', install_dir: '/etc/systemd')

# Install the 'scx' file to the '/etc/default' directory
install_data('../scx', install_dir: '/etc/default')
