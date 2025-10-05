# Migration Guide

This document describes the migration process for users and packagers of **scx_loader** and related schedulers.

## Dropping `scx.service`

Starting with **scx 1.0.17**, the legacy `scx.service` unit has been removed.
You must switch to using `scx_loader.service` and the new configuration file format.

### Migration Steps

1. **Disable the old service**

```bash
sudo systemctl disable --now scx.service
```

2. **Copy the default configuration**

```bash
sudo cp /usr/share/scx_loader/config.toml /etc/scx_loader/config.toml
```

3. **Edit the configuration**

Uncomment or set proper values in `/etc/scx_loader/config.toml`. For example:

```toml
# This field specifies the scheduler that will be started automatically when scx_loader starts (e.g., on boot).
default_sched = "scx_flash"

# This field specifies the mode which will be used when scx_loader starts (e.g., on boot).
default_mode = "Auto"

# This "structure" allows configuring flags for each scheduler mode of particular scx scheduler
#[scheds.'scheduler']
#auto_mode = []
#gaming_mode = []
#lowlatency_mode = []
#powersave_mode = []
#server_mode = []
```

You can choose your preferred scheduler and modes here.

4. **Enable the new service**

```bash
sudo systemctl enable --now scx_loader.service
```

5. **Reboot and check the status**

```bash
systemctl status scx_loader.service
```

Example output:

```bash
● scx_loader.service - DBUS on-demand loader of sched-ext schedulers
     Loaded: loaded (/usr/lib/systemd/system/scx_loader.service; enabled; preset: disabled)
     Active: active (running) since Thu 2025-09-18 10:56:06 CEST; 2s ago
   Main PID: 79046 (scx_loader)
      Tasks: 23 (limit: 37394)
     Memory: 11.7M (peak: 11.7M)
        CPU: 92ms
     CGroup: /system.slice/scx_loader.service
             ├─79046 /usr/bin/scx_loader
             └─79066 scx_flash
```

## Configuration File Lookup Order

`scx_loader` looks for its configuration file in the following paths **in order**:

1. `/etc/scx_loader/config.toml`
2. `/etc/scx_loader.toml`
3. `$VENDORDIR/scx_loader/config.toml`
4. `$VENDORDIR/scx_loader.toml`

> **Note**: `$VENDORDIR` defaults to `/usr/share`, but distributions may override this path.

This means that if multiple configuration files exist, the first one found in the above order will be used.
To avoid confusion, it is recommended to keep only **one active configuration file** in the system.

---
