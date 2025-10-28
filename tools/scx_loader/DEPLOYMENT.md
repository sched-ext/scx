# scx_loader Deployment Guide

Quick start guide for deploying scx_loader with security hardening.

## Quick Start

### 1. Generate Secure Configuration

```bash
# For server/production systems (group-based auth)
sudo scx_loader init-config --secure \
  --auth-mode group \
  --required-group wheel \
  --output /etc/scx_loader.toml

# For desktop systems (Polkit auth)
sudo scx_loader init-config --secure \
  --auth-mode polkit \
  --output /etc/scx_loader.toml
```

### 2. Review Configuration

```bash
sudo cat /etc/scx_loader.toml
```

Verify security settings:
- `authorization_mode` is NOT "permissive"
- `validate_arguments = true`
- `allow_auto_mode = false` (for production)

### 3. Install System Files

```bash
cd /path/to/scx/tools/scx_loader

# D-Bus configuration
sudo cp org.scx.Loader.conf /usr/share/dbus-1/system.d/

# Polkit policy (if using Polkit)
sudo cp org.scx.Loader.policy /usr/share/polkit-1/actions/

# Reload D-Bus configuration
sudo systemctl reload dbus
```

### 4. Set File Permissions

```bash
# Restrict config file to root only
sudo chmod 600 /etc/scx_loader.toml
sudo chown root:root /etc/scx_loader.toml
```

### 5. Install and Start Service

```bash
# Copy binary (if not already installed)
sudo cp target/release/scx_loader /usr/bin/

# Install systemd service
sudo cp scx_loader.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start
sudo systemctl enable scx_loader
sudo systemctl start scx_loader
```

### 6. Verify Service

```bash
# Check service status
sudo systemctl status scx_loader

# Check for security warnings in logs
sudo journalctl -u scx_loader -n 50 | grep -E "WARNING|AUDIT"

# Test D-Bus connectivity
busctl list | grep scx.Loader
```

## Configuration Examples

### Production Server

**Goal**: Maximum security, group-based authorization, no auto-mode

```toml
[security]
authorization_mode = "group"
required_group = "wheel"
validate_arguments = true
strict_allowlist = false
max_arguments = 128
max_argument_length = 4096
allow_auto_mode = false
max_concurrent_starts = 3
retry_delay_ms = 500
```

### Development Workstation

**Goal**: Convenient but validated, Polkit with auto-mode enabled

```toml
[security]
authorization_mode = "polkit"
validate_arguments = true
strict_allowlist = false
max_arguments = 128
max_argument_length = 4096
allow_auto_mode = true
max_concurrent_starts = 5
retry_delay_ms = 250
```

### High-Security Environment

**Goal**: Strict allowlist, minimal resource limits, no auto-mode

```toml
[security]
authorization_mode = "polkit"
validate_arguments = true
strict_allowlist = true
max_arguments = 32
max_argument_length = 1024
allow_auto_mode = false
max_concurrent_starts = 1
retry_delay_ms = 2000

[security.allowlist.scx_rusty]
allowed_args = ["--help", "--version", "-d"]
allowed_arg_patterns = ["^--interval=[0-9]+$"]
```

## Testing Authorization

### Test Group-Based Authorization

```bash
# As authorized user (in wheel group)
busctl call org.scx.Loader /org/scx/Loader \
  org.scx.Loader StartScheduler ss "scx_rusty" "auto"
# Should succeed

# As unauthorized user (not in wheel group)
sudo -u nobody busctl call org.scx.Loader /org/scx/Loader \
  org.scx.Loader StartScheduler ss "scx_rusty" "auto"
# Should fail with "Access denied"
```

### Test Argument Validation

```bash
# Valid arguments
busctl call org.scx.Loader /org/scx/Loader \
  org.scx.Loader StartSchedulerWithArgs sas \
  "scx_rusty" 2 "--interval" "1000"
# Should succeed

# Invalid arguments (command injection attempt)
busctl call org.scx.Loader /org/scx/Loader \
  org.scx.Loader StartSchedulerWithArgs sas \
  "scx_rusty" 1 "; rm -rf /"
# Should fail with validation error
```

### Monitor Audit Logs

```bash
# Watch audit logs in real-time
sudo journalctl -u scx_loader -f | grep AUDIT

# Example output:
# [AUDIT] [info] [authorization_check] Authorization succeeded for method 'start_scheduler'
# [AUDIT] [info] [scheduler_started] Scheduler 'scx_rusty' started with args: []
```

### Monitor D-Bus Security Signals

```bash
# Monitor for security violations
dbus-monitor "type='signal',interface='org.scx.Loader',member='SecurityViolation'"

# Trigger a violation (as unauthorized user)
sudo -u nobody busctl call org.scx.Loader /org/scx/Loader \
  org.scx.Loader StopScheduler

# You should see a SecurityViolation signal emitted
```

## Monitoring

### Systemd Journal

```bash
# All scx_loader logs
sudo journalctl -u scx_loader

# Only audit events
sudo journalctl -u scx_loader | grep '\[AUDIT\]'

# Security warnings
sudo journalctl -u scx_loader | grep -E 'WARNING|security'

# Follow logs in real-time
sudo journalctl -u scx_loader -f
```

### D-Bus Introspection

```bash
# List available methods
busctl introspect org.scx.Loader /org/scx/Loader

# Check current scheduler
busctl get-property org.scx.Loader /org/scx/Loader \
  org.scx.Loader CurrentScheduler
```

### Security Audit

```bash
# Count authorization failures
sudo journalctl -u scx_loader --since today | \
  grep '\[AUDIT\].*authorization_check.*failed' | wc -l

# List failed authorization attempts with details
sudo journalctl -u scx_loader --since "1 hour ago" | \
  grep '\[AUDIT\].*\[warning\].*authorization'

# Check for argument validation failures
sudo journalctl -u scx_loader --since today | \
  grep '\[AUDIT\].*argument_validation.*failed'
```

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status scx_loader

# View detailed logs
sudo journalctl -u scx_loader -xe

# Common issues:
# 1. Config file missing
sudo ls -l /etc/scx_loader.toml

# 2. Config file invalid
sudo scx_loader init-config --output /tmp/test.toml
sudo diff /etc/scx_loader.toml /tmp/test.toml

# 3. D-Bus configuration issue
sudo dbus-send --system --print-reply \
  --dest=org.freedesktop.DBus /org/freedesktop/DBus \
  org.freedesktop.DBus.ListNames | grep scx
```

### Authorization Failures

```bash
# Check user's groups
groups $USER

# Verify required group in config
grep required_group /etc/scx_loader.toml

# Add user to group
sudo usermod -aG wheel $USER

# Re-login for group changes to take effect
```

### D-Bus Access Denied

```bash
# Check D-Bus policy
sudo cat /usr/share/dbus-1/system.d/org.scx.Loader.conf

# Test D-Bus connectivity
busctl call org.scx.Loader /org/scx/Loader \
  org.scx.Loader SupportedSchedulers

# If this fails, D-Bus policy is too restrictive
```

## Upgrading

### From Non-Secure Version

1. **Backup current config**:
```bash
sudo cp /etc/scx_loader.toml /etc/scx_loader.toml.backup
```

2. **Generate new config**:
```bash
sudo scx_loader init-config --secure --output /etc/scx_loader.toml.new
```

3. **Merge custom settings**:
```bash
# Review both files
sudo diff /etc/scx_loader.toml.backup /etc/scx_loader.toml.new

# Manually merge custom scheduler settings
sudo vim /etc/scx_loader.toml.new
```

4. **Install new config**:
```bash
sudo mv /etc/scx_loader.toml.new /etc/scx_loader.toml
sudo chmod 600 /etc/scx_loader.toml
```

5. **Restart service**:
```bash
sudo systemctl restart scx_loader
```

6. **Verify**:
```bash
sudo journalctl -u scx_loader -n 50
```

### Updating Security Settings

```bash
# Edit config
sudo vim /etc/scx_loader.toml

# Validate changes (service will validate on startup)
sudo systemctl restart scx_loader

# Check for validation errors
sudo systemctl status scx_loader
```

## Uninstallation

```bash
# Stop and disable service
sudo systemctl stop scx_loader
sudo systemctl disable scx_loader

# Remove service file
sudo rm /etc/systemd/system/scx_loader.service
sudo systemctl daemon-reload

# Remove binary
sudo rm /usr/bin/scx_loader

# Remove configuration
sudo rm /etc/scx_loader.toml

# Remove D-Bus configuration
sudo rm /usr/share/dbus-1/system.d/org.scx.Loader.conf

# Remove Polkit policy
sudo rm /usr/share/polkit-1/actions/org.scx.Loader.policy

# Reload D-Bus
sudo systemctl reload dbus
```

## Best Practices

### Security

1. ✅ **Always use authorization** (group or Polkit)
2. ✅ **Enable argument validation**
3. ✅ **Disable auto-mode in production**
4. ✅ **Restrict config file permissions** (0600)
5. ✅ **Monitor audit logs regularly**
6. ✅ **Set up D-Bus signal monitoring**
7. ✅ **Review logs for authorization failures**
8. ✅ **Test security controls periodically**

### Performance

1. Use group-based auth for minimal overhead
2. Keep default resource limits unless needed
3. Adjust retry delays based on workload
4. Monitor semaphore contention in logs

### Maintenance

1. Review audit logs weekly
2. Update allowlists as schedulers evolve
3. Test authorization after user/group changes
4. Keep scx_loader updated for security fixes
5. Backup configuration before changes

## Support

For issues:
1. Check SECURITY.md for detailed troubleshooting
2. Review audit logs for detailed error messages
3. Test with permissive mode to isolate auth issues
4. Check D-Bus and Polkit configurations

## License

SPDX-License-Identifier: GPL-2.0
