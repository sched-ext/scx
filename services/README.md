# A Quick Start Guide

This guide provides instructions for running the SCX schedulers as a systemd service and checking its logs.

## Getting Started

To start, create the scx_loader configuration directory:
```bash
sudo mkdir /etc/scx_loader
```
then copy the default configuration into said directory
```bash
sudo cp /usr/share/scx_loader/config.toml /etc/scx_loader/config.toml
```
now you can edit the copied file
```bash
sudo nano /etc/scx_loader/config.toml
```
- First uncomment `#default_sched = "scx_cosmos"` and `#default_mode = "Auto"` as both of these variables are required to set your preferred scheduler.
- From here you can change the default_sched to your preferred scheduler. You can get more information on the available schedulers at [scheds](https://github.com/sched-ext/scx/tree/main/scheds).
- The default_mode variable corresponds to the mode scx_loader will launch in by default, and by extension, the scheduler flags listed therein. (Be sure to uncomment this line as well).

For example if you set  
`default_sched = "scx_rusty"`  
`default_mode = "Auto"`  
`auto_mode = ["--perf"]`  
Then scx_loader would launch `scx_rusty --perf` as the default scheduler.

- To see what flags you can add to any given scheduler:

```
scx_SCHEDNAME --help
```

To start the SCX scheduler at boot, you need to run the systemd service as root. Here are the steps:


- Enable the service:

```
systemctl enable scx_loader.service
```

- Start the service:

```
systemctl start scx_loader.service
```

Alternatively, you can use a shortened version of these commands:

```
systemctl enable --now scx_loader.service
```

- To check the status of the service, use the following command:

```
systemctl status scx_loader.service
```

## Checking journald Logs


- To view the logs, use the following command:

```
journalctl -u scx_loader.service
```

- To view the logs of the current session use the command

```
journalctl -u scx_loader.service -b 0
```

