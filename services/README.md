# A Quick Start Guide

This guide provides instructions on how to start the SCX scheduler and check its logs.

## Getting Started
To start the SCX scheduler at boot, you need to run the systemd service as root. Here are the steps:

- Enable the service:

```
systemctl enable scx_SCHEDNAME
```

- Start the service:

```
systemctl start scx_SCHEDNAME
```

Alternatively, you can use a shortened version of these commands:

```
systemctl enable --now scx_SCHEDNAME
```

- To check the status of the service, use the following command:

```
systemctl status scx_SCHEDNAME
```

## Checking Journald Logs

The SCX schedulers do not log to the main journald. Instead, they save logs in a dedicated journald namespace.
This is where you should look for information about possible errors.

- To view the logs, use the following command:

```
journalctl --namespace=sched-ext
```

- To find logs from another system startup and identify when a potential error might have occurred, use:

```
journalctl --namespace=sched-ext --list-boots
```

- To verify the amount of space taken up by the logs, use:

```
journalctl --namespace=sched-ext --disk-usage
```

