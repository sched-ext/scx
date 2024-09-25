# scx_loader: A DBUS Interface for Managing sched-ext Schedulers

`scx_loader` is a utility that provides a convenient DBUS interface for starting, stopping, and managing sched_ext schedulers.

## Features

* **`StartScheduler` Method:**  Launches a scheduler specified by its `scx_name` (e.g., "scx_rusty") and a scheduler mode (profile) represented as an unsigned integer.
* **`StartSchedulerWithArgs` Method:** Starts a scheduler with its `scx_name` and allows passing arbitrary CLI arguments directly to the scheduler.
* **`StopScheduler` Method:** Terminates the currently running scheduler.
* **`CurrentScheduler` Property:** Returns the `scx_name` of the active scheduler or "unknown" if none is running.
* **`SchedulerMode` Property:** Provides information about the currently active scheduler's mode (profile).
* **`SupportedSchedulers` Property:**  Lists the schedulers currently supported by `scx_loader`.

## Usage

`scx_loader` interacts with schedulers through its DBUS interface.  You can use tools like `dbus-send` or `gdbus` to communicate with it.

**Examples using `dbus-send`:**

* **Start a Scheduler:**
  ```bash
  dbus-send --system --print-reply --dest=org.scx.Loader /org/scx/Loader org.scx.Loader.StartScheduler string:scx_rusty uint32:0
  ```
  (This starts `scx_rusty` with scheduler mode 0)

* **Start a Scheduler with Arguments:**
  ```bash
  dbus-send --system --print-reply --dest=org.scx.Loader /org/scx/Loader org.scx.Loader.StartSchedulerWithArgs string:scx_bpfland array:string:"-k","-c","0"
  ```
  (This starts `scx_bpfland` with arguments `-k -c 0`)

* **Stop the Current Scheduler:**
  ```bash
  dbus-send --system --print-reply --dest=org.scx.Loader /org/scx/Loader org.scx.Loader.StopScheduler
  ```

* **Get the Currently Active Scheduler:**
  ```bash
  dbus-send --system --print-reply --dest=org.scx.Loader /org/scx/Loader org.freedesktop.DBus.Properties.Get string:org.scx.Loader string:CurrentScheduler
  ```

* **Get the Supported Schedulers:**
  ```bash
  dbus-send --system --print-reply --dest=org.scx.Loader /org/scx/Loader org.freedesktop.DBus.Properties.Get string:org.scx.Loader string:SupportedSchedulers
  ```

**Note:** Replace the example scheduler names and arguments with the actual ones you want to use.

## DBUS and Systemd Service

`scx_loader` provides the `org.scx.Loader` DBUS service and is automatically started by `dbus-daemon` when an application calls into this service.  Users and administrators do not need to manually start the `scx_loader` daemon.

`scx_loader` is managed by the `scx_loader.service` systemd unit. This service is distinct from the `scx.service` unit, which is used to manage schedulers directly (without DBUS).

## Debugging

In case of issues with `scx_loader`, you can debug the service using the following steps:

1. **Check the service status:**
   ```bash
   systemctl status scx_loader.service
   ```

2. **View the service logs:**
   ```bash
   journalctl -u scx_loader.service
   ```

3. **Enable debug logging:** You can temporarily enable debug logging by modifying the systemd service file:

   - Edit the service file:
     ```bash
     sudo systemctl edit scx_loader.service
     ```
   - Add the following lines under the `[Service]` section:
     ```
     Environment=RUST_LOG=trace
     ```
   - Restart the service:
     ```bash
     sudo systemctl restart scx_loader.service
     ```
   - Check the logs again for detailed debugging information.

## Development Status

`scx_loader` is under active development.  Future improvements may include:

* More robust error handling.
* Configuration file.
