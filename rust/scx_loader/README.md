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

## Development Status

`scx_loader` is under active development.  Future improvements may include:

* More robust error handling.
* Configuration file.
