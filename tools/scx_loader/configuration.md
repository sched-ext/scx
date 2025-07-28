# scx_loader Configuration File

The `scx_loader` can be configured using a TOML file. This file allows you to customize the default scheduler mode, specify custom flags for each supported scheduler and mode, and set a default scheduler to start on boot.

## Configuration File Location

`scx_loader` looks for the configuration file in the following paths (in order):

1. `/etc/scx_loader/config.toml`
2. `/etc/scx_loader.toml`
3. `$VENDORDIR/scx_loader/config.toml` (`$VENDORDIR` is `/usr/share` by default, though your distribution may customize this)
4. `$VENDORDIR/scx_loader.toml` (`$VENDORDIR` is `/usr/share` by default, though your distribution may customize this)

If no configuration file is found at any of these paths, `scx_loader` will use the built-in default configuration.

## Configuration Structure

The configuration file has the following structure:

```toml
default_sched = "scx_flash"
default_mode = "Auto"

[scheds.scx_rustland]
auto_mode = []
gaming_mode = []
lowlatency_mode = []
powersave_mode = []
server_mode = []

[scheds.scx_lavd]
auto_mode = []
gaming_mode = ["--performance"]
lowlatency_mode = ["--performance"]
powersave_mode = ["--powersave"]
server_mode = []

[scheds.scx_flash]
auto_mode = []
gaming_mode = ["-m", "all"]
lowlatency_mode = ["-m", "performance", "-w", "-C", "0"]
powersave_mode = ["-m", "powersave", "-I", "10000", "-t", "10000", "-s", "10000", "-S", "1000"]
server_mode = ["-m", "all", "-s", "20000", "-S", "1000", "-I", "-1", "-D", "-L"]

[scheds.scx_p2dq]
auto_mode = []
gaming_mode = []
lowlatency_mode = ["-y"]
powersave_mode = []
server_mode = ["--keep-running"]

[scheds.scx_rusty]
auto_mode = []
gaming_mode = []
lowlatency_mode = []
powersave_mode = []
server_mode = []

[scheds.scx_bpfland]
auto_mode = []
gaming_mode = ["-m", "performance"]
lowlatency_mode = ["-s", "5000", "-S", "500", "-l", "5000", "-m", "performance"]
powersave_mode = ["-m", "powersave"]
server_mode = ["-p"]

[scheds.scx_tickless]
auto_mode = []
gaming_mode = ["-f", "5000", "-s", "5000"]
lowlatency_mode = ["-f", "5000", "-s", "1000"]
powersave_mode = ["-f", "50", "-p"]
server_mode = ["-f", "100"]

[scheds.scx_cosmos]
auto_mode = ["-d"]
gaming_mode = ["-c", "0", "-p", "0"]
lowlatency_mode = ["-m", "performance", "-c", "0", "-p", "0", "-w"]
powersave_mode = ["-m", "powersave", "-d", "-p", "5000"]
server_mode = ["-a", "-s", "20000"]
```

**`default_sched`:**

* This field specifies the scheduler that will be started automatically when `scx_loader` starts (e.g., on boot).
* It should be set to the name of a supported scheduler (e.g., `"scx_bpfland"`, `"scx_rusty"`, `"scx_lavd"`, `"scx_flash"`, `"scx_p2dq"`, `"scx_rustland"`).
* If this field is not present or is set to an empty string, no scheduler will be started automatically.

**`default_mode`:**

* This field specifies the default scheduler mode that will be used when starting a scheduler without explicitly specifying a mode.
* Possible values are: `"Auto"`, `"Gaming"`, `"LowLatency"`, `"PowerSave"`, `"Server"`.
* If this field is not present, it defaults to `"Auto"`.

**`[scheds.scx_name]`:**

* This section defines the custom flags for a specific scheduler. Replace `scx_name` with the actual name of the scheduler (e.g., `scx_bpfland`, `scx_rusty`, `scx_lavd`, `scx_flash`, `scx_p2dq`, `scx_rustland`).

**`auto_mode`, `gaming_mode`, `lowlatency_mode`, `powersave_mode`, `server_mode`:**

* These fields specify the flags to be used for each scheduler mode.
* Each field is an array of strings, where each string represents a flag.
* If a field is not present or is an empty array, the default flags for that mode will be used.

## Example Configuration

The example configuration above shows how to set custom flags for different schedulers and modes, and how to configure `scx_bpfland` to start automatically on boot.

* For `scx_bpfland`:
    * Gaming mode: `-m performance`
    * Low Latency mode: `-s 5000 -S 500 -l 5000 -m performance`
    * Power Save mode: `-m powersave`
    * Server mode: `-p`
* For `scx_rusty`:
    * No custom flags are defined, so the default flags for each mode will be used.
* For `scx_lavd`:
    * Gaming mode: `--performance`
    * Low Latency mode: `--performance`
    * Power Save mode: `--powersave`
* For `scx_flash`:
    * Gaming mode: `-m all`
    * Low Latency mode: `-m performance -w -C 0`
    * Power Save mode: `-m powersave -I 10000 -t 10000 -s 10000 -S 1000`
    * Server mode: `-m all -s 20000 -S 1000 -I -1 -D -L`
* For `scx_tickless`:
    * Gaming mode: `-f 5000 -s 5000`
    * Low Latency mode: `-f 5000 -s 1000`
    * Power Save mode: `-f 50 -p`
    * Server mode: `-f 100`
* For `scx_p2dq`:
    * Low Latency mode: `-y`
    * Server mode: `--keep-running`
* For `scx_rustland`:
    * No custom flags are defined, so the default flags for each mode will be used.
* For `scx_cosmos`:
    * Gaming mode: `-c 0 -p 0`
    * Low Latency mode: `-m performance -c 0 -p 0 -w`
    * Power Save mode: `-m powersave -d -p 5000`
    * Server mode: `-a -s 20000`

## Fallback Behavior

If a specific flag is not defined in the configuration file, `scx_loader` will fall back to the default flags defined in the code.

## Missing Required Fields

If the `default_mode` field is missing, it will default to `"Auto"`. If a `[scheds.scx_name]` section is missing, or if specific mode flags are missing within that section, the default flags for the corresponding scheduler and mode will be used. If `default_sched` is missing or empty, no scheduler will be started automatically.
