# scxtop
`scxtop` is a top like utility for sched_ext schedulers. It collects and
aggregates system performance metrics and scheduler events via bpf and
aggregates the data in a live view across CPUs, LLCs, and NUMA nodes. It uses
[`ratatui`](https://ratatui.rs/) for rendering the TUI.

### Using `scxtop`
`scxtop` must be run as root or with capabilities as it uses `perf_event_open`
as well as BPF programs for data collection. Use the help menu (`h` key is the
default to see keybindings) to view the current keybindings:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/38d11e5d-edb7-4567-b62f-da223a47efd9" />

`scxtop` has multiple views for presenting aggregated data. The bar chart view
displays live value bar charts:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/8b3a806c-64d4-4f9e-a07d-9321c94cfbb9" />

The sparkline view is useful for seeing a historical view of the metrics:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/83238b44-5580-4587-a370-b2f9a68d925a" />

### Configuration
`scxtop` can use a configuration file, which can be generated using the `S` key
in the default keymap configuration. The config file follows the
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/latest/).

An example configuration shows customization of default tick rates, theme and keymaps:
```
theme = "IAmBlue"
tick_rate_ms = 250
debug = false
exclude_bpf = false
worker_threads = 4

[keymap]
d = "AppStateDefault"
"?" = "AppStateHelp"
"[" = "DecBpfSampleRate"
q = "Quit"
"+" = "IncTickRate"
u = "ToggleUncoreFreq"
"Page Down" = "PageDown"
S = "SaveConfig"
Up = "Up"
P = "RecordTrace"
- = "DecTickRate"
L = "ToggleLocalization"
t = "ChangeTheme"
"]" = "IncBpfSampleRate"
Down = "Down"
l = "AppStateLlc"
k = "NextEvent"
a = "RecordTrace"
j = "PrevEvent"
v = "NextViewState"
h = "AppStateHelp"
n = "AppStateNode"
s = "AppStateScheduler"
e = "AppStateEvent"
w = "RecordTrace"
f = "ToggleCpuFreq"
Enter = "Enter"
"Page Up" = "PageUp"
x = "ClearEvent"
```

### Shell completions
`scxtop` is able to generate shell completions for various shells using the
`scxtop generate-completions` subcommand:
```
scxtop generate-completions -h
Usage: scxtop generate-completions [OPTIONS]

Options:
  -s, --shell <SHELL>    The shell type [default: bash] [possible values: bash, elvish, fish, powershell, zsh]
      --output <OUTPUT>  Output file, stdout if not present
  -h, --help             Print help
```

### Generating Traces
`scxtop` is able to generate [Perfetto](https://perfetto.dev/) compatible traces.
The trace data also contains DSQ (dispatch queue) data for any active sched_ext
scheduler. Soft IRQs are also collected as part of the trace. Traces can be
collected with the `scxtop trace` subcommand as well as from keybindings from
the TUI.
![scxtop](https://github.com/user-attachments/assets/1be4ace4-e153-48ad-b63e-16f2b4e4c756)

### Aggregating Across Hardware Boundaries
`scxtop` can be used to observe scheduling decisions across hardware boundaries
by using the LLC aggregated view:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/f7b867d8-7afa-4f69-a64a-584859919795" />
For systems with multiple NUMA nodes aggregations can also be done at the NUMA
level:
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/32b6b27d-d7fa-4893-890d-84070caf3497" />

### Scheduler Stats
The scheduler view displays scheduler related stats. For schedulers that use
[`scx_stats`](https://github.com/sched-ext/scx/tree/main/rust/scx_stats) the stats
will be collected and aggregated. The scheduler view displays stats such as DSQ latency,
DSQ slice consumed (how much of the given timeslice was used), and vtime delta. Vtime
delta is useful in understanding the progression of scheduler vtime. For most schedulers
vtime delta should remain rather stable as DSQs are consumed. If a scheduler is using FIFO
scheduling this field may be blank.
<img width="1919" alt="image" src="https://github.com/user-attachments/assets/34b645d0-afd9-4b8c-a2e3-db2118d87dfd" />
