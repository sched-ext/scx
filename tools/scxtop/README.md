# scxtop
`scxtop` is a top like utility for sched_ext schedulers. It collects and
aggregates system performance metrics and scheduler events via bpf and
aggregates the data in a live view across CPUs, LLCs, and NUMA nodes. It uses
[`ratatui`](https://ratatui.rs/) for rendering the TUI.
