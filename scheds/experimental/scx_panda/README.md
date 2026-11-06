# <img src="assets/sched_ext-logo.svg" alt="sched_ext" height="72"> <img src="assets/panda.svg" alt="panda" height="72">

*scx_panda: It's been to Hell and back.*

scx_panda is a Linux CPU scheduler built from discarded ideas and unspent
potential. It runs on the kernel's `sched_ext` class, which lets a scheduler
written as a BPF program replace the default one while the system is running,
and it can be switched off again at any time with no reboot.

It descends from [PANDEMONIUM](https://github.com/wllclngn/PANDEMONIUM), by
the same author, and is measured with PANDEMONIUM's benches.

## What it does

A scheduler decides which thread runs on which CPU, and for how long, when
there are more threads than CPUs. scx_panda makes every one of those
decisions inside the kernel, in a BPF program written in C. A small Rust
program loads it, measures the machine's cache layout once, hands the program
a few tables built from that layout, and then gets out of the way.

Three ideas carry it:

**Every CPU has its own queue, judged by a clock.** A thread that wakes up is
seated on one CPU's queue rather than thrown into a shared pile. Each queue
keeps a clock of how long its oldest waiter has been waiting, and when that
wait passes a target, the running thread is preempted so the waiter gets in.
The target comes from CoDel, the same control law that keeps network queues
short, so a queue that keeps standing is acted on faster and faster until it
drains.

**Distance is a price, not a rule.** Moving a thread to another CPU costs
something, more across a cache boundary than within one. scx_panda measures
that cost once from the cache layout as an effective resistance, the way one
measures distance in an electrical network, and every placement decision adds
it to the wait it is trying to avoid. A thread moves when the move is cheaper
than waiting, and not before.

**Each thread's habit is remembered.** The scheduler keeps a running average of
how long each thread runs before it blocks. When it looks at a busy CPU, it
uses the current thread's habit to estimate how soon that CPU frees up, so a
seat held by a thread that always blocks in a few hundred microseconds reads as
nearly free, and one held by a thread that never blocks reads as taken. The
habit is only ever a number in a sum. Nothing is classified, and no thread is
sorted into a tier.

Everything else is bookkeeping: The loader fills the tables, refills them if a
CPU is plugged in or out, prints counters on request, and restarts the program
if the kernel asks it to.

## Requirements

- Linux 6.12 or later, built with `CONFIG_SCHED_CLASS_EXT=y`
- clang 17 or later and Rust 1.91 or later, to build
- bpftool, for the first build on each kernel

## Install

```
./panda.py install --enable
```

That builds the program, installs `/usr/local/bin/scx_panda`, writes a
`scx_panda.service` unit, starts it, and starts it again on every boot. The
binary carries the file capabilities it needs to load without running as
root. Everything else you need:

```
./panda.py status       # what is built, what is installed, what is running
./panda.py stop         # back to the kernel's default scheduler
./panda.py start        # scx_panda again (refuses while another sched_ext scheduler is loaded)
./panda.py uninstall    # remove the binary and the unit
./panda.py check        # load the program through the kernel's verifier without attaching it
```

Builds go to `~/.cache/panda-build`, outside the source tree. The first build
on a kernel saves that kernel's type information under `~/.cache/panda`, and
the loader's constants are taken from the same file, so the program and the
values it is given always describe one kernel.

Running it by hand instead: `scx_panda` attaches and runs, `scx_panda -v`
prints a counter line every second, `scx_panda --version` names the build.
When it exits it prints a summary and writes the same under
`/tmp/panda/summary-<time>.txt`; if the kernel ever ejects it, the kernel's
dump of every queue lands under `/tmp/panda/dump-<time>.txt`.

## Measuring it

scx_panda is scored with PANDEMONIUM's prism benches from a checkout of
PANDEMONIUM in the sibling directory (`PANDEMONIUM_DIR` points elsewhere if
needed):

```
./panda.py prism --dev frame --iterations 5
```

That runs the frame bench, a stand-in for a game's threads (a simulation
thread fanning jobs out to workers, a render and submit chain, audio and
input threads, with and without background load) with scx_panda as the
scheduler under test. `prism` passes its arguments through and asks for sudo
itself.

A change to the scheduler is never judged by eye. It is built as a
measurement arm, the same program with one lever changed, and run against the
shipped program on the same benches:

```
./panda.py measure --iterations 3
```

`measure` installs each arm in turn, runs the frame bench and the scale
bench on it alone, and prints the results side by side. The arms that exist
today are listed by `./panda.py measure --help`; each one is a single
compile-time define, named in the binary's version so no run is ever read
against the wrong program, and none is left installed afterwards.

## scx catalog and export

`catalog/profiles.json` carries the profile that scxcli and scxtui can start
the scheduler by once scx's own build of scx_panda is installed; `panda.py
install` offers it where scxcli is present. `export_scx.py /path/to/scx`
prepares the crate for the scx repository the way PANDEMONIUM's exporter
does: On a first import it lands the crate in `scheds/experimental` and lists
it as experimental in scx's catalog, and on a later one it replaces the crate
where the checkout has it. `--dry-run` shows what it would do without
touching cargo or the network. It commits nothing.

## Credits

None of the three ideas is new on its own. What scx_panda adds is the
refusal to turn any of them into a rule.

- The queue clock and its target are CoDel: Kathleen Nichols and Van
  Jacobson, "Controlling Queue Delay", ACM Queue, 2012, and RFC 8289 by
  Nichols, Jacobson, McGregor and Iyengar. The target's motion between its
  bounds is a damped harmonic oscillator, standard control.
- Distance as effective resistance is resistance distance: D. J. Klein and
  M. Randić, Journal of Mathematical Chemistry, 1993. The spectral side is
  M. Fiedler, "Algebraic connectivity of graphs", Czechoslovak Mathematical
  Journal, 1973. The loader's solvers follow Christiano, Kelner, Mądry,
  Spielman and Teng (STOC 2011) and Chen, Kyng, Liu, Peng, Probst Gutenberg
  and Sachdeva (FOCS 2022); the exact small-graph form is the spanning
  two-forest ratio of Barrett, Evans and Francis.
- The run habit is an exponentially weighted moving average of service per
  run, standard practice in schedulers for decades; no novelty is claimed
  for it, only for reading it as a price and never as a class.
- sched_ext is the Linux kernel's extensible scheduler class by Tejun Heo,
  David Vernet and the sched-ext contributors; the BPF program is written
  against scx's common headers, which keep their own copyright.
- The mechanisms themselves come from PANDEMONIUM's record, the author's
  earlier scheduler, and from silica, the author's record before it: What
  converged there was kept, what the record said failed was not rebuilt.
### Images

Both images at the top belong to other projects and are not covered by this
repository's license. Each SVG carries the same citation inside it.

- **sched_ext logo**, the mark alone. Owner: The sched_ext project,
  [sched-ext.com](https://sched-ext.com/). Source:
  [sched-ext.com/img/scx_Logo_Color.svg](https://sched-ext.com/img/scx_Logo_Color.svg),
  whose repository is
  [sched-ext/sched-ext.com](https://github.com/sched-ext/sched-ext.com),
  licensed GPL-2.0; the project states no separate artwork license or
  author. Retrieved 2026-11-06. Stored as `assets/sched_ext-logo.svg` with the
  embedded print colour profile and editor metadata removed and the drawing
  unchanged. It marks what this scheduler runs on.
- **Panda face**, Unicode U+1F43C, from Google's
  [Noto Emoji](https://github.com/googlefonts/noto-emoji), release
  [v2.042](https://github.com/googlefonts/noto-emoji/releases/tag/v2.042),
  file `svg/emoji_u1f43c.svg`. Owner: Google LLC, the Noto Emoji project.
  License: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0),
  the license the project's README places its image resources under; its
  text is `assets/LICENSE-noto-emoji`. Retrieved 2026-11-06. Stored as
  `assets/panda.svg` with the drawing unchanged. It is this project's mark.

## License

GPL-2.0-only. Copyright (c) 2026 Will Clingan.
