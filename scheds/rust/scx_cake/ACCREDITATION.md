# Accreditation

Every scheduler in the sched-ext/scx repository is licensed under the GPL-2.0.
scx_cake is one of them.

This repository publishes schedulers side by side so that their authors can
read them, run them, measure them and learn from them. scx_cake has learned
from the schedulers here, and it is published on the same terms, so they are
free to learn from it too.

Thanks to all of their authors.

## Andrea Righi and the private idle word

Thanks to Andrea Righi for `lib/cid_idle.h` (`c2080b1e3`, with the idle re-arm
in `bf12c2959`), which scx_eevdf and scx_rustsched use. It keeps idle state in
memory the scheduler owns, sets and clears it from `ops.update_idle`, claims
it atomically at selection and re-arms it from `ops.dispatch`, so the scheduler
can stop paying for the kernel's idle masks.

The idea for scx_cake's private idle word came from there. Cake's version, one
word on hosts with CPU ids below 64, is our adaptation, and any bugs in it are
ours. [PERFORMANCE.md](./docs/PERFORMANCE.md#private-idle-word) shows what it
measured.
