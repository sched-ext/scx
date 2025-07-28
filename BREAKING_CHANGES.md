# Breaking Changes

[`sched_ext`](https://github.com/sched-ext/scx) is still experimental and while we're trying to reduce the number of breaking changes, sometimes they're neccessary to fix bugs or improve the usability.

Below are the changes in both the `sched_ext` kernel tree and the associated commits in this repo.

scx: Rename prep_enable() and cancel_enable(), add exit_task() [[Kernel commit](https://github.com/sched-ext/sched_ext/commit/81e1051116ce50b3b9c99ed3de41927cdb981e77) / [PR](https://github.com/sched-ext/sched_ext/pull/100)] [[scx commit](https://github.com/sched-ext/scx/commit/552b75a9c7513cb3635c06a0ade4abdb227d1dc7)]

* `ops.prep_enable()` is now called `ops.init_task()`
    * `struct scx_enable_args` is now `struct scx_init_task_args`
* `ops.enable()` and `ops.disable()` are now called when a task enters and exits `sched_ext` respectively. This is the same for when all tasks are using scx, but the callbacks can now be fired multiple times for tasks switching their sched policy.
    * No longer passing struct `scx_enable_args *args` to `ops.enable()`.
* `ops.cancel_enable()` has been removed, and `ops.exit_task()` (explained below) is invoked in its stead.
* `ops.exit_task()` has been added, and is called exactly once when a task is exiting if `ops.init_task()` had been successfully invoked on the task previously (or would have been invoked if the callback was defined).
    * Called in lieu of `ops.cancel_enable()` as described above
    * Called with `struct scx_exit_task_args *args` instead of `scx_enable_args *args`.

---

scx: Add scx_bpf_select_cpu_dfl() kfunc [[Kernel commit](https://github.com/sched-ext/sched_ext/commit/07acdca60031900f7d2ae824951342e0cd98f74e)…[Kernel commit](https://github.com/sched-ext/sched_ext/commit/fadfa2fb5894723302e579a0edbd17b595572d91), [PR](https://github.com/sched-ext/sched_ext/pull/104)] [[scx commit](https://github.com/sched-ext/scx/commit/552b75a9c7513cb3635c06a0ade4abdb227d1dc7)]

* The default CPU selection logic operates differently now. We no longer pass `SCX_ENQ_LOCAL` when the default CPU selection has found a core to schedule. Callers can instead use `scx_bpf_select_cpu_dfl()` to get the same behavior and then decide whether to direct dispatch or not.
* Tasks can now be direct-dispatched from `ops.select_cpu()`.
