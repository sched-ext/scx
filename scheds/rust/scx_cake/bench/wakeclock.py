"""Runnable-since clock for wake latency read from a sched tracepoint stream.

sched_waking and sched_wakeup also fire for a task that is still on a CPU (it
set a sleep state but was woken before it switched out) and for a task already
queued. Pairing such a wake with the task's next switch-in reports run time as
wait time. So the first wake wins, and a task's switch-out discards any wake
that arrived while it was running.
"""


class WakeClock:
    __slots__ = ("_since",)

    def __init__(self):
        self._since = {}

    def wake(self, pid, t, info=None):
        """Start pid's wait at t unless an earlier wake already started it."""
        self._since.setdefault(pid, (t, info))

    def pending(self, pid):
        """The (t, info) of pid's open wait, or None."""
        return self._since.get(pid)

    def switch(self, prev_pid, next_pid):
        """Close prev's stale wake; return next's (t, info) or None."""
        self._since.pop(prev_pid, None)
        return self._since.pop(next_pid, None)
