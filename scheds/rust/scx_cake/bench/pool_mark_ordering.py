#!/usr/bin/env python3
"""Small TSO publication model, not an emulation of the kernel or BPF JIT.

The producer's queue write may remain buffered past a subsequent mark read.
An atomic exchange drains prior writes. The retirer atomically clears before
checking the lockless queue count. Explore instructions and FIFO store drains.
See kernel LKMM recipes, Store Buffering, for the corresponding ordering rule.
"""
from collections import deque


def explore(atomic_publish):
    # Producer PC, retirer PC, queue, mark, producer FIFO, conditional-set flag.
    initial = (0, 0, 0, 1, (), False)
    pending = deque([(initial, ())])
    visited = {initial}
    bad = []
    while pending:
        state, trace = pending.popleft()
        p, r, queued, mark, buf, need = state
        if p == 3 and r == 4 and not buf:
            if queued and not mark:
                bad.append(trace)
            continue
        successors = []
        if buf:
            addr, value = buf[0]
            successors.append(((p, r, value if addr == 'queue' else queued,
                                value if addr == 'mark' else mark, buf[1:], need),
                               f'drain {addr}={value}'))
        if p == 0:
            successors.append(((1, r, queued, mark, buf + (('queue', 1),), need),
                               'producer buffers queue=1'))
        elif p == 1:
            if atomic_publish:
                if not buf:
                    successors.append(((3, r, queued, 1, buf, need),
                                       'producer exchanges mark=1 after draining stores'))
            else:
                successors.append(((2, r, queued, mark, buf, not mark),
                                   f'producer reads mark={mark}'))
        elif p == 2:
            successors.append(((3, r, queued, mark,
                                buf + (('mark', 1),) if need else buf, need),
                               'producer conditionally buffers mark=1' if need else 'producer skips mark store'))
        if r == 0:
            successors.append(((p, 1 if mark else 4, queued, mark, buf, need),
                               f'retirer reads mark={mark}'))
        elif r == 1:
            successors.append(((p, 2, queued, 0, buf, need), 'retirer exchanges mark=0'))
        elif r == 2:
            successors.append(((p, 3 if queued else 4, queued, mark, buf, need),
                               f'retirer reads queue={queued}'))
        elif r == 3:
            successors.append(((p, 4, queued, 1, buf, need), 'retirer republishes nonempty mark'))
        for nxt, event in successors:
            if nxt not in visited:
                visited.add(nxt)
                pending.append((nxt, trace + (event,)))
    return len(visited), bad


if __name__ == '__main__':
    old_states, old_bad = explore(False)
    fixed_states, fixed_bad = explore(True)
    assert old_bad, 'The model must reproduce the original lost-publication case.'
    assert not fixed_bad, fixed_bad
    print(f'CONFIRMED: conditional publication admits a lost mark ({old_states} TSO states).')
    print('\n'.join('  ' + step for step in old_bad[0]))
    print(f'PASS: atomic publication excludes the lost mark in all {fixed_states} modeled states.')
    print('Boundary: two-thread TSO model; not a live kernel race reproduction or a proof for every architecture.')
