"""When the renderer wakes onto its OWN cpu and is slow, WHO is sitting there?

If the occupant is mostly the game's own disposable worker pool -- on a machine
with idle CPUs going spare -- then keeping workers off a hot task's home removes
the wait entirely, which is something native has no notion of.
"""
import re, subprocess, sys, statistics as st
from collections import Counter, defaultdict
HEAD = re.compile(r"^\s*(\S.*?)\s+(\d+)(?:/(\d+))?\s+\[(\d+)\]\s+([\d.]+):\s+(\S+):\s+(.*)$")
SW = re.compile(r"prev_comm=(.*?) prev_pid=(\d+) prev_prio=\d+ prev_state=(\S+) ==> next_comm=(.*?) next_pid=(\d+)")
WK = re.compile(r"comm=(.*?) pid=(\d+)")
trace, role = sys.argv[1], sys.argv[2]
p = subprocess.Popen(["perf","script","-i",trace], stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL, text=True, bufsize=1<<20)
cpu_cur = {}            # cpu -> comm running there
pend = {}               # tid -> (waketime, occupant_of_its_home)
lastcpu = {}
slow, fast = Counter(), Counter()
lat_by = defaultdict(list)
for line in p.stdout:
    m = HEAD.match(line)
    if not m: continue
    _c,_p,_t,cpu,tstr,ev,rest = m.groups()
    try: t=float(tstr)
    except ValueError: continue
    if ev.endswith("sched_switch"):
        s = SW.search(rest)
        if not s: continue
        cpu_cur[cpu] = s.group(4)
        if s.group(4)==role:
            tid=s.group(5); w=pend.pop(tid,None); prev=lastcpu.get(tid); lastcpu[tid]=cpu
            if w is None or prev is None or prev!=cpu: continue
            lat=(t-w[0])*1e6
            if not (0<=lat<=1e6): continue
            occ = w[1] or "?"
            if lat>20: lat_by[occ].append(lat)
            (slow if lat>20 else fast)[occ]+=1
    elif ev.endswith(("sched_waking","sched_wakeup","sched_wakeup_new")):
        w=WK.search(rest)
        if w and w.group(1)==role:
            tid=w.group(2)
            pend.setdefault(tid,(t, cpu_cur.get(lastcpu.get(tid,""),None)))
p.wait()
tot_s=sum(slow.values()); tot_f=sum(fast.values())
print(f"{trace.split('/')[-1]}  same-cpu wakes: {tot_f} fast(<=20us) / {tot_s} SLOW(>20us)")
print(f"\n  occupant of home when the renderer woke and was SLOW:")
for c,n in slow.most_common(9):
    med=st.median(lat_by[c]) if lat_by[c] else 0
    print(f"    {c:22} {n:6}  {n/max(tot_s,1)*100:5.1f}%   median SLOW lat {med:7.1f}us")
