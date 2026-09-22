"""How much of cake's renderer tail is the migration RATE vs the per-path latency?

Resample cake's own two populations at native's migration rate. If that closes
the gap, locality is still the lever. If it does not, the stayed path itself is
slower and placement is eliminated.
"""
import re, subprocess, sys, statistics as st, random
HEAD = re.compile(r"^\s*(\S.*?)\s+(\d+)(?:/(\d+))?\s+\[(\d+)\]\s+([\d.]+):\s+(\S+):\s+(.*)$")
SW = re.compile(r"prev_comm=(.*?) prev_pid=(\d+) prev_prio=\d+ prev_state=(\S+) ==> next_comm=(.*?) next_pid=(\d+)")
WK = re.compile(r"comm=(.*?) pid=(\d+)")

def split(trace, role):
    p = subprocess.Popen(["perf","script","-i",trace], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1<<20)
    pend, lastcpu, same, migr = {}, {}, [], []
    for line in p.stdout:
        m = HEAD.match(line)
        if not m: continue
        _c,_p,_t,cpu,tstr,ev,rest = m.groups()
        try: t=float(tstr)
        except ValueError: continue
        if ev.endswith(("sched_waking","sched_wakeup","sched_wakeup_new")):
            w=WK.search(rest)
            if w and w.group(1)==role: pend.setdefault(w.group(2), t)
        elif ev.endswith("sched_switch"):
            s=SW.search(rest)
            if not s or s.group(4)!=role: continue
            tid=s.group(5); w=pend.pop(tid,None); prev=lastcpu.get(tid); lastcpu[tid]=cpu
            if w is None or prev is None: continue
            lat=(t-w)*1e6
            if 0<=lat<=1e6: (migr if prev!=cpu else same).append(lat)
    p.wait(); return same, migr

def p99(v): return st.quantiles(v,n=1000)[988] if len(v)>100 else float('nan')

cs,cm = split(sys.argv[1],'renderer')
ns,nm = split(sys.argv[2],'renderer')
crate=len(cm)/(len(cs)+len(cm)); nrate=len(nm)/(len(ns)+len(nm))
actual_c=p99(cs+cm); actual_n=p99(ns+nm)
random.seed(1)
N=len(cs)+len(cm)
cf=[random.choice(cm) if random.random()<nrate else random.choice(cs) for _ in range(N)]
print(f"migration rate   cake {crate*100:5.1f}%   native {nrate*100:5.1f}%")
print(f"per-path p99     cake stayed {p99(cs):6.1f}  migrated {p99(cm):6.1f}")
print(f"                 nat  stayed {p99(ns):6.1f}  migrated {p99(nm):6.1f}")
print()
print(f"cake p99 ACTUAL                         {actual_c:7.1f} us")
print(f"cake p99 IF it migrated at native rate  {p99(cf):7.1f} us   <- counterfactual")
print(f"native p99 ACTUAL                       {actual_n:7.1f} us")
gap=actual_c-actual_n; closed=actual_c-p99(cf)
print(f"\ngap to native {gap:.1f}us;  fixing the RATE alone closes {closed:.1f}us = {closed/gap*100:.0f}%")
