from pathlib import Path
import csv, json, random, statistics, subprocess

p = Path(__file__).resolve().parent
root = p.parent.parent.parent / 'scx_cake_bench/runs' / p.name
plan = []
for block in range(5):
    order = ['hash', 'direct', 'direct', 'hash'] if block % 2 == 0 else ['direct', 'hash', 'hash', 'direct']
    for slot, arm in enumerate(order):
        plan.append(dict(block=block+1, slot=slot+1, arm=arm,
                         name=f'sim-b{block+1}-s{slot+1}-{arm}'))
(root/'simulation-plan.json').write_text(json.dumps(dict(
    blocks=5, order='alternating ABBA/BAAB', cpus=2, host_performance_claim=False,
    primary='all fixed-work checksums and completion; TCG timing diagnostic only',
    kernel='same candidate image; hash arm sets sched_ext.dsq_direct=0', slots=plan), indent=2)+'\n')
rows = []
for item in plan:
    cmd = ['python3', str(p/'run-vm.py'), item['name'], '--sim']
    if item['arm'] == 'hash': cmd.append('--hash-only')
    subprocess.run(cmd, check=True)
    result = json.loads((root/item['name']/'result.json').read_text())
    assert result['passed']
    samples = [t for t in result['tests'] if 'checksum' in t]
    assert len(samples) == 1
    rows.append(dict(**item, **samples[0]))
assert len({r['checksum'] for r in rows}) == 1
paired = []
for block in range(1, 6):
    selected = [r for r in rows if r['block'] == block]
    entry = dict(block=block)
    for metric in ['elapsed_ns', 'wake_late_max_ns']:
        av = {arm: statistics.mean(r[metric] for r in selected if r['arm'] == arm)
              for arm in ['hash', 'direct']}
        entry[metric] = dict(**av, delta=av['direct']-av['hash'], percent=100*(av['direct']/av['hash']-1))
    paired.append(entry)
rng = random.Random(2048)
summary = {}
for metric in ['elapsed_ns', 'wake_late_max_ns']:
    deltas = [b[metric]['delta'] for b in paired]
    boot = sorted(statistics.mean(rng.choices(deltas, k=5)) for _ in range(10000))
    summary[metric] = dict(mean_delta_ns=statistics.mean(deltas),
                           paired_bootstrap_95=[boot[250], boot[9750]],
                           mean_hash_ns=statistics.mean(b[metric]['hash'] for b in paired),
                           mean_direct_ns=statistics.mean(b[metric]['direct'] for b in paired))
with (root/'simulation.csv').open('w') as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
result = dict(slots=len(rows), blocks=5, workers_per_slot=4,
              total_frames=sum(r['frames'] for r in rows), total_steps=sum(r['steps'] for r in rows),
              checksums_match=True, paired=paired, summary=summary,
              limitation='TCG has no faithful 9800X3D cache/coherence timing. wake_late_max_ns is completion lateness against a per-iteration deadline, not measured scheduler wake-to-run latency. Five blocks are a small diagnostic sample.')
(root/'simulation.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result), flush=True)
