#!/usr/bin/env python3
"""Extract current scheduler policy into bounded, deterministic helper models."""
import hashlib
import argparse
import importlib.util
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
OUT = parser.parse_args().output.resolve()
if not OUT.is_relative_to(ROOT):
    parser.error('output must be inside the scx repository')
OUT.mkdir(parents=True, exist_ok=True)
SRC = ROOT / 'scheds/rust/scx_cake/src/bpf/cake.bpf.c'
spec = importlib.util.spec_from_file_location('extract', ROOT / 'scheds/rust/scx_cake/bench/review_regressions.py')
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)
source = SRC.read_text()
names = ['cake_idle_word', 'cake_core_word', 'cake_core_contended', 'cake_seat_update', 'cake_seat_retire', 'cake_handoff_yields',
         'cake_rank_tier', 'cake_smt_expand', 'cake_prefer_irq_clean',
         'cake_cpu_irq_bad', 'cake_core_irq_bad', 'cake_pick_cold', 'cake_claim_warm',
         'cake_pick_idle_clean', 'cake_wake_vtime', 'cake_direct_clamp', 'cake_wake_preempt',
         'cake_wake_mark_set', 'cake_wake_mark_retire', 'cake_llc_pool_rescue', 'cake_take_remote',
         'cake_offer_remote', 'cake_ring_steal', 'cake_frontier_candidate',
         'cake_pool_insert', 'cake_enqueue', 'cake_slice_from_service']
code = '\n\n'.join(extract.function(source, n) for n in names)
# The existing extractor covers static functions and select_cpu. This global
# helper has the same signature/body grammar after adding a static prefix.
code += '\n\n' + extract.function(source.replace('__noinline s32 cake_wake_notify(',
                          'static __noinline s32 cake_wake_notify('), 'cake_wake_notify')
weights = re.search(r'static const u64 recip_weight\[.*?\n};', source, re.S).group()
code = weights + '\n' + code
stats = sorted(set(re.findall(r'\bCAKE_(?:STAT|SITE)_\w+', code)))
(OUT / 'stats.h').write_text('enum {' + ','.join(stats) + '};\n')
(OUT / 'functions.h').write_text(code)
binary = OUT / 'audit'
subprocess.run(['cc', '-std=gnu11', '-O2', '-pthread', '-Wall', '-Wextra', '-Werror',
                '-Wno-unused-parameter', '-Wno-unused-function',
                '-fsanitize=undefined', '-fno-sanitize-recover=all',
                '-I' + str(OUT), '-I' + str(SRC.parent),
                str(Path(__file__).with_suffix('.c')), '-o', str(binary)], check=True)
result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
text = 'BPF source SHA256: ' + hashlib.sha256(source.encode()).hexdigest() + '\n' + result.stdout
(OUT / 'result.txt').write_text(text)
print(text, end='')
