#!/usr/bin/env python3
"""Analyze a retained clock-only observation, not scheduler performance."""
import argparse
import json
import statistics
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("input", type=Path)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
data = json.loads(args.input.read_text())
samples = data["samples"]
assert len(samples) >= 2
idx = {domain: i for i, domain in enumerate(data["domains"])}
assert all(domain in idx for domain in (0, 1, 2))
period = data["timestamp_period_ns"]
assert period == 1, "This dated analysis uses integer device ns; handle other periods explicitly."
first, last = samples[0], samples[-1]
gpu_mono = [s["values"][idx[0]] - s["values"][idx[1]] for s in samples]
gpu_raw = [s["values"][idx[0]] - s["values"][idx[2]] for s in samples]
mono_raw = [s["values"][idx[1]] - s["values"][idx[2]] for s in samples]
span = last["values"][idx[2]] - first["values"][idx[2]]
span_mono = last["values"][idx[1]] - first["values"][idx[1]]
assert span > 0 and span_mono > 0


def stats(values):
    return {"min": min(values), "median": statistics.median(values), "max": max(values)}


result = {
    "samples": len(samples), "duration_raw_ns": span,
    "timestamp_period_ns": period,
    "queue_timestamp_valid_bits": data["queue_timestamp_valid_bits"],
    "adjtimex": data["adjtimex"],
    "adjtimex_freq_ppm": data["adjtimex"]["freq_scaled_ppm"] / 65536,
    "coarse_resolution_ns": data["coarse_resolution_ns"],
    "query_wall_ns": stats([s["query_after"] - s["query_before"] for s in samples]),
    "reported_max_deviation_ns": stats([s["max_deviation_ns"] for s in samples]),
    "mono_raw_change_ns": mono_raw[-1] - mono_raw[0],
    "mono_relative_to_raw_ppm": (mono_raw[-1] - mono_raw[0]) / span * 1e6,
    "gpu_mono_change_ns": gpu_mono[-1] - gpu_mono[0],
    "gpu_relative_to_mono_ppm": (gpu_mono[-1] - gpu_mono[0]) / span_mono * 1e6,
    "gpu_raw_change_ns": gpu_raw[-1] - gpu_raw[0],
    "gpu_relative_to_raw_ppm": (gpu_raw[-1] - gpu_raw[0]) / span * 1e6,
    "endpoint_reported_uncertainty_ppm": (last["max_deviation_ns"] + first["max_deviation_ns"]) / span * 1e6,
    "interpretation": "Short observed clock-mapping change; not a stable oscillator drift bound, source-to-consumer latency or scheduler speedup. pMaxDeviation is implementation-reported, not an independently measured confidence interval.",
}
args.output.mkdir(parents=True, exist_ok=True)
(args.output / "clock-analysis.json").write_text(json.dumps(result, indent=2) + "\n")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

elapsed = [(s["values"][idx[2]] - first["values"][idx[2]]) / 1e9 for s in samples]
uncertainty = [(s["max_deviation_ns"] + first["max_deviation_ns"]) / 1000 for s in samples]
uncertainty[0] = 0  # The reference sample minus itself is identically zero.
fig, ax = plt.subplots(figsize=(9.6, 5.2), layout="constrained")
ax.errorbar(elapsed, [(v - gpu_mono[0]) / 1000 for v in gpu_mono],
            yerr=uncertainty, fmt="o-", capsize=3, label="GPU minus MONOTONIC offset change")
ax.plot(elapsed, [(v - mono_raw[0]) / 1000 for v in mono_raw],
        "s--", label="MONOTONIC minus RAW offset change")
ax.set(title="Clock offsets change: a one-time conversion becomes stale",
       xlabel="Elapsed RAW time (seconds)", ylabel="Offset change from first sample (µs)")
ax.grid(alpha=0.25)
ax.legend(loc="lower left")
fig.suptitle("RTX 4090 · NVIDIA 615.71.09 · 16 clock queries · 2026-10-02", fontsize=11)
fig.text(0.5, -0.025, "Clock observation only. Error bars sum reported calibration deviations for each pair; not confidence intervals.", ha="center", fontsize=9)
fig.savefig(args.output / "clock-offset-drift.png", dpi=180, bbox_inches="tight")
plt.close(fig)
print(json.dumps(result, indent=2))
