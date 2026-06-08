#!/usr/bin/env python3
"""Extract game-run Cake action-path features from headless diagnostics.

The live MangoHud CSV tells us the frame outcome.  This helper turns the
matching ``cake_diag_latest.json``/``.txt`` snapshot into a compact ML-friendly
feature packet so a game run can also answer *which scheduler path* was active:
fastscan prev, SMT contention, native fallback, local-waiter admission,
LLC-vtime shared fallback, callback cost, and wake/tail monitors.

The preferred input is the JSON written by:

    scx_cake --verbose --diag-dir <dir> --diag-period <seconds>

Text snapshots are accepted as a fallback for a few high-value scalar lines.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import hashlib
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1

ROUTE_LABELS = ["none", "prev", "slot0", "slot1", "slot2", "slot3", "tunnel"]
PROBE_LABELS = [
    "hit",
    "busy",
    "dirty",
    "smt_busy",
    "claim_fail",
    "claim_skip",
    "invalid",
]
NATIVE_FALLBACK_LABELS = ["entry", "default", "and"]
ROUTE_BLOCK_LABELS = [
    "invalid_prev",
    "affinity",
    "kthread",
    "route_low",
    "select_low",
    "trust_low",
    "load_shock",
    "floor_low",
    "owner_low",
    "pull_low",
    "audit",
    "latency_gate",
    "unknown_route",
]
STORM_GUARD_MODE_LABELS = ["off", "shadow", "shield", "full"]
STORM_GUARD_DECISION_LABELS = [
    "none",
    "allow",
    "shadow",
    "shield",
    "full",
    "throttle",
    "kick_idle",
    "kick_preempt",
    "unknown",
]


def pct(num: float, den: float) -> float:
    return (num * 100.0 / den) if den else 0.0


def rate(num: float, seconds: float) -> float:
    return (num / seconds) if seconds > 0 else 0.0


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def maybe_git_head(repo: Path | None) -> str:
    if repo is None:
        return ""
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return ""


def maybe_git_dirty(repo: Path | None) -> str:
    if repo is None:
        return ""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo), "status", "--porcelain"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        return "1" if out.strip() else "0"
    except Exception:
        return ""


def maybe_git_source_diff_sha(repo: Path | None) -> str:
    """Hash dirty scheduler source/build inputs without letting docs skew UUIDs."""
    if repo is None:
        return ""
    source_paths = [
        "scheds/rust/scx_cake/src",
        "scheds/rust/scx_cake/Cargo.toml",
        "scheds/rust/scx_cake/build.rs",
        "Cargo.toml",
        "Cargo.lock",
    ]
    chunks: list[bytes] = []
    for diff_mode in ([], ["--cached"]):
        try:
            out = subprocess.check_output(
                ["git", "-C", str(repo), "diff", "--binary", *diff_mode, "HEAD", "--", *source_paths],
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            return ""
        chunks.append(out)
    dirty_source = b"\0".join(chunks)
    return hashlib.sha256(dirty_source).hexdigest() if dirty_source.strip(b"\0") else ""


def put(features: dict[str, Any], key: str, value: Any) -> None:
    if value is None:
        return
    if isinstance(value, bool):
        features[key] = int(value)
    elif isinstance(value, (int, float, str)):
        features[key] = value


def numeric_leafs(prefix: str, value: Any, out: dict[str, Any]) -> None:
    if isinstance(value, bool):
        out[prefix] = int(value)
    elif isinstance(value, (int, float)):
        out[prefix] = value
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            numeric_leafs(f"{prefix}_{idx}", item, out)
    elif isinstance(value, dict):
        for key, item in value.items():
            safe = re.sub(r"[^a-zA-Z0-9_]+", "_", str(key)).strip("_").lower()
            if safe:
                numeric_leafs(f"{prefix}_{safe}", item, out)


def array_features(
    features: dict[str, Any],
    prefix: str,
    values: list[Any],
    labels: list[str],
) -> None:
    for idx, label in enumerate(labels):
        if idx < len(values):
            put(features, f"{prefix}_{label}", values[idx])


def route_triplet_features(
    features: dict[str, Any],
    prefix: str,
    attempts: list[Any],
    hits: list[Any],
    misses: list[Any],
) -> None:
    for idx, label in enumerate(ROUTE_LABELS):
        att = int(attempts[idx]) if idx < len(attempts) else 0
        hit = int(hits[idx]) if idx < len(hits) else 0
        miss = int(misses[idx]) if idx < len(misses) else 0
        put(features, f"{prefix}_{label}_attempt", att)
        put(features, f"{prefix}_{label}_hit", hit)
        put(features, f"{prefix}_{label}_miss", miss)
        put(features, f"{prefix}_{label}_hit_pct", round(pct(hit, hit + miss), 3))


def scoreboard_probe_features(
    features: dict[str, Any],
    matrix: list[Any],
) -> None:
    for route_idx, route in enumerate(ROUTE_LABELS):
        row = matrix[route_idx] if route_idx < len(matrix) and isinstance(matrix[route_idx], list) else []
        row_total = 0
        for outcome_idx, outcome in enumerate(PROBE_LABELS):
            val = int(row[outcome_idx]) if outcome_idx < len(row) else 0
            row_total += val
            put(features, f"cake_scoreboard_{route}_{outcome}", val)
        for outcome_idx, outcome in enumerate(PROBE_LABELS):
            val = int(row[outcome_idx]) if outcome_idx < len(row) else 0
            put(features, f"cake_scoreboard_{route}_{outcome}_pct", round(pct(val, row_total), 3))


def extract_release_game_diag(
    data: dict[str, Any],
    features: dict[str, Any],
    interpretation: list[str],
) -> None:
    """Extract the opt-in low-overhead release diagnostic sidecar.

    Release Cake builds intentionally compile the full debug/TUI telemetry out,
    so game captures use a tiny BSS counter packet under ``release_game_diag``.
    Keep feature names short and stable because bench-assets stores these in
    per-capture action sidecars.
    """
    release_diag = data.get("release_game_diag") or {}
    if not isinstance(release_diag, dict):
        return

    totals = release_diag.get("totals") or {}
    derived = release_diag.get("derived") or {}
    if not isinstance(totals, dict):
        totals = {}
    if not isinstance(derived, dict):
        derived = {}

    for key, value in totals.items():
        safe = re.sub(r"[^a-zA-Z0-9_]+", "_", str(key)).strip("_").lower()
        if safe:
            put(features, f"cake_release_{safe}", value)
    for key, value in derived.items():
        safe = re.sub(r"[^a-zA-Z0-9_]+", "_", str(key)).strip("_").lower()
        if safe:
            put(features, f"cake_release_{safe}", value)

    per_cpu = release_diag.get("per_cpu") or []
    if isinstance(per_cpu, list):
        active_cpus = 0
        maxima: dict[str, float] = {}
        for row in per_cpu:
            if not isinstance(row, dict):
                continue
            row_active = False
            for key, value in row.items():
                if key == "cpu" or isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                safe = re.sub(r"[^a-zA-Z0-9_]+", "_", str(key)).strip("_").lower()
                if not safe:
                    continue
                maxima[safe] = max(float(value), maxima.get(safe, 0.0))
                row_active = row_active or value != 0
            active_cpus += int(row_active)
        put(features, "cake_release_active_cpus", active_cpus)
        for key, value in maxima.items():
            put(features, f"cake_release_per_cpu_max_{key}", round(value, 3))

    nfw_entry = float(features.get("cake_release_nfw_entry", 0.0))
    nfw_hit = float(features.get("cake_release_nfw_hit", 0.0))
    nfw_hit_prev_cpu = float(features.get("cake_release_nfw_hit_prev_cpu", 0.0))
    nfw_hit_other_cpu = float(features.get("cake_release_nfw_hit_other_cpu", 0.0))
    nfw_hit_select_cpu = float(features.get("cake_release_nfw_hit_select_cpu", 0.0))
    nfw_hit_prev_primary = float(features.get("cake_release_nfw_hit_prev_primary", 0.0))
    nfw_hit_other_primary = float(features.get("cake_release_nfw_hit_other_primary", 0.0))
    nfw_hit_local_depth_sample = float(features.get("cake_release_nfw_hit_local_depth_sample", 0.0))
    nfw_hit_local_depth_nonzero = float(features.get("cake_release_nfw_hit_local_depth_nonzero", 0.0))
    nfw_hit_local_depth_gt1 = float(features.get("cake_release_nfw_hit_local_depth_gt1", 0.0))
    nfw_hit_local_depth_gt3 = float(features.get("cake_release_nfw_hit_local_depth_gt3", 0.0))
    nfw_prev_idle_attempt = float(features.get("cake_release_nfw_prev_idle_attempt", 0.0))
    nfw_prev_idle_sibling_block = float(
        features.get("cake_release_nfw_prev_idle_sibling_block", 0.0)
    )
    nfw_prev_idle_claim = float(features.get("cake_release_nfw_prev_idle_claim", 0.0))
    nfw_prev_idle_fallback_attempt = float(
        features.get("cake_release_nfw_prev_idle_fallback_attempt", 0.0)
    )
    nfw_prev_idle_fallback_hit = float(
        features.get("cake_release_nfw_prev_idle_fallback_hit", 0.0)
    )
    nfw_prev_idle_fallback_prev = float(
        features.get("cake_release_nfw_prev_idle_fallback_prev", 0.0)
    )
    nfw_prev_idle_fallback_other = float(
        features.get("cake_release_nfw_prev_idle_fallback_other", 0.0)
    )
    nfw_miss = float(features.get("cake_release_nfw_miss", 0.0))
    nfw_miss_tunnel = float(features.get("cake_release_nfw_miss_tunnel", 0.0))
    enqueue_wakeup = float(features.get("cake_release_enqueue_wakeup", 0.0))
    enqueue_wake_busy = float(features.get("cake_release_enqueue_wake_busy", 0.0))
    wake_kick_preempt = float(features.get("cake_release_wake_kick_preempt", 0.0))
    local_waiter_attempt = float(features.get("cake_release_local_waiter_attempt", 0.0))
    local_waiter_reject = float(features.get("cake_release_local_waiter_reject", 0.0))
    stopping_call = float(features.get("cake_release_stopping_call", 0.0))
    stopping_runnable = float(features.get("cake_release_stopping_runnable", 0.0))
    stopping_blocked = float(features.get("cake_release_stopping_blocked", 0.0))
    stopping_owner_update = float(features.get("cake_release_stopping_owner_update", 0.0))
    stopping_route_observe = float(features.get("cake_release_stopping_route_observe", 0.0))
    stopping_route_pending = float(features.get("cake_release_stopping_route_pending", 0.0))
    stopping_route_no_pending = float(features.get("cake_release_stopping_route_no_pending", 0.0))
    stopping_route_total = stopping_route_pending + stopping_route_no_pending
    stopping_account_relaxed = float(features.get("cake_release_stopping_account_relaxed", 0.0))
    stopping_account_audit = float(features.get("cake_release_stopping_account_audit", 0.0))
    stopping_account_total = stopping_account_relaxed + stopping_account_audit
    stopping_scoreboard_owner_result = float(
        features.get("cake_release_stopping_scoreboard_owner_result", 0.0)
    )
    stopping_lean_return = float(features.get("cake_release_stopping_lean_return", 0.0))
    dispatch_call = float(features.get("cake_release_dispatch_call", 0.0))
    dispatch_idle_core_rescue_hit = float(
        features.get("cake_release_dispatch_idle_core_rescue_hit", 0.0)
    )
    dispatch_idle_llc_rescue_hit = float(
        features.get("cake_release_dispatch_idle_llc_rescue_hit", 0.0)
    )
    dispatch_cache_hit = float(features.get("cake_release_dispatch_cache_hit", 0.0))
    dispatch_throughput_hit = float(features.get("cake_release_dispatch_throughput_hit", 0.0))
    dispatch_core_steal_hit = float(features.get("cake_release_dispatch_core_steal_hit", 0.0))
    dispatch_llc_pull_hit = float(features.get("cake_release_dispatch_llc_pull_hit", 0.0))
    dispatch_keep_running = float(features.get("cake_release_dispatch_keep_running", 0.0))
    dispatch_idle = float(features.get("cake_release_dispatch_idle", 0.0))
    publish_idle_call = float(features.get("cake_release_publish_idle_call", 0.0))
    publish_idle_write = float(features.get("cake_release_publish_idle_write", 0.0))
    publish_idle_noop = float(features.get("cake_release_publish_idle_noop", 0.0))
    publish_running_call = float(features.get("cake_release_publish_running_call", 0.0))
    publish_running_write = float(features.get("cake_release_publish_running_write", 0.0))
    publish_running_noop = float(features.get("cake_release_publish_running_noop", 0.0))
    publish_owner_call = float(features.get("cake_release_publish_owner_call", 0.0))
    publish_owner_write = float(features.get("cake_release_publish_owner_write", 0.0))
    publish_owner_noop = float(features.get("cake_release_publish_owner_noop", 0.0))

    # Fill common derived rates if the recorder did not write them.
    features.setdefault("cake_release_nfw_hit_pct", round(pct(nfw_hit, nfw_entry), 3))
    features.setdefault("cake_release_nfw_hit_prev_cpu_pct", round(pct(nfw_hit_prev_cpu, nfw_hit), 3))
    features.setdefault("cake_release_nfw_hit_other_cpu_pct", round(pct(nfw_hit_other_cpu, nfw_hit), 3))
    features.setdefault("cake_release_nfw_hit_select_cpu_pct", round(pct(nfw_hit_select_cpu, nfw_hit), 3))
    features.setdefault(
        "cake_release_nfw_hit_prev_primary_pct",
        round(pct(nfw_hit_prev_primary, nfw_hit), 3),
    )
    features.setdefault(
        "cake_release_nfw_hit_other_primary_pct",
        round(pct(nfw_hit_other_primary, nfw_hit), 3),
    )
    for suffix in [
        "game_thread",
        "render_thread",
        "taskgraph_thread",
        "pool_thread",
        "fpsaim_thread",
        "chrome_thread",
        "crgpu_thread",
        "dxvk_thread",
        "audio_thread",
        "other_thread",
    ]:
        value = float(features.get(f"cake_release_nfw_hit_{suffix}", 0.0))
        features.setdefault(
            f"cake_release_nfw_hit_{suffix}_pct",
            round(pct(value, nfw_hit), 3),
        )
    features.setdefault("cake_release_nfw_miss_pct", round(pct(nfw_miss, nfw_entry), 3))
    features.setdefault("cake_release_nfw_miss_tunnel_pct", round(pct(nfw_miss_tunnel, nfw_miss), 3))
    features.setdefault(
        "cake_release_nfw_hit_local_depth_nonzero_pct",
        round(pct(nfw_hit_local_depth_nonzero, nfw_hit_local_depth_sample), 3),
    )
    features.setdefault(
        "cake_release_nfw_hit_local_depth_gt1_pct",
        round(pct(nfw_hit_local_depth_gt1, nfw_hit_local_depth_sample), 3),
    )
    features.setdefault(
        "cake_release_nfw_hit_local_depth_gt3_pct",
        round(pct(nfw_hit_local_depth_gt3, nfw_hit_local_depth_sample), 3),
    )
    features.setdefault(
        "cake_release_nfw_prev_idle_attempt_pct",
        round(pct(nfw_prev_idle_attempt, nfw_entry), 3),
    )
    features.setdefault(
        "cake_release_nfw_prev_idle_sibling_block_pct",
        round(pct(nfw_prev_idle_sibling_block, nfw_prev_idle_attempt), 3),
    )
    features.setdefault(
        "cake_release_nfw_prev_idle_claim_pct",
        round(pct(nfw_prev_idle_claim, nfw_prev_idle_attempt), 3),
    )
    features.setdefault(
        "cake_release_nfw_prev_idle_fallback_hit_pct",
        round(pct(nfw_prev_idle_fallback_hit, nfw_prev_idle_fallback_attempt), 3),
    )
    features.setdefault(
        "cake_release_nfw_prev_idle_fallback_prev_pct",
        round(pct(nfw_prev_idle_fallback_prev, nfw_prev_idle_fallback_hit), 3),
    )
    features.setdefault(
        "cake_release_nfw_prev_idle_fallback_other_pct",
        round(pct(nfw_prev_idle_fallback_other, nfw_prev_idle_fallback_hit), 3),
    )
    features.setdefault(
        "cake_release_enqueue_wake_busy_pct",
        round(pct(enqueue_wake_busy, enqueue_wakeup), 3),
    )
    features.setdefault(
        "cake_release_wake_kick_preempt_pct",
        round(pct(wake_kick_preempt, enqueue_wake_busy), 3),
    )
    features.setdefault(
        "cake_release_local_waiter_reject_pct",
        round(pct(local_waiter_reject, local_waiter_attempt), 3),
    )
    features.setdefault(
        "cake_release_stopping_runnable_pct",
        round(pct(stopping_runnable, stopping_call), 3),
    )
    features.setdefault(
        "cake_release_stopping_blocked_pct",
        round(pct(stopping_blocked, stopping_call), 3),
    )
    features.setdefault(
        "cake_release_stopping_owner_update_pct",
        round(pct(stopping_owner_update, stopping_call), 3),
    )
    features.setdefault(
        "cake_release_stopping_route_observe_pct",
        round(pct(stopping_route_observe, stopping_call), 3),
    )
    features.setdefault(
        "cake_release_stopping_route_pending_pct",
        round(pct(stopping_route_pending, stopping_route_total), 3),
    )
    features.setdefault(
        "cake_release_stopping_route_no_pending_pct",
        round(pct(stopping_route_no_pending, stopping_route_total), 3),
    )
    features.setdefault(
        "cake_release_stopping_account_relaxed_pct",
        round(pct(stopping_account_relaxed, stopping_account_total), 3),
    )
    features.setdefault(
        "cake_release_stopping_account_audit_pct",
        round(pct(stopping_account_audit, stopping_account_total), 3),
    )
    features.setdefault(
        "cake_release_stopping_scoreboard_owner_result_pct",
        round(pct(stopping_scoreboard_owner_result, stopping_call), 3),
    )
    features.setdefault(
        "cake_release_stopping_lean_return_pct",
        round(pct(stopping_lean_return, stopping_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_idle_core_rescue_hit_pct",
        round(pct(dispatch_idle_core_rescue_hit, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_idle_llc_rescue_hit_pct",
        round(pct(dispatch_idle_llc_rescue_hit, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_cache_hit_pct",
        round(pct(dispatch_cache_hit, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_throughput_hit_pct",
        round(pct(dispatch_throughput_hit, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_core_steal_hit_pct",
        round(pct(dispatch_core_steal_hit, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_llc_pull_hit_pct",
        round(pct(dispatch_llc_pull_hit, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_keep_running_pct",
        round(pct(dispatch_keep_running, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_dispatch_idle_pct",
        round(pct(dispatch_idle, dispatch_call), 3),
    )
    features.setdefault(
        "cake_release_publish_idle_write_pct",
        round(pct(publish_idle_write, publish_idle_call), 3),
    )
    features.setdefault(
        "cake_release_publish_idle_noop_pct",
        round(pct(publish_idle_noop, publish_idle_call), 3),
    )
    features.setdefault(
        "cake_release_publish_running_write_pct",
        round(pct(publish_running_write, publish_running_call), 3),
    )
    features.setdefault(
        "cake_release_publish_running_noop_pct",
        round(pct(publish_running_noop, publish_running_call), 3),
    )
    features.setdefault(
        "cake_release_publish_owner_write_pct",
        round(pct(publish_owner_write, publish_owner_call), 3),
    )
    features.setdefault(
        "cake_release_publish_owner_noop_pct",
        round(pct(publish_owner_noop, publish_owner_call), 3),
    )

    if nfw_entry and float(features.get("cake_release_nfw_miss_pct", 0.0)) >= 50.0:
        interpretation.append("release_nfw_miss_dominant")
    if nfw_hit and float(features.get("cake_release_nfw_hit_other_cpu_pct", 0.0)) >= 50.0:
        interpretation.append("release_nfw_remote_hits_dominant")
    if nfw_hit and float(features.get("cake_release_nfw_hit_other_primary_pct", 0.0)) >= 50.0:
        interpretation.append("release_nfw_cross_primary_hits_dominant")
    if nfw_miss and float(features.get("cake_release_nfw_miss_tunnel_pct", 0.0)) >= 50.0:
        interpretation.append("release_nfw_tunnel_dominant")
    if nfw_hit_local_depth_sample and float(features.get("cake_release_nfw_hit_local_depth_nonzero_pct", 0.0)) >= 5.0:
        interpretation.append("release_nfw_local_dsq_depth_nonzero")
    if nfw_hit_local_depth_sample and float(features.get("cake_release_nfw_hit_local_depth_gt3_pct", 0.0)) >= 1.0:
        interpretation.append("release_nfw_local_dsq_depth_gt3")
    if nfw_prev_idle_attempt and float(features.get("cake_release_nfw_prev_idle_sibling_block_pct", 0.0)) >= 10.0:
        interpretation.append("release_nfw_prev_idle_sibling_blocks")
    if nfw_prev_idle_fallback_attempt and float(features.get("cake_release_nfw_prev_idle_fallback_hit_pct", 0.0)) < 50.0:
        interpretation.append("release_nfw_prev_idle_fallback_miss_heavy")
    if nfw_prev_idle_fallback_hit and float(features.get("cake_release_nfw_prev_idle_fallback_other_pct", 0.0)) >= 50.0:
        interpretation.append("release_nfw_prev_idle_fallback_other_dominant")
    if enqueue_wakeup and float(features.get("cake_release_enqueue_wake_busy_pct", 0.0)) >= 50.0:
        interpretation.append("release_enqueue_busy_dominant")
    if enqueue_wake_busy and float(features.get("cake_release_wake_kick_preempt_pct", 0.0)) >= 25.0:
        interpretation.append("release_wake_preempt_active")
    if local_waiter_attempt and float(features.get("cake_release_local_waiter_reject_pct", 0.0)) >= 25.0:
        interpretation.append("release_local_waiter_rejecting")
    if dispatch_call:
        rescue_hits = dispatch_idle_core_rescue_hit + dispatch_idle_llc_rescue_hit
        if pct(rescue_hits, dispatch_call) < 1.0:
            interpretation.append("release_dispatch_rescue_unused")
        if float(features.get("cake_release_dispatch_keep_running_pct", 0.0)) >= 50.0:
            interpretation.append("release_dispatch_keep_running_dominant")
        if float(features.get("cake_release_dispatch_idle_pct", 0.0)) >= 50.0:
            interpretation.append("release_dispatch_idle_dominant")
        if float(features.get("cake_release_dispatch_llc_pull_hit_pct", 0.0)) >= 50.0:
            interpretation.append("release_dispatch_llc_pull_dominant")
    if publish_idle_call and float(features.get("cake_release_publish_idle_noop_pct", 0.0)) >= 90.0:
        interpretation.append("release_publish_idle_noop_dominant")
    if publish_running_call and float(features.get("cake_release_publish_running_noop_pct", 0.0)) >= 90.0:
        interpretation.append("release_publish_running_noop_dominant")
    if publish_owner_call and float(features.get("cake_release_publish_owner_noop_pct", 0.0)) >= 90.0:
        interpretation.append("release_publish_owner_noop_dominant")


def extract_from_service_json(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    features: dict[str, Any] = {}
    interpretation: list[str] = []
    accelerator = data.get("accelerator") or {}
    live = data.get("live_data") or {}

    extract_release_game_diag(data, features, interpretation)

    numeric_leafs("cake_health", data.get("health", {}), features)
    numeric_leafs("cake_graph", data.get("graph", {}), features)
    numeric_leafs("cake_lifecycle", data.get("lifecycle", {}), features)
    numeric_leafs("cake_live", live, features)

    route_triplet_features(
        features,
        "cake_accel_route",
        accelerator.get("route_attempt_counts", []),
        accelerator.get("route_hit_counts", []),
        accelerator.get("route_miss_counts", []),
    )
    route_triplet_features(
        features,
        "cake_accel_fast",
        accelerator.get("fast_attempt_counts", []),
        accelerator.get("fast_hit_counts", []),
        accelerator.get("fast_miss_counts", []),
    )
    scoreboard_probe_features(features, accelerator.get("scoreboard_probe_counts", []))
    array_features(
        features,
        "cake_route_block",
        accelerator.get("route_block_counts", []),
        ROUTE_BLOCK_LABELS,
    )
    array_features(
        features,
        "cake_native_fallback",
        accelerator.get("native_fallback_counts", []),
        NATIVE_FALLBACK_LABELS,
    )
    array_features(
        features,
        "cake_storm_mode",
        accelerator.get("storm_guard_mode_counts", []),
        STORM_GUARD_MODE_LABELS,
    )
    array_features(
        features,
        "cake_storm_decision",
        accelerator.get("storm_guard_decision_counts", []),
        STORM_GUARD_DECISION_LABELS,
    )

    for key in [
        "trained_cpus",
        "route_ready_cpus",
        "floor_ready_cpus",
        "shock_cpus",
        "trust_low_cpus",
        "owner_low_cpus",
        "select_tunnel",
        "select_idle",
        "wake_target_hit",
        "wake_target_miss",
        "wake_direct",
        "wake_busy",
        "wake_queued",
        "dispatch_hit",
        "dispatch_miss",
        "accounting_relaxed",
        "accounting_audit",
        "trust_prev_enabled_cpus",
        "trust_prev_active_cpus",
        "trust_prev_blocked_cpus",
        "trust_prev_demotions",
        "trust_prev_attempts",
        "trust_prev_hits",
        "trust_prev_misses",
        "frontier_pending_set",
        "frontier_observe_count",
        "frontier_observe_good",
        "frontier_observe_bad",
        "frontier_conf_promote",
        "frontier_conf_decay",
        "frontier_conf_high",
        "frontier_dispatch_trusted_attempts",
        "frontier_dispatch_trusted_hits",
        "frontier_dispatch_trusted_fails",
        "frontier_dispatch_audit_skips",
        "frontier_dispatch_audit_due",
        "frontier_select_prev_attempts",
        "frontier_select_prev_hits",
        "frontier_select_prev_misses",
        "frontier_enqueue_fact_attempts",
        "frontier_enqueue_fact_hits",
        "frontier_enqueue_fact_misses",
        "frontier_token_clears",
    ]:
        put(features, f"cake_accel_{key}", accelerator.get(key))

    for monitor in data.get("monitors", []) or []:
        if not isinstance(monitor, dict):
            continue
        monitor_id = re.sub(r"[^a-zA-Z0-9_]+", "_", str(monitor.get("id", ""))).strip("_").lower()
        if monitor_id:
            put(features, f"cake_monitor_{monitor_id}_score", monitor.get("score"))
            state = str(monitor.get("state", "")).lower()
            for candidate in ["pass", "warn", "fail", "not_ready"]:
                put(features, f"cake_monitor_{monitor_id}_state_{candidate}", int(state == candidate))

    # AC6-focused derived features for the current investigation.
    prev_att = int(features.get("cake_accel_fast_prev_attempt", 0))
    prev_hit = int(features.get("cake_accel_fast_prev_hit", 0))
    prev_miss = int(features.get("cake_accel_fast_prev_miss", 0))
    prev_probe_total = sum(int(features.get(f"cake_scoreboard_prev_{outcome}", 0)) for outcome in PROBE_LABELS)
    prev_smt_busy = int(features.get("cake_scoreboard_prev_smt_busy", 0))
    prev_claim_fail = int(features.get("cake_scoreboard_prev_claim_fail", 0))
    prev_busy = int(features.get("cake_scoreboard_prev_busy", 0))
    native_per_sec = float(features.get("cake_live_native_fallback_per_sec", 0.0))
    local_waiter_attempt = int(features.get("cake_live_local_waiter_attempt_60s", 0))
    local_waiter_insert = int(features.get("cake_live_local_waiter_insert_60s", 0))
    local_waiter_reject = int(features.get("cake_live_local_waiter_reject_60s", 0))
    wake_ge5 = int(features.get("cake_live_wake_ge5ms_60s", 0))

    put(features, "cake_ac6_fast_prev_hit_pct", round(pct(prev_hit, prev_hit + prev_miss), 3))
    put(features, "cake_ac6_fast_prev_smt_busy_pct", round(pct(prev_smt_busy, prev_probe_total), 3))
    put(features, "cake_ac6_fast_prev_claim_fail_pct", round(pct(prev_claim_fail, prev_probe_total), 3))
    put(features, "cake_ac6_fast_prev_busy_pct", round(pct(prev_busy, prev_probe_total), 3))
    put(features, "cake_ac6_local_waiter_insert_pct", round(pct(local_waiter_insert, local_waiter_attempt), 3))
    put(features, "cake_ac6_local_waiter_reject_pct", round(pct(local_waiter_reject, local_waiter_attempt), 3))

    if prev_att and pct(prev_smt_busy, prev_probe_total) >= 5.0:
        interpretation.append("fastscan_prev_smt_contention")
    if prev_att and pct(prev_claim_fail, prev_probe_total) >= 5.0:
        interpretation.append("fastscan_prev_claim_race")
    if native_per_sec >= 500.0:
        interpretation.append("native_idle_fallback_tax")
    if local_waiter_attempt and pct(local_waiter_reject, local_waiter_attempt) >= 25.0:
        interpretation.append("local_waiter_admission_rejecting")
    if wake_ge5 > 0:
        interpretation.append("wake_tail_ge5ms_present")
    if int(features.get("cake_accel_wake_target_miss", 0)) > int(
        features.get("cake_accel_wake_target_hit", 0)
    ):
        interpretation.append("wake_target_miss_dominant")

    return features, interpretation


WIN_LINE_RE = re.compile(r"^(?:win\.)?(?P<section>[a-zA-Z0-9_.]+):\s*(?P<body>.*)$")
KEYVAL_RE = re.compile(r"(?P<key>[-a-zA-Z0-9_./]+)=\[?(?P<value>-?\d+(?:\.\d+)?)")


def extract_from_diag_text(text: str) -> dict[str, Any]:
    """Best-effort scalar fallback for text-only snapshots."""
    features: dict[str, Any] = {}
    for line in text.splitlines():
        m = WIN_LINE_RE.match(line.strip())
        if not m:
            continue
        section = m.group("section").replace(".", "_")
        body = m.group("body")
        for kv in KEYVAL_RE.finditer(body):
            key = re.sub(r"[^a-zA-Z0-9_]+", "_", kv.group("key")).strip("_").lower()
            if not key:
                continue
            value = kv.group("value")
            features[f"cake_text_{section}_{key}"] = float(value) if "." in value else int(value)
    return features


@dataclass
class ExtractInput:
    diag_json: Path | None
    diag_text: Path | None
    game: str
    scheduler: str
    scenario: str
    capture_id: str
    mangohud_csv: str
    binary: Path | None
    bpf_object: Path | None
    repo: Path | None


@dataclass
class ExtractResult:
    metadata: dict[str, Any]
    build_identity: dict[str, Any]
    features: dict[str, Any]
    interpretation: list[str] = field(default_factory=list)

    def to_json_obj(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": "scx_cake_game_action_path_features",
            "metadata": self.metadata,
            "build_identity": self.build_identity,
            "features": dict(sorted(self.features.items())),
            "interpretation": self.interpretation,
        }


def extract(inp: ExtractInput) -> ExtractResult:
    features: dict[str, Any] = {}
    interpretation: list[str] = []
    metadata = {
        "game": inp.game,
        "scheduler": inp.scheduler,
        "scenario": inp.scenario,
        "capture_id": inp.capture_id,
        "mangohud_csv": inp.mangohud_csv,
        "diag_json": str(inp.diag_json) if inp.diag_json else "",
        "diag_text": str(inp.diag_text) if inp.diag_text else "",
    }

    if inp.diag_json:
        data = json.loads(inp.diag_json.read_text())
        json_features, json_interpretation = extract_from_service_json(data)
        features.update(json_features)
        interpretation.extend(json_interpretation)
    if inp.diag_text and inp.diag_text.exists():
        for key, value in extract_from_diag_text(inp.diag_text.read_text(errors="replace")).items():
            features.setdefault(key, value)

    binary_sha = sha256_file(inp.binary) if inp.binary and inp.binary.exists() else ""
    bpf_sha = sha256_file(inp.bpf_object) if inp.bpf_object and inp.bpf_object.exists() else ""
    git_head = maybe_git_head(inp.repo)
    git_dirty = maybe_git_dirty(inp.repo)
    source_dirty_sha = maybe_git_source_diff_sha(inp.repo)
    source_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"scx-cake-source:{git_head}|{source_dirty_sha}"))
    build_seed = "|".join([binary_sha, bpf_sha, git_head, source_dirty_sha])
    build_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"scx-cake-build:{build_seed}"))
    build_identity = {
        "binary": str(inp.binary) if inp.binary else "",
        "binary_sha256": binary_sha,
        "bpf_object": str(inp.bpf_object) if inp.bpf_object else "",
        "bpf_object_sha256": bpf_sha,
        "git_head": git_head,
        "git_dirty": git_dirty,
        "source_dirty_diff_sha256": source_dirty_sha,
        "source_uuid": source_uuid,
        "build_uuid": build_uuid,
        "complete": int(bool(binary_sha and bpf_sha and git_head)),
    }

    return ExtractResult(metadata, build_identity, features, sorted(set(interpretation)))


def write_tsv(path: Path, result: ExtractResult) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write("namespace\tkey\tvalue\n")
        for key, value in sorted(result.metadata.items()):
            f.write(f"metadata\t{key}\t{value}\n")
        for key, value in sorted(result.build_identity.items()):
            f.write(f"build_identity\t{key}\t{value}\n")
        for key, value in sorted(result.features.items()):
            f.write(f"feature\t{key}\t{value}\n")
        for item in result.interpretation:
            f.write(f"interpretation\t{item}\t1\n")


def run_self_test() -> None:
    sample = {
        "schema_version": 10,
        "health": {"dsq_depth": 2, "total_dispatches": 100},
        "graph": {"wait_max_us": 6000},
        "lifecycle": {"run_stop_avg_us": 700},
        "accelerator": {
            "fast_attempt_counts": [0, 100, 10, 0, 0, 0, 0],
            "fast_hit_counts": [0, 80, 1, 0, 0, 0, 0],
            "fast_miss_counts": [0, 20, 9, 0, 0, 0, 0],
            "route_attempt_counts": [0, 0, 0, 0, 0, 0, 0],
            "route_hit_counts": [0, 0, 0, 0, 0, 0, 0],
            "route_miss_counts": [0, 0, 0, 0, 0, 0, 0],
            "scoreboard_probe_counts": [
                [0, 0, 0, 0, 0, 0, 0],
                [80, 5, 0, 10, 5, 0, 0],
                [1, 9, 0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0, 0, 0],
                [0, 0, 0, 0, 0, 0, 0],
            ],
            "native_fallback_counts": [601, 0, 0],
            "wake_target_hit": 10,
            "wake_target_miss": 20,
        },
        "live_data": {
            "native_fallback_per_sec": 601.0,
            "local_waiter_attempt_60s": 10,
            "local_waiter_insert_60s": 6,
            "local_waiter_reject_60s": 4,
            "wake_ge5ms_60s": 1,
        },
        "monitors": [{"id": "scoreboard", "state": "warn", "score": 60}],
    }
    features, interp = extract_from_service_json(sample)
    assert features["cake_accel_fast_prev_attempt"] == 100
    assert features["cake_ac6_fast_prev_hit_pct"] == 80.0
    assert features["cake_ac6_fast_prev_smt_busy_pct"] == 10.0
    assert features["cake_ac6_local_waiter_reject_pct"] == 40.0
    assert "fastscan_prev_smt_contention" in interp
    assert "native_idle_fallback_tax" in interp
    assert "wake_target_miss_dominant" in interp

    release_sample = {
        "schema_version": 1,
        "artifact_kind": "scx_cake_release_game_diag",
        "uptime_secs": 60.0,
        "release_game_diag": {
            "totals": {
                "nfw_entry": 100,
                "nfw_hit": 25,
                "nfw_hit_prev_cpu": 10,
                "nfw_hit_other_cpu": 15,
                "nfw_hit_select_cpu": 5,
                "nfw_hit_prev_primary": 12,
                "nfw_hit_other_primary": 13,
                "nfw_hit_game_thread": 7,
                "nfw_hit_render_thread": 3,
                "nfw_hit_taskgraph_thread": 4,
                "nfw_hit_pool_thread": 5,
                "nfw_hit_fpsaim_thread": 2,
                "nfw_hit_chrome_thread": 1,
                "nfw_hit_crgpu_thread": 1,
                "nfw_hit_dxvk_thread": 1,
                "nfw_hit_audio_thread": 1,
                "nfw_hit_local_depth_sample": 25,
                "nfw_hit_local_depth_nonzero": 5,
                "nfw_hit_local_depth_gt1": 2,
                "nfw_hit_local_depth_gt3": 1,
                "nfw_prev_idle_attempt": 80,
                "nfw_prev_idle_sibling_block": 20,
                "nfw_prev_idle_claim": 30,
                "nfw_prev_idle_fallback_attempt": 50,
                "nfw_prev_idle_fallback_hit": 40,
                "nfw_prev_idle_fallback_prev": 10,
                "nfw_prev_idle_fallback_other": 30,
                "nfw_miss": 75,
                "nfw_miss_tunnel": 60,
                "enqueue_wakeup": 200,
                "enqueue_wake_busy": 150,
                "enqueue_wake_busy_local": 90,
                "enqueue_wake_busy_remote": 60,
                "wake_kick_preempt": 45,
                "local_waiter_attempt": 20,
                "local_waiter_insert": 5,
                "local_waiter_reject": 15,
                "stopping_call": 100,
                "stopping_runnable": 40,
                "stopping_blocked": 60,
                "stopping_owner_update": 90,
                "stopping_route_observe": 80,
                "stopping_route_pending": 30,
                "stopping_route_no_pending": 50,
                "stopping_account_relaxed": 75,
                "stopping_account_audit": 25,
                "stopping_scoreboard_owner_result": 25,
                "stopping_lean_return": 10,
                "dispatch_call": 200,
                "dispatch_idle_core_rescue_hit": 10,
                "dispatch_idle_llc_rescue_hit": 5,
                "dispatch_cache_hit": 20,
                "dispatch_throughput_hit": 30,
                "dispatch_core_steal_hit": 15,
                "dispatch_llc_pull_hit": 40,
                "dispatch_keep_running": 60,
                "dispatch_idle": 20,
                "publish_idle_call": 100,
                "publish_idle_write": 25,
                "publish_idle_noop": 75,
                "publish_running_call": 200,
                "publish_running_write": 50,
                "publish_running_noop": 150,
                "publish_owner_call": 400,
                "publish_owner_write": 100,
                "publish_owner_noop": 300,
            },
            "derived": {
                "nfw_hit_pct": 25.0,
                "nfw_miss_tunnel_pct": 80.0,
                "enqueue_wake_busy_pct": 75.0,
                "wake_kick_preempt_pct": 30.0,
                "local_waiter_reject_pct": 75.0,
            },
            "per_cpu": [],
        },
    }
    release_features, release_interp = extract_from_service_json(release_sample)
    assert release_features["cake_release_nfw_entry"] == 100
    assert release_features["cake_release_nfw_hit_other_cpu_pct"] == 60.0
    assert release_features["cake_release_nfw_hit_other_primary_pct"] == 52.0
    assert release_features["cake_release_nfw_hit_game_thread_pct"] == 28.0
    assert release_features["cake_release_nfw_hit_pool_thread_pct"] == 20.0
    assert release_features["cake_release_nfw_hit_local_depth_nonzero_pct"] == 20.0
    assert release_features["cake_release_nfw_hit_local_depth_gt1_pct"] == 8.0
    assert release_features["cake_release_nfw_hit_local_depth_gt3_pct"] == 4.0
    assert release_features["cake_release_nfw_prev_idle_attempt"] == 80
    assert release_features["cake_release_nfw_prev_idle_attempt_pct"] == 80.0
    assert release_features["cake_release_nfw_prev_idle_sibling_block_pct"] == 25.0
    assert release_features["cake_release_nfw_prev_idle_claim_pct"] == 37.5
    assert release_features["cake_release_nfw_prev_idle_fallback_hit_pct"] == 80.0
    assert release_features["cake_release_nfw_prev_idle_fallback_prev_pct"] == 25.0
    assert release_features["cake_release_nfw_prev_idle_fallback_other_pct"] == 75.0
    assert release_features["cake_release_nfw_miss_tunnel_pct"] == 80.0
    assert release_features["cake_release_enqueue_wake_busy_local"] == 90
    assert release_features["cake_release_local_waiter_reject_pct"] == 75.0
    assert release_features["cake_release_stopping_runnable_pct"] == 40.0
    assert release_features["cake_release_stopping_route_pending_pct"] == 37.5
    assert release_features["cake_release_stopping_route_no_pending_pct"] == 62.5
    assert release_features["cake_release_stopping_account_relaxed_pct"] == 75.0
    assert release_features["cake_release_stopping_account_audit_pct"] == 25.0
    assert release_features["cake_release_stopping_scoreboard_owner_result_pct"] == 25.0
    assert release_features["cake_release_stopping_lean_return_pct"] == 10.0
    assert release_features["cake_release_dispatch_idle_core_rescue_hit_pct"] == 5.0
    assert release_features["cake_release_dispatch_llc_pull_hit_pct"] == 20.0
    assert release_features["cake_release_dispatch_keep_running_pct"] == 30.0
    assert release_features["cake_release_dispatch_idle_pct"] == 10.0
    assert release_features["cake_release_publish_idle_write_pct"] == 25.0
    assert release_features["cake_release_publish_idle_noop_pct"] == 75.0
    assert release_features["cake_release_publish_running_write_pct"] == 25.0
    assert release_features["cake_release_publish_running_noop_pct"] == 75.0
    assert release_features["cake_release_publish_owner_write_pct"] == 25.0
    assert release_features["cake_release_publish_owner_noop_pct"] == 75.0
    assert "release_nfw_tunnel_dominant" in release_interp
    assert "release_nfw_remote_hits_dominant" in release_interp
    assert "release_nfw_cross_primary_hits_dominant" in release_interp
    assert "release_enqueue_busy_dominant" in release_interp
    assert "release_local_waiter_rejecting" in release_interp
    print("self-test ok")


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--diag-json", type=Path, help="cake_diag_latest.json/service report JSON")
    ap.add_argument("--diag-text", type=Path, help="cake_diag_latest.txt text dump")
    ap.add_argument("--game", default="")
    ap.add_argument("--scheduler", default="")
    ap.add_argument("--scenario", default="")
    ap.add_argument("--capture-id", default="")
    ap.add_argument("--mangohud-csv", default="")
    ap.add_argument("--binary", type=Path, help="scx_cake binary used for the run")
    ap.add_argument("--bpf-object", type=Path, help="linked cake.bpf.o used for the run")
    ap.add_argument("--repo", type=Path, default=Path.cwd(), help="scx git checkout for identity")
    ap.add_argument("--out-json", type=Path)
    ap.add_argument("--out-tsv", type=Path)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return args
    if not args.diag_json and not args.diag_text:
        ap.error("provide --diag-json and/or --diag-text")
    if args.diag_json and not args.diag_json.exists():
        ap.error(f"--diag-json does not exist: {args.diag_json}")
    if args.diag_text and not args.diag_text.exists():
        ap.error(f"--diag-text does not exist: {args.diag_text}")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.self_test:
        run_self_test()
        return 0

    result = extract(
        ExtractInput(
            diag_json=args.diag_json,
            diag_text=args.diag_text,
            game=args.game,
            scheduler=args.scheduler,
            scenario=args.scenario,
            capture_id=args.capture_id,
            mangohud_csv=args.mangohud_csv,
            binary=args.binary,
            bpf_object=args.bpf_object,
            repo=args.repo,
        )
    )
    json_obj = result.to_json_obj()
    json_text = json.dumps(json_obj, indent=2, sort_keys=True) + "\n"
    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json_text, encoding="utf-8")
    else:
        sys.stdout.write(json_text)
    if args.out_tsv:
        args.out_tsv.parent.mkdir(parents=True, exist_ok=True)
        write_tsv(args.out_tsv, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
