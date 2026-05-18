import csv
import json
import math
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import cakebench_goal_score


HEADER = [
    "seq",
    "variant",
    "benchmark",
    "subcase",
    "metric",
    "value",
    "direction",
    "unit",
    "source",
    "wall_seconds",
    "output_metric",
    "output_value",
    "output_direction",
    "output_unit",
    "task_clock_ms",
    "context_switches",
    "cpu_migrations",
    "repeat",
    "run_dir",
]


def write_metrics(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER, delimiter="\t")
        writer.writeheader()
        for row in rows:
            full = {key: "" for key in HEADER}
            full.update(row)
            writer.writerow(full)


def write_native_metrics(path: Path, rows: list[dict[str, str]]) -> None:
    header = [
        "seq",
        "variant",
        "benchmark",
        "repeat",
        "metric",
        "value",
        "unit",
        "direction",
        "source",
        "run_dir",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header, delimiter="\t")
        writer.writeheader()
        for native_row in rows:
            full = {key: "" for key in header}
            full.update(native_row)
            writer.writerow(full)


def row(benchmark: str, metric: str, value: float, direction: str, wall: float) -> dict[str, str]:
    return {
        "seq": "01",
        "variant": "cake-release-default",
        "benchmark": benchmark,
        "metric": metric,
        "value": str(value),
        "direction": direction,
        "unit": "unit",
        "wall_seconds": str(wall),
        "repeat": "repeat_1",
    }


class CakebenchGoalScoreTests(unittest.TestCase):
    def test_equal_weight_score_buckets_multi_metric_benchmark_once(self):
        baseline = [
            row("stress-ng-cpu-cache-mem", "cache_ops", 100.0, "higher", 30.0),
            row("stress-ng-cpu-cache-mem", "memcpy_ops", 100.0, "higher", 30.0),
            row("ffmpeg-compilation", "wall_time", 10.0, "lower", 10.0),
        ]
        candidate = [
            row("stress-ng-cpu-cache-mem", "cache_ops", 200.0, "higher", 30.0),
            row("stress-ng-cpu-cache-mem", "memcpy_ops", 50.0, "higher", 30.0),
            row("ffmpeg-compilation", "wall_time", 9.0, "lower", 9.0),
        ]

        report = cakebench_goal_score.compare_metric_rows(baseline, candidate)

        self.assertAlmostEqual(report["benchmark_scores"]["stress-ng-cpu-cache-mem"]["score"], 1.0)
        self.assertAlmostEqual(report["benchmark_scores"]["ffmpeg-compilation"]["score"], 10.0 / 9.0)
        self.assertAlmostEqual(report["equal_weight_score"], math.sqrt(10.0 / 9.0))
        self.assertAlmostEqual(report["equal_weight_delta_pct"], (math.sqrt(10.0 / 9.0) - 1.0) * 100.0)

    def test_wallclock_summary_tracks_total_and_primary_lower_wall_rows(self):
        baseline = [
            row("stress-ng-cpu-cache-mem", "cache_ops", 100.0, "higher", 30.0),
            row("ffmpeg-compilation", "wall_time", 10.0, "lower", 10.5),
            row("x265-encoding", "wall_time", 2.0, "lower", 2.5),
        ]
        candidate = [
            row("stress-ng-cpu-cache-mem", "cache_ops", 101.0, "higher", 31.0),
            row("ffmpeg-compilation", "wall_time", 9.0, "lower", 9.5),
            row("x265-encoding", "wall_time", 2.1, "lower", 2.6),
        ]

        report = cakebench_goal_score.compare_metric_rows(baseline, candidate)

        wall = report["wallclock"]
        self.assertAlmostEqual(wall["baseline_wall_seconds_sum"], 43.0)
        self.assertAlmostEqual(wall["candidate_wall_seconds_sum"], 43.1)
        self.assertAlmostEqual(wall["baseline_primary_lower_wall_sum"], 12.0)
        self.assertAlmostEqual(wall["candidate_primary_lower_wall_sum"], 11.1)
        self.assertLess(wall["primary_lower_wall_delta_pct"], 0.0)

    def test_directory_loads_stress_cache_mem_native_memcpy_inside_one_bucket(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / "baseline"
            candidate = root / "candidate"
            write_metrics(
                baseline / "analysis_metrics.tsv",
                [row("stress-ng-cpu-cache-mem", "cache_ops", 100.0, "higher", 30.0)],
            )
            write_native_metrics(
                baseline / "analysis_native_metrics.tsv",
                [
                    {
                        "seq": "01",
                        "variant": "cake-release-default",
                        "benchmark": "stress-ng-cpu-cache-mem",
                        "repeat": "repeat_1",
                        "metric": "stress_memcpy_bogo_ops_per_s_realtime",
                        "value": "100.0",
                        "unit": "bogo_ops/s",
                        "direction": "higher",
                    }
                ],
            )
            write_metrics(
                candidate / "analysis_metrics.tsv",
                [row("stress-ng-cpu-cache-mem", "cache_ops", 121.0, "higher", 30.0)],
            )
            write_native_metrics(
                candidate / "analysis_native_metrics.tsv",
                [
                    {
                        "seq": "01",
                        "variant": "cake-release-default",
                        "benchmark": "stress-ng-cpu-cache-mem",
                        "repeat": "repeat_1",
                        "metric": "stress_memcpy_bogo_ops_per_s_realtime",
                        "value": "81.0",
                        "unit": "bogo_ops/s",
                        "direction": "higher",
                    }
                ],
            )

            report = cakebench_goal_score.compare_metric_rows(
                cakebench_goal_score.read_goal_rows(baseline),
                cakebench_goal_score.read_goal_rows(candidate),
            )

            bucket = report["benchmark_scores"]["stress-ng-cpu-cache-mem"]
            self.assertEqual(bucket["metric_count"], 2)
            self.assertAlmostEqual(bucket["score"], math.sqrt(1.21 * 0.81))

    def test_single_capture_metrics_directory_scores_like_analysis_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / "baseline"
            candidate = root / "candidate"
            write_metrics(
                baseline / "analysis_metrics.tsv",
                [
                    row("stress-ng-cpu-cache-mem", "cache_ops", 100.0, "higher", 30.0),
                    row("stress-ng-cpu-cache-mem", "memcpy_ops", 100.0, "higher", 30.0),
                ],
            )
            write_metrics(
                candidate / "capture_metrics.tsv",
                [
                    row("stress-ng-cpu-cache-mem", "cache_ops", 90.0, "higher", 30.0),
                    row("stress-ng-cpu-cache-mem", "memcpy_ops", 125.0, "higher", 30.0),
                ],
            )

            report = cakebench_goal_score.compare_metric_rows(
                cakebench_goal_score.read_goal_rows(baseline),
                cakebench_goal_score.read_goal_rows(candidate),
            )

            self.assertAlmostEqual(
                report["benchmark_scores"]["stress-ng-cpu-cache-mem"]["score"],
                math.sqrt(0.90 * 1.25),
            )

    def test_directory_all_scheduler_baseline_filters_to_default_cake(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / "baseline"
            candidate = root / "candidate"
            write_metrics(
                baseline / "analysis_metrics.tsv",
                [
                    row("kernel-defconfig", "wall_time", 2.28, "lower", 2.28),
                    {
                        **row("kernel-defconfig", "wall_time", 2.25, "lower", 2.25),
                        "seq": "02",
                        "variant": "native",
                    },
                ],
            )
            write_metrics(
                candidate / "capture_metrics.tsv",
                [
                    {
                        **row("kernel-defconfig", "wall_time", 2.27, "lower", 2.27),
                        "variant": "kernel-defconfig_release-cake",
                    }
                ],
            )

            report = cakebench_goal_score.compare_metric_rows(
                cakebench_goal_score.read_goal_rows(baseline),
                cakebench_goal_score.read_goal_rows(candidate),
            )

            self.assertEqual(report["coverage"]["baseline_rows"], 1)
            self.assertAlmostEqual(
                report["benchmark_scores"]["kernel-defconfig"]["score"],
                2.28 / 2.27,
            )

    def test_stress_cache_metric_matches_matrix_blank_subcase_to_capture_cache_subcase(self):
        baseline = [
            row("stress-ng-cpu-cache-mem", "cache_ops", 100.0, "higher", 30.0),
            {
                **row("stress-ng-cpu-cache-mem", "memcpy_ops", 100.0, "higher", 30.0),
                "subcase": "memcpy",
            },
        ]
        candidate = [
            {
                **row("stress-ng-cpu-cache-mem", "cache_ops", 110.0, "higher", 30.0),
                "subcase": "cache",
            },
            {
                **row("stress-ng-cpu-cache-mem", "memcpy_ops", 90.0, "higher", 30.0),
                "subcase": "memcpy",
            },
        ]

        report = cakebench_goal_score.compare_metric_rows(baseline, candidate)

        bucket = report["benchmark_scores"]["stress-ng-cpu-cache-mem"]
        self.assertEqual(bucket["metric_count"], 2)
        self.assertAlmostEqual(bucket["score"], math.sqrt(1.10 * 0.90))
        self.assertEqual(report["coverage"]["common_rows"], 2)

    def test_schbench_request_subcase_matches_matrix_blank_subcase(self):
        baseline = [
            row("schbench", "request_p99", 5000.0, "lower", 60.0),
        ]
        candidate = [
            {
                **row("schbench", "request_p99", 4900.0, "lower", 60.0),
                "subcase": "request",
            },
        ]

        report = cakebench_goal_score.compare_metric_rows(baseline, candidate)

        self.assertEqual(report["coverage"]["common_rows"], 1)
        self.assertAlmostEqual(
            report["benchmark_scores"]["schbench"]["score"], 5000.0 / 4900.0
        )

    def test_single_capture_runtime_row_backfills_wall_time_from_wall_seconds(self):
        baseline = [
            {**row("perf-sched-thread", "wall_time", 0.160, "lower", 0.160), "unit": "s"},
        ]
        candidate = [
            {**row("perf-sched-thread", "runtime", 0.115, "lower", 0.160), "unit": "s"},
        ]

        report = cakebench_goal_score.compare_metric_rows(baseline, candidate)

        self.assertEqual(report["coverage"]["common_rows"], 1)
        self.assertAlmostEqual(
            report["benchmark_scores"]["perf-sched-thread"]["score"], 1.0
        )

    def test_cli_writes_json_and_markdown_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / "baseline.tsv"
            candidate = root / "candidate.tsv"
            out_json = root / "score.json"
            out_md = root / "score.md"
            write_metrics(
                baseline,
                [
                    row("perf-memcpy", "throughput", 100.0, "higher", 1.0),
                    row("kernel-defconfig", "wall_time", 4.0, "lower", 4.0),
                ],
            )
            write_metrics(
                candidate,
                [
                    row("perf-memcpy", "throughput", 110.0, "higher", 1.0),
                    row("kernel-defconfig", "wall_time", 3.8, "lower", 3.8),
                ],
            )

            rc = cakebench_goal_score.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--mutation-id",
                    "route-token-v1",
                    "--mutation-size",
                    "M",
                    "--mutation-kind",
                    "policy",
                    "--mutation-subsystem",
                    "dispatch",
                    "--mutation-concept",
                    "branch reduction",
                    "--mutation-concept",
                    "O(1) rewrite",
                    "--decision",
                    "keep",
                ]
            )

            self.assertEqual(rc, 0)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertGreater(data["equal_weight_score"], 1.0)
            self.assertEqual(data["mutation"]["id"], "route-token-v1")
            self.assertEqual(data["mutation"]["concepts"], ["branch reduction", "O(1) rewrite"])
            text = out_md.read_text(encoding="utf-8")
            self.assertIn("# scx_cake Goal Score", text)
            self.assertIn("route-token-v1", text)
            self.assertIn("Equal-weight score", text)

    def test_cli_appends_mutation_ledger_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            baseline = root / "baseline.tsv"
            candidate = root / "candidate.tsv"
            ledger = root / "mutation_ledger.jsonl"
            out_json = root / "score.json"
            write_metrics(
                baseline,
                [row("perf-memcpy", "throughput", 100.0, "higher", 1.0)],
            )
            write_metrics(
                candidate,
                [row("perf-memcpy", "throughput", 103.0, "higher", 1.0)],
            )

            rc = cakebench_goal_score.main(
                [
                    "--baseline",
                    str(baseline),
                    "--candidate",
                    str(candidate),
                    "--append-ledger",
                    str(ledger),
                    "--out-json",
                    str(out_json),
                    "--mutation-id",
                    "memcpy-fast-path",
                    "--mutation-size",
                    "S",
                    "--mutation-kind",
                    "hot-path codegen",
                    "--mutation-subsystem",
                    "dispatch",
                    "--mutation-concept",
                    "instruction reduction",
                    "--decision",
                    "mutate",
                ]
            )

            self.assertEqual(rc, 0)
            records = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["mutation"]["id"], "memcpy-fast-path")
            self.assertEqual(records[0]["decision"], "mutate")
            self.assertGreater(records[0]["equal_weight_score"], 1.0)

    def test_mutation_metadata_requires_goal_ledger_fields(self):
        with self.assertRaisesRegex(ValueError, "mutation size"):
            cakebench_goal_score.validate_mutation_metadata(
                {
                    "id": "bad",
                    "size": "tiny",
                    "kind": "policy",
                    "subsystem": "dispatch",
                    "concepts": ["branch reduction"],
                    "decision": "keep",
                }
            )

        valid = cakebench_goal_score.validate_mutation_metadata(
            {
                "id": "good",
                "size": "XL",
                "kind": "hot-path codegen",
                "subsystem": "select",
                "concepts": ["ILP/MLP latency hiding", "helper/kfunc reduction"],
                "decision": "park",
            }
        )
        self.assertEqual(valid["size"], "XL")

    def test_script_help_uses_real_argv(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "cakebench_goal_score.py"), "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Compare Cake runs with equal benchmark weighting", result.stdout)

    def test_repo_cakebench_exposes_goal_score_command(self):
        result = subprocess.run(
            [str(ROOT / "cakebench"), "goal-score", "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Compare Cake runs with equal benchmark weighting", result.stdout)

    def test_repo_cakebench_matrix_commands_use_repo_sudo_reexec_path(self):
        text = (ROOT / "cakebench").read_text(encoding="utf-8")

        self.assertIn("run_matrix_command()", text)
        self.assertIn('if has_arg --help "$@" || has_arg -h "$@"; then', text)
        self.assertIn('sudo_reexec "${subcommand}" "$@"', text)
        self.assertIn("cake|all|native|suite|release-matrix)", text)

    def test_sudo_reexec_execs_noninteractive_sudo_without_wrapping_child_errors(self):
        text = (ROOT / "cakebench").read_text(encoding="utf-8")

        self.assertIn('exec sudo -n -E "${SCX_REPO_ROOT}/cakebench" "${subcommand}" "$@"', text)
        self.assertNotIn('if ! sudo -n -E "${SCX_REPO_ROOT}/cakebench"', text)

    def test_repo_cakebench_exposes_stop_active_cleanup_command(self):
        text = (ROOT / "cakebench").read_text(encoding="utf-8")

        self.assertIn("run_stop_active_command()", text)
        self.assertIn("stop-bench|stop-active|stop_active)", text)
        self.assertIn('sudo_reexec stop-bench "$@"', text)


if __name__ == "__main__":
    unittest.main()
