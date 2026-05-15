import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import cakebench_history


def run(cmd, cwd, **kwargs):
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, **kwargs)


class CakebenchHistoryTests(unittest.TestCase):
    def test_parse_single_run_scores_and_perf_counters(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = Path(td) / "runs" / "20260514T010814Z_stress-ng-cpu-cache-mem_release-cake.dIS1lD"
            (run_dir / "logs").mkdir(parents=True)
            (run_dir / "perf").mkdir()
            (run_dir / "summary.md").write_text(
                "# Benchmark Summary\n\n- Benchmark: stress-ng-cpu-cache-mem\n",
                encoding="utf-8",
            )
            (run_dir / "logs" / "repeat_1_stat.log").write_text(
                "\n".join(
                    [
                        "stress-ng: metrc: [15199] stressor       bogo ops real time  usr time  sys time   bogo ops/s     bogo ops/s",
                        "stress-ng: metrc: [15199] cache         115239540     30.01    132.41      0.17   3839562.97      869257.78",
                        "stress-ng: metrc: [15199] memcpy            47983     30.00    125.14      0.32      1599.48         382.43",
                    ]
                ),
                encoding="utf-8",
            )
            (run_dir / "perf" / "repeat_1_stat.perf_stat.csv").write_text(
                "\n".join(
                    [
                        "2738492,,context-switches,480465280105,100.00,,",
                        "134520,,cpu-migrations,480465277237,100.00,,",
                    ]
                ),
                encoding="utf-8",
            )
            noise_dir = run_dir.parent.parent / "noise"
            noise_dir.mkdir()
            (noise_dir / "summary.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "severity": "warn",
                        "score": 42.5,
                        "sample_count": 3,
                        "sampled_secs": 0.75,
                        "max_external_cpu_pct": 31.0,
                        "avg_external_cpu_pct": 10.0,
                        "top_external": [
                            {"comm": "firefox", "cmdline": "firefox", "reason": "browser", "max_cpu_pct": 31.0}
                        ],
                    }
                ),
                encoding="utf-8",
            )

            parsed = cakebench_history.parse_run_artifacts(run_dir.parent.parent)

            self.assertEqual(parsed["run_dir"], str(run_dir))
            self.assertEqual(parsed["metrics"]["stress_cache_bogo_ops_per_s"], 3839562.97)
            self.assertEqual(parsed["metrics"]["stress_memcpy_bogo_ops_per_s"], 1599.48)
            self.assertEqual(parsed["metrics"]["context_switches"], 2738492)
            self.assertEqual(parsed["metrics"]["cpu_migrations"], 134520)
            self.assertEqual(parsed["noise"]["severity"], "warn")
            self.assertEqual(parsed["noise"]["top_external"][0]["comm"], "firefox")

    def test_record_run_captures_git_dirty_patch_and_best_summary(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "scx"
            bench = root / "scx_cake_bench_assets"
            out_dir = bench / "runs" / "single" / "20260514T010813Z_stress-ng-cpu-cache-mem_release-cake"
            run_dir = out_dir / "runs" / "20260514T010814Z_stress-ng-cpu-cache-mem_release-cake.dIS1lD"
            artifact_dir = repo / "target" / "release" / "build" / "scx_cake-test" / "out"

            repo.mkdir()
            run(["git", "init"], repo, stdout=subprocess.DEVNULL)
            run(["git", "config", "user.email", "ritz@example.test"], repo)
            run(["git", "config", "user.name", "Ritz"], repo)
            source = repo / "scheds" / "rust" / "scx_cake" / "src" / "bpf" / "cake.bpf.c"
            source.parent.mkdir(parents=True)
            source.write_text("int before;\n", encoding="utf-8")
            run(["git", "add", str(source.relative_to(repo))], repo)
            run(["git", "commit", "-m", "baseline"], repo, stdout=subprocess.DEVNULL)
            source.write_text("int after;\n", encoding="utf-8")

            artifact_dir.mkdir(parents=True)
            (artifact_dir / "cake.bpf.o").write_bytes(b"bpf-object")
            (artifact_dir / "cake_constants.rs").write_text(
                'pub const BAKED_QUEUE_POLICY: &str = "local";\n'
                'pub const BAKED_STORM_GUARD: &str = "shield";\n',
                encoding="utf-8",
            )

            (run_dir / "logs").mkdir(parents=True)
            (run_dir / "perf").mkdir()
            (run_dir / "summary.md").write_text("# Summary\n", encoding="utf-8")
            (run_dir / "logs" / "repeat_1_stat.log").write_text(
                "stress-ng: metrc: [1] cache 1 30.00 1.0 0.0 5213078.50 1.0\n"
                "stress-ng: metrc: [1] memcpy 1 30.00 1.0 0.0 3430.92 1.0\n",
                encoding="utf-8",
            )
            (run_dir / "perf" / "repeat_1_stat.perf_stat.csv").write_text(
                "1004683,,context-switches,1,100.00,,\n"
                "258938,,cpu-migrations,1,100.00,,\n",
                encoding="utf-8",
            )
            (out_dir / "noise").mkdir()
            (out_dir / "noise" / "summary.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "severity": "clean",
                        "score": 0.0,
                        "sample_count": 2,
                        "sampled_secs": 0.5,
                        "max_external_cpu_pct": 0.0,
                    }
                ),
                encoding="utf-8",
            )

            record = cakebench_history.record_run(
                out_dir=out_dir,
                history_root=bench / "history",
                scx_repo=repo,
                bench_repo=bench,
                benchmark="stress-ng-cpu-cache-mem",
                scheduler="scx_cake",
                capture="stat",
                command=["./cakebench", "one", "stress-ng-cpu-cache-mem", "--capture", "stat"],
                hypothesis="cap memcpy slice",
                mutation_kind="policy",
            )

            ledger = bench / "history" / "runs.jsonl"
            latest = json.loads((bench / "history" / "latest.json").read_text(encoding="utf-8"))
            best = json.loads((bench / "history" / "best.json").read_text(encoding="utf-8"))

            self.assertTrue(ledger.exists())
            self.assertEqual(latest["run_id"], record["run_id"])
            self.assertEqual(best["stress_cache_bogo_ops_per_s"]["value"], 5213078.50)
            self.assertEqual(record["git"]["dirty"], True)
            self.assertTrue(Path(record["git"]["dirty_patch_path"]).exists())
            self.assertEqual(record["mutation"]["hypothesis"], "cap memcpy slice")
            self.assertEqual(record["mutation"]["kind"], "policy")
            self.assertEqual(record["noise"]["severity"], "clean")
            self.assertAlmostEqual(
                record["metrics"]["stress_cache_mem_dual_score"],
                min(5213078.50 / 5484539.37, 3430.92 / 5859.61),
            )
            self.assertEqual(record["baked_constants"]["BAKED_QUEUE_POLICY"], "local")

    def test_import_old_runs_backfills_single_and_matrix_without_duplicates(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = root / "scx"
            bench = root / "scx_cake_bench_assets"
            runs_root = bench / "runs"
            single_out = runs_root / "single" / "20260514T010813Z_stress-ng-cpu-cache-mem_release-cake"
            single_run = single_out / "runs" / "20260514T010814Z_stress-ng-cpu-cache-mem_release-cake.dIS1lD"
            matrix_dir = runs_root / "full" / "suite" / "matrix" / "20260510T174127Z_core_scheduler-matrix.test"
            matrix_run = matrix_dir / "20260510T174128Z_stress-ng-cpu-cache-mem.abc123"

            repo.mkdir(parents=True)
            (single_run / "logs").mkdir(parents=True)
            (single_run / "perf").mkdir()
            (single_run / "summary.md").write_text(
                "# Summary\n\n"
                "- Benchmark: stress-ng-cpu-cache-mem\n"
                "- Started UTC: 20260514T010814Z\n"
                "- Git head: abcdef123456\n"
                "- Capture mode: stat\n",
                encoding="utf-8",
            )
            (single_run / "logs" / "repeat_1_stat.log").write_text(
                "stress-ng: metrc: [1] cache 1 30.00 1.0 0.0 3839562.97 1.0\n"
                "stress-ng: metrc: [1] memcpy 1 30.00 1.0 0.0 1599.48 1.0\n",
                encoding="utf-8",
            )
            (single_run / "perf" / "repeat_1_stat.perf_stat.csv").write_text(
                "2738492,,context-switches,1,100.00,,\n",
                encoding="utf-8",
            )

            matrix_dir.mkdir(parents=True)
            (matrix_dir / "analysis_metrics.tsv").write_text(
                "\t".join(
                    [
                        "seq",
                        "variant",
                        "benchmark",
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
                )
                + "\n"
                + "\t".join(
                    [
                        "01",
                        "cake-release-default",
                        "stress-ng-cpu-cache-mem",
                        "cache_ops",
                        "5213078.50",
                        "higher",
                        "bogo_ops/s",
                        "log",
                        "30.03",
                        "cache_ops",
                        "5213078.50",
                        "higher",
                        "bogo_ops/s",
                        "480403.61",
                        "1004683",
                        "258938",
                        "repeat_1",
                        str(matrix_run),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (matrix_dir / "analysis_native_metrics.tsv").write_text(
                "seq\tvariant\tbenchmark\trepeat\tmetric\tvalue\tdirection\tunit\tsource\trun_dir\n"
                f"01\tcake-release-default\tstress-ng-cpu-cache-mem\trepeat_1\tstress_memcpy_bogo_ops_per_s_realtime\t3430.92\thigher\tbogo_ops/s\tlog\t{matrix_run}\n",
                encoding="utf-8",
            )

            first = cakebench_history.import_old_runs(
                runs_root=runs_root,
                history_root=bench / "history",
                scx_repo=repo,
                bench_repo=bench,
            )
            second = cakebench_history.import_old_runs(
                runs_root=runs_root,
                history_root=bench / "history",
                scx_repo=repo,
                bench_repo=bench,
            )
            records = cakebench_history.read_ledger(bench / "history" / "runs.jsonl")
            best = json.loads((bench / "history" / "best.json").read_text(encoding="utf-8"))
            catalog = json.loads((bench / "history" / "catalog.json").read_text(encoding="utf-8"))

            self.assertEqual(first["added"], 2)
            self.assertEqual(second["added"], 0)
            self.assertEqual(len(records), 2)
            self.assertEqual(best["stress_cache_bogo_ops_per_s"]["value"], 5213078.50)
            self.assertEqual(best["stress_memcpy_bogo_ops_per_s"]["value"], 3430.92)
            self.assertEqual(catalog["sources"]["single_import"], 1)
            self.assertEqual(catalog["sources"]["matrix_import"], 1)


if __name__ == "__main__":
    unittest.main()
