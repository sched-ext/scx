import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import cakebench_mutation_report


def ledger_record(
    mutation_id: str,
    *,
    decision: str,
    delta: float,
    common_rows: int,
    missing: list[str] | None = None,
    kind: str = "policy",
    size: str = "S",
    subsystem: str = "dispatch",
    concepts: list[str] | None = None,
    wall: float = 0.0,
) -> dict:
    return {
        "created_utc": "2026-05-16T00:00:00Z",
        "decision": decision,
        "equal_weight_delta_pct": delta,
        "mutation": {
            "id": mutation_id,
            "kind": kind,
            "size": size,
            "subsystem": subsystem,
            "concepts": concepts or ["branch-reduction"],
            "decision": decision,
        },
        "coverage": {
            "common_rows": common_rows,
            "missing_in_candidate": missing or [],
        },
        "wallclock": {
            "primary_lower_wall_delta_pct": wall,
            "wall_seconds_delta_pct": wall,
        },
    }


class CakebenchMutationReportTests(unittest.TestCase):
    def test_summary_splits_comma_concepts_and_counts_positive_full_keeps(self):
        records = [
            ledger_record(
                "good",
                decision="keep",
                delta=1.2,
                common_rows=14,
                concepts=["branch-reduction,hot-read-elimination"],
                wall=0.1,
            ),
            ledger_record(
                "bad",
                decision="revert",
                delta=-2.0,
                common_rows=7,
                concepts=["branch-reduction"],
            ),
        ]

        summary = cakebench_mutation_report.summarize_records(records)

        self.assertEqual(summary["total_records"], 2)
        self.assertEqual(summary["positive_full_keep_records"], 1)
        branch = summary["groups"]["concept:branch-reduction"]
        self.assertEqual(branch["records"], 2)
        self.assertEqual(branch["positive_full_keep_records"], 1)
        self.assertIn("concept:hot-read-elimination", summary["groups"])

    def test_later_revert_supersedes_historical_positive_keep(self):
        records = [
            ledger_record(
                "s20_busy_owner_short_200us_full",
                decision="keep",
                delta=0.5,
                common_rows=14,
                wall=0.1,
            ),
            ledger_record(
                "s20_busy_owner_short_200us_revert_decision",
                decision="revert",
                delta=-1.3,
                common_rows=14,
                wall=0.1,
            ),
        ]

        summary = cakebench_mutation_report.summarize_records(records)

        self.assertEqual(summary["historical_positive_full_keep_records"], 1)
        self.assertEqual(summary["positive_full_keep_records"], 0)
        self.assertEqual(summary["latest_decisions_by_family"]["s20"], "revert")

    def test_group_best_and_worst_prefer_full_suite_over_noisy_singles(self):
        records = [
            ledger_record(
                "single_huge_win",
                decision="keep",
                delta=44.4,
                common_rows=1,
                kind="policy",
                concepts=["routing"],
            ),
            ledger_record(
                "full_small_win",
                decision="keep",
                delta=0.6,
                common_rows=14,
                kind="policy",
                concepts=["routing"],
            ),
            ledger_record(
                "full_loss",
                decision="revert",
                delta=-1.2,
                common_rows=14,
                kind="policy",
                concepts=["routing"],
            ),
        ]

        summary = cakebench_mutation_report.summarize_records(records)

        group = summary["groups"]["concept:routing"]
        self.assertEqual(group["representative_rank_scope"], "full-suite")
        self.assertEqual(group["best"]["id"], "full_small_win")
        self.assertEqual(group["worst"]["id"], "full_loss")

    def test_cli_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ledger = root / "ledger.jsonl"
            out_json = root / "summary.json"
            out_md = root / "summary.md"
            ledger.write_text(
                json.dumps(
                    ledger_record(
                        "good",
                        decision="keep",
                        delta=0.5,
                        common_rows=14,
                        kind="hot-path-codegen",
                        concepts=["instruction reduction"],
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            rc = cakebench_mutation_report.main(
                [
                    "--ledger",
                    str(ledger),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                ]
            )

            self.assertEqual(rc, 0)
            data = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(data["positive_full_keep_records"], 1)
            self.assertIn("Mutation Style Summary", out_md.read_text(encoding="utf-8"))

    def test_script_help_and_repo_wrapper_expose_mutation_report(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "cakebench_mutation_report.py"), "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Summarize scx_cake mutation ledger patterns", result.stdout)

        wrapper = subprocess.run(
            [str(ROOT / "cakebench"), "mutation-report", "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(wrapper.returncode, 0)
        self.assertIn("Summarize scx_cake mutation ledger patterns", wrapper.stdout)


if __name__ == "__main__":
    unittest.main()
