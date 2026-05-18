import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import cakebench_bpf_audit


SAMPLE_OBJDUMP = """
0000000000000000 <hot_func>:
       0:       r1 = *(u64 *)(r10 - 0x8)
       1:       if r1 == 0x0 goto +0x2 <hot_func+0x18>
       2:       call -0x1
       3:       *(u64 *)(r10 - 0x10) = r0
       4:       exit

0000000000000028 <other_func>:
       5:       r0 = 0x1
       6:       goto -0x1 <other_func>
"""


class CakebenchBpfAuditTests(unittest.TestCase):
    def test_parse_objdump_counts_hot_function_hazards(self):
        report = cakebench_bpf_audit.audit_objdump_text(SAMPLE_OBJDUMP, ["hot_func", "other_func"])

        self.assertEqual(report["hot_func"]["instructions"], 5)
        self.assertEqual(report["hot_func"]["branches"], 1)
        self.assertEqual(report["hot_func"]["calls"], 1)
        self.assertEqual(report["hot_func"]["stack_refs"], 2)
        self.assertEqual(report["hot_func"]["stack_load_refs"], 1)
        self.assertEqual(report["hot_func"]["stack_store_refs"], 1)
        self.assertEqual(report["hot_func"]["loads"], 1)
        self.assertEqual(report["hot_func"]["stores"], 1)
        self.assertEqual(report["other_func"]["branches"], 1)

    def test_stack_access_shape_flags_partial_overlap_risk(self):
        lines = [
            "    0: *(u32 *)(r10 - 0x4) = r1",
            "    1: r2 = *(u64 *)(r10 - 0x8)",
            "    2: *(u64 *)(r10 - 0x10) = r3",
            "    3: r4 = *(u32 *)(r10 - 0xc)",
            "    4: r5 = *(u64 *)(r10 - 0x10)",
        ]

        shape = cakebench_bpf_audit.stack_access_shape(lines)

        self.assertEqual(shape["relation_counts"]["store_contained_in_load"], 1)
        self.assertEqual(shape["relation_counts"]["load_contained_in_store"], 1)
        self.assertEqual(shape["relation_counts"]["exact"], 1)
        self.assertEqual(shape["stlf_risk_loads"], 1)

    def test_delta_counts_reports_candidate_minus_baseline(self):
        baseline = {"hot_func": {"instructions": 5, "branches": 1}}
        candidate = {"hot_func": {"instructions": 4, "branches": 2}}

        delta = cakebench_bpf_audit.delta_counts(baseline, candidate)

        self.assertEqual(delta["hot_func"]["instructions"], -1)
        self.assertEqual(delta["hot_func"]["branches"], 1)

    def test_sha256_file_hashes_artifact_contents(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "artifact.o"
            path.write_bytes(b"cake")

            self.assertEqual(
                cakebench_bpf_audit.sha256_file(path),
                "32cdb619196200050ab0af581a10fb83cfc63b1a20f58d4bafb6313d55a3f0e9",
            )

    def test_render_markdown_includes_comparison(self):
        report = {
            "created_utc": "2026-05-16T00:00:00Z",
            "functions": ["hot_func"],
            "baseline": {
                "path": "/tmp/base.o",
                "size_bytes": 100,
                "sha256": "basehash",
                "functions": {"hot_func": cakebench_bpf_audit.count_function([])},
            },
            "candidate": {
                "path": "/tmp/cand.o",
                "size_bytes": 92,
                "sha256": "candhash",
                "functions": {"hot_func": cakebench_bpf_audit.count_function(["    0: exit"])},
            },
            "delta": {
                "size_bytes": -8,
                "functions": {
                    "hot_func": cakebench_bpf_audit.delta_counts(
                        {"hot_func": cakebench_bpf_audit.count_function([])},
                        {"hot_func": cakebench_bpf_audit.count_function(["    0: exit"])},
                    )["hot_func"]
                },
            },
        }

        text = cakebench_bpf_audit.render_markdown(report)

        self.assertIn("BPF Hot-Function Audit", text)
        self.assertIn("Size delta", text)
        self.assertIn("Candidate SHA256", text)
        self.assertIn("hot_func", text)

    def test_script_help_and_repo_wrapper_expose_bpf_audit(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "cakebench_bpf_audit.py"), "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Audit scx_cake BPF hot-function instruction shape", result.stdout)

        wrapper = subprocess.run(
            [str(ROOT / "cakebench"), "bpf-audit", "--help"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(wrapper.returncode, 0)
        self.assertIn("Audit scx_cake BPF hot-function instruction shape", wrapper.stdout)

    def test_cli_writes_json_and_markdown_from_fake_build_report(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            out_json = root / "audit.json"
            out_md = root / "audit.md"
            report = {
                "created_utc": "2026-05-16T00:00:00Z",
                "functions": ["hot_func"],
                "object": {
                    "path": "/tmp/fake.o",
                    "size_bytes": 10,
                    "sha256": "fakehash",
                    "functions": {"hot_func": cakebench_bpf_audit.count_function(["    0: exit"])},
                },
            }
            out_json.write_text(json.dumps(report), encoding="utf-8")
            out_md.write_text(cakebench_bpf_audit.render_markdown(report), encoding="utf-8")

            self.assertEqual(json.loads(out_json.read_text(encoding="utf-8"))["object"]["size_bytes"], 10)
            self.assertIn("fake.o", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
