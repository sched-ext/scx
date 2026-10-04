import unittest

from analyze import summarize


def fixture():
    rows = [{"type": "environment", "check_only": False, "repeat": 10, "blocks": 2},
            {"type": "correctness", "program_runs": 5780, "mismatches": 0}]
    for op in ("ctz", "pop"):
        for chain in (0, 1):
            for batch in (64, 256, 1024):
                for block in range(2):
                    for slot in range(4):
                        native = bool(slot in (1, 2)) ^ bool(block & 1)
                        rows.append({"type": "timing", "name": ("hw_" if native else "sw_") + op,
                                     "chain": chain, "batch": batch, "block": block, "slot": slot,
                                     "repeat": 10, "wall_ns": batch * 10 * (5 if native else 8),
                                     "seed": "1234", "checksum": "5678"})
    return rows


class AnalysisTests(unittest.TestCase):
    def test_known_paired_saving(self):
        result = summarize(fixture())
        self.assertEqual(len(result), 12)
        self.assertTrue(all(r["saving_ns_per_op"] == 3 for r in result))
        self.assertTrue(all(r["paired_bootstrap_95_ci"] is None for r in result))

    def test_rejects_incomplete_block(self):
        with self.assertRaises(ValueError):
            summarize(fixture()[:-1])

    def test_rejects_missing_whole_group(self):
        with self.assertRaises(ValueError):
            summarize(fixture()[:-8])

    def test_rejects_mismatched_results(self):
        rows = fixture()
        rows[-1]["checksum"] = "bad"
        with self.assertRaises(ValueError):
            summarize(rows)

    def test_rejects_wrong_order(self):
        rows = fixture()
        rows[-1]["name"] = "sw_pop"
        with self.assertRaises(ValueError):
            summarize(rows)

    def test_rejects_failed_correctness(self):
        rows = fixture()
        rows[1]["mismatches"] = 1
        with self.assertRaises(ValueError):
            summarize(rows)

    def test_rejects_duplicate_slot(self):
        rows = fixture()
        with self.assertRaises(ValueError):
            summarize(rows + [rows[-1]])


if __name__ == "__main__":
    unittest.main()
