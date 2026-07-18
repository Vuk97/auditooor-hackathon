"""Regression: _executed_call_count must parse medusa >=1.5's progress-line format
("calls: N ( M/sec)") as the MAX cumulative total, while still SUMMING forge's
per-invariant "calls: N". Before the fix the reader only knew "Total calls:" /
"calls tested:" so a genuine medusa 1.5.1 campaign parsed to 0 (uncreditable under
strict), and a naive shared regex either summed the cumulative snapshots (massive
over-count -> fabrication-flag mismatch) or backtracked and truncated the number.
Verified against a real 1,217,043-call DedicatedVaultRouter run (NUVA 2026-07-06)."""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "ifc_calls", os.path.join(_HERE, "..", "invariant-fuzz-completeness.py"))
_ifc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ifc)


class TestMedusaCallsParse(unittest.TestCase):
    def test_medusa_progress_takes_max_not_sum(self):
        log = (
            "fuzz: elapsed: 3s, calls:      46110 ( 15368/sec), seq/s: 311\n"
            "fuzz: elapsed: 6s, calls:      91356 ( 15076/sec), seq/s: 301\n"
            "fuzz: elapsed: 1m27s, calls:    1217043 ( 13565/sec), seq/s: 271\n"
        )
        # MAX of the cumulative snapshots, NOT their sum (which would be ~1.35M here).
        self.assertEqual(_ifc._executed_call_count(log), 1217043)

    def test_forge_per_invariant_still_summed(self):
        log = "invariant_a() (calls: 500000)\ninvariant_b() (calls: 600000)\n"
        self.assertEqual(_ifc._executed_call_count(log), 1100000)

    def test_medusa_500k_smoke_stays_below_1m(self):
        log = "fuzz: elapsed: 30s, calls:  500172 ( 15000/sec)\n"
        self.assertEqual(_ifc._executed_call_count(log), 500172)

    def test_total_calls_legacy_format_still_parsed(self):
        self.assertEqual(_ifc._executed_call_count("Total calls: 1,024,000"), 1024000)


if __name__ == "__main__":
    unittest.main()
