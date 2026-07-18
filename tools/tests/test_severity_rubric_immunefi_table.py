"""Loop-fix 2026-06-22: severity_rubric.parse_tier_rows recognized 3 SEVERITY.md formats
(dydx bullets, spark `| CRIT-1 | impact | USD |`, hyperbridge) but NOT the Immunefi-standard
"tier-in-first-column" table (`| Critical | Direct theft... |`, tier in col-1 under CATEGORY
headings like `## Smart Contract`). Polygon uses that format -> parse_tier_rows returned 0 rows
-> RUBRIC-COVERAGE-WORKSPACE failed `fail-no-rubric-rows` and R52 was unsatisfiable for every
finding. The 4th-format pass fixes it. Header/separator rows must NOT be mis-parsed; the
existing spark 3-column format must still parse (no regression).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_LIB = Path(__file__).resolve().parent.parent / "lib"
if str(_LIB) not in sys.path:
    sys.path.insert(0, str(_LIB))
import severity_rubric as sr  # noqa: E402


_IMMUNEFI = """# SEVERITY - Example

## Smart Contract - impacts in scope

| Severity | Impact (verbatim) |
|----------|-------------------|
| Critical | Direct theft of any user funds, whether at-rest or in-motion |
| Critical | Permanent freezing of funds |
| High     | Theft of unclaimed yield |
| Medium   | Griefing (damage to users/protocol with no direct attacker profit) |

## Blockchain / DLT - impacts in scope

| Severity | Impact (verbatim) |
|----------|-------------------|
| Critical | Direct loss of funds |
| High     | Transient consensus failures |
"""

_SPARK = """### Critical (Blockchain/DLT)

| ID | Impact | Reward |
|----|--------|--------|
| CRIT-1 | Direct loss of funds | USD 100,000 |
"""


class TestImmunefiTierColumnTable(unittest.TestCase):
    def test_immunefi_tier_first_column_parses(self):
        rows = sr.parse_tier_rows(_IMMUNEFI)
        self.assertEqual(len(rows), 6, f"expected 6 impact rows, got {len(rows)}")
        tiers = sorted(sr.tier_set(rows))
        self.assertEqual(tiers, ["critical", "high", "medium"])
        sents = " ".join(r.sentence for r in rows)
        self.assertIn("Direct theft of any user funds", sents)
        self.assertIn("Transient consensus failures", sents)

    def test_no_header_or_separator_rows(self):
        rows = sr.parse_tier_rows(_IMMUNEFI)
        for r in rows:
            self.assertNotIn(r.sentence.lower(), ("impact (verbatim)", "severity"))
            self.assertFalse(set(r.sentence) <= set("-: "), "separator row leaked")

    def test_spark_3col_still_parses(self):
        rows = sr.parse_tier_rows(_SPARK)
        self.assertTrue(any(r.tier == "critical" and "Direct loss of funds" in r.sentence for r in rows))


if __name__ == "__main__":
    unittest.main(verbosity=2)
