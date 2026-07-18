#!/usr/bin/env python3
"""Guard test for D2-promotion-enricher.

A promoted hacker_question record (via _extract_dispatch_ledger_generic with
kind="hacker_question") must gain a NON-EMPTY target_function_patterns from the
canonical LIFT-28 enricher, so corpus-driven-hunt can route it. A detector_seed
row promoted via the SAME extractor must NOT gain routing fields - the
enrichment is gated strictly on kind == "hacker_question" and is additive.

Fail-before / pass-after: before the fix, the hacker_question row carried no
target_function_patterns key at all (every promotion was born flat).
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_PROMOTE = REPO_ROOT / "tools" / "promote-mined-to-canonical.py"
_spec = importlib.util.spec_from_file_location("promote_mined", str(_PROMOTE))
_pm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pm)


def _make_rec(item: dict) -> dict:
    """Wrap a single result-item dict as a dispatch-ledger record."""
    return {"task_id": "TASK-D2-GUARD", "status": "ok", "result": json.dumps(item)}


# An item whose lifted statement names a 'withdraw' role so the enricher
# back-derives a non-empty target_function_patterns for the grep-less row.
_ITEM = {
    "lifted_statement_any": "A withdraw call bypasses the access-control check.",
    "attack_class": "access-control",
}


class TestPromoteHackerQEnrichment(unittest.TestCase):
    def test_hacker_question_gains_routing_patterns(self):
        rows = _pm._extract_dispatch_ledger_generic(
            _make_rec(_ITEM), Path("hq_expansions/x.json"), "hq_expansions",
            kind="hacker_question",
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # The whole point of the fix: a routable needle exists.
        self.assertIn("target_function_patterns", row)
        self.assertTrue(
            row["target_function_patterns"],
            "promoted hacker_question must gain a NON-EMPTY "
            "target_function_patterns",
        )
        # Companion routing fields the enricher emits.
        self.assertIn("target_function_roles", row)
        self.assertIn("scope_specificity", row)
        # question_text was seeded from the lifted statement.
        self.assertEqual(
            row.get("question_text"), _ITEM["lifted_statement_any"]
        )

    def test_detector_seed_does_not_gain_routing_patterns(self):
        rows = _pm._extract_dispatch_ledger_generic(
            _make_rec(_ITEM), Path("detector_synthesis_v2/x.json"),
            "detector_synthesis_v2", kind="detector_seed",
        )
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertNotIn(
            "target_function_patterns", row,
            "detector_seed rows must remain untouched (enrichment is "
            "gated strictly on kind == 'hacker_question')",
        )
        self.assertNotIn("question_text", row)


if __name__ == "__main__":
    unittest.main()
