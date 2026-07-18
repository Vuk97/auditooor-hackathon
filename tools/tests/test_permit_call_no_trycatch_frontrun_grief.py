"""Fixture-pair self-test for the permit-call-no-trycatch-frontrun-grief detector.

This is a same-class generalizer for the transaction-ordering-race attack class
(approve/permit front-run family). It evaluates the DSL pattern directly via
detectors/_predicate_engine.py - the same engine the catch-rate backtest and the
compiled Slither detectors use - so the test does not depend on the compiled
wave* tree being in sync.

Asserted invariants:
  * the pattern fires on its OWN vulnerable fixture (>=1 hit),
  * the pattern stays SILENT on its OWN clean fixture (0 hits) - no FP,
  * the reference YAML points at the owned fixture pair,
  * the detector is registered as transaction-ordering-race in the class map.
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATTERN = "permit-call-no-trycatch-frontrun-grief"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "permit_call_no_trycatch_frontrun_grief"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"


def _imports_ok() -> bool:
    try:
        import yaml  # noqa: F401
        import slither  # noqa: F401
        return True
    except Exception:
        return False


def _hits(spec: dict, sol_path: Path) -> int:
    os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    sys.path.insert(0, str(ROOT / "detectors"))
    from _predicate_engine import eval_preconditions, eval_function_match
    from _template_utils import is_leaf_helper, is_vendored_or_test_contract
    from slither import Slither

    sl = Slither(str(sol_path))
    include_leaf = bool(spec.get("include_leaf_helpers", False))
    preconds = spec.get("preconditions") or []
    matches = spec.get("match") or []
    hits = 0
    for c in sl.contracts:
        if is_vendored_or_test_contract(c):
            continue
        if not eval_preconditions(c, preconds):
            continue
        for fn in c.functions_and_modifiers_declared:
            if not include_leaf and is_leaf_helper(fn):
                continue
            if eval_function_match(fn, matches):
                hits += 1
    return hits


class PermitCallNoTryCatchFrontrunGriefTest(unittest.TestCase):
    def _spec(self) -> dict:
        import yaml
        return yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(
            "vuln: detectors/fixtures/permit_call_no_trycatch_frontrun_grief/positive.sol",
            text,
        )
        self.assertIn(
            "clean: detectors/fixtures/permit_call_no_trycatch_frontrun_grief/clean.sol",
            text,
        )

    def test_tagged_transaction_ordering_race(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn("transaction-ordering-race", text)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        if not _imports_ok():
            self.skipTest("pyyaml / slither-analyzer not importable")
        spec = self._spec()
        self.assertGreaterEqual(_hits(spec, POSITIVE), 1)
        self.assertEqual(_hits(spec, CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
