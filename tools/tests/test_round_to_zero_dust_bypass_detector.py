"""Unit test for the round-to-zero-dust-bypass-no-guard DSL detector.

Wave-2 arithmetic lift. Verifies the new same-class detector for the
integer-overflow-clamp / rounding-direction round-to-zero cluster:

  * self-test: fires on its own positive fixture, NOT on its clean fixture.
  * cross-fire recall: catches the 4 narrow sibling vuln fixtures
    (mint-fee / ec-fee / dust-redeem / glider-solvency) that each only
    cover one function name -- the same-class recall lift this detector
    exists for.
  * no over-fire: stays silent on each sibling's CLEAN fixture (correct
    rounding / zero-result guard), so the recall is not bought with FP.

The detector logic is the DSL preconditions/match evaluated by
detectors/_predicate_engine.py -- the same engine the catch-rate backtest
and the compiled Slither detectors use.
"""
from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PATTERN_YAML = REPO_ROOT / "reference/patterns.dsl/round-to-zero-dust-bypass-no-guard.yaml"

# fixture-smoke mode so fixture-named contracts are not vendored-filtered.
os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"

# Narrow sibling detectors this lift is meant to cross-cover. Each is keyed on
# ONE function name; held out, none of them catches the others -- the gap the
# general shape detector closes.
SIBLINGS = {
    "mint-fee-rounds-to-zero": (
        "patterns/fixtures/mint-fee-rounds-to-zero_vuln.sol",
        "patterns/fixtures/mint-fee-rounds-to-zero_clean.sol",
    ),
    "ec-fee-rounding-truncates-to-zero": (
        "patterns/fixtures/ec-fee-rounding-truncates-to-zero_vuln.sol",
        "patterns/fixtures/ec-fee-rounding-truncates-to-zero_clean.sol",
    ),
    "dust-redeem-floor-rounds-to-zero": (
        "patterns/fixtures/dust-redeem-floor-rounds-to-zero_vuln.sol",
        "patterns/fixtures/dust-redeem-floor-rounds-to-zero_clean.sol",
    ),
    "glider-rounding-to-zero-solvency-bypass": (
        "patterns/fixtures/glider-rounding-to-zero-solvency-bypass_vuln.sol",
        "patterns/fixtures/glider-rounding-to-zero-solvency-bypass_clean.sol",
    ),
}


def _load_backtest_module():
    spec = importlib.util.spec_from_file_location(
        "catch_rate_backtest", REPO_ROOT / "tools/audit/detector-catch-rate-backtest.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRoundToZeroDustBypassDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import slither  # noqa: F401
        except Exception:
            raise unittest.SkipTest("slither-analyzer is not importable")
        cls.bt = _load_backtest_module()
        try:
            cls.engine = cls.bt._import_engine()
        except Exception as e:  # pragma: no cover
            raise unittest.SkipTest(f"predicate engine unavailable: {e}")
        cls.pat = yaml.safe_load(PATTERN_YAML.read_text())

    def _hits(self, rel_path: str) -> int:
        h, err = self.bt.run_pattern_on_file(self.pat, str(REPO_ROOT / rel_path), self.engine)
        self.assertIsNone(err, f"eval error on {rel_path}: {err}")
        return h

    def test_pattern_yaml_well_formed(self):
        self.assertEqual(self.pat.get("pattern"), "round-to-zero-dust-bypass-no-guard")
        self.assertIn("integer-overflow-clamp", self.pat.get("tags", []))
        fx = self.pat.get("fixtures") or {}
        self.assertTrue((REPO_ROOT / fx["vuln"]).exists())
        self.assertTrue((REPO_ROOT / fx["clean"]).exists())

    def test_self_positive_fires(self):
        self.assertGreater(
            self._hits("detectors/fixtures/round-to-zero-dust-bypass-no-guard/positive.sol"),
            0,
            "detector must fire on its own positive fixture",
        )

    def test_self_clean_silent(self):
        self.assertEqual(
            self._hits("detectors/fixtures/round-to-zero-dust-bypass-no-guard/clean.sol"),
            0,
            "detector must NOT fire on its own clean fixture (no over-fire)",
        )

    def test_cross_fire_catches_all_siblings(self):
        for name, (vuln, _clean) in SIBLINGS.items():
            with self.subTest(sibling=name):
                self.assertGreater(
                    self._hits(vuln), 0,
                    f"same-class lift must catch sibling vuln {name}",
                )

    def test_no_over_fire_on_sibling_cleans(self):
        for name, (_vuln, clean) in SIBLINGS.items():
            with self.subTest(sibling=name):
                self.assertEqual(
                    self._hits(clean), 0,
                    f"detector must stay silent on sibling clean {name} (recall not bought with FP)",
                )


if __name__ == "__main__":
    unittest.main()
