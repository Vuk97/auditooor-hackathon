from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / "callback_reentrancy_no_guard.yaml"
POSITIVE = ROOT / "detectors" / "fixtures" / "callback_reentrancy_no_guard_dsl" / "positive.sol"
CLEAN = ROOT / "detectors" / "fixtures" / "callback_reentrancy_no_guard_dsl" / "clean.sol"
MORPHO_PRELIQUIDATION = Path("/Users/wolf/audits/morpho/src/pre-liquidation/src/PreLiquidation.sol")


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReentrancyRecallLiftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest")
        cls.engine = cls.backtest._import_engine()
        cls.spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

    def _hits(self, path: Path) -> int:
        hits, error = self.backtest.run_pattern_on_file(self.spec, path, self.engine)
        if error and error.startswith("slither-import-error"):
            self.skipTest(error)
        self.assertIsNone(error)
        return hits

    def test_callback_dsl_catches_token_and_callback_before_settlement_shapes(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 2)

    def test_callback_dsl_suppresses_guarded_and_inverse_cei_shapes(self) -> None:
        self.assertEqual(self._hits(CLEAN), 0)

    def test_external_morpho_preliquidation_sample_fires_when_available(self) -> None:
        if not MORPHO_PRELIQUIDATION.is_file():
            self.skipTest("Morpho pre-liquidation checkout is not present")

        hits, error = self.backtest.run_pattern_on_file(
            self.spec,
            MORPHO_PRELIQUIDATION,
            self.engine,
        )
        if error and error.startswith(("compile-error", "slither-import-error")):
            self.skipTest(error)
        self.assertIsNone(error)
        self.assertGreaterEqual(hits, 1)

    def test_dsl_uses_invariant_shape_not_receiver_inheritance_only(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn("include_leaf_helpers: true", text)
        self.assertIn("function.body_ordered_regex", text)
        self.assertIn("safeTransferFrom", text)
        self.assertNotIn("contract.inherits_any", text)


if __name__ == "__main__":
    unittest.main()
