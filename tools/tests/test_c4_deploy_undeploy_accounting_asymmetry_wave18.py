from __future__ import annotations

import importlib.util
import os
import py_compile
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "c4-deploy-undeploy-accounting-asymmetry"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
DETECTOR = ROOT / "detectors" / "wave18" / "c4_deploy_undeploy_accounting_asymmetry.py"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class C4DeployUndeployAccountingAsymmetryWave18Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile_worker_av")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder_worker_av")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest_worker_av")

    def test_reference_yaml_stays_accounting_state_scoped(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))
        self.assertIn("accounting-state", spec.get("tags", []))
        self.assertIn("paired-state-asymmetry", spec.get("tags", []))

        classified = self.classifier.classify_pattern(spec, PATTERN)
        self.assertEqual(classified["attack_class"], "fund-loss-via-arithmetic")
        self.assertEqual(self.backtest.derive_attack_class(PATTERN, spec.get("tags")), "fund-loss-via-arithmetic")

        shared_map = yaml.safe_load(
            (ROOT / "reference" / "detector_class_map_complete.yaml").read_text(encoding="utf-8")
        )
        row = shared_map["mappings"][PATTERN]
        self.assertEqual(row["attack_class"], "fund-loss-via-arithmetic")
        self.assertEqual(row["evidence"], "description")

    def test_pattern_compiles_under_strict_guards_into_wave18_shape(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            ok = self.compiler.compile_pattern(
                REFERENCE,
                Path(tmp) / "wave18",
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
        self.assertTrue(ok)

        py_compile.compile(str(DETECTOR), doraise=True)
        source = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', source)
        self.assertIn("contract.has_function_body_matching", source)
        self.assertIn("function.body_not_contains_regex", source)

    def test_fixtures_model_the_intended_accounting_asymmetry(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("_deployedAmount += amount;", positive)
        self.assertIn("market.redeem(amount);", positive)
        self.assertNotIn("_deployedAmount -= amount;", positive)

        self.assertIn("_deployedAmount += amount;", clean)
        self.assertIn("_deployedAmount -= amount;", clean)
        self.assertIn("market.redeem(amount);", clean)

    def test_direct_pattern_runner_hits_positive_and_skips_clean(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        engine = self.backtest._import_engine()

        positive_hits, positive_error = self.backtest.run_pattern_on_file(spec, POSITIVE, engine)
        self.assertIsNone(positive_error)
        self.assertEqual(positive_hits, 1)

        clean_hits, clean_error = self.backtest.run_pattern_on_file(spec, CLEAN, engine)
        self.assertIsNone(clean_error)
        self.assertEqual(clean_hits, 0)


if __name__ == "__main__":
    unittest.main()
