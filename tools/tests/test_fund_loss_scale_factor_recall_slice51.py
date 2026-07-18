from __future__ import annotations

import importlib.util
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "scale-factor-ratio-no-positive-postcheck"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
VULN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
CONSTRUCTOR_VULN = ROOT / "detectors" / "test_fixtures" / "constructor_precision_factor_truncates_to_zero_vulnerable.sol"
CONSTRUCTOR_CLEAN = ROOT / "detectors" / "test_fixtures" / "constructor_precision_factor_truncates_to_zero_clean.sol"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class FundLossScaleFactorRecallSlice51Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile_slice51")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder_slice51")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest_slice51")

    def test_pattern_metadata_and_taxonomy(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(spec["fixtures"]["vuln"], str(VULN.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))
        self.assertIn("fund-loss-via-arithmetic", spec.get("tags", []))

        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "fund-loss-via-arithmetic",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "fund-loss-via-arithmetic",
        )

        shared_map = yaml.safe_load(
            (ROOT / "reference" / "detector_class_map_complete.yaml").read_text(encoding="utf-8")
        )
        row = shared_map["mappings"][PATTERN]
        self.assertEqual(row["attack_class"], "fund-loss-via-arithmetic")
        self.assertEqual(row["evidence"], "tags")

    def test_pattern_compiles_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            ok = self.compiler.compile_pattern(
                REFERENCE,
                Path(tmp) / "wave18",
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
        self.assertTrue(ok)

    def test_direct_pattern_runner_hits_positive_and_sibling_sample(self) -> None:
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        engine = self.backtest._import_engine()
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        positive_hits, positive_error = self.backtest.run_pattern_on_file(spec, VULN, engine)
        self.assertIsNone(positive_error)
        self.assertGreaterEqual(positive_hits, 1)

        sibling_hits, sibling_error = self.backtest.run_pattern_on_file(spec, CONSTRUCTOR_VULN, engine)
        self.assertIsNone(sibling_error)
        self.assertGreaterEqual(sibling_hits, 1)

        clean_hits, clean_error = self.backtest.run_pattern_on_file(spec, CLEAN, engine)
        self.assertIsNone(clean_error)
        self.assertEqual(clean_hits, 0)

        constructor_clean_hits, constructor_clean_error = self.backtest.run_pattern_on_file(
            spec, CONSTRUCTOR_CLEAN, engine
        )
        self.assertIsNone(constructor_clean_error)
        self.assertEqual(constructor_clean_hits, 0)

        clean_source = CLEAN.read_text(encoding="utf-8")
        self.assertIn("quoteVaultConversionSample >= baseVaultConversionSample", clean_source)
        self.assertIn("TimeoutConfigRatioClean", clean_source)
        self.assertIn("LiteralScaleRatioClean", clean_source)

    def test_run_custom_sees_generated_detector_on_positive_and_clean(self) -> None:
        python = _python_with_slither()
        if python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        for path, expected_hits in ((VULN, True), (CLEAN, False)):
            with self.subTest(path=path.name):
                proc = subprocess.run(
                    [
                        python,
                        str(RUN_CUSTOM),
                        "--tier=ALL",
                        str(path),
                        PATTERN,
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertIn("[ok] loaded 1 custom detector(s)", proc.stdout)
                self.assertIn(f"=== Running {PATTERN} ===", proc.stdout)
                if expected_hits:
                    self.assertRegex(proc.stdout, r"\[done\] total hits: [1-9][0-9]*")
                else:
                    self.assertIn("[done] total hits: 0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
