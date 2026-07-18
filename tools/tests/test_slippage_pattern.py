from __future__ import annotations

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
PATTERN = REPO / "reference" / "patterns.dsl" / "slippage.yaml"
POSITIVE = REPO / "detectors" / "_fixtures" / "slippage" / "positive.sol"
CLEAN = REPO / "detectors" / "_fixtures" / "slippage" / "clean.sol"
COMPILER = REPO / "tools" / "pattern-compile.py"


def _load_compiler():
    spec = importlib.util.spec_from_file_location("pattern_compile", COMPILER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _regex_for(key: str) -> str:
    spec = yaml.safe_load(PATTERN.read_text(encoding="utf-8"))
    for pred in spec["match"]:
        if key in pred:
            return pred[key]
    raise AssertionError(f"missing predicate {key}")


class SlippagePatternTest(unittest.TestCase):
    def test_pattern_compiles_under_strict_guards(self) -> None:
        compiler = _load_compiler()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            wave = Path(tmp) / "wave99"
            ok = compiler.compile_pattern(
                PATTERN,
                wave,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )

            self.assertTrue(ok)
            emitted = (wave / "slippage.py").read_text(encoding="utf-8")
            self.assertIn('ARGUMENT = "slippage"', emitted)
            self.assertIn("CONFIDENCE = DetectorClassification.MEDIUM", emitted)

    def test_literal_zero_min_output_regex_matches_positive_fixture(self) -> None:
        rx = re.compile(_regex_for("function.source_matches_regex"), re.IGNORECASE)
        positive = POSITIVE.read_text(encoding="utf-8")

        self.assertRegex(positive, rx)
        self.assertIn("amountOutMinimum: 0", positive)
        self.assertIn("curve.exchange(0, 1, amountIn, 0)", positive)

    def test_literal_zero_min_output_regex_skips_clean_fixture(self) -> None:
        rx = re.compile(_regex_for("function.source_matches_regex"), re.IGNORECASE)
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertNotRegex(clean, rx)
        self.assertIn("amountOutMinimum: amountOutMin", clean)
        self.assertIn("curve.exchange(0, 1, amountIn, minDy)", clean)
