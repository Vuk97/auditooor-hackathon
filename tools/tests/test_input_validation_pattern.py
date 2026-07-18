from __future__ import annotations

import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
PATTERN = REPO / "reference" / "patterns.dsl" / "input-validation.yaml"
POSITIVE = REPO / "detectors" / "_fixtures" / "input_validation" / "positive.sol"
CLEAN = REPO / "detectors" / "_fixtures" / "input_validation" / "clean.sol"
CLEAN_SELECTOR_BAN = (
    REPO
    / "detectors"
    / "_fixtures"
    / "input_validation"
    / "clean_selector_ban.sol"
)
COMPILER = REPO / "tools" / "pattern-compile.py"


def _load_compiler():
    spec = importlib.util.spec_from_file_location("pattern_compile", COMPILER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _pattern_spec() -> dict:
    return yaml.safe_load(PATTERN.read_text(encoding="utf-8"))


def _regexes_for(key: str) -> list[str]:
    spec = _pattern_spec()
    return [pred[key] for pred in spec["match"] if key in pred]


class InputValidationPatternTest(unittest.TestCase):
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
            emitted = (wave / "input_validation.py").read_text(encoding="utf-8")
            self.assertIn('ARGUMENT = "input-validation"', emitted)
            self.assertIn("CONFIDENCE = DetectorClassification.LOW", emitted)
            self.assertIn("_INCLUDE_LEAF_HELPERS = True", emitted)

    def test_safe_fallback_handler_regex_matches_positive_fixture(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        source_regexes = _regexes_for("function.source_matches_regex")

        for pattern in source_regexes:
            self.assertRegex(positive, re.compile(pattern, re.IGNORECASE))
        self.assertIn("SET_FALLBACK_HANDLER_SELECTOR", positive)
        self.assertNotIn("allowedFallbackHandlers[", positive)

    def test_guard_regex_suppresses_clean_fixture(self) -> None:
        clean = CLEAN.read_text(encoding="utf-8")
        suppressors = _regexes_for("function.not_source_matches_regex")

        self.assertRegex(clean, re.compile(suppressors[0], re.IGNORECASE))
        self.assertIn("allowedFallbackHandlers[handler]", clean)
        self.assertIn("revert UnauthorizedFallbackHandler(handler)", clean)

    def test_guard_regex_suppresses_selector_ban_clean_fixture(self) -> None:
        clean = CLEAN_SELECTOR_BAN.read_text(encoding="utf-8")
        source_regexes = _regexes_for("function.source_matches_regex")
        suppressors = _regexes_for("function.not_source_matches_regex")

        for pattern in source_regexes:
            self.assertRegex(clean, re.compile(pattern, re.IGNORECASE))
        self.assertRegex(clean, re.compile(suppressors[0], re.IGNORECASE))
        self.assertIn("SET_FALLBACK_HANDLER_SELECTOR", clean)
        self.assertIn("revert FallbackHandlerChangesDisabled()", clean)


if __name__ == "__main__":
    unittest.main()
