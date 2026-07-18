from __future__ import annotations

import importlib.util
import json
import logging
import os
import py_compile
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "incorrect-is-source-logic"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "syntax_broken"
    / "incorrect_is_source_logic.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "incorrect_is_source_logic"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


def _python_can_import_slither() -> bool:
    try:
        import slither  # type: ignore  # noqa: F401
        import slither.detectors.abstract_detector  # type: ignore  # noqa: F401
    except ImportError:
        return False
    return True


def _load_detector_class():
    if str(DETECTOR.parents[2]) not in sys.path:
        sys.path.insert(0, str(DETECTOR.parents[2]))
    spec = importlib.util.spec_from_file_location("incorrect_is_source_logic", DETECTOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load detector spec from {DETECTOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.IncorrectIsSourceLogic


class IncorrectIsSourceLogicTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        if not _python_can_import_slither():
            self.skipTest("slither-analyzer is not importable by the tested Python interpreter")

        from slither import Slither  # type: ignore

        detector_class = _load_detector_class()
        slither = Slither(str(fixture))
        hits = 0
        logger = logging.getLogger(f"auditooor.{PATTERN}.test")
        old_smoke_mode = os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE")
        os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        try:
            for compilation_unit in slither.compilation_units:
                detector = detector_class(compilation_unit, slither, logger)
                hits += len(detector.detect())
        finally:
            if old_smoke_mode is None:
                os.environ.pop("AUDITOOOR_FIXTURE_SMOKE_MODE", None)
            else:
                os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = old_smoke_mode
        return hits

    def test_detector_compiles_and_reference_points_at_owned_fixtures(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        reference = REFERENCE.read_text(encoding="utf-8")
        self.assertIn("vuln: detectors/fixtures/incorrect_is_source_logic/positive.sol", reference)
        self.assertIn("clean: detectors/fixtures/incorrect_is_source_logic/clean.sol", reference)
        self.assertIn("Fixture-smoke/source-shape proof only", reference)

    def test_smoke_metadata_marks_not_submit_ready(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_slug"], "incorrect_is_source_logic")
        self.assertEqual(payload["detector_path"], "detectors/wave17/incorrect_is_source_logic.py")
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertIn(
            "python3 detectors/run_custom.py --tier=ALL detectors/fixtures/incorrect_is_source_logic/positive.sol incorrect-is-source-logic",
            payload["positive_command"],
        )
        self.assertIn(
            "python3 detectors/run_custom.py --tier=ALL detectors/fixtures/incorrect_is_source_logic/clean.sol incorrect-is-source-logic",
            payload["clean_command"],
        )
        self.assertIn("source-shape proof only", payload["limitation_note"])

    def test_fixture_pair_models_raw_vs_negated_source_prefix_polarity(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn('string.concat(sourcePort, "/", sourceChannel, "/")', positive)
        self.assertIn("return _startsWith(denom, prefix);", positive)
        self.assertIn("return !_startsWith(denom, prefix);", clean)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
