from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "flash-loan-price-manipulation-spot-totals-preview"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "flash_loan_price_manipulation_spot_totals_preview.py"
)
SPEC_DRAFT = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / f"{PATTERN}.yaml"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "flash_loan_price_manipulation_spot_totals_preview"
POSITIVE = FIXTURE_DIR / "flash_loan_price_manipulation_spot_totals_preview_vulnerable.sol"
CLEAN = FIXTURE_DIR / "flash_loan_price_manipulation_spot_totals_preview_clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
SNIPPET = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "flash_loan_price_manipulation_spot_totals_preview.test.snippet"
)


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


class FlashLoanPriceManipulationSpotTotalsPreviewTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--include-graveyard",
                "--tier=ALL",
                str(fixture),
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_and_draft_capture_fixture_smoke_posture(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        draft_text = SPEC_DRAFT.read_text(encoding="utf-8")
        snippet_text = SNIPPET.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("preview|quote|spot|convert", detector_text)
        self.assertIn("twap|oracle|consult|observe|getprice|getoracle|latestrounddata", detector_text)
        self.assertIn("spot DEX reserves", draft_text)
        self.assertIn("totals", draft_text)
        self.assertIn("preview", draft_text)
        self.assertIn('"flash_loan_price_manipulation_spot_totals_preview_vulnerable.sol"', snippet_text)
        self.assertIn('"flash_loan_price_manipulation_spot_totals_preview_clean.sol"', snippet_text)
        self.assertFalse(REFERENCE.exists())

    def test_fixture_pair_and_smoke_record_stay_honest(self) -> None:
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn("function previewSpotTotals", positive_text)
        self.assertIn("reserveQuote", positive_text)
        self.assertIn("totalAssets", positive_text)
        self.assertNotIn("_oracleTwapQuote", positive_text)

        self.assertIn("function previewSpotTotals", clean_text)
        self.assertIn("_oracleTwapQuote", clean_text)
        self.assertIn("getOraclePrice", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertIn("--include-graveyard", payload["positive_command"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
