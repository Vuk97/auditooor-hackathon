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
PATTERN = "oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "oracle_decimal_mis_scaling_hardcoded_scale_without_feed_decimals.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "oracle_decimal_mis_scaling_hardcoded_scale_without_feed_decimals"
)
ALT_FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals"
)
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
ALT_POSITIVE = ALT_FIXTURE_DIR / "positive.sol"
ALT_CLEAN = ALT_FIXTURE_DIR / "clean.sol"
ALT_SMOKE = ALT_FIXTURE_DIR / "smoke.json"


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
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class OracleDecimalMisScalingHardcodedScaleWithoutFeedDecimalsTest(unittest.TestCase):
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
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_scope_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn("_ORACLE_SIGS", detector_text)
        self.assertIn("_HARDCODED_SCALE_SOURCE_RE", detector_text)
        self.assertIn("_DYNAMIC_DECIMALS_SOURCE_RE", detector_text)
        self.assertNotIn("state_write_without_paired_write", detector_text)

        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn(str(ALT_POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(ALT_CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("Fixture-smoke/source-shape proof only", reference_text)

        self.assertIn("function quoteCollateralValue(uint256 collateralAmount)", positive_text)
        self.assertIn("priceFeed.latestRoundData()", positive_text)
        self.assertIn("return collateralAmount * oraclePrice / 1e18;", positive_text)
        self.assertNotIn("priceFeed.decimals()", positive_text)

        self.assertIn("function quoteCollateralValue(uint256 collateralAmount)", clean_text)
        self.assertIn("uint8 feedDecimals = priceFeed.decimals();", clean_text)
        self.assertIn("10 ** uint256(feedDecimals)", clean_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("AUDITOOOR_FIXTURE_SMOKE_MODE=1", payload["positive_command"])
        self.assertIn("AUDITOOOR_SLITHER_NOCACHE=1", payload["clean_command"])
        self.assertIn("not real-corpus exploit evidence", payload["limitation_note"])

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), ALT_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), ALT_CLEAN.read_text(encoding="utf-8"))

        canonical = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror = json.loads(ALT_SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(canonical["pattern"], mirror["pattern"])
        self.assertEqual(canonical["positive_hits"], mirror["positive_hits"])
        self.assertEqual(canonical["clean_hits"], mirror["clean_hits"])
        self.assertEqual(mirror["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
